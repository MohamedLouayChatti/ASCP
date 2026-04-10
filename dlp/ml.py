from typing import Any, Optional
import os

from .models import ScanSurface, DLPAction
from .config import DLPConfig

_engine = None

class MLInferenceEngine:
    def __init__(self, config: DLPConfig):
        self.config = config
        self.tokenizer = None
        self.model = None
        self._initialize_model()

    def _initialize_model(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel

        base_model = getattr(self.config, "ml_base_model", "unsloth/phi-2")
        lora_path = getattr(self.config, "ml_lora_path", None)

        self.tokenizer = AutoTokenizer.from_pretrained(base_model)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # Determine strict generation config (deterministic)
        self.model = AutoModelForCausalLM.from_pretrained(
            base_model,
            device_map="auto",
            torch_dtype=getattr(torch, "float16", torch.float32),
            low_cpu_mem_usage=True,
            trust_remote_code=True,
        )
        
        if lora_path and os.path.exists(lora_path):
            self.model = PeftModel.from_pretrained(self.model, lora_path)

        self.model.eval()

    def generate_allowed_action(self, text: str, surface: ScanSurface, features: dict[str, Any]) -> str:
        # Strictly format features as in train.ipynb
        features_str = "\n".join([f"{k}={v}" for k, v in features.items()])
        
        surface_val = surface.value if hasattr(surface, 'value') else str(surface)
        
        prompt = f"""You are a classifier for AI agents Data Leakage Prevention (DLP).

Your task is to analyze the input and classify its risk level into EXACTLY one of:
ALLOW, REDACT, ESCALATE, BLOCK.

You are given:
- SURFACE: where the data appears (OUTPUT:LLM's final output to the user, TOOL_ARGS: arguments for the tool calling, TOOL_RESULT: result from the tool)
- FEATURES: extracted signals from deterministic analysis
- TEXT: the raw content

You must follow these rules:

DEFINITIONS:

- ALLOW:
  Content is safe. It may include examples, placeholders, documentation, or synthetic data.
  No real sensitive data is exposed.

- REDACT:
  Contains limited personal data (e.g., one or a few emails, phone numbers, or credit cards).
  Data is real or realistic but not highly sensitive.

- ESCALATE:
  Content is ambiguous or potentially risky.
  Examples:
    - multiple PII entries
    - high-entropy strings that may be tokens
    - partial or unclear secrets
    - mixed benign and sensitive signals
  If you are unsure, choose ESCALATE.

- BLOCK:
  Content clearly contains highly sensitive data or secrets.
  Examples:
    - API keys, tokens, credentials
    - database connection strings with passwords
    - private keys
    - authentication headers
  Always BLOCK if a real secret is present.

FEATURE USAGE GUIDELINES:

- num_emails > 0 -> indicates presence of PII (REDACT or ESCALATE depending on amount)
- num_phones > 0 -> PII signal (REDACT or ESCALATE)
- num_credit_cards > 0 -> sensitive PII (REDACT or ESCALATE)
- has_valid_credit_card = true -> strong sensitive signal (prefer REDACT or ESCALATE)
- num_secrets_detected > 0 -> strong signal for BLOCK
- has_api_key_pattern = true -> strong signal for BLOCK
- has_db_connection = true -> strong signal for BLOCK (especially if credentials present)
- has_private_key = true -> definite BLOCK
- high max_entropy or avg_entropy -> may indicate tokens/secrets -> ESCALATE or BLOCK depending on context
- is_example_context = true -> reduces risk (may allow ALLOW)
- is_code_context = true -> may indicate examples or documentation (reduce risk unless real secrets present)
- multiple risk signals combined -> increase severity

PRIORITY RULES:

1. If real secrets or credentials are present -> BLOCK
2. Else if clear PII is present -> REDACT
3. Else if ambiguous or suspicious -> ESCALATE
4. Else -> ALLOW

IMPORTANT:

- Use TEXT as the primary source of truth
- Use FEATURES as supporting signals, not absolute truth
- If conflicting signals exist, prioritize safety
- If unsure, choose ESCALATE
- Do NOT explain your answer
- Output ONLY one word: ALLOW, REDACT, ESCALATE, or BLOCK

### Input:
[SURFACE={surface_val}]

[FEATURES]
{features_str}

[TEXT]
{text}"""

        # Graceful fallback if the tokenizer does not natively support chat_template
        if self.tokenizer.chat_template is not None:
            convo = [{"role": "user", "content": prompt}]
            formatted = self.tokenizer.apply_chat_template(convo, tokenize=False, add_generation_prompt=True)
        else:
            # Fallback for models like Phi-2 
            formatted = f"Instruct: {prompt}\nOutput: "

        inputs = self.tokenizer(formatted, return_tensors="pt").to(self.model.device)
        
        import torch
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=10,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id,
            )
        
        # strip prompt tokens
        generated_id = outputs[0][inputs['input_ids'].shape[-1]:]
        generated_text = self.tokenizer.decode(generated_id, skip_special_tokens=True).strip()
        
        # In case the model outputs extra whitespace or a newline before the actual word
        generated_text = generated_text.split('\n')[0].strip()
        return generated_text


def classify(text: str, surface: ScanSurface, features: dict[str, Any], config: Optional[DLPConfig] = None) -> DLPAction:
    global _engine
    
    try:
        # Initialize engine if needed.
        if _engine is None:
            if config is None:
                # Fallback to default if no config passed
                config = DLPConfig.defaults()
            _engine = MLInferenceEngine(config)
            
        raw_output = _engine.generate_allowed_action(text, surface, features).upper()
        
        # Valid output validation & safety fallback
        valid_actions = {
            "ALLOW": DLPAction.ALLOW,
            "REDACT": DLPAction.REDACT,
            "ESCALATE": DLPAction.ESCALATE,
            "BLOCK": DLPAction.BLOCK
        }
        
        if raw_output in valid_actions:
            return valid_actions[raw_output]
            
        return DLPAction.ESCALATE
        
    except Exception:
        # Fallback to escalate on exception (e.g. missing ml packages, unparseable output)
        return DLPAction.ESCALATE
