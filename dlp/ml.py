"""
ml.py — DLP ML Inference Engine
Integrates the fine-tuned Gemma-2-2b-it + LoRA adapter for local, offline DLP classification.

Architecture
------------
- Base model : google/gemma-2-2b-it  (auto-downloaded from HuggingFace on first run)
- Adapter    : dlp_lora_package/      (bundled with the project, loaded on top of the base)
- Quantization: 4-bit NF4 (bitsandbytes) — matches the training setup and keeps RAM ≤ 6 GB
- Inference  : greedy decoding, max_new_tokens=10, deterministic

The engine is a singleton (_engine). First call loads everything; subsequent calls are instant.
All heavy imports (torch, transformers, peft, bitsandbytes) are deferred so that the rest of
the DLP module can be imported and used without them being installed if ML is disabled.
"""

from __future__ import annotations

import os

# Automatically enable high-speed downloads if the 'hf_transfer' package is present
try:
    import hf_transfer  # noqa: F401
    os.environ["HF_HUB_ENABLE_HF_TRANSFER"] = "1"
except ImportError:
    pass

import logging
from pathlib import Path
from typing import Any, Optional

from .models import ScanSurface, DLPAction
from .config import DLPConfig

logger = logging.getLogger(__name__)

# ── Singleton ─────────────────────────────────────────────────────────────────
_engine: Optional["MLInferenceEngine"] = None

# ── Resolve the adapter path relative to this file ───────────────────────────
_THIS_DIR = Path(__file__).parent
_DEFAULT_LORA_PATH = _THIS_DIR / "ML" / "dlp_lora_package"

# ── Canonical base model (same as training) ───────────────────────────────────
_BASE_MODEL_ID = "google/gemma-2-2b-it"

# ── Valid output tokens ────────────────────────────────────────────────────────
_VALID_ACTIONS: dict[str, DLPAction] = {
    "ALLOW": DLPAction.ALLOW,
    "REDACT": DLPAction.REDACT,
    "ESCALATE": DLPAction.ESCALATE,
    "BLOCK": DLPAction.BLOCK,
}


class MLInferenceEngine:
    """
    Loads the Gemma-2-2b-it base model with 4-bit quantization and applies
    the fine-tuned LoRA adapter from dlp_lora_package/.

    Parameters
    ----------
    config : DLPConfig
        Runtime config. Reads:
          - ml_base_model  : HF model ID (default: google/gemma-2-2b-it)
          - ml_lora_path   : path to the adapter folder (default: ML/dlp_lora_package)
    """

    def __init__(self, config: DLPConfig) -> None:
        self.config = config
        self.tokenizer = None
        self.model = None
        self._load()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load(self) -> None:
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
        from peft import PeftModel

        base_model_id: str = getattr(self.config, "ml_base_model", _BASE_MODEL_ID) or _BASE_MODEL_ID
        lora_path = Path(getattr(self.config, "ml_lora_path", None) or _DEFAULT_LORA_PATH)

        if not lora_path.exists():
            raise FileNotFoundError(
                f"LoRA adapter not found at '{lora_path}'. "
                "Make sure the dlp_lora_package/ folder is present in dlp/ML/."
            )

        logger.info("DLP-ML: Loading tokenizer from adapter package (%s)…", lora_path)

        # ── Tokenizer — load from the adapter package so we get the exact
        #    vocabulary and chat template that was used during fine-tuning.
        self.tokenizer = AutoTokenizer.from_pretrained(
            str(lora_path),
            local_files_only=True,  # tokenizer is always bundled — no network call
        )
        # Gemma-2 uses <eos> as pad token (set during training)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        self.tokenizer.padding_side = "right"

        # ── 4-bit quantization — mirrors the training BitsAndBytesConfig exactly
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
        )

        logger.info("DLP-ML: Loading base model '%s' (4-bit NF4)…", base_model_id)
        logger.info("DLP-ML: On first run this will download ~1.5 GB from HuggingFace.")

        # device_map="auto" picks GPU if available, otherwise CPU (slow but functional)
        self.model = AutoModelForCausalLM.from_pretrained(
            base_model_id,
            quantization_config=bnb_config,
            device_map="auto",
            dtype=torch.bfloat16,
            low_cpu_mem_usage=True,
        )
        self.model.config.use_cache = True  # inference mode — cache is beneficial

        logger.info("DLP-ML: Applying LoRA adapter from '%s'…", lora_path)
        self.model = PeftModel.from_pretrained(
            self.model,
            str(lora_path),
            is_trainable=False,
        )
        self.model.eval()
        logger.info("DLP-ML: Engine ready.")

    # ── Prompt construction — must exactly match format_dlp_prompt() in train.ipynb ──

    def _build_prompt(self, text: str, surface: ScanSurface, features: dict[str, Any]) -> str:
        features_str = "\n".join(f"{k}={v}" for k, v in features.items())
        surface_val = surface.value if hasattr(surface, "value") else str(surface)

        user_content = f"""You are a Data Leakage Prevention (DLP) classifier for AI agents.

Your task is to analyze the input and classify its risk level into EXACTLY one of:
ALLOW, REDACT, ESCALATE, BLOCK.

You are given:
- SURFACE: where the data appears (OUTPUT: scanning the agent's final output to the user, TOOL_ARGS: scanning the agent's arguments in a tool call, TOOL_RESULT: scanning the results of a tool call)
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
{text}

### Output:"""

        # Apply the Gemma-2 chat template (bundled in the adapter package)
        messages = [{"role": "user", "content": user_content}]
        formatted = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        return formatted

    # ── Inference ─────────────────────────────────────────────────────────────

    def infer(self, text: str, surface: ScanSurface, features: dict[str, Any]) -> str:
        import torch

        prompt = self._build_prompt(text, surface, features)
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)

        with torch.no_grad():
            output_ids = self.model.generate(
                **inputs,
                max_new_tokens=10,
                do_sample=False,           # greedy — deterministic, matches eval setup
                temperature=1.0,           # ignored when do_sample=False, but explicit
                pad_token_id=self.tokenizer.eos_token_id,
            )

        # Strip the prompt tokens; keep only what the model generated
        generated_ids = output_ids[0][inputs["input_ids"].shape[-1]:]
        raw = self.tokenizer.decode(generated_ids, skip_special_tokens=True).strip()

        # Model may emit "BLOCK\n" or "BLOCK." — take only the first word
        return raw.split()[0].upper() if raw.split() else ""


# ── Public API ────────────────────────────────────────────────────────────────

def classify(
    text: str,
    surface: ScanSurface,
    features: dict[str, Any],
    config: Optional[DLPConfig] = None,
) -> DLPAction:
    """
    Classify *text* and return the appropriate DLPAction.

    This is the only function the rest of the DLP module calls.
    The engine is lazily initialised on the first call and reused afterwards.

    Falls back to DLPAction.ESCALATE on any error (missing packages,
    model load failure, unparseable output) so the rest of the pipeline
    can still make a safe decision.
    """
    global _engine

    try:
        if _engine is None:
            if config is None:
                config = DLPConfig.defaults()
            _engine = MLInferenceEngine(config)

        raw_output = _engine.infer(text, surface, features)

        if raw_output in _VALID_ACTIONS:
            return _VALID_ACTIONS[raw_output]

        logger.warning("DLP-ML: Unexpected model output %r — falling back to ESCALATE.", raw_output)
        return DLPAction.ESCALATE

    except FileNotFoundError as exc:
        logger.error("DLP-ML: %s", exc)
        return DLPAction.ESCALATE
    except Exception as exc:  # noqa: BLE001
        logger.exception("DLP-ML: Inference failed (%s) — defaulting to ESCALATE.", exc)
        return DLPAction.ESCALATE


def reset_engine() -> None:
    """Force the next classify() call to reload the engine. Useful in tests."""
    global _engine
    _engine = None