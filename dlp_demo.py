"""
demo.py — DLP Module End-to-End Demo & Evaluation
==================================================

PURPOSE
-------
  1. Shows exactly how the DLP module must be used by any consumer
     (agentic frameworks, other project modules, CI pipelines).
  2. Exercises every public endpoint defined in dlp/__init__.py across
     all four scan surfaces using realistic, hardcoded mock inputs.
  3. Serves as a smoke-test: if this file runs without unexpected BLOCKs
     on clean inputs, the full stack (patterns → features → ML) is working.

USAGE
-----
    # One-time setup for secret-based scenarios:
    #   1) Copy dlp_demo_secrets_example.py -> dlp_demo_secrets.py
    #   2) Edit dlp_demo_secrets.py with local test-only secret-like values
    #
  # From the repo root (the folder that contains the dlp/ package):
  python demo.py

  # Skip ML inference (faster, tests everything except the model):
  DLP_SKIP_ML=1 python demo.py

EXPECTED OUTCOME
----------------
  Each scenario prints a one-line verdict. The final summary shows how
  many scenarios matched their expected action. A fully working stack
  should show 0 unexpected results.

PUBLIC API USED (dlp/__init__.py)
----------------------------------
  dlp.init(config)
  dlp.inject_canary_into_system_prompt(system_prompt)
  dlp.inject_canaries_into_context(docs)
  dlp.inject_canary_into_tool_result(tool_name, result)
  dlp.scan_output(text)
  dlp.scan_tool_args(tool_name, args)
  dlp.scan_tool_result(tool_name, result)
"""

import os
import sys
import json
import textwrap
from pathlib import Path
from dataclasses import dataclass

# ── Make sure the dlp package is importable when running from repo root ───────
sys.path.insert(0, str(Path(__file__).parent))

import dlp
from dlp.models import DLPAction, EnforcementDecision

# Load secret-like fixtures from an ignored local file when available.
# This keeps git history clean while preserving realistic demo scenarios.
try:
    from dlp_demo_secrets import (
        DLP_DEMO_PAYMENT_GATEWAY_KEY,
        DLP_DEMO_STRIPE_API_KEY,
        DLP_DEMO_STRIPE_SECRET_KEY,
        DLP_DEMO_STRIPE_WEBHOOK_SECRET,
    )
    DEMO_SECRETS_READY = True
    DEMO_SECRETS_SOURCE = "dlp_demo_secrets.py"
except ImportError:
    from dlp_demo_secrets_example import (
        DLP_DEMO_PAYMENT_GATEWAY_KEY,
        DLP_DEMO_STRIPE_API_KEY,
        DLP_DEMO_STRIPE_SECRET_KEY,
        DLP_DEMO_STRIPE_WEBHOOK_SECRET,
    )
    DEMO_SECRETS_READY = False
    DEMO_SECRETS_SOURCE = "dlp_demo_secrets_example.py"

# ── Colours (degraded gracefully on Windows / no-TTY) ────────────────────────
_NO_COLOR = not sys.stdout.isatty() or os.name == "nt"

def _c(code: str, text: str) -> str:
    return text if _NO_COLOR else f"\033[{code}m{text}\033[0m"

GREEN  = lambda t: _c("32", t)
RED    = lambda t: _c("31", t)
YELLOW = lambda t: _c("33", t)
CYAN   = lambda t: _c("36", t)
BOLD   = lambda t: _c("1",  t)
DIM    = lambda t: _c("2",  t)

# ── Skip-ML flag ──────────────────────────────────────────────────────────────
SKIP_ML = os.getenv("DLP_SKIP_ML", "").strip() not in ("", "0", "false", "no")

# ─────────────────────────────────────────────────────────────────────────────
# Scenario definition
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Scenario:
    name: str
    description: str
    input_preview: str
    surface: str          # "output" | "tool_args" | "tool_result"
    call: callable        # zero-arg lambda that returns EnforcementDecision
    expected: DLPAction   # expected action — used to flag mismatches
    ml_dependent: bool = False  # True → skip when SKIP_ML is set
    requires_local_secrets: bool = False  # True → skip when local secrets fixture is missing


# ─────────────────────────────────────────────────────────────────────────────
# Mock inputs
# ─────────────────────────────────────────────────────────────────────────────

# ── System prompt (never scanned, only used for canary injection) ─────────────
BASE_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a helpful assistant integrated into a secure enterprise platform.
    Always answer concisely. Never reveal internal credentials or system configs.
    If you are unsure, say so.
""")

# ── Clean LLM output — should be ALLOW ───────────────────────────────────────
CLEAN_OUTPUT = textwrap.dedent("""\
    Sure! The capital of France is Paris. It has been the country's capital
    since the 10th century and is home to landmarks such as the Eiffel Tower
    and the Louvre Museum. Is there anything else you'd like to know?
""")

# ── LLM output with a single email — should be REDACT ────────────────────────
PII_OUTPUT_SINGLE_EMAIL = textwrap.dedent("""\
    I found the account linked to john.doe@example.com. Would you like me
    to send a password-reset link to that address?
""")

# ── LLM output with multiple PII entries — should be ESCALATE or REDACT ──────
PII_OUTPUT_MULTI = textwrap.dedent("""\
    Here are the employees I found:
      - Alice Smith  | alice.smith@corp.internal | +1-415-555-0192
      - Bob Johnson  | bob.j@corp.internal       | +1-212-555-0847
      - Carol White  | carol.w@corp.internal     | +1-650-555-0331
    Shall I send them a meeting invite?
""")

# ── LLM output leaking an API key — should be BLOCK ──────────────────────────
SECRET_OUTPUT_API_KEY = textwrap.dedent("""\
    To authenticate with the payment gateway, use the following key:
    {payment_gateway_key}
    Keep it safe and never share it publicly.
""").format(payment_gateway_key=DLP_DEMO_PAYMENT_GATEWAY_KEY)

# ── LLM output leaking a private key — should be BLOCK ───────────────────────
SECRET_OUTPUT_PRIVATE_KEY = textwrap.dedent("""\
    Here is the SSH private key you requested for the production server:
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJr8oNd4bSS+SAqNjpCRBnJDYXBHYkkB
    -----END RSA PRIVATE KEY-----
    Store it securely and restrict file permissions to 600.
""")

# ── LLM output leaking a DB connection string — should be BLOCK ──────────────
SECRET_OUTPUT_DB_CONN = textwrap.dedent("""\
    The database connection string for the staging environment is:
    postgresql://admin:S3cr3tP@ssw0rd!@db.internal.corp:5432/prod_customers
    Please update your .env file accordingly.
""")

# ── Clean tool arguments — should be ALLOW ───────────────────────────────────
CLEAN_TOOL_ARGS = {
    "tool_name": "web_search",
    "args": {
        "query": "best practices for REST API design",
        "num_results": 5,
    },
}

# ── Tool args containing a canary (simulated exfiltration) — should be BLOCK ─
# (populated at runtime after canary injection — see canary tests below)

# ── Tool args with a secret embedded — should be BLOCK ───────────────────────
SECRET_TOOL_ARGS = {
    "tool_name": "send_http_request",
    "args": {
        "url": "https://api.payment-provider.com/charge",
        "headers": {
            "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.secret_token_abcdef1234567890",
        },
        "body": {"amount": 9999, "currency": "USD"},
    },
}

# ── Clean tool result — should be ALLOW ──────────────────────────────────────
CLEAN_TOOL_RESULT = {
    "tool_name": "get_weather",
    "result": {
        "location": "Paris, France",
        "temperature_c": 18,
        "condition": "Partly cloudy",
        "wind_kph": 14,
    },
}

# ── Tool result with PII from an external DB — should be REDACT ──────────────
PII_TOOL_RESULT = {
    "tool_name": "crm_lookup",
    "result": {
        "customer_id": "CUST-00192",
        "name": "Jane Doe",
        "email": "jane.doe@customer.com",
        "phone": "+1-800-555-0147",
        "account_tier": "Gold",
    },
}

# ── Tool result with secrets from a config store — should be BLOCK ────────────
SECRET_TOOL_RESULT = {
    "tool_name": "vault_read",
    "result": {
        "path": "secret/prod/stripe",
        "data": {
            "api_key": DLP_DEMO_STRIPE_API_KEY,
            "webhook_secret": DLP_DEMO_STRIPE_WEBHOOK_SECRET,
        },
    },
}

# ── RAG documents for context injection ──────────────────────────────────────
RAG_DOCS = [
    {"id": "doc-1", "text": "The refund policy allows returns within 30 days of purchase."},
    {"id": "doc-2", "text": "Our SLA guarantees 99.9% uptime for enterprise customers."},
    {"id": "doc-3", "text": "Contact support at support@company.com for billing issues."},
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _action_label(action: DLPAction) -> str:
    colors = {
        DLPAction.ALLOW:    GREEN,
        DLPAction.REDACT:   YELLOW,
        DLPAction.ESCALATE: YELLOW,
        DLPAction.BLOCK:    RED,
    }
    return colors.get(action, str)(action.name)


def _preview(value, max_len: int = 110) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    text = " ".join(text.split())
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def _print_decision(decision: EnforcementDecision, expected: DLPAction, input_preview: str) -> bool:
    """Print a compact scenario result. Returns True if outcome matched expected."""
    action = decision.action
    matched = action == expected

    print(f"    Input              : {_preview(input_preview)}")
    print(f"    Expected Action    : {_action_label(expected)}")
    print(f"    Actual Action      : {_action_label(action)}")
    print(f"    Decision Layer     : {decision.decision_layer}")
    print(f"    Decision Reason    : {decision.decision_reason}")
    print(f"    Final Message Passed: {_preview(decision.clean_text)}")
    print(f"    Result             : {GREEN('PASS') if matched else RED('MISMATCH')}")
    return matched


def _section(title: str) -> None:
    width = 72
    print()
    print(BOLD(CYAN("=" * width)))
    print(BOLD(CYAN(f"  {title}")))
    print(BOLD(CYAN("=" * width)))


def _run(scenario: Scenario, results: list[bool | None]) -> None:
    if scenario.requires_local_secrets and not DEMO_SECRETS_READY:
        print(f"\n  {BOLD(scenario.name)}")
        print(f"  {DIM(scenario.description)}")
        print(f"    {YELLOW('⚠  Skipped (configure dlp_demo_secrets.py to enable this scenario)')}")
        results.append(None)
        return

    if SKIP_ML and scenario.ml_dependent:
        print(f"\n  {BOLD(scenario.name)}")
        print(f"  {DIM(scenario.description)}")
        print(f"    {YELLOW('⚠  Skipped (DLP_SKIP_ML=1)')}")
        results.append(None)
        return

    print(f"\n  {BOLD(scenario.name)}")
    print(f"  {DIM(scenario.description)}")
    try:
        decision: EnforcementDecision = scenario.call()
        matched = _print_decision(decision, scenario.expected, scenario.input_preview)
        results.append(matched)
    except Exception as exc:
        print(f"    {RED('ERROR')}: {exc}")
        results.append(False)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print()
    print(BOLD("DLP Module — End-to-End Demo & Evaluation"))
    print(DIM("  All mock inputs are hardcoded. No real data is used."))
    if DEMO_SECRETS_READY:
        print(DIM(f"  Secret fixture source: {DEMO_SECRETS_SOURCE}"))
    else:
        print(YELLOW("  ⚠  Running with placeholder secret fixtures from dlp_demo_secrets_example.py"))
        print(YELLOW("     Copy dlp_demo_secrets_example.py to dlp_demo_secrets.py to run secret-based scenarios."))
    if SKIP_ML:
        print(YELLOW("  ⚠  DLP_SKIP_ML=1 — ML inference is disabled for this run."))

    # ── 0. Initialise the module ───────────────────────────────────────────────
    # Pass no arguments to use the built-in safe defaults (no YAML file required).
    # In production, pass a Path to your policy YAML:
    #   dlp.init(Path("dlp/policy.default.yaml"))
    _section("0 · Initialisation")
    print("  dlp.init() — using built-in safe defaults")
    dlp.init()
    print(f"  {GREEN('✓')} Module initialised")

    results: list[bool | None] = []

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Canary injection & detection
    # ─────────────────────────────────────────────────────────────────────────
    _section("1 · Canary Injection & Detection")

    # 1a — Inject into system prompt
    print(f"\n  {BOLD('1a. inject_canary_into_system_prompt()')}")
    print(f"  {DIM('Seeds a hidden token into the system prompt before each LLM call.')}")
    modified_prompt, canary_token, canary_label = dlp.inject_canary_into_system_prompt(BASE_SYSTEM_PROMPT)
    print(f"    Canary label : {canary_label}")
    print(f"    Canary token : {DIM(canary_token[:32] + '…')}")
    print(f"    Prompt delta : +{len(modified_prompt) - len(BASE_SYSTEM_PROMPT)} chars")
    print(f"    {GREEN('✓')} Injection OK — pass modified_prompt to the LLM instead of the original")

    # 1b — Inject into RAG context
    print(f"\n  {BOLD('1b. inject_canaries_into_context(docs)')}")
    print(f"  {DIM('Seeds a canary into one of the retrieved RAG documents.')}")
    modified_docs, ctx_token, ctx_label = dlp.inject_canaries_into_context(RAG_DOCS)
    if ctx_token:
        print(f"    Injected into doc id : {modified_docs[0].get('id', '?')}")
        print(f"    Canary label         : {ctx_label}")
        print(f"    {GREEN('✓')} Context injection OK")
    else:
        print(f"    {YELLOW('⚠  No canary injected (empty docs or engine disabled)')}")

    # 1c — Inject into tool result
    print(f"\n  {BOLD('1c. inject_canary_into_tool_result()')}")
    print(f"  {DIM('Embeds a canary into a tool result before the agent sees it.')}")
    raw_tool_result = {"status": "ok", "record_id": "REC-9921", "value": 42}
    modified_result, tr_token, tr_label = dlp.inject_canary_into_tool_result(
        "db_read", raw_tool_result
    )
    if tr_token:
        print(f"    Canary label  : {tr_label}")
        print(f"    Modified keys : {list(modified_result.keys()) if isinstance(modified_result, dict) else type(modified_result).__name__}")
        print(f"    {GREEN('✓')} Tool result injection OK")
    else:
        print(f"    {YELLOW('⚠  Injection returned no token')}")

    # 1d — Simulate canary leaking in LLM output → should BLOCK
    print(f"\n  {BOLD('1d. Canary leak detected in scan_output()')}")
    print(f"  {DIM('LLM echoes the canary token in its response → must be BLOCKED.')}")
    canary_leak_output = (
        f"Here is the credential you requested: {canary_token}. "
        "Please store it securely and do not share it."
    )
    try:
        decision = dlp.scan_output(canary_leak_output)
        matched = _print_decision(decision, DLPAction.BLOCK, canary_leak_output)
        results.append(matched)
    except Exception as exc:
        print(f"    {RED('ERROR')}: {exc}")
        results.append(False)

    # ─────────────────────────────────────────────────────────────────────────
    # 2. scan_output — OUTPUT surface
    # ─────────────────────────────────────────────────────────────────────────
    _section("2 · scan_output()  —  OUTPUT surface")

    scenarios_output = [
        Scenario(
            name="2a. Clean response",
            description="Plain factual answer — no PII, no secrets. Should be ALLOW.",
            input_preview=CLEAN_OUTPUT,
            surface="output",
            call=lambda: dlp.scan_output(CLEAN_OUTPUT),
            expected=DLPAction.ALLOW,
            ml_dependent=True,
        ),
        Scenario(
            name="2b. Single email address",
            description="One email in the response — mild PII. Should be REDACT.",
            input_preview=PII_OUTPUT_SINGLE_EMAIL,
            surface="output",
            call=lambda: dlp.scan_output(PII_OUTPUT_SINGLE_EMAIL),
            expected=DLPAction.REDACT,
            ml_dependent=True,
        ),
        Scenario(
            name="2c. Multiple PII entries",
            description="Three names + emails + phones — ambiguous volume. Should be ESCALATE or REDACT.",
            input_preview=PII_OUTPUT_MULTI,
            surface="output",
            call=lambda: dlp.scan_output(PII_OUTPUT_MULTI),
            expected=DLPAction.ESCALATE,  # ML may also return REDACT — both are acceptable
            ml_dependent=True,
        ),
        Scenario(
            name="2d. API key in response",
            description="Live-style API key leaked in output. Should be BLOCK.",
            input_preview=SECRET_OUTPUT_API_KEY,
            surface="output",
            call=lambda: dlp.scan_output(SECRET_OUTPUT_API_KEY),
            expected=DLPAction.BLOCK,
            ml_dependent=False,  # pattern engine catches this deterministically
            requires_local_secrets=True,
        ),
        Scenario(
            name="2e. RSA private key in response",
            description="-----BEGIN RSA PRIVATE KEY----- detected. Must be BLOCK.",
            input_preview=SECRET_OUTPUT_PRIVATE_KEY,
            surface="output",
            call=lambda: dlp.scan_output(SECRET_OUTPUT_PRIVATE_KEY),
            expected=DLPAction.BLOCK,
            ml_dependent=False,
        ),
        Scenario(
            name="2f. DB connection string in response",
            description="postgresql://user:password@host/db detected. Must be BLOCK.",
            input_preview=SECRET_OUTPUT_DB_CONN,
            surface="output",
            call=lambda: dlp.scan_output(SECRET_OUTPUT_DB_CONN),
            expected=DLPAction.BLOCK,
            ml_dependent=False,
        ),
    ]

    for s in scenarios_output:
        _run(s, results)

    # ─────────────────────────────────────────────────────────────────────────
    # 3. scan_tool_args — TOOL_ARGS surface
    # ─────────────────────────────────────────────────────────────────────────
    _section("3 · scan_tool_args()  —  TOOL_ARGS surface")

    scenarios_tool_args = [
        Scenario(
            name="3a. Clean tool call (web search)",
            description="Benign search query — no sensitive data. Should be ALLOW.",
            input_preview=CLEAN_TOOL_ARGS["args"],
            surface="tool_args",
            call=lambda: dlp.scan_tool_args(
                CLEAN_TOOL_ARGS["tool_name"], CLEAN_TOOL_ARGS["args"]
            ),
            expected=DLPAction.ALLOW,
            ml_dependent=True,
        ),
        Scenario(
            name="3b. Bearer token in Authorization header",
            description="JWT bearer token passed as a tool arg. Must be BLOCK.",
            input_preview=SECRET_TOOL_ARGS["args"],
            surface="tool_args",
            call=lambda: dlp.scan_tool_args(
                SECRET_TOOL_ARGS["tool_name"], SECRET_TOOL_ARGS["args"]
            ),
            expected=DLPAction.BLOCK,
            ml_dependent=False,
        ),
        Scenario(
            name="3c. Email address in tool args",
            description="Single email in args for an email-send tool. Should be REDACT.",
            input_preview={
                "to": "alice@example.com",
                "subject": "Your invoice is ready",
                "body": "Please find your invoice attached.",
            },
            surface="tool_args",
            call=lambda: dlp.scan_tool_args(
                "send_email",
                {
                    "to": "alice@example.com",
                    "subject": "Your invoice is ready",
                    "body": "Please find your invoice attached.",
                },
            ),
            expected=DLPAction.REDACT,
            ml_dependent=True,
        ),
    ]

    for s in scenarios_tool_args:
        _run(s, results)

    # ─────────────────────────────────────────────────────────────────────────
    # 4. scan_tool_result — TOOL_RESULT surface
    # ─────────────────────────────────────────────────────────────────────────
    _section("4 · scan_tool_result()  —  TOOL_RESULT surface")

    scenarios_tool_result = [
        Scenario(
            name="4a. Clean tool result (weather API)",
            description="Structured weather data — no PII, no secrets. Should be ALLOW.",
            input_preview=CLEAN_TOOL_RESULT["result"],
            surface="tool_result",
            call=lambda: dlp.scan_tool_result(
                CLEAN_TOOL_RESULT["tool_name"], CLEAN_TOOL_RESULT["result"]
            ),
            expected=DLPAction.ALLOW,
            ml_dependent=True,
        ),
        Scenario(
            name="4b. CRM result with PII",
            description="Customer record with email + phone. Should be REDACT (surface policy downgrade).",
            input_preview=PII_TOOL_RESULT["result"],
            surface="tool_result",
            call=lambda: dlp.scan_tool_result(
                PII_TOOL_RESULT["tool_name"], PII_TOOL_RESULT["result"]
            ),
            expected=DLPAction.REDACT,
            ml_dependent=True,
        ),
        Scenario(
            name="4c. Vault result with secrets",
            description="Secret store returns live Stripe keys. Must be BLOCK.",
            input_preview=SECRET_TOOL_RESULT["result"],
            surface="tool_result",
            call=lambda: dlp.scan_tool_result(
                SECRET_TOOL_RESULT["tool_name"], SECRET_TOOL_RESULT["result"]
            ),
            expected=DLPAction.BLOCK,
            ml_dependent=False,
            requires_local_secrets=True,
        ),
        Scenario(
            name="4d. Raw string tool result",
            description="Tool returns a plain-text string with a secret embedded.",
            input_preview=f"STRIPE_SECRET_KEY={DLP_DEMO_STRIPE_SECRET_KEY}",
            surface="tool_result",
            call=lambda: dlp.scan_tool_result(
                "config_fetch",
                f"STRIPE_SECRET_KEY={DLP_DEMO_STRIPE_SECRET_KEY}",
            ),
            expected=DLPAction.BLOCK,
            ml_dependent=False,
            requires_local_secrets=True,
        ),
    ]

    for s in scenarios_tool_result:
        _run(s, results)

    # ─────────────────────────────────────────────────────────────────────────
    # 5. Integration — simulated full agent turn
    # ─────────────────────────────────────────────────────────────────────────
    _section("5 · Simulated Full Agent Turn")

    print(textwrap.dedent("""
      This simulates how the DLP module wraps a complete agentic request:

        ① inject_canary_into_system_prompt  ─→  send to LLM
        ②   LLM decides to call a tool
        ③ scan_tool_args                    ─→  tool executes only if ALLOW/REDACT
        ④ inject_canary_into_tool_result    ─→  result returned to agent
        ⑤   LLM formulates its final answer
        ⑥ scan_output                       ─→  response delivered to user only if safe
    """).rstrip())

    # ① Inject canary into system prompt
    sys_prompt, turn_token, turn_label = dlp.inject_canary_into_system_prompt(BASE_SYSTEM_PROMPT)
    print(f"  ① Canary injected into system prompt  [{turn_label}]")

    # ② LLM wants to call get_customer_record(customer_id="CUST-00192")
    turn_tool_name = "get_customer_record"
    turn_tool_args = {"customer_id": "CUST-00192", "fields": ["name", "email", "tier"]}
    print(f"  ② LLM emits tool call → {turn_tool_name}({turn_tool_args})")

    # ③ Scan tool args before executing
    args_decision = dlp.scan_tool_args(turn_tool_name, turn_tool_args)
    print("  ③ Tool-args pre-check")
    args_matched = _print_decision(
        args_decision,
        DLPAction.ALLOW,
        {"tool_name": turn_tool_name, "args": turn_tool_args},
    )
    if args_decision.should_block:
        print(f"  {RED('TOOL CALL ABORTED')}")
        results.append(args_matched)  # expected ALLOW
    else:
        # ④ Tool executes and returns PII; inject canary before agent sees it
        raw_crm_result = {"name": "Jane Doe", "email": "jane.doe@customer.com", "tier": "Gold"}
        instrumented_result, _, _ = dlp.inject_canary_into_tool_result(turn_tool_name, raw_crm_result)
        print(f"  ④ Canary injected into tool result")

        # ⑤ LLM formulates answer (it received the instrumented result with the canary)
        # Simulate a benign final answer that does NOT echo the canary
        llm_final_output = (
            "The customer Jane Doe (Gold tier) has been located. "
            "Her contact details have been flagged for review per data handling policy."
        )
        print(f"  ⑤ LLM final output prepared")

        # ⑥ Scan output before delivering to user
        output_decision = dlp.scan_output(llm_final_output)
        print("  ⑥ Final output check")
        matched = _print_decision(output_decision, DLPAction.ALLOW, llm_final_output)
        results.append(matched)

    # ─────────────────────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────────────────────
    _section("Summary")

    passed   = sum(1 for r in results if r is True)
    failed   = sum(1 for r in results if r is False)
    skipped  = sum(1 for r in results if r is None)
    total    = passed + failed + skipped

    print(f"\n  Total scenarios : {total}")
    print(f"  {GREEN(f'Passed          : {passed}')}")
    if failed:
        print(f"  {RED(f'Failed          : {failed}')}")
    if skipped:
        print(f"  {YELLOW(f'Skipped (no ML) : {skipped}')}")

    print()
    if failed == 0:
        if skipped > 0:
            print(YELLOW("  ⚠  Partial pass — run without DLP_SKIP_ML=1 to validate the full ML stack."))
        else:
            print(GREEN("  ✓ All scenarios matched expected actions. DLP stack is working end-to-end."))
    else:
        print(RED(f"  ✗ {failed} scenario(s) did not match. Review the output above."))
        print(DIM("    A mismatch on an ML-dependent scenario may mean the model is still"))
        print(DIM("    downloading or that the adapter path is misconfigured."))

    print()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()