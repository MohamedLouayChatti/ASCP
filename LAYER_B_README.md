# Layer B README

## What Layer B Is

Layer B is the typed capability security contract layer.

Its job is simple:

- every capability call is treated as security-sensitive
- the call is checked against policy before execution
- the result is one of:
  - `allow`
  - `block`
  - `require_approval`

Layer B does not execute tools. It decides whether a capability, resource read, or prompt access is permitted.

## What Files Matter

If you only care about Layer B, these are the important files:

- [layer_b.py](/c:/ML/ascp/layer_b.py)
- [apps/gateway/middleware/pep_tool.py](/c:/ML/ascp/apps/gateway/middleware/pep_tool.py)
- [policy/tool_permissions.yaml](/c:/ML/ascp/policy/tool_permissions.yaml)
- [examples/layer_b_only.py](/c:/ML/ascp/examples/layer_b_only.py)
- [tests/test_layer_b_only.py](/c:/ML/ascp/tests/test_layer_b_only.py)
- [tests/test_contracts.py](/c:/ML/ascp/tests/test_contracts.py)
- the schemas in [/c:/ML/ascp/schemas](/c:/ML/ascp/schemas)

## Architecture

Layer B has three pieces:

1. Policy
   - YAML contracts in [policy/tool_permissions.yaml](/c:/ML/ascp/policy/tool_permissions.yaml)
   - JSON Schemas in [/c:/ML/ascp/schemas](/c:/ML/ascp/schemas)

2. Enforcement engine
   - `ContractValidator` in [apps/gateway/middleware/pep_tool.py](/c:/ML/ascp/apps/gateway/middleware/pep_tool.py)

3. Standalone interface
   - `LayerBPolicy`, `LayerBEngine`, and CLI in [layer_b.py](/c:/ML/ascp/layer_b.py)

The usual flow is:

```text
policy yaml + json schemas
        ->
ContractValidator
        ->
validate_capability_call / validate_resource_read / validate_prompt_get
        ->
allow | block | require_approval
```

## Policy Model

The policy file is [policy/tool_permissions.yaml](/c:/ML/ascp/policy/tool_permissions.yaml).

It contains these top-level sections:

- `capabilities`
- `resources`
- `prompts`
- `capability_sequences`
- `runtime_rules`

### `capabilities`

Each capability defines:

- `risk`
- `scopes`
- `approval_required`
- `schema`
- `constraints`

Example shape:

```yaml
capabilities:
  send_email:
    risk: high
    scopes: [network, external_api, write]
    approval_required: true
    schema: schemas/send_email.schema.json
    constraints:
      recipient_domain_allowlist: [company.com, internal.org]
      max_body_chars: 5000
```

### `resources`

Resources define read access policies for URIs such as file or HTTPS resources.

They usually include:

- matching rules like `uri_prefixes` or `schemes`
- path and domain constraints
- approval requirements

### `prompts`

Prompts are treated as protected components too.

That lets Layer B constrain:

- prompt arguments
- prompt registration
- prompt access approval

### `capability_sequences`

This is the workflow logic layer.

It defines:

- allowed transition graphs
- allowed or denied capabilities for a workflow
- evidence required for specific capability chains
- cumulative risk thresholds
- intent requirements
- state requirements

Example ideas already present in policy:

- `db_query -> send_email`
- `web_fetch -> retrieval_summary`
- workflow-specific rules for `research`
- workflow-specific rules for `outbound_notification`

### `runtime_rules`

These are dynamic overlays applied on top of the static contract.

They are useful for:

- temporary blocks
- additional regex checks
- incident response rules
- environment-specific restrictions

They are merged into base contracts at runtime.

## Public Layer B API

The standalone interface is [layer_b.py](/c:/ML/ascp/layer_b.py).

### `LayerBPaths`

Small dataclass that stores:

- `policy_path`
- `schemas_dir`

### `LayerBPolicy`

Small loader object.

Main method:

- `load()`

What it does:

- creates a `ContractValidator`
- points it at the Layer B YAML and schemas

### `LayerBEngine`

This is the easiest way to use Layer B alone.

Main methods:

- `from_defaults()`
- `list_capabilities()`
- `inspect_capability(capability_name)`
- `inspect_workflow(workflow_name)`
- `validate_capability(...)`
- `explain_decision(...)`

What each one does:

- `list_capabilities()`
  - returns registered capability names
- `inspect_capability()`
  - returns the merged contract and schema for one capability
- `inspect_workflow()`
  - returns workflow sequence policy and global transition graph
- `validate_capability()`
  - returns raw `ContractResult`
- `explain_decision()`
  - returns a JSON-friendly dict with decision, reason code, details, approval token, and sanitized args

### CLI in `layer_b.py`

The CLI commands are:

- `list`
- `inspect <capability>`
- `workflow <workflow>`
- `validate <capability> --args ...`

Examples:

```powershell
.\.venv\Scripts\python.exe -m layer_b list
.\.venv\Scripts\python.exe -m layer_b inspect send_email
.\.venv\Scripts\python.exe -m layer_b workflow outbound_notification
.\.venv\Scripts\python.exe -m layer_b validate send_email --args "{\"recipient\":\"ops@company.com\",\"subject\":\"Report\",\"body\":\"Send it\"}"
```

## Core Enums and Result Types

These are defined in [apps/gateway/middleware/pep_tool.py](/c:/ML/ascp/apps/gateway/middleware/pep_tool.py).

### `PolicyValidationError`

Raised when the policy itself is malformed.

Examples:

- invalid top-level section type
- invalid scope
- invalid risk value
- schema path not found

### `PermissionScope`

Supported scopes:

- `read_only`
- `write`
- `network`
- `local_fs`
- `external_api`
- `custom`

### `RiskLevel`

Supported risks:

- `low`
- `medium`
- `high`
- `critical`
- `unknown`

### `ComponentType`

Supported component kinds:

- `tool`
- `resource`
- `prompt`
- `rule_override`

### `ContractDecision`

Possible decisions:

- `allow`
- `block`
- `require_approval`

### `ContractResult`

Returned by every validation call.

Fields:

- `decision`
- `tool_name`
- `reason_code`
- `details`
- `violations`
- `approval_token`
- `sanitized_args`

`capability_name` is just an alias property for `tool_name`.

## Helper Functions in `pep_tool.py`

These helpers implement the lower-level security mechanics.

### Schema and serialization helpers

- `validate(instance, schema)`
  - thin wrapper over `jsonschema.validate`
- `_stringify_json(value)`
  - stable JSON serialization used for approval fingerprints

### Approval helper

- `_approval_fingerprint(component_type, component_name, args)`
  - binds approvals to both component identity and exact arguments

This prevents token reuse for different actions.

### Filesystem helpers

- `_check_path_traversal(path)`
  - blocks `..` traversal
- `_resolve_policy_path(path)`
  - normalizes paths for comparison
- `_check_path_allowlist(path, allowlist, denylist)`
  - enforces path boundaries

### Network helpers

- `_parse_ip_literal(host)`
  - parses raw IP hosts
- `_check_ip_policy(addr, cidr_denylist)`
  - blocks loopback, private, link-local, multicast, reserved, and denied CIDRs
- `_check_resolved_ips(host, cidr_denylist)`
  - optionally resolves DNS and applies the IP policy
- `_check_domain(url, allowlist, denylist, allowed_schemes, ...)`
  - enforces URL scheme, hostname, and SSRF-style restrictions

### SQL helper

- `_check_sql(sql, allowlisted_tables)`
  - enforces select-only and table allowlisting

### Merge and extraction helpers

- `_deep_merge_dicts(base, overlay)`
  - merges runtime rules onto base contracts
- `_extract_field_values(payload, field_path)`
  - extracts nested fields for dynamic arg rules
- `_match_arg_rule(candidate, rule)`
  - evaluates one dynamic arg rule

### Resource and sequence helpers

- `_find_resource_match(resource_uri, name, contract)`
  - matches a resource URI to a resource contract
- `_normalize_uri_path(path)`
  - cleans URI paths before path policy checks
- `_as_dict(value)`
  - makes trust vectors and similar objects easy to inspect
- `_normalize_chain_history(history)`
  - normalizes workflow history into a clean list
- `_sequence_matches(history, capability_name, expected_chain)`
  - tests whether the current call completes a specific chain
- `_risk_weight(level)`
  - converts risk levels into cumulative numeric weights

## `ContractValidator` Walkthrough

`ContractValidator` is the real Layer B engine.

### Initialization and loading

#### `__init__(tool_permissions_path, schemas_dir)`

Sets up internal state:

- raw policy snapshot
- capability contracts
- resource contracts
- prompt contracts
- sequence policy
- runtime rules
- loaded schemas
- pending approval tokens
- last modified time for hot reload

Then it calls `_load()`.

#### `_get_capability_contracts(policy)`

Reads `capabilities` first, and falls back to legacy `tools`.

#### `_get_runtime_capability_rules()`

Reads `runtime_rules.capabilities`, and falls back to `runtime_rules.tools`.

#### `_get_capability_sequence_policy(policy)`

Reads the `capability_sequences` section.

#### `_validate_policy_shape(policy)`

Validates the policy structure before runtime use.

Checks:

- top-level sections are mappings
- capability contracts are mappings
- risks are valid
- scopes are valid
- `approval_required` is boolean

#### `_load()`

Loads YAML, validates it, stores sections, and preloads schemas.

Also records file modification time so the policy can hot-reload.

#### `_preload_schemas(kind, contracts)`

Loads JSON schemas for capabilities, resources, and prompts into memory.

#### `_maybe_reload()`

Reloads policy automatically if the YAML file changed on disk.

## Contract Merging and Schema Checks

#### `_merged_contract(kind, name, base_contract)`

Combines the base contract with any matching runtime overlay.

#### `_validate_schema(kind, name, payload)`

Applies JSON Schema validation.

Returns `SCHEMA_VIOLATION` on failure.

## Approval Logic

#### `_issue_or_validate_approval(...)`

This is the approval gate.

Behavior:

- if no approval is required, returns `None`
- if approval is required and no token is provided:
  - creates a new token
  - stores it in `_pending_approvals`
  - returns `require_approval`
- if a token is provided and matches the exact operation fingerprint:
  - consumes the token
  - allows execution to continue
- if a token does not match:
  - returns `APPROVAL_TOKEN_MISMATCH`

This is used for:

- capability approval
- resource approval
- prompt approval
- dynamic rule escalation
- cumulative risk escalation

## Constraint and Preconditions Logic

#### `_apply_dynamic_arg_rules(name, args, constraints)`

Runs `arg_rules` from policy.

Useful for:

- regex-based blocking
- host/path/content specific emergency rules
- dynamic approvals

#### `_validate_identity_constraints(name, agent_id, framework, constraints)`

Checks:

- `allowed_agents`
- `allowed_frameworks`

#### `_validate_preconditions(name, constraints, evidence_ids, trust_vector)`

Checks:

- `require_evidence`
- `min_evidence_ids`
- `min_grounding_score`
- `max_hallucination_risk`

This is where “prove it before acting” is enforced for individual capabilities.

#### `_validate_field_lengths(name, args, constraints)`

Checks `max_arg_lengths`.

## Sequence and Workflow Logic

This is the part that makes Layer B capability-flow aware, not just single-call aware.

#### `_sequence_policy_for_workflow(workflow)`

Returns the policy for one workflow name.

#### `_validate_transition_graph(capability_name, history, graph, reason_code)`

Enforces what may follow what.

Examples:

- `__start__ -> db_query`
- `db_query -> send_email`
- `web_fetch -> retrieval_summary`

#### `_validate_allowed_capabilities(capability_name, workflow_policy)`

Enforces:

- `allowed_capabilities`
- `denied_capabilities`

#### `_validate_required_evidence_for_chain(...)`

Requires evidence for specific chains.

Example:

- `db_query -> send_email` requires at least 2 evidence ids

#### `_validate_cumulative_risk(...)`

Adds up risk across the history plus the current capability.

If the workflow threshold is exceeded:

- either blocks
- or requires approval

depending on `risk_escalation_action`.

#### `_validate_intent_and_state(...)`

Checks whether the requested capability matches:

- the current user intent text
- the current workflow state

This is where Layer B can say:

- the tool choice does not match the request
- the workflow state is not ready for this action

#### `_validate_capability_sequence(...)`

This is the sequence orchestrator.

It ties together:

- workflow lookup
- allowed capability checks
- chain-specific evidence checks
- workflow and global transition graphs
- cumulative risk escalation
- intent and state checks

If there is no workflow and no history, it skips sequence checks entirely.

## Common Constraint Logic

#### `_validate_common_constraints(name, args, constraints)`

This is the main argument and content policy checker.

It enforces:

- dynamic arg rules
- max arg lengths
- path traversal blocking
- path allowlist and denylist
- URL scheme, allowlist, denylist, and SSRF checks
- recipient email domain allowlists
- SQL safety rules
- max body size
- regex rules

Common reason codes from here include:

- `PATH_TRAVERSAL`
- `PATH_POLICY_VIOLATION`
- `DOMAIN_POLICY_VIOLATION`
- `RECIPIENT_DOMAIN_NOT_ALLOWED`
- `SQL_POLICY_VIOLATION`
- `CONTENT_TOO_LARGE`
- `REGEX_CONSTRAINT_FAILED`

## Public Validation Methods

These are the methods other code should call.

### `validate_call(...)`

Primary capability validation entrypoint.

Execution order:

1. hot-reload policy if needed
2. deny by default if capability is not registered
3. merge runtime rules
4. schema validation
5. identity validation
6. sequence and workflow validation
7. capability preconditions
8. common argument and content constraints
9. approval gate
10. return `ALLOW`

### `validate_capability_call(...)`

Alias to `validate_call(...)`.

This is the capability-first API and the preferred Layer B naming.

### `validate_resource_read(...)`

Resource read validation entrypoint.

Execution order:

1. find matching resource contract
2. schema validation
3. identity validation
4. URI/path/domain constraint checks
5. approval gate

### `validate_prompt_get(...)`

Prompt access validation entrypoint.

Execution order:

1. ensure prompt is registered
2. schema validation
3. identity validation
4. common constraints
5. approval gate

## Postconditions

#### `sanitize_output(tool_name, output)`

This is the output postcondition helper.

It recursively redacts sensitive-looking fields such as:

- `password`
- `secret`
- `token`
- `api_key`
- `private_key`
- `credential`
- `authorization`

It returns a sanitized copy of the output.

## Introspection Methods

These make Layer B easy to inspect from tests or a CLI.

- `list_tools()`
- `list_capabilities()`
- `list_resources()`
- `list_prompts()`
- `get_risk_level(tool_name)`
- `get_capability_risk_level(capability_name)`
- `get_tool_contract(tool_name)`
- `get_capability_contract(capability_name)`
- `get_resource_contract(resource_name)`
- `get_prompt_contract(prompt_name)`
- `get_schema(kind, name)`
- `get_capability_schema(capability_name)`
- `policy_snapshot()`
- `pending_approvals_snapshot()`
- `reload()`

## How to See Layer B Working

### 1. List capabilities

```powershell
.\.venv\Scripts\python.exe -m layer_b list
```

### 2. Inspect one capability

```powershell
.\.venv\Scripts\python.exe -m layer_b inspect send_email
```

### 3. Inspect a workflow

```powershell
.\.venv\Scripts\python.exe -m layer_b workflow outbound_notification
```

### 4. Validate a capability call

```powershell
.\.venv\Scripts\python.exe -m layer_b validate web_fetch --args "{\"url\":\"http://169.254.169.254/latest/meta-data/\"}"
```

### 5. Run the demo

```powershell
.\.venv\Scripts\python.exe examples/layer_b_only.py
```

The demo in [examples/layer_b_only.py](/c:/ML/ascp/examples/layer_b_only.py) shows:

- capability listing
- contract inspection
- workflow inspection
- blocked SSRF attempt
- approval-required email
- workflow-gated capability call

## How to Read the Tests

### [tests/test_layer_b_only.py](/c:/ML/ascp/tests/test_layer_b_only.py)

This verifies the standalone Layer B surface:

- policy load
- capability listing
- contract inspection
- direct explanation of a block decision

### [tests/test_contracts.py](/c:/ML/ascp/tests/test_contracts.py)

This is the main Layer B behavior suite.

It verifies:

- approval workflow
- approval token binding
- path traversal blocking
- SQL safety
- identity constraints
- evidence requirements
- trust threshold checks
- regex and length constraints
- transition graph enforcement
- workflow sequence policy
- chain-specific evidence requirements
- cumulative risk escalation
- intent and state verification
- output sanitization

## What Layer B Does Not Do

Layer B does not:

- execute the capability
- fetch the resource itself
- generate prompts
- do end-user DLP scanning across arbitrary output text
- replace sandboxing or OS isolation

It is a policy decision and contract enforcement layer.

## If You Move Layer B To A New Repo

Take these files:

- [layer_b.py](/c:/ML/ascp/layer_b.py)
- [apps/gateway/middleware/pep_tool.py](/c:/ML/ascp/apps/gateway/middleware/pep_tool.py)
- [policy/tool_permissions.yaml](/c:/ML/ascp/policy/tool_permissions.yaml)
- the schema files in [/c:/ML/ascp/schemas](/c:/ML/ascp/schemas)
- [examples/layer_b_only.py](/c:/ML/ascp/examples/layer_b_only.py)
- [tests/test_layer_b_only.py](/c:/ML/ascp/tests/test_layer_b_only.py)
- [tests/test_contracts.py](/c:/ML/ascp/tests/test_contracts.py)

The minimum Python dependencies are:

- `pyyaml`
- `jsonschema`
- `pytest` for tests

## Short Mental Model

Layer B is:

- typed
- deny-by-default
- policy-driven
- workflow-aware
- approval-capable
- introspectable

Its core question is always:

“Given this exact capability call, with this context, should the system allow it, block it, or pause for approval?”
