# Layer B SDK

Layer B is the capability contract and policy enforcement layer for tool-using agents.

It does one job:

- validate every tool, resource, or prompt access before execution
- return `allow`, `block`, or `require_approval`
- write local decision events to an easy-to-find JSONL log

Layer B is now packaged for SDK use through `layerb`.

## Package Surface

Python:

```python
from layerb import LayerBEngine, register_runtime_tool

engine = LayerBEngine.from_defaults()
print(engine.describe_paths())
```

Runtime helpers also exposed by the package:

- `register_runtime_tool(...)`
- `resolve_tool_path(...)`

CLI:

```powershell
python -m layerb paths
python -m layerb list
python -m layerb events
python -m layerb feedback --report
```

## Matching Order

Layer B resolves capability contracts in this order:

1. exact capability name
2. argument schema hash
3. inferred family
4. catch-all default
5. unknown capability mode

This keeps the original logic intact while making the SDK usable out of the box.

## Zero-Config Defaults

The package ships with bundled defaults for common families such as:

- `file_read`
- `file_write`
- `web_fetch`
- `db_query`
- `shell_exec`

These bundled defaults live inside the package and are loaded automatically.

Developers can still override behavior in their project YAML:

- exact tool name contracts in `policy/tool_permissions.yaml`
- family templates using `match.inferred_family`
- custom constraints and approval requirements

`policy/tool_permissions.yaml` is the expected override path in the developer's
project. It is not bundled inside this repository.

## Local Event Logging

Layer B no longer depends on any external observability service.

All decision tracking is local by default through a JSONL event log. The default path is:

```text
logs/layer_b/events.jsonl
```

You can override it with:

- constructor argument `event_log_path=...`
- environment variable `LAYERB_EVENT_LOG`
- CLI flag `--event-log`

Unknown capability handling can also be tuned with:

- environment variable `LAYERB_UNKNOWN_CAPABILITY_MODE`

Useful API:

```python
engine = LayerBEngine(event_log_path="logs/my_app/layer_b.jsonl")
print(engine.describe_paths()["event_log_path"])
events = engine.recent_security_events(limit=20)
```

## Policy Files

Layer B uses two policy sources:

- bundled base policy inside the SDK package
- optional project policy at `policy/tool_permissions.yaml`

At load time, the project policy overrides the bundled defaults.

This gives developers:

- zero-config startup
- project-local control
- no need to describe every tool up front

## Developer Overrides

Example exact-name override:

```yaml
capabilities:
  my_custom_reader:
    risk: high
    scopes: [local_fs]
    approval_required: true
    constraints:
      deny_path_traversal: true
```

Example family override:

```yaml
capabilities:
  default_file_read_family:
    risk: medium
    scopes: [local_fs]
    approval_required: false
    match:
      inferred_family: file_read
    constraints:
      deny_path_traversal: true
      path_denylist:
      - C:/Windows
```

## What Layer B Enforces

Layer B can validate:

- JSON Schema for tool arguments
- agent and framework identity constraints
- workflow and sequence rules
- path constraints
- URL/domain and SSRF protections
- SQL safety rules
- argument and body size limits
- preconditions and approval flows
- output sanitization

## Main API

Key methods on `LayerBEngine`:

- `describe_paths()`
- `list_capabilities()`
- `inspect_capability(name)`
- `inspect_workflow(name)`
- `validate_capability(...)`
- `explain_decision(...)`
- `recent_security_events(...)`
- `generate_contract_candidates()`
- `generate_feedback_suggestions(...)`
- `generate_feedback_report(...)`

## Main Files

- `layerb/engine.py`
  SDK-facing Layer B API and CLI.

- `layerb/validator.py`
  Main validator and runtime enforcement engine.

- `layerb/policy/default_tool_permissions.yaml`
  Bundled default Layer B policy for zero-config use.

- `policy/tool_permissions.yaml`
  Expected project-local override policy path in the developer application.

- `layerb/schemas/`
  Bundled schemas used by the SDK defaults.

- `layerb/policies/candidates.py`
  Candidate generation for newly observed tools.

- `layerb/policies/feedback.py`
  Feedback suggestions and aggregated reports from repeated incidents. The feedback loop is advisory only and never mutates the active policy by itself.

## Scope

Layer B is the policy and decision layer.

It does not:

- sandbox the operating system
- isolate processes
- enforce network egress at the OS level
- implement the other SDK layers

Those concerns remain outside Layer B by design.









