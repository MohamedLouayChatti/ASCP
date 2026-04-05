from __future__ import annotations

import json
import time
from pathlib import Path
from uuid import uuid4

import yaml

from layerb import ContractDecision, ContractValidator


def _case_dir(name: str) -> Path:
    root = Path('.pytest_validator_hardening') / f'{name}-{uuid4().hex}'
    root.mkdir(parents=True, exist_ok=True)
    return root


def _make_validator(
    name: str,
    policy: dict[str, object],
    *,
    unknown_capability_mode: str = 'sandbox_allow',
) -> ContractValidator:
    root = _case_dir(name)
    schemas_dir = root / 'schemas'
    schemas_dir.mkdir(parents=True, exist_ok=True)
    policy_path = root / 'tool_permissions.yaml'
    policy_path.write_text(yaml.safe_dump(policy), encoding='utf-8')
    return ContractValidator(
        policy_path,
        schemas_dir,
        unknown_capability_mode=unknown_capability_mode,
    )


def test_unknown_capability_blocks_http_url_without_hostname() -> None:
    validator = _make_validator(
        'missing-hostname',
        {'version': '1.0', 'capabilities': {}},
    )

    result = validator.validate_call('unknown_tool', {'url': 'https://'})

    assert result.decision == ContractDecision.BLOCK
    assert result.reason_code == 'DOMAIN_POLICY_VIOLATION'
    assert 'missing_hostname' in result.details


def test_sql_allowlist_checks_referenced_tables_not_comment_text() -> None:
    validator = _make_validator(
        'sql-allowlist',
        {
            'version': '1.0',
            'capabilities': {
                'db_query': {
                    'risk': 'medium',
                    'scopes': ['read_only'],
                    'approval_required': False,
                    'constraints': {
                        'sql_mode': 'select_only',
                        'allowlisted_tables': ['users'],
                    },
                }
            },
        },
        unknown_capability_mode='require_approval',
    )

    result = validator.validate_call('db_query', {'sql': 'SELECT * FROM secrets -- users'})

    assert result.decision == ContractDecision.BLOCK
    assert result.reason_code == 'SQL_POLICY_VIOLATION'
    assert 'sql_table_not_allowlisted:SECRETS' in result.details


def test_dynamic_arg_rule_approval_token_round_trip_allows_call() -> None:
    validator = _make_validator(
        'arg-rule-approval',
        {
            'version': '1.0',
            'capabilities': {
                'review_tool': {
                    'risk': 'medium',
                    'scopes': ['custom'],
                    'approval_required': False,
                    'constraints': {
                        'arg_rules': [
                            {
                                'field': 'query',
                                'op': 'contains',
                                'value': 'secret',
                                'action': 'require_approval',
                                'reason': 'NEEDS_APPROVAL',
                            }
                        ]
                    },
                }
            },
        },
    )

    first = validator.validate_call('review_tool', {'query': 'secret plans'})
    second = validator.validate_call(
        'review_tool',
        {'query': 'secret plans'},
        approval_token=first.approval_token,
    )

    assert first.decision == ContractDecision.REQUIRE_APPROVAL
    assert first.approval_token is not None
    assert second.decision == ContractDecision.ALLOW
    assert second.reason_code == 'ALLOWED'


def test_schema_changes_reload_without_touching_policy_file() -> None:
    root = _case_dir('schema-reload')
    schemas_dir = root / 'schemas'
    schemas_dir.mkdir(parents=True, exist_ok=True)
    schema_path = schemas_dir / 'demo.schema.json'
    schema_path.write_text(
        json.dumps(
            {
                'type': 'object',
                'required': ['a'],
                'additionalProperties': False,
                'properties': {'a': {'type': 'string'}},
            }
        ),
        encoding='utf-8',
    )
    policy_path = root / 'tool_permissions.yaml'
    policy_path.write_text(
        yaml.safe_dump(
            {
                'version': '1.0',
                'capabilities': {
                    'demo_tool': {
                        'risk': 'low',
                        'scopes': ['custom'],
                        'approval_required': False,
                        'schema': 'schemas/demo.schema.json',
                    }
                },
            }
        ),
        encoding='utf-8',
    )

    validator = ContractValidator(policy_path, schemas_dir)

    initial = validator.validate_call('demo_tool', {'a': 'ok'})

    time.sleep(0.02)
    schema_path.write_text(
        json.dumps(
            {
                'type': 'object',
                'required': ['b'],
                'additionalProperties': False,
                'properties': {'b': {'type': 'string'}},
            }
        ),
        encoding='utf-8',
    )

    stale_payload = validator.validate_call('demo_tool', {'a': 'ok'})
    fresh_payload = validator.validate_call('demo_tool', {'b': 'ok'})
    reloaded_schema = validator.get_capability_schema('demo_tool')

    assert initial.decision == ContractDecision.ALLOW
    assert stale_payload.decision in {ContractDecision.ALLOW, ContractDecision.BLOCK}
    assert fresh_payload.decision == ContractDecision.ALLOW
    assert reloaded_schema is not None
    assert reloaded_schema['required'] == ['b']
    assert 'b' in reloaded_schema['properties']
