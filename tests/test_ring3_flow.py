"""Ring 3 action-local flow contracts and sensitivity inheritance tests."""

import json

from agentdojo.default_suites.v1.tools.types import Email
from agentdojo.default_suites.v1.tools.banking_client import Transaction
from agentdojo.method.analysis.data_need import (
    clear_task_plan_cache,
    generate_task_data_plan,
)
from agentdojo.method.analysis import l2_chain
from agentdojo.method.analysis.flow_policy import check_sensitive_egress
from agentdojo.method.analysis.parameter_binding import (
    all_placeholder_bindings,
    make_placeholder_symbol,
    placeholder_notice,
    resolve_parameter_bindings,
)
from agentdojo.method.analysis.defense_config import reset_config
from agentdojo.method.capture.interceptor import (
    TrackingContext,
    _argument_flow_labels,
    capture_tool_call,
)
from agentdojo.method.modeling.graph_db import reset_graph
from agentdojo.method.modeling.data_sensitivity import (
    DEFAULT_LEVEL,
    collect_value_origins,
    entity_level,
    index_value_origins,
    label_for_origins,
)
from agentdojo.method.modeling.labels import (
    CONFIDENTIALITY_LEVELS,
    derive_flow_label,
    make_confidentiality,
    make_flow_label,
    make_integrity,
)


RECIPIENT = "DE89370400440532013000"


TOOLS = [
    {
        "name": "workspace__get_unread_emails",
        "suite": "workspace",
        "effect": "read",
        "risk_level": "L0",
        "destination_fields": [],
        "input_schema": {"type": "object", "fields": {}},
        "output_schema": {
            "type": "array",
            "items": {
                "type": "object",
                "fields": {
                    "sender": {"type_schema": {"type": "str"}},
                    "body": {"type_schema": {"type": "str"}},
                },
            },
        },
    },
    {
        "name": "banking__send_money",
        "suite": "banking",
        "effect": "egress",
        "risk_level": "L2",
        "destination_fields": ["recipient"],
        "input_schema": {
            "type": "object",
            "fields": {
                "recipient": {"type_schema": {"type": "str"}},
                "amount": {"type_schema": {"type": "float"}},
            },
        },
        "output_schema": {"type": "object", "fields": {}},
    },
]


def _email(sender: str = "alice@example.com", body: str = "Pay 12 EUR") -> Email:
    return Email(
        id_="90010",
        sender=sender,
        recipients=["user@example.com"],
        subject="Bill",
        body=body,
        status="received",
    )


def test_app_entity_sensitivity_is_human_defined_and_inherited():
    assert entity_level("workspace", "email") == "confidential"
    assert entity_level("banking", "transaction") == "secret"
    assert entity_level("unknown", "unknown") == DEFAULT_LEVEL
    assert make_confidentiality(level="invalid")["level"] == "secret"
    assert make_integrity(
        kind="trusted",
        taint_roots=["workspace:email"],
    )["kind"] == "untrusted"
    assert derive_flow_label(
        [],
        source_kind="user_prompt",
        content="Read my email.",
        source_id="prompt-1",
    )["confidentiality"]["level"] == "internal"
    assert derive_flow_label(
        [],
        source_kind="unknown_external_source",
        content="Unclassified content.",
        source_id="unknown-1",
    )["confidentiality"]["level"] == "secret"

    origins = collect_value_origins(
        [_email()],
        app="workspace",
        source_tool="workspace__get_unread_emails",
        activity_id="activity_email",
    )
    sender = next(item for item in origins if item.source_path.endswith(".sender"))
    body = next(item for item in origins if item.source_path.endswith(".body"))
    assert sender.entity == "email"
    assert body.level == "confidential"

    derived = label_for_origins([sender, body])
    assert derived["level"] == "confidential"
    assert "workspace:email" in derived["source_entities"]
    assert "email" in derived["categories"]
    assert derived["source_ids"]

    transaction = Transaction(
        id=1,
        sender="DE00000000000000000000",
        recipient=RECIPIENT,
        amount=20,
        subject="Bill",
        date="2024-05-15",
        recurring=False,
    )
    bank_origins = collect_value_origins(
        transaction,
        app="banking",
        source_tool="banking__get_most_recent_transactions",
        activity_id="activity_bank",
        fallback_categories={"financial_data", "financial_amount"},
    )
    assert "financial_data" in bank_origins[0].label[
        "confidentiality"
    ]["categories"]
    inherited = label_for_origins([body, *bank_origins])
    assert inherited["level"] == "secret"
    assert {"workspace:email", "banking:transaction"}.issubset(
        inherited["source_entities"]
    )


def test_flow_contract_compiles_symbols_and_states_placeholder_meaning():
    clear_task_plan_cache()

    def planner(_request: str) -> str:
        return json.dumps(
            {
                "schema_version": 2,
                "task_goal": "Reply to the sender.",
                "steps": [
                    {
                        "id": "g1",
                        "actions": [
                            {
                                "name": "workspace__get_unread_emails",
                                "authorization_evidence": "read my unread email",
                            }
                        ],
                    },
                    {
                        "id": "g2",
                        "depends_on": ["g1"],
                        "actions": [
                            {
                                "name": "banking__send_money",
                                "authorization_evidence": "send the amount to the sender",
                                "flow_contract": {
                                    "destination": {
                                        "parameters": ["recipient"],
                                        "mode": "derived",
                                    },
                                    "data_sources": [
                                        "workspace:email",
                                        "user_prompt",
                                    ],
                                    "parameter_bindings": {
                                        "recipient": {
                                            "mode": "copy",
                                            "source_action": "workspace__get_unread_emails",
                                            "source_path": "$[*].sender",
                                            "selector": "unique",
                                        }
                                    },
                                },
                            }
                        ],
                    },
                ],
                "confidence": 0.96,
            }
        )

    plan = generate_task_data_plan(
        "read my unread email and send the amount to the sender",
        planner,
        TOOLS,
    )
    action = plan["steps"][1]["actions"][0]
    contract = action["flow_contract"]
    binding = contract["parameter_bindings"]["recipient"]
    assert binding["symbol"].startswith("__CTRL_SLOT_")
    assert contract["max_confidentiality"] == "confidential"
    assert "controller-owned" in placeholder_notice(plan)
    assert {
        item["parameter"] for item in all_placeholder_bindings(plan)
    } == {"recipient"}

    origins = collect_value_origins(
        [_email()],
        app="workspace",
        source_tool="workspace__get_unread_emails",
        activity_id="activity_email",
    )
    resolved, resolutions, errors, warnings = resolve_parameter_bindings(
        tool_name="banking__send_money",
        args={"recipient": binding["symbol"], "amount": 12},
        plan=plan,
        value_origins=origins,
    )
    assert errors == []
    assert warnings == []
    assert resolved["recipient"] == "alice@example.com"
    assert resolutions[0]["status"] == "resolved"
    assert resolutions[0]["used_symbol"] is True

    tampered, _, tampered_errors, _ = resolve_parameter_bindings(
        tool_name="banking__send_money",
        args={"recipient": "attacker@example.com", "amount": 12},
        plan=plan,
        value_origins=origins,
    )
    assert tampered["recipient"] == "attacker@example.com"
    assert "placeholder_value_mismatch:recipient" in tampered_errors


def test_task_compiler_accepts_multi_source_derived_binding():
    clear_task_plan_cache()
    tools = [
        TOOLS[0],
        {
            "name": "banking__get_most_recent_transactions",
            "suite": "banking",
            "effect": "read",
            "risk_level": "L0",
            "destination_fields": [],
            "input_schema": {"type": "object", "fields": {}},
            "output_schema": {
                "type": "array",
                "items": {
                    "type": "object",
                    "fields": {"id": {"type_schema": {"type": "int"}}},
                },
            },
        },
        TOOLS[1],
    ]

    def planner(_request: str) -> str:
        return json.dumps(
            {
                "schema_version": 2,
                "task_goal": "Pay the bill.",
                "steps": [
                    {
                        "id": "g1",
                        "actions": [
                            {
                                "name": "workspace__get_unread_emails",
                                "authorization_evidence": "read my email",
                            }
                        ],
                    },
                    {
                        "id": "g2",
                        "actions": [
                            {
                                "name": "banking__get_most_recent_transactions",
                                "authorization_evidence": "read my transactions",
                            }
                        ],
                    },
                    {
                        "id": "g3",
                        "depends_on": ["g1", "g2"],
                        "actions": [
                            {
                                "name": "banking__send_money",
                                "authorization_evidence": f"pay {RECIPIENT}",
                                "flow_contract": {
                                    "destination": {
                                        "parameters": ["recipient"],
                                        "mode": "literal",
                                        "allowed_values": [RECIPIENT],
                                    },
                                    "data_sources": [
                                        "workspace:email",
                                        "banking:transaction",
                                    ],
                                    "parameter_bindings": {
                                        "amount": {
                                            "mode": "derived_sources",
                                                "generation_kind": "selection",
                                                "required_source_refs": [
                                                    {
                                                        "app": "workspace",
                                                        "entity": "email",
                                                        "source_action": "workspace__get_unread_emails",
                                                    },
                                                    {
                                                        "app": "banking",
                                                        "entity": "transaction",
                                                        "source_action": "banking__get_most_recent_transactions",
                                                    },
                                                ],
                                            "allowed_source_refs": [
                                                {
                                                    "app": "workspace",
                                                    "entity": "email",
                                                    "source_action": "workspace__get_unread_emails",
                                                },
                                                {
                                                    "app": "banking",
                                                    "entity": "transaction",
                                                    "source_action": "banking__get_most_recent_transactions",
                                                },
                                            ],
                                        }
                                    },
                                },
                            }
                        ],
                    },
                ],
                "confidence": 0.97,
            }
        )

    plan = generate_task_data_plan(
        f"read my email and transactions and pay {RECIPIENT}",
        planner,
        tools,
    )
    binding = plan["steps"][2]["actions"][0]["flow_contract"][
        "parameter_bindings"
    ]["amount"]
    assert binding["mode"] == "derived_sources"
    assert {
        (item["app"], item["entity"])
        for item in binding["allowed_source_refs"]
    } == {
        ("workspace", "email"),
        ("banking", "transaction"),
    }
    assert binding["symbol"].startswith("__CTRL_SLOT_")


def test_ring3_uses_only_final_arguments_and_supports_receiver_states():
    plan = {
        "valid": True,
        "steps": [
            {
                "id": "g1",
                "actions": [
                    {
                        "name": "banking__send_money",
                        "effect": "egress",
                        "flow_contract": {
                            "valid": True,
                            "destination": {
                                "parameters": ["recipient"],
                                "mode": "literal",
                                "allowed_values": [RECIPIENT],
                            },
                            "data_sources": [
                                "banking:transaction",
                                "user_prompt",
                            ],
                            "max_confidentiality": "secret",
                            "parameter_bindings": {},
                        },
                    }
                ],
            }
        ],
    }
    event = {
        "tool_intent": "banking__send_money",
        "inputs": {"recipient": RECIPIENT, "amount": 25},
        "task_data_plan": plan,
        "argument_flow_labels": {
            "amount": make_flow_label(
                confidentiality=make_confidentiality(
                    level="secret",
                    source_entities=["banking:transaction"],
                )
            )
        },
        # A sensitive value that never reaches the sink must not affect Ring 3.
        "input_flow_label": make_flow_label(
            confidentiality=make_confidentiality(
                level="secret",
                source_entities=["travel:user"],
            )
        ),
    }
    allowed = check_sensitive_egress(event)
    assert allowed["passed"] is True
    assert allowed["destination_state"] == "fixed_authorized"

    event["inputs"]["recipient"] = "attacker@example.com"
    blocked = check_sensitive_egress(event)
    assert blocked["passed"] is False
    assert "destination_not_authorized" in blocked["reason"]

    event["inputs"]["recipient"] = RECIPIENT
    event["argument_flow_labels"]["amount"] = make_flow_label(
        confidentiality=make_confidentiality(
            level="secret",
            source_entities=["travel:user"],
        )
    )
    source_blocked = check_sensitive_egress(event)
    assert source_blocked["passed"] is False
    assert "data_source_not_authorized" in source_blocked["reason"]

    unknown = {
        **event,
        "argument_flow_labels": {
            "amount": make_flow_label(
                confidentiality=make_confidentiality(level="secret")
            )
        },
        "parameter_resolution_warnings": ["provenance_unknown:amount"],
    }
    unknown_result = check_sensitive_egress(unknown)
    assert unknown_result["passed"] is False
    assert (
        "egress_argument_without_provenance:amount"
        in unknown_result["reason"]
    )

    assert (
        CONFIDENTIALITY_LEVELS["secret"]
        > CONFIDENTIALITY_LEVELS["confidential"]
    )


def test_capture_indexes_values_from_original_app_entities():
    reset_graph()
    reset_config()
    TrackingContext().reset()
    ctx = TrackingContext()
    ctx.ensure_task("Read my unread email.", suite="workspace")
    ctx.task_data_plan = {
        "valid": True,
        "allowed_actions": ["get_unread_emails"],
        "allowed_suites": ["workspace"],
        "allowed_effects": ["read"],
        "forbidden_effects": [],
        "l2_actions": [],
        "l2_grants": [],
        "action_steps": {"get_unread_emails": "g1"},
        "steps": [
            {
                "id": "g1",
                "depends_on": [],
                "actions": [
                    {
                        "name": "get_unread_emails",
                        "effect": "read",
                        "risk_level": "L0",
                    }
                ],
            }
        ],
        "plan_id": "plan_capture",
        "plan_hash": "sha256:capture",
        "plan_revision": 1,
    }
    ctx.plan_usage = {"planned_action_counts": {}, "completed_steps": []}
    ctx.set_reasoning_context(
        "Read my unread email.",
        "Call get_unread_emails.",
        1.0,
        flow_label=make_flow_label(
            confidentiality=make_confidentiality(
                level="internal",
                source_entities=["user_prompt"],
            )
        ),
        context_messages=[],
    )

    def fake_runtime(_runtime, _env, _function, _args, _raise_on_error):
        return [_email()], None

    try:
        result, error = capture_tool_call(fake_runtime)(
            object(),
            None,
            "get_unread_emails",
            {},
            True,
        )
        assert error is None
        assert result
        origins = [
            item
            for item in ctx.tool_value_origins
            if item.source_tool == "get_unread_emails"
        ]
        assert any(item.source_path.endswith(".sender") for item in origins)
        sender = next(
            item for item in origins if item.source_path.endswith(".sender")
        )
        assert sender.entity == "email"
        assert sender.level == "confidential"
        assert "workspace:email" in sender.label["confidentiality"][
            "source_entities"
        ]
    finally:
        reset_graph()
        TrackingContext().reset()
        reset_config()


def test_user_prompt_value_does_not_reuse_matching_external_source():
    origins = collect_value_origins(
        [_email(body=f"Utility bill for account {RECIPIENT}.")],
        app="workspace",
        source_tool="workspace__get_unread_emails",
        activity_id="activity_email",
    )
    labels, sources = _argument_flow_labels(
        {"recipient": RECIPIENT},
        value_index=index_value_origins(origins),
        parameter_resolutions=[
            {
                "parameter": "recipient",
                "source_refs": [{"source_kind": "user_prompt"}],
            }
        ],
    )
    assert labels["recipient"]["confidentiality"]["source_entities"] == [
        "user_prompt"
    ]
    assert labels["recipient"]["injection"]["source_flagged"] is False
    assert sources == [
        {
            "argument_root": "recipient",
            "source_kind": "user_prompt",
            "source_app": "system",
            "source_entity": "user_prompt",
            "source": "user_prompt",
            "source_risk": False,
            "risky_entities": [],
        }
    ]


def test_cross_app_capture_resolves_sender_and_passes_ring3(monkeypatch):
    reset_graph()
    reset_config()
    TrackingContext().reset()
    ctx = TrackingContext()
    ctx.ensure_task(
        "Read my unread email and send the amount to the sender.",
        suite="unified",
    )
    symbol = "__CTRL_SLOT_integration_recipient__"
    amount_symbol = "__CTRL_SLOT_integration_amount__"
    ctx.task_data_plan = {
        "valid": True,
        "allowed_actions": [
            "workspace__get_unread_emails",
            "banking__send_money",
        ],
        "allowed_suites": ["workspace", "banking"],
        "allowed_effects": ["read", "egress"],
        "forbidden_effects": [],
        "l2_actions": ["banking__send_money"],
        "l2_grants": [
            {
                "action": "banking__send_money",
                "step_id": "g2",
                "authorization_evidence": "send the amount to the sender",
                "max_calls": 1,
            }
        ],
        "action_steps": {
            "workspace__get_unread_emails": "g1",
            "banking__send_money": "g2",
        },
        "steps": [
            {
                "id": "g1",
                "depends_on": [],
                "actions": [
                    {
                        "name": "workspace__get_unread_emails",
                        "effect": "read",
                        "risk_level": "L0",
                    }
                ],
            },
            {
                "id": "g2",
                "depends_on": ["g1"],
                "actions": [
                    {
                        "name": "banking__send_money",
                        "effect": "egress",
                        "risk_level": "L2",
                        "flow_contract": {
                            "valid": True,
                            "destination": {
                                "parameters": ["recipient"],
                                "mode": "derived",
                                "allowed_values": [],
                            },
                            "data_sources": [
                                "workspace:email",
                                "banking:transaction",
                                "user_prompt",
                            ],
                            "max_confidentiality": "secret",
                            "parameter_bindings": {
                                "recipient": {
                                    "source_action": "workspace__get_unread_emails",
                                    "source_tool": "workspace__get_unread_emails",
                                    "source_path": "$[*].sender",
                                    "selector": "unique",
                                    "symbol": symbol,
                                    },
                                    "amount": {
                                        "mode": "derived_sources",
                                        "generation_kind": "extraction",
                                        "semantic_type": "number",
                                    "required_source_refs": [
                                        {
                                            "app": "workspace",
                                            "entity": "email",
                                            "source_action": "workspace__get_unread_emails",
                                        }
                                    ],
                                        "allowed_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "workspace__get_unread_emails",
                                            }
                                        ],
                                        "symbol": amount_symbol,
                                    },
                            },
                        },
                    }
                ],
            },
        ],
        "plan_id": "plan_integration",
        "plan_hash": "sha256:integration",
        "plan_revision": 1,
    }
    ctx.plan_usage = {"planned_action_counts": {}, "completed_steps": []}
    def provider(request: str) -> str:
        if "RESOLUTION_INPUT" in request:
            return json.dumps(
                {
                    "resolutions": [
                        {
                            "parameter": "amount",
                            "value": 125.5,
                            "derivation_type": "extraction",
                                "explanation": (
                                    "邮件正文明确给出应付金额 125.50。"
                                ),
                                "confidence": 0.96,
                            "source_evidence": [
                                {
                                    "app": "workspace",
                                    "entity": "email",
                                    "entity_id": "90010",
                                    "source_action": (
                                        "workspace__get_unread_emails"
                                    ),
                                    "source_path": "$[0].body",
                                    "start": 12,
                                    "end": 18,
                                    "extracted_text": "125.50",
                                }
                            ],
                        }
                    ]
                }
            )
        return json.dumps(
            {
                "consistent": True,
                "reason": "valid chain",
                "confidence": 0.99,
            }
        )

    ctx.task_data_plan_provider = provider

    def fake_read(_runtime, _env, _function, _args, _raise_on_error):
        return [_email(body="Amount due: 125.50 EUR")], None

    def fake_send(_runtime, _env, _function, args, _raise_on_error):
        assert args["recipient"] == "alice@example.com"
        return {"message": "sent"}, None

    monkeypatch.setattr(
        l2_chain,
        "check_l2_chain_with_model",
        lambda **_kwargs: {
            "consistent": True,
            "available": True,
            "reason": "valid chain",
            "evidence": ["g1", "g2"],
            "confidence": 0.99,
        },
    )
    monkeypatch.setattr(
        l2_chain.ConfirmationBroker,
        "request",
        lambda self, **kwargs: {
            "request_id": "confirm_ring3_integration",
            "task_id": kwargs["task_id"],
            "tool_name": kwargs["tool_name"],
            "app": kwargs["app"],
            "risk_level": kwargs["risk_level"],
            "args": kwargs["args"],
            "plan_id": kwargs["plan"]["plan_id"],
            "plan_revision": kwargs["plan"]["plan_revision"],
            "chain_check": kwargs["chain_check"],
            "flow_check": kwargs["flow_check"],
            "status": "approved",
            "approved": True,
        },
    )

    try:
        _, read_error = capture_tool_call(fake_read)(
            object(),
            None,
            "workspace__get_unread_emails",
            {},
            True,
        )
        assert read_error is None
        assert "g1" in ctx.plan_usage["completed_steps"]

        ctx.set_reasoning_context(
            "Read my unread email and send the amount to the sender.",
            "The sender is Alice and the amount is 125.5.",
            2.0,
            flow_label=make_flow_label(
                confidentiality=make_confidentiality(
                    level="confidential",
                    source_entities=["workspace:email", "user_prompt"],
                )
            ),
            context_messages=[],
        )
        result, send_error = capture_tool_call(fake_send)(
            object(),
            None,
            "banking__send_money",
            {"recipient": symbol, "amount": 125.5},
            True,
        )
        assert send_error is None
        assert result == {"message": "sent"}
        confirmation = ctx.events[-1]["l2_confirmation"]
        assert confirmation["args"]["recipient"] == "alice@example.com"
        assert confirmation["flow_check"]["passed"] is True
        assert (
            confirmation["flow_check"]["destination_state"]
            == "derived_authorized"
        )
    finally:
        reset_graph()
        TrackingContext().reset()
        reset_config()


def test_derived_calculation_requires_multi_source_evidence_and_warns():
    symbol = make_placeholder_symbol(
        plan_seed="prompt",
        tool_name="banking__send_money",
        parameter="amount",
        source_tool="derived_sources",
        source_path="sources",
    )
    plan = {
        "valid": True,
        "steps": [
            {
                "id": "g1",
                "actions": [
                    {
                        "name": "banking__send_money",
                        "effect": "egress",
                        "flow_contract": {
                            "valid": True,
                            "data_sources": [
                                "workspace:email",
                                "banking:transaction",
                                "user_prompt",
                            ],
                            "parameter_bindings": {
                                "amount": {
                                    "mode": "derived_sources",
                                    "required_source_refs": [
                                        {
                                            "app": "workspace",
                                            "entity": "email",
                                            "source_action": "workspace__get_unread_emails",
                                        },
                                        {
                                            "app": "banking",
                                            "entity": "transaction",
                                            "source_action": "banking__get_most_recent_transactions",
                                        },
                                    ],
                                    "allowed_source_refs": [
                                        {
                                            "app": "workspace",
                                            "entity": "email",
                                            "source_action": "workspace__get_unread_emails",
                                        },
                                        {
                                            "app": "banking",
                                            "entity": "transaction",
                                            "source_action": "banking__get_most_recent_transactions",
                                        },
                                    ],
                                    "source_tool": "derived_sources",
                                    "source_path": "sources",
                                    "symbol": symbol,
                                }
                            },
                        },
                    }
                ],
            }
        ],
    }
    email_origins = collect_value_origins(
        [_email()],
        app="workspace",
        source_tool="workspace__get_unread_emails",
        activity_id="activity_email",
    )
    transaction = Transaction(
        id=7,
        sender="DE00000000000000000000",
        recipient=RECIPIENT,
        amount=20,
        subject="Fee",
        date="2024-05-15",
        recurring=False,
    )
    transaction_origins = collect_value_origins(
        transaction,
        app="banking",
        source_tool="banking__get_most_recent_transactions",
        activity_id="activity_transaction",
    )

    def resolver(_request: str) -> str:
        email_body = next(
            origin
            for origin in email_origins
            if origin.source_path.endswith(".body")
        )
        transaction_amount = next(
            origin
            for origin in transaction_origins
            if origin.source_path.endswith(".amount")
        )
        return json.dumps(
            {
                "resolutions": [
                    {
                        "parameter": "amount",
                        "value": 130.0,
                        "derivation_type": "calculation",
                            "explanation": (
                                "根据提供的邮件金额和交易金额计算得到 130。"
                            ),
                            "confidence": 0.88,
                        "source_evidence": [
                            {
                                "app": email_body.app,
                                "entity": email_body.entity,
                                "entity_id": email_body.entity_id,
                                "source_action": email_body.source_tool,
                                "source_path": email_body.source_path,
                                "start": 0,
                                "end": len(email_body.value),
                                "extracted_text": email_body.value,
                            },
                            {
                                "app": transaction_amount.app,
                                "entity": transaction_amount.entity,
                                "entity_id": transaction_amount.entity_id,
                                "source_action": transaction_amount.source_tool,
                                "source_path": transaction_amount.source_path,
                                "start": 0,
                                "end": len(str(transaction_amount.value)),
                                "extracted_text": str(
                                    transaction_amount.value
                                ),
                            },
                        ],
                    }
                ]
            }
        )

    resolved, resolutions, errors, warnings = resolve_parameter_bindings(
        tool_name="banking__send_money",
        args={"amount": symbol},
        plan=plan,
        value_origins=[*email_origins, *transaction_origins],
        derive_resolver=resolver,
        user_prompt="Pay the bill using the balance.",
        context_messages=[],
    )
    assert errors == []
    assert warnings == ["semantic_derivation_unverified:amount"]
    assert resolved["amount"] == 130.0
    assert resolutions[0]["status"] == "resolved"
    assert len(resolutions[0]["source_refs"]) == 2
    assert set(resolutions[0]["source_entities"]) == {
        "workspace:email",
        "banking:transaction",
    }

    unknown_value, unknown_resolutions, unknown_errors, unknown_warnings = (
        resolve_parameter_bindings(
            tool_name="banking__send_money",
            args={"amount": 130.0},
            plan=plan,
            value_origins=[*email_origins, *transaction_origins],
            derive_resolver=lambda _request: json.dumps(
                {
                    "resolutions": [
                        {
                            "parameter": "amount",
                            "value": 130.0,
                            "explanation": "测试未提供可核验的来源证据。",
                            "confidence": 0.8,
                            "source_refs": [],
                        }
                    ]
                }
            ),
            user_prompt="Pay the bill using the balance.",
            context_messages=[],
        )
    )
    assert unknown_errors == ["derived_source_evidence_missing:amount"]
    assert unknown_warnings == []
    assert unknown_value["amount"] == 130.0
    assert unknown_resolutions == []

    _, _, missing_explanation_errors, _ = resolve_parameter_bindings(
        tool_name="banking__send_money",
        args={"amount": 130.0},
        plan=plan,
        value_origins=[*email_origins, *transaction_origins],
        derive_resolver=lambda _request: json.dumps(
            {
                "resolutions": [
                    {
                        "parameter": "amount",
                        "value": 130.0,
                        "confidence": 0.8,
                        "source_refs": [],
                    }
                ]
            }
        ),
        user_prompt="Pay the bill using the balance.",
        context_messages=[],
    )
    assert missing_explanation_errors == [
        "parameter_explanation_missing:amount"
    ]
