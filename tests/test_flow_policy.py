"""Tests for the lightweight capture-labelled runtime policy."""

import json
import time

from agentdojo.method.analysis.data_need import (
    clear_task_plan_cache,
    compile_runtime_plan_update,
    generate_task_data_plan,
)
from agentdojo.method.analysis.defense_config import (
    RING_METHODS,
    get_config,
    reset_config,
)
from agentdojo.method.analysis.flow_policy import (
    check_sensitive_egress,
    check_task_scope,
    check_untrusted_control,
)
from agentdojo.method.analysis.pipeline import (
    process_after_execution,
    process_before_execution,
)
from agentdojo.method.modeling.graph_db import (
    get_graph_data,
    record_activity,
    record_risk_assessments,
    record_task_start,
    reset_graph,
)
from agentdojo.method.modeling.labels import (
    derive_flow_label,
    make_confidentiality,
    make_flow_label,
    make_injection,
    make_integrity,
)


RECIPIENT = "DE89370400440532013000"

TOOLS = [
    {
        "name": "workspace__get_unread_emails",
        "suite": "workspace",
        "description": "Read unread email",
        "effect": "read",
                    "risk_level": "L0",
        "confidentiality": "internal",
        "categories": ["email"],
        "control_fields": [],
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
        "name": "get_current_day",
        "suite": "workspace",
        "description": "Get the current day",
        "effect": "read",
        "risk_level": "L0",
        "confidentiality": "public",
        "categories": [],
        "control_fields": [],
        "destination_fields": [],
        "input_schema": {"type": "object", "fields": {}},
        "output_schema": {"type": "date"},
    },
    {
        "name": "banking__send_money",
        "suite": "banking",
        "description": "Transfer money",
        "effect": "egress",
        "risk_level": "L2",
        "confidentiality": "secret",
        "categories": ["financial_data", "financial_amount"],
        "control_fields": [
            "recipient",
            "amount",
            "subject",
            "date",
            "recurring",
        ],
        "destination_fields": ["recipient"],
        "input_schema": {
            "type": "object",
            "fields": {
                "recipient": {"type_schema": {"type": "str"}},
                "amount": {"type_schema": {"type": "float"}},
                "date": {"type_schema": {"type": "date"}},
            },
        },
        "output_schema": {"type": "object", "fields": {}},
    },
]


def _task_plan() -> dict:
    return {
        "valid": True,
        "confidence": 0.96,
        "task_goal": "Use a bill email to transfer money.",
        "allowed_actions": [
            "workspace__get_unread_emails",
            "banking__send_money",
        ],
        "allowed_effects": ["read", "egress"],
        "l2_actions": ["banking__send_money"],
        "l2_grants": [
            {
                "action": "banking__send_money",
                "authorization_evidence": "Use a bill email to transfer money.",
                "max_calls": 1,
            }
        ],
        "steps": [
            {
                "id": "g1",
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
                                "mode": "literal",
                                "allowed_values": [RECIPIENT],
                            },
                            "data_sources": [
                                "workspace:email",
                                "banking:transaction",
                                "user_prompt",
                            ],
                            "max_confidentiality": "secret",
                            "parameter_bindings": {},
                        },
                    }
                ],
            },
        ],
        "action_steps": {
            "workspace__get_unread_emails": "g1",
            "banking__send_money": "g2",
        },
    }


def _tainted_label(level: str = "confidential") -> dict:
    return make_flow_label(
        confidentiality=make_confidentiality(
            level=level,
            categories=["email", "financial_amount"],
            source_ids=["email-output"],
        ),
        integrity=make_integrity(
            kind="tainted",
            taint_roots=["email-output"],
        ),
        control_influence=True,
    )


def test_configuration_only_exposes_lightweight_methods():
    assert set(RING_METHODS["ring_0"]) == {"small_model"}
    assert set(RING_METHODS["ring_1"]) == {"chunk_scanner", "untrusted_flow"}
    assert set(RING_METHODS["ring_2"]) == {"task_scope"}
    assert set(RING_METHODS["ring_3"]) == {"sensitive_egress"}
    assert get_config()["direct_injection_mode"] == "quarantine"


def test_unknown_label_metadata_fails_closed():
    confidentiality = make_confidentiality(
        level="internal",
        categories=["unregistered-category"],
    )
    assert confidentiality["level"] == "secret"

    derived = derive_flow_label(
        [],
        source_kind="unregistered-source",
        content="value",
        source_id="source:1",
    )
    assert derived["integrity"]["kind"] == "untrusted"


def test_untrusted_control_is_advisory_and_never_rewrites_output():
    risky = make_flow_label(
        injection=make_injection(
            source_flagged=True,
            risky_entities=["$[0]"],
            evidence_refs=["email:$[0].body:chunk:1"],
        ),
        control_influence=True,
    )
    trusted = make_flow_label(
        confidentiality=make_confidentiality(
            level="internal",
            source_entities=["user_prompt"],
        ),
        control_influence=True,
    )
    event = {
        "tool_intent": "send_money",
        "inputs": {"recipient": RECIPIENT, "amount": 120},
        "input_flow_label": _tainted_label(),
        "argument_flow_labels": {
            "recipient": trusted,
            "amount": risky,
        },
    }
    details = check_untrusted_control(event)
    assert details["risk"]["decision"] == "ADVISORY"
    assert details["control_arguments"] == ["amount", "recipient"]
    assert details["risky_control_arguments"] == ["amount"]
    output = {"result": "unchanged"}
    assert process_after_execution(event, output) is output


def test_trusted_control_does_not_raise_flow_risk():
    event = {
        "tool_intent": "send_money",
        "inputs": {"recipient": RECIPIENT, "amount": 120},
        "input_flow_label": make_flow_label(
            integrity=make_integrity(kind="trusted"),
            control_influence=True,
        ),
    }
    details = check_untrusted_control(event)
    assert details["tainted"] is False
    assert details["risk"] is None


def test_task_scope_allows_bound_cross_app_action_and_blocks_escape():
    allowed = {
        "tool_intent": "banking__send_money",
        "task_data_plan": _task_plan(),
            "plan_usage": {"completed_steps": ["g1"]},
    }
    allowed_result = check_task_scope(allowed)
    assert allowed_result["passed"] is True
    assert allowed_result["confirmation_required"] is True
    assert allowed_result["risk"]["decision"] == "HOLD"

    blocked = {
        "tool_intent": "slack__send_direct_message",
        "task_data_plan": _task_plan(),
    }
    result = check_task_scope(blocked)
    assert result["passed"] is False
    assert result["risk"]["decision"] == "BLOCK"
    assert result["reason"] == "action_not_bound_to_task_scope"
    assert "not included in the current task plan" in result["risk"]["reason"]
    assert "outside the task authorization contract" not in result["risk"]["reason"]

    pipeline_event = {
        **blocked,
        "inputs": {},
    }
    allow, _, diagnostics, _ = process_before_execution(pipeline_event)
    assert allow is False
    assert "not included in the current task plan" in pipeline_event["block_reason"]
    assert "outside the current task scope" not in pipeline_event["block_reason"]


def test_task_scope_is_advisory_when_planning_is_unavailable():
    result = check_task_scope(
        {"tool_intent": "workspace__get_unread_emails"}
    )
    assert result["passed"] is True
    assert result["reason"] == "task_scope_unavailable"
    assert result["advisory"] is True

    sensitive = check_task_scope(
        {"tool_intent": "banking__send_money"}
    )
    assert sensitive["passed"] is False
    assert sensitive["reason"] == "task_scope_unavailable"
    assert sensitive["risk"]["decision"] == "BLOCK"
    assert sensitive["risk"]["source_ids"] == []


def test_runtime_plan_update_adds_same_suite_read_before_execution():
    plan = {
        "valid": True,
        "confidence": 0.9,
        "allowed_actions": [
            "workspace__get_unread_emails",
            "banking__send_money",
        ],
        "allowed_suites": ["workspace", "banking"],
        "allowed_effects": ["read", "egress"],
        "forbidden_effects": [],
        "runtime_updates": [],
        "steps": [],
        "action_steps": {},
        "action_evidence": {},
        "plan_revision": 1,
        "plan_id": "plan_initial",
        "plan_hash": "sha256:initial",
    }

    patch = json.dumps(
        {
            "base_revision": 1,
            "reason": "The Agent needs a balance check before transfer.",
            "operations": [
                {
                    "op": "add_step",
                    "step": {
                        "id": "runtime_read_1",
                        "description": "Check balance before transfer",
                        "condition": "before send_money",
                        "actions": [
                            {
                                "name": "banking__get_balance",
                                "purpose": "Verify the account before transfer.",
                                "authorization_evidence": "Continue the authorized banking task.",
                            }
                        ],
                    },
                }
            ],
        }
    )
    updated, updates, warnings = compile_runtime_plan_update(
        plan,
        patch,
        [
            *TOOLS,
            {
                "name": "banking__get_balance",
                "suite": "banking",
                "effect": "read",
                    "risk_level": "L0",
            },
        ],
    )

    assert warnings == []
    assert updates[0]["actions"] == ["banking__get_balance"]
    assert updated is not plan
    assert plan["plan_revision"] == 1
    assert updated["plan_revision"] == 2
    assert updated["plan_id"] != plan["plan_id"]
    assert "banking__get_balance" in updated["allowed_actions"]
    assert set(updated["allowed_suites"]) == {"banking", "workspace"}

    authorization = check_task_scope(
        {
            "tool_intent": "banking__get_balance",
            "task_data_plan": updated,
        }
    )
    assert authorization["passed"] is True
    assert authorization["matched_step"] == "runtime_read_1"


def test_runtime_plan_update_does_not_add_cross_suite_or_side_effect_action():
    plan = {
        "valid": True,
        "confidence": 0.9,
        "allowed_actions": ["banking__send_money"],
        "allowed_suites": ["banking"],
        "allowed_effects": ["read", "egress"],
        "forbidden_effects": [],
        "steps": [],
        "plan_revision": 1,
    }
    catalog = [
        {
            "name": "workspace__search_emails",
            "suite": "workspace",
            "effect": "read",
                "risk_level": "L0",
        },
        {
            "name": "banking__update_password",
            "suite": "banking",
            "effect": "privilege",
                "risk_level": "L2",
        },
    ]

    patch = json.dumps(
        {
            "base_revision": 1,
            "reason": "Attempt expanded permissions.",
            "operations": [
                {
                    "op": "add_step",
                    "step": {
                        "id": "runtime_bad_1",
                        "description": "Unsafe expansion",
                        "condition": "always",
                        "actions": [
                            {
                                "name": "workspace__search_emails",
                                "purpose": "Cross-suite read",
                                "authorization_evidence": "attempt",
                            },
                            {
                                "name": "banking__update_password",
                                "purpose": "Privilege action",
                                "authorization_evidence": "attempt",
                            },
                        ],
                    },
                }
            ],
        }
    )
    updated, updates, warnings = compile_runtime_plan_update(
        plan,
        patch,
        catalog,
    )

    assert updates == []
    assert "runtime_expansion_cross_suite:workspace__search_emails" in warnings
    assert "runtime_l2_expansion_forbidden:banking__update_password" in warnings
    assert updated["allowed_actions"] == ["banking__send_money"]
    assert updated["plan_revision"] == 1


def test_runtime_plan_update_can_add_l1_but_never_l2():
    plan = {
        "valid": True,
        "confidence": 0.9,
        "allowed_actions": ["get_unread_emails"],
        "allowed_suites": ["workspace"],
        "allowed_effects": ["read"],
        "forbidden_effects": [],
        "steps": [],
        "plan_revision": 1,
        "plan_id": "plan_initial",
        "plan_hash": "sha256:initial",
    }
    patch = json.dumps(
        {
            "base_revision": 1,
            "reason": "Add a reminder event after finding the bill.",
            "operations": [
                {
                    "op": "add_step",
                    "step": {
                        "id": "add_reminder",
                        "description": "Add a reminder event",
                        "actions": [
                            {
                                "name": "create_calendar_event",
                                "purpose": "Record the payment deadline.",
                                "authorization_evidence": "Continue the task in workspace.",
                            }
                        ],
                    },
                }
            ],
        }
    )
    catalog = [
        {
            "name": "get_unread_emails",
            "suite": "workspace",
            "effect": "read",
            "risk_level": "L0",
        },
        {
            "name": "create_calendar_event",
            "suite": "workspace",
            "effect": "write",
            "risk_level": "L1",
        },
    ]

    updated, updates, warnings = compile_runtime_plan_update(
        plan,
        patch,
        catalog,
    )

    assert warnings == []
    assert updates[0]["actions"] == ["create_calendar_event"]
    assert updated["plan_revision"] == 2
    assert "write" in updated["allowed_effects"]


def test_task_plan_uses_human_risk_metadata_for_l2_grant():
    clear_task_plan_cache()
    tools = [
        {
            "name": "get_unread_emails",
            "suite": "workspace",
            "effect": "read",
            "risk_level": "L0",
            "categories": ["email"],
        },
        {
            "name": "send_money",
            "suite": "banking",
            "effect": "egress",
            "risk_level": "L2",
            "categories": ["financial_data"],
        },
    ]

    def planner(_request: str) -> str:
        return json.dumps(
            {
                "schema_version": 2,
                "task_goal": "Read the bill and transfer it.",
                "steps": [
                    {
                        "id": "g1",
                        "actions": [
                            {
                                "name": "get_unread_emails",
                                "authorization_evidence": "read my unread emails",
                                "necessity": "explicit",
                            }
                        ],
                    },
                    {
                        "id": "g2",
                        "actions": [
                            {
                                "name": "banking__send_money",
                                "authorization_evidence": "transfer the bill amount",
                                "necessity": "explicit",
                                "flow_contract": {
                                    "destination": {
                                        "parameters": ["recipient"],
                                        "mode": "literal",
                                        "allowed_values": [
                                            "DE89370400440532013000"
                                        ],
                                    },
                                    "data_sources": ["workspace:email"],
                                    "parameter_bindings": {
                                        "amount": {
                                            "mode": "derived_sources",
                                            "generation_kind": "extraction",
                                            "allowed_source_refs": [
                                                {
                                                    "app": "workspace",
                                                    "entity": "email",
                                                    "source_action": "workspace__get_unread_emails",
                                                }
                                            ],
                                            "required_source_refs": [
                                                {
                                                    "app": "workspace",
                                                    "entity": "email",
                                                    "source_action": "workspace__get_unread_emails",
                                                }
                                            ],
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

    prompt = "Read my unread emails and transfer the bill amount."
    plan = generate_task_data_plan(prompt, planner, tools)

    assert plan["steps"][1]["actions"][0]["risk_level"] == "L2"
    assert plan["l2_actions"] == ["send_money"]
    assert plan["l2_grants"][0]["action"] == "send_money"


def test_scope_block_does_not_claim_injection_causation_without_control_flow():
    plan = {
        "valid": True,
        "confidence": 0.9,
        "allowed_actions": ["banking__send_money"],
        "allowed_effects": ["egress"],
        "forbidden_effects": [],
        "plan_id": "plan_test",
        "plan_hash": "sha256:test",
    }
    result = check_task_scope(
        {
            "tool_intent": "banking__get_balance",
            "task_data_plan": plan,
            "input_flow_label": make_flow_label(
                injection={
                    "source_flagged": True,
                    "max_score": 0.99,
                    "evidence_refs": ["email:body:chunk:1"],
                }
            ),
        }
    )

    assert result["passed"] is False
    assert "action_not_bound_to_task_scope" in result["risk"]["reason"]
    assert result["risk"]["source_ids"] == []


def test_l2_requires_initial_grant_and_respects_call_limit():
    plan = _task_plan()
    plan.pop("l2_actions")
    event = {
        "tool_intent": "banking__send_money",
        "task_data_plan": plan,
        "plan_usage": {},
    }
    missing_grant = check_task_scope(event)
    assert missing_grant["passed"] is False
    assert missing_grant["reason"] == "l2_not_in_initial_plan"

    plan = _task_plan()
    event = {
        "tool_intent": "banking__send_money",
        "task_data_plan": plan,
        "plan_usage": {
            "planned_action_counts": {"banking__send_money": 1},
                "completed_steps": ["g1"],
        },
    }
    over_limit = check_task_scope(event)
    assert over_limit["passed"] is False
    assert over_limit["reason"] == "l2_call_limit_exceeded"


def _egress_event(
    *,
    recipient: str = RECIPIENT,
    level: str = "secret",
    categories: list[str] | None = None,
) -> dict:
    return {
        "tool_intent": "banking__send_money",
        "inputs": {"recipient": recipient, "amount": 120},
        "input_flow_label": make_flow_label(
            confidentiality=make_confidentiality(
                level=level,
                categories=categories
                or ["financial_data", "financial_amount"],
                source_ids=["email-output"],
            ),
            integrity=make_integrity(kind="trusted"),
            control_influence=True,
        ),
        "argument_flow_labels": {
            "recipient": make_flow_label(
                confidentiality=make_confidentiality(
                    level="internal",
                    source_entities=["user_prompt"],
                )
            ),
            "amount": make_flow_label(
                confidentiality=make_confidentiality(
                    level=level,
                    categories=categories
                    or ["financial_data", "financial_amount"],
                    source_entities=["banking:transaction"],
                )
            ),
        },
        "task_data_plan": _task_plan(),
    }


def test_sensitive_egress_checks_receiver_sources_and_level():
    allowed = check_sensitive_egress(_egress_event())
    assert allowed["passed"] is True
    assert allowed["reason"] == "authorized_sensitive_egress"

    wrong_destination = check_sensitive_egress(
        _egress_event(recipient="attacker@example.com")
    )
    assert wrong_destination["passed"] is False
    assert wrong_destination["reason"] == "destination_not_authorized"

    event = _egress_event()
    event["argument_flow_labels"]["amount"] = make_flow_label(
        confidentiality=make_confidentiality(
            level="secret",
            source_entities=["travel:user"],
        )
    )
    wrong_source = check_sensitive_egress(event)
    assert wrong_source["passed"] is False
    assert wrong_source["reason"] == "data_source_not_authorized"

    event = _egress_event()
    contract = event["task_data_plan"]["steps"][1]["actions"][0][
        "flow_contract"
    ]
    contract["max_confidentiality"] = "internal"
    too_sensitive = check_sensitive_egress(event)
    assert too_sensitive["passed"] is False
    assert too_sensitive["reason"] == "confidentiality_exceeds_sink_limit"


def test_egress_authorization_uses_direct_sources_not_ancestors():
    event = _egress_event()
    event["argument_flow_labels"]["amount"] = make_flow_label(
        confidentiality=make_confidentiality(
            level="secret",
            categories=["financial_data", "financial_amount"],
            source_entities=[
                "banking:transaction",
                "travel:hotel",
                "workspace:email",
            ],
        )
    )
    event["parameter_resolutions"] = [
        {
            "parameter": "amount",
            "status": "resolved",
            "source_refs": [
                {
                    "app": "banking",
                    "entity": "transaction",
                    "source_action": "get_most_recent_transactions",
                }
            ],
            "source_entities": [
                "banking:transaction",
                "travel:hotel",
                "workspace:email",
            ],
            "source_evidence": [
                {
                    "app": "banking",
                    "entity": "transaction",
                    "source_action": "get_most_recent_transactions",
                    "source_path": "$.amount",
                    "extracted_text": "120",
                }
            ],
            "provenance_refs": [],
            "generation_kind": "copy",
            "explanation": "直接复制交易金额。",
            "confidence": 1.0,
        }
    ]

    result = check_sensitive_egress(event)

    assert result["passed"] is True
    assert result["data_sources"] == ["banking:transaction"]
    assert set(result["provenance_ancestors"]) == {
        "banking:transaction",
        "travel:hotel",
        "workspace:email",
    }


def test_parameter_explanations_are_preserved_in_egress_diagnostics():
    event = _egress_event()
    event["parameter_resolutions"] = [
        {
            "parameter": "amount",
            "generation_kind": "calculation",
            "semantic_type": "number",
            "parameter_role": "amount",
            "constraints": {"minimum": 0},
            "explanation": "账单金额与已有交易金额合并后得到本次转账金额。",
            "confidence": 0.87,
            "semantic_supported": False,
        }
    ]

    result = check_sensitive_egress(event)

    assert result["passed"] is True
    assert result["parameter_generation"]["amount"] == {
        "generation_kind": "calculation",
        "validation_mode": "structured",
        "semantic_type": "number",
        "parameter_role": "amount",
        "constraints": {"minimum": 0},
        "explanation": "账单金额与已有交易金额合并后得到本次转账金额。",
        "confidence": 0.87,
        "semantic_supported": False,
    }


def test_runtime_sources_are_required_only_when_bound_to_parameters():
    plan = {
        "valid": True,
        "plan_revision": 1,
        "allowed_actions": ["reserve_hotel"],
        "allowed_suites": ["travel", "workspace"],
        "allowed_effects": ["egress", "read"],
        "forbidden_effects": [],
        "required_outcomes": [
            {
                "id": "o1",
                "description": "Reserve the selected hotel.",
                "kind": "action",
                "step_ids": ["g1"],
                "required_sources": ["trip_email"],
                "required_source_refs": [
                    {
                        "app": "workspace",
                        "entity": "email",
                        "source_action": "get_unread_emails",
                    }
                ],
            }
        ],
        "steps": [
            {
                "id": "g1",
                "depends_on": [],
                "actions": [
                    {
                        "name": "reserve_hotel",
                        "effect": "egress",
                        "flow_contract": {
                            "valid": True,
                            "data_sources": ["workspace:email", "travel:hotel"],
                            "allowed_sources": ["trip_email", "paris_hotels"],
                            "required_sources": ["trip_email"],
                            "source_bindings": {},
                            "parameter_bindings": {
                                "hotel": {
                                    "allowed_source_refs": [
                                        {
                                            "app": "travel",
                                            "entity": "hotel",
                                            "source_action": (
                                                "get_all_hotels_in_city"
                                            ),
                                        }
                                    ],
                                    "required_source_refs": [],
                                },
                                "start_day": {
                                    "allowed_source_refs": [
                                        {
                                            "app": "workspace",
                                            "entity": "email",
                                            "source_action": (
                                                "get_unread_emails"
                                            ),
                                        }
                                    ],
                                    "required_source_refs": [],
                                },
                            },
                        },
                    }
                ],
            }
        ],
    }
    tools = [
        {"name": "get_current_day", "suite": "workspace", "effect": "read", "risk_level": "L0"},
        {"name": "get_hotels_address", "suite": "travel", "effect": "read", "risk_level": "L0"},
    ]
    response = json.dumps(
        {
            "base_revision": 1,
            "operations": [
                {
                    "op": "add_step",
                    "step": {
                        "id": "g_runtime",
                        "depends_on": [],
                        "supports_outcomes": ["o1"],
                        "actions": [
                            {
                                "name": "get_current_day",
                                "purpose": "辅助校验当前日期。",
                            },
                            {
                                "name": "get_hotels_address",
                                "purpose": "核验酒店位置。",
                            },
                        ],
                    },
                }
            ],
        }
    )

    updated, _updates, warnings = compile_runtime_plan_update(
        plan,
        response,
        tools,
    )

    assert warnings == []
    outcome = updated["required_outcomes"][0]
    assert any(
        item.startswith("src_g_runtime_get_current_day")
        for item in outcome["supporting_sources"]
    )
    assert not any(
        item.startswith("src_g_runtime_get_current_day")
        for item in outcome["required_sources"]
    )
    contract = updated["steps"][0]["actions"][0]["flow_contract"]
    assert not any(
        source_id.startswith("src_g_runtime_get_current_day")
        for source_id in contract["allowed_sources"]
    )
    assert any(
        source_id.startswith("src_g_runtime_get_hotels_address")
        for source_id in contract["allowed_sources"]
    )
    assert updated["steps"][0]["depends_on"] == ["g_runtime"]


def test_sensitive_egress_switch_is_independent():
    result = check_sensitive_egress(
        _egress_event(recipient="attacker@example.com"),
        options={
            "ring_3": {
                "methods": {"sensitive_egress": False}
            }
        },
    )
    assert result["passed"] is True
    assert result["skipped"] is True


def test_task_planner_builds_and_caches_compact_execution_grant():
    clear_task_plan_cache()
    calls = 0

    def planner(_request: str) -> str:
        nonlocal calls
        calls += 1
        return json.dumps(
            {
                "task_goal": "Pay the email bill.",
                "steps": [
                    {
                        "id": "g1",
                        "actions": [
                            {
                                "name": "workspace__get_unread_emails",
                                "authorization_evidence": "read my bill",
                            }
                        ],
                    },
                    {
                        "id": "g2",
                        "depends_on": ["g1"],
                        "actions": [
                            {
                                "name": "banking__send_money",
                                "authorization_evidence": f"transfer the amount to {RECIPIENT}",
                                "flow_contract": {
                                    "destination": {
                                        "parameters": ["recipient"],
                                        "mode": "literal",
                                        "allowed_values": [RECIPIENT],
                                    },
                                    "data_sources": ["workspace:email"],
                                    "parameter_bindings": {
                                        "amount": {
                                            "mode": "derived_sources",
                                            "generation_kind": "extraction",
                                            "allowed_source_refs": [
                                                {
                                                    "app": "workspace",
                                                    "entity": "email",
                                                    "source_action": "workspace__get_unread_emails",
                                                }
                                            ],
                                            "required_source_refs": [
                                                {
                                                    "app": "workspace",
                                                    "entity": "email",
                                                    "source_action": "workspace__get_unread_emails",
                                                }
                                            ],
                                        }
                                    },
                                },
                            }
                        ],
                    },
                ],
                "confidence": 0.95,
            }
        )

    prompt = f"Read my bill and transfer the amount to {RECIPIENT}."
    first = generate_task_data_plan(prompt, planner, TOOLS)
    second = generate_task_data_plan(prompt, planner, TOOLS)
    assert first == second
    assert calls == 1, first.get("warnings")
    first["steps"][0]["actions"][0]["name"] = "mutated_by_caller"
    third = generate_task_data_plan(prompt, planner, TOOLS)
    assert (
        third["steps"][0]["actions"][0]["name"]
        == "workspace__get_unread_emails"
    )
    assert calls == 1
    assert "egress_capabilities" not in first
    assert first["allowed_actions"] == _task_plan()["allowed_actions"]
    contract = first["steps"][1]["actions"][0]["flow_contract"]
    assert contract["max_confidentiality"] == "confidential"
    assert contract["destination"]["allowed_values"] == [RECIPIENT]


def test_pipeline_attaches_advisory_and_egress_risks_to_graph_event():
    reset_graph()
    reset_config()
    task = record_task_start("Pay the bill.", suite="unified")
    event = _egress_event()
    event.update(
        {
            "task_id": task["task_id"],
            "activity_id": "activity_flow_policy",
            "suite": "unified",
            "app_domain": "banking",
            "target_app": "banking",
            "input_flow_label": _tainted_label(level="secret"),
            "argument_flow_labels": {
                "recipient": make_flow_label(
                    confidentiality=make_confidentiality(
                        level="internal",
                        source_entities=["user_prompt"],
                    )
                ),
                "amount": make_flow_label(
                    confidentiality=make_confidentiality(
                        level="secret",
                        source_entities=["banking:transaction"],
                    ),
                    injection=make_injection(
                        source_flagged=True,
                        risky_entities=["$[0]"],
                        evidence_refs=["email:$[0].body:chunk:1"],
                    ),
                ),
            },
            "plan_usage": {"completed_steps": ["g1"]},
        }
    )
    event["task_data_plan"]["steps"][1]["actions"][0]["flow_contract"][
        "destination"
    ]["allowed_values"] = ["someone-else@example.com"]
    activity_event = {
        **event,
        "timestamp": time.time(),
        "tool_intent": "banking__send_money",
        "tool_base_name": "send_money",
        "type": "api_call_start",
    }
    record_activity(activity_event)
    event["activity_id"] = activity_event["activity_id"]
    allow, _, diagnostics, _ = process_before_execution(
        event,
        options={"user_anchor_mode": "advisory"},
    )
    assert allow is False
    risks = diagnostics["risk_assessments"]
    assert any(risk["decision"] == "ADVISORY" for risk in risks)
    assert any(
        risk["policy_id"] == "ring3.sensitive_egress"
        and risk["decision"] == "BLOCK"
        for risk in risks
    )
    record_risk_assessments(event, risks)
    graph = get_graph_data()
    assert any(node.get("type") == "RiskEvent" for node in graph["nodes"])
