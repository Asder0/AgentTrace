import json

from agentdojo.method.analysis.data_need import (
    _attach_runtime_source_to_contract,
    _validate_task_plan,
)
from agentdojo.method.analysis.flow_policy import check_task_scope
from agentdojo.method.analysis.outcome_audit import audit_task_outcomes
from agentdojo.method.analysis.parameter_binding import action_flow_contract
from agentdojo.method.capture.interceptor import (
    TrackingContext,
    _plan_step_for_action,
)
from agentdojo.method.visualization.server import _record_execution_outcome


def _read_tool_catalog():
    return [
        {
            "name": "workspace__get_unread_emails",
            "suite": "workspace",
            "effect": "read",
            "risk_level": "L0",
            "input_schema": {"type": "object", "fields": {}},
            "output_schema": {"type": "array", "items": {"type": "object"}},
        }
    ]


def test_runtime_source_updates_matching_parameter_bindings():
    contract = {
        "allowed_sources": ["paris_hotels"],
        "required_sources": ["paris_hotels"],
        "required_source_refs": [
            {
                "app": "travel",
                "entity": "hotel",
                "source_action": "get_all_hotels_in_city",
            }
        ],
        "source_bindings": {},
        "parameter_bindings": {
            "hotel": {
                "allowed_source_refs": [
                    {
                        "app": "travel",
                        "entity": "hotel",
                        "source_action": "get_all_hotels_in_city",
                    }
                ],
                "required_source_refs": [
                    {
                        "app": "travel",
                        "entity": "hotel",
                        "source_action": "get_all_hotels_in_city",
                    }
                ],
            },
            "start_day": {
                "allowed_source_refs": [
                    {
                        "app": "workspace",
                        "entity": "email",
                        "source_action": "get_unread_emails",
                    }
                ]
            },
        },
    }
    source_ref = {
        "id": "src_g3b_get_hotels_address",
        "app": "travel",
        "entity": "hotel",
        "producer_step": "g3b",
        "source_action": "get_hotels_address",
    }

    _attach_runtime_source_to_contract(
        contract,
        "src_g3b_get_hotels_address",
        source_ref,
    )

    assert "src_g3b_get_hotels_address" in contract["allowed_sources"]
    assert "src_g3b_get_hotels_address" in contract["required_sources"]
    assert any(
        item["source_action"] == "get_hotels_address"
        for item in contract["required_source_refs"]
    )
    assert any(
        item["source_action"] == "get_hotels_address"
        for item in contract["parameter_bindings"]["hotel"][
            "allowed_source_refs"
        ]
    )
    assert all(
        item["source_action"] != "get_hotels_address"
        for item in contract["parameter_bindings"]["start_day"][
            "allowed_source_refs"
        ]
    )


def test_schema_v3_requires_verified_outcomes():
    plan = _validate_task_plan(
        {
            "schema_version": 3,
            "task_goal": "Show unread email.",
            "steps": [
                {
                    "id": "g1",
                    "actions": [
                        {
                            "name": "workspace__get_unread_emails",
                            "authorization_evidence": "show unread email",
                        }
                    ],
                }
            ],
            "confidence": 0.95,
        },
        "Show my unread email.",
        _read_tool_catalog(),
    )

    assert plan["valid"] is False
    assert "task_plan_without_required_outcomes" in plan["warnings"]


def test_structurally_ambiguous_plan_is_invalid():
    catalog = _read_tool_catalog() + [
        {
            "name": "workspace__create_file",
            "suite": "workspace",
            "effect": "write",
            "risk_level": "L1",
            "input_schema": {"type": "object", "fields": {}},
            "output_schema": {"type": "object", "fields": {}},
        }
    ]
    plan = _validate_task_plan(
        {
            "schema_version": 3,
            "task_goal": "Create a file.",
            "required_outcomes": [
                {
                    "id": "o1",
                    "description": "The file exists.",
                    "kind": "action",
                    "step_ids": ["g1"],
                }
            ],
            "steps": [
                {
                    "id": "g1",
                    "actions": [
                        {
                            "name": "workspace__create_file",
                            "authorization_evidence": "create a file",
                        }
                    ],
                },
                {
                    "id": "g1",
                    "depends_on": ["missing"],
                    "actions": [
                        {
                            "name": "workspace__get_unread_emails",
                            "authorization_evidence": "read email",
                        }
                    ],
                },
            ],
            "stop_conditions": [
                {
                    "id": "stop_1",
                    "when": "Email is missing.",
                    "behavior": "finish",
                    "step_ids": [],
                }
            ],
            "confidence": 0.95,
        },
        "Create a file after checking email.",
        catalog,
    )

    assert plan["valid"] is False
    assert any(
        warning.startswith("duplicate_step_ids:")
        for warning in plan["warnings"]
    )
    assert any(
        warning.startswith("invalid_step_dependencies:")
        for warning in plan["warnings"]
    )
    assert "stop_condition_without_steps:stop_1" in plan["warnings"]


def test_effect_specific_confidence_threshold_is_enforced():
    plan = _validate_task_plan(
        {
            "schema_version": 3,
            "task_goal": "Read the unread email.",
            "required_outcomes": [
                {
                    "id": "o1",
                    "description": "Show the unread email.",
                    "kind": "data",
                    "step_ids": ["g1"],
                }
            ],
            "steps": [
                {
                    "id": "g1",
                    "actions": [
                        {
                            "name": "workspace__get_unread_emails",
                            "authorization_evidence": "read my email",
                        }
                    ],
                }
            ],
            "confidence": 0.3,
        },
        "Read my email.",
        _read_tool_catalog(),
    )

    assert plan["valid"] is False
    assert any(
        warning.startswith(
            "task_plan_effect_low_confidence:"
            "workspace__get_unread_emails:read:"
        )
        for warning in plan["warnings"]
    )


def test_trace_plan_shape_canonicalizes_aliases_and_infers_presentation():
    tools = [
        {
            "name": "get_unread_emails",
            "suite": "workspace",
            "effect": "read",
            "risk_level": "L0",
            "input_schema": {"type": "object", "fields": {}},
            "output_schema": {"type": "array"},
        },
        {
            "name": "get_all_hotels_in_city",
            "suite": "travel",
            "effect": "read",
            "risk_level": "L0",
            "input_schema": {"type": "object", "fields": {}},
            "output_schema": {"type": "str"},
        },
        {
            "name": "get_hotels_prices",
            "suite": "travel",
            "effect": "read",
            "risk_level": "L0",
            "input_schema": {"type": "object", "fields": {}},
            "output_schema": {"type": "object", "dynamic": True},
        },
        {
            "name": "reserve_hotel",
            "suite": "travel",
            "effect": "egress",
            "risk_level": "L2",
            "destination_fields": ["hotel"],
            "input_schema": {
                "type": "object",
                "fields": {
                    "hotel": {
                        "type_schema": {"type": "str"},
                        "required": True,
                        "role": "destination",
                    },
                    "start_day": {
                        "type_schema": {"type": "date"},
                        "required": True,
                        "role": "control",
                        "semantic_type": "date",
                    },
                    "end_day": {
                        "type_schema": {"type": "date"},
                        "required": True,
                        "role": "control",
                        "semantic_type": "date",
                    },
                },
            },
            "output_schema": {"type": "str"},
        },
        {
            "name": "workspace__send_email",
            "suite": "workspace",
            "effect": "egress",
            "risk_level": "L2",
            "destination_fields": ["recipients"],
            "input_schema": {
                "type": "object",
                "fields": {
                    "recipients": {
                        "type_schema": {"type": "array"},
                        "required": True,
                        "role": "destination",
                        "semantic_type": "email",
                    },
                    "subject": {
                        "type_schema": {"type": "str"},
                        "required": True,
                        "role": "presentation",
                    },
                    "body": {
                        "type_schema": {"type": "str"},
                        "required": True,
                        "role": "presentation",
                    },
                },
            },
            "output_schema": {"type": "dict"},
        },
    ]
    plan = _validate_task_plan(
        {
            "schema_version": 3,
            "task_goal": "Reserve a hotel and confirm by email.",
            "source_refs": {
                "trip_email": {
                    "app": "workspace",
                    "entity": "email",
                    "producer_step": "g1",
                    "source_action": "get_unread_emails",
                },
                "paris_hotels": {
                    "app": "travel",
                    "entity": "hotels",
                    "producer_step": "g2",
                    "source_action": "get_all_hotels_in_city",
                },
                "hotel_prices": {
                    "app": "travel",
                    "entity": "hotel",
                    "producer_step": "g3",
                    "source_action": "get_hotels_prices",
                },
                "reservation": {
                    "app": "travel",
                    "entity": "reservation",
                    "producer_step": "g4",
                    "source_action": "reserve_hotel",
                },
            },
            "required_outcomes": [
                {
                    "id": "o1",
                    "description": "Read the hotel request.",
                    "kind": "data",
                    "step_ids": ["g1"],
                    "required_sources": ["trip_email"],
                },
                {
                    "id": "o2",
                    "description": "Search the hotel candidates.",
                    "kind": "data",
                    "step_ids": ["g2"],
                    "required_sources": ["paris_hotels"],
                },
                {
                    "id": "o3",
                    "description": "Select a hotel within the budget.",
                    "kind": "semantic",
                    "step_ids": ["g1", "g2", "g3"],
                    "required_sources": [
                        "trip_email",
                        "paris_hotels",
                        "hotel_prices",
                    ],
                },
                {
                    "id": "o4",
                    "description": "Reserve the selected hotel.",
                    "kind": "action",
                    "step_ids": ["g4"],
                    "required_sources": [
                        "trip_email",
                        "paris_hotels",
                        "hotel_prices",
                    ],
                },
                {
                    "id": "o5",
                    "description": "Send Julie the confirmation.",
                    "kind": "action",
                    "step_ids": ["g5"],
                    "required_sources": ["trip_email", "reservation"],
                },
                {
                    "id": "o6",
                    "description": (
                        "The confirmation email wording is brief and accurate."
                    ),
                    "kind": "semantic",
                    "step_ids": ["g5"],
                },
            ],
            "steps": [
                {
                    "id": "g1",
                    "actions": [
                        {
                            "name": "get_unread_emails",
                            "authorization_evidence": "Read my emails",
                        }
                    ],
                },
                {
                    "id": "g2",
                    "depends_on": ["g1"],
                    "actions": [
                        {
                            "name": "get_all_hotels_in_city",
                            "authorization_evidence": "Search hotels",
                        }
                    ],
                },
                {
                    "id": "g3",
                    "depends_on": ["g1", "g2"],
                    "actions": [
                        {
                            "name": "get_hotels_prices",
                            "authorization_evidence": "Search prices",
                        }
                    ],
                },
                {
                    "id": "g4",
                    "depends_on": ["g1", "g2", "g3"],
                    "actions": [
                        {
                            "name": "reserve_hotel",
                            "authorization_evidence": "Reserve the hotel",
                            "flow_contract": {
                                "allowed_sources": [
                                    "trip_email",
                                    "paris_hotels",
                                    "hotel_prices",
                                ],
                                "data_sources": [
                                    "workspace:email",
                                    "travel:hotels",
                                ],
                                "destination": {
                                    "parameters": ["hotel"],
                                    "mode": "derived",
                                },
                                "parameter_bindings": {
                                    "hotel": {
                                        "mode": "derived_sources",
                                        "generation_kind": "selection",
                                        "allowed_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "get_unread_emails",
                                            },
                                            {
                                                "app": "travel",
                                                "entity": "hotels",
                                                "source_action": "get_all_hotels_in_city",
                                            },
                                            {
                                                "app": "travel",
                                                "entity": "hotel",
                                                "source_action": "get_hotels_prices",
                                            },
                                        ],
                                        "required_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "get_unread_emails",
                                            },
                                            {
                                                "app": "travel",
                                                "entity": "hotel",
                                                "source_action": "get_hotels_prices",
                                            },
                                        ],
                                    },
                                    "start_day": {
                                        "mode": "derived_sources",
                                        "generation_kind": "normalization",
                                        "allowed_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "get_unread_emails",
                                            }
                                        ],
                                        "required_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "get_unread_emails",
                                            }
                                        ],
                                    },
                                    "end_day": {
                                        "mode": "derived_sources",
                                        "generation_kind": "normalization",
                                        "allowed_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "get_unread_emails",
                                            }
                                        ],
                                        "required_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "get_unread_emails",
                                            }
                                        ],
                                    },
                                },
                            },
                        }
                    ],
                },
                {
                    "id": "g5",
                    "depends_on": ["g1", "g4"],
                    "actions": [
                        {
                            "name": "workspace__send_email",
                            "authorization_evidence": "Send the confirmation",
                            "flow_contract": {
                                "allowed_sources": [
                                    "trip_email",
                                    "reservation",
                                ],
                                "data_sources": [
                                    "workspace:email",
                                    "travel:reservation",
                                ],
                                "destination": {
                                    "parameters": ["recipients"],
                                    "mode": "derived",
                                },
                                "parameter_bindings": {
                                    "recipients": {
                                        "mode": "derived_sources",
                                        "generation_kind": "selection",
                                        "allowed_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "get_unread_emails",
                                            }
                                        ],
                                        "required_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "get_unread_emails",
                                            }
                                        ],
                                    },
                                    "body": {
                                        "mode": "derived_sources",
                                        "generation_kind": "presentation",
                                        "allowed_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "get_unread_emails",
                                            },
                                            {
                                                "app": "travel",
                                                "entity": "reservation",
                                                "source_action": "reserve_hotel",
                                            },
                                        ],
                                        "required_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": "get_unread_emails",
                                            }
                                        ],
                                    },
                                },
                            },
                        }
                    ],
                },
            ],
            "confidence": 0.96,
        },
        "Reserve the hotel and send a confirmation.",
        tools,
    )

    assert plan["valid"] is True, plan["warnings"]
    assert plan["source_refs"]["paris_hotels"]["entity"] == "hotel"
    assert plan["source_refs"]["reservation"]["entity"] == "reservation"
    subject = plan["steps"][4]["actions"][0]["flow_contract"][
        "parameter_bindings"
    ]["subject"]
    email_contract = plan["steps"][4]["actions"][0]["flow_contract"]
    assert subject["generation_kind"] == "presentation"
    assert subject["required_source_refs"]
    assert {
        item["entity"] for item in subject["allowed_source_refs"]
    } == {"email", "reservation"}
    assert {
        item["entity"] for item in email_contract["required_source_refs"]
    } == {"email", "reservation"}
    assert (
        "required_presentation_binding_inferred:"
        "workspace__send_email:subject:body"
    ) in plan["warnings"]
    assert "o6" not in {
        item["id"] for item in plan["required_outcomes"]
    }
    assert "o3" in {
        item["id"] for item in plan["required_outcomes"]
    }
    assert plan["manual_review_outcomes"][0]["id"] == "o6"
    assert plan["manual_review_outcomes"][0]["kind"] == (
        "presentation_review"
    )
    assert (
        "presentation_semantic_outcome_downgraded:o6"
        in plan["warnings"]
    )

    scope = check_task_scope(
        {
            "tool_intent": "reserve_hotel",
            "task_data_plan": plan,
            "plan_step_id": "g4",
            "plan_usage": {
                "completed_steps": ["g1", "g2", "g3"],
            },
        }
    )
    assert scope["passed"] is True
    assert scope["confirmation_required"] is True


def test_read_only_outcome_can_complete_task():
    plan = _validate_task_plan(
        {
            "schema_version": 3,
            "task_goal": "Show unread email.",
            "required_outcomes": [
                {
                    "id": "o1",
                    "description": "Show the unread email content.",
                    "kind": "data",
                    "step_ids": ["g1"],
                }
            ],
            "steps": [
                {
                    "id": "g1",
                    "actions": [
                        {
                            "name": "workspace__get_unread_emails",
                            "authorization_evidence": "show unread email",
                        }
                    ],
                }
            ],
            "confidence": 0.95,
        },
        "Show my unread email.",
        _read_tool_catalog(),
    )
    assert plan["valid"] is True, plan["warnings"]

    context = TrackingContext()
    context.reset()
    context.ensure_task("Show my unread email.", suite="workspace")
    context.task_data_plan = plan
    outcome = _record_execution_outcome(
        context,
        blocked=False,
        task_stopped=False,
        stop_reason="",
        execution_error="",
        block_reason="",
        tool_activity={
            "executed_tools": ["workspace__get_unread_emails"],
            "failed_tools": [],
            "blocked_tools": [],
            "tool_call_count": 1,
            "successful_tool_call_count": 1,
            "failed_tool_call_count": 0,
            "blocked_tool_call_count": 0,
        },
        completion_audit={
            "overall": "completed",
            "summary": "Unread email was returned.",
        },
    )

    assert outcome["status"] == "completed"


def test_verified_completion_wins_over_nonblocking_stop():
    context = TrackingContext()
    context.reset()
    context.ensure_task("Show my unread email.", suite="workspace")

    try:
        outcome = _record_execution_outcome(
            context,
            blocked=False,
            task_stopped=True,
            stop_reason="No further action is needed.",
            execution_error="",
            block_reason="",
            tool_activity={
                "executed_tools": ["workspace__get_unread_emails"],
                "failed_tools": [],
                "blocked_tools": [],
                "tool_call_count": 1,
                "successful_tool_call_count": 1,
                "failed_tool_call_count": 0,
                "blocked_tool_call_count": 0,
            },
            completion_audit={
                "overall": "completed",
                "summary": "All required outcomes were verified.",
            },
        )
    finally:
        context.reset()

    assert outcome["status"] == "completed"
    assert outcome["task_stopped"] is True


def test_initial_plan_can_grant_repeated_l2_calls():
    catalog = [
        {
            "name": "workspace__send_email",
            "suite": "workspace",
            "effect": "egress",
            "risk_level": "L2",
            "destination_fields": ["recipients"],
            "input_schema": {
                "type": "object",
                "fields": {
                    "recipients": {
                        "type_schema": {"type": "array"},
                        "required": True,
                    }
                },
            },
        }
    ]

    def step(step_id: str):
        return {
            "id": step_id,
            "actions": [
                {
                    "name": "workspace__send_email",
                    "authorization_evidence": (
                        "send both confirmation emails"
                    ),
                    "flow_contract": {
                        "destination": {
                            "parameters": ["recipients"],
                            "mode": "literal",
                            "allowed_values": ["julie@example.com"],
                        },
                        "allowed_sources": [],
                        "data_sources": ["user_prompt"],
                        "parameter_bindings": {},
                    },
                }
            ],
        }

    plan = _validate_task_plan(
        {
            "schema_version": 3,
            "task_goal": "Send two confirmations.",
            "required_outcomes": [
                {
                    "id": "o1",
                    "description": "First confirmation sent.",
                    "kind": "action",
                    "step_ids": ["g1"],
                },
                {
                    "id": "o2",
                    "description": "Second confirmation sent.",
                    "kind": "action",
                    "step_ids": ["g2"],
                },
            ],
            "steps": [step("g1"), step("g2")],
            "confidence": 0.95,
        },
        "Send two confirmation emails to Julie.",
        catalog,
    )

    assert plan["valid"] is True, plan["warnings"]
    grant = next(
        item
        for item in plan["l2_grants"]
        if item["action"] == "workspace__send_email"
    )
    assert grant["max_calls"] == 2
    assert grant["step_ids"] == ["g1", "g2"]

    plan["steps"][0]["actions"][0]["flow_contract"]["destination"][
        "allowed_values"
    ] = ["first@example.com"]
    plan["steps"][1]["actions"][0]["flow_contract"]["destination"][
        "allowed_values"
    ] = ["second@example.com"]
    assert (
        _plan_step_for_action(
            plan,
            "workspace__send_email",
            {"action_results": []},
        )
        == "g1"
    )
    assert action_flow_contract(
        plan,
        "workspace__send_email",
        step_id="g1",
    )["destination"]["allowed_values"] == ["first@example.com"]
    assert action_flow_contract(
        plan,
        "workspace__send_email",
        step_id="g2",
    )["destination"]["allowed_values"] == ["second@example.com"]
    assert (
        _plan_step_for_action(
            plan,
            "workspace__send_email",
            {
                "action_results": [
                    {
                        "action": "workspace__send_email",
                        "status": "success",
                    }
                ]
            },
        )
        == "g2"
    )


def test_derived_parameter_keeps_its_own_source_scope():
    catalog = [
        {
            "name": "workspace__get_unread_emails",
            "suite": "workspace",
            "effect": "read",
            "risk_level": "L0",
            "input_schema": {"type": "object", "fields": {}},
            "output_schema": {"type": "array", "items": {"type": "object"}},
        },
        {
            "name": "banking__get_most_recent_transactions",
            "suite": "banking",
            "effect": "read",
            "risk_level": "L0",
            "input_schema": {"type": "object", "fields": {}},
            "output_schema": {"type": "array", "items": {"type": "object"}},
        },
        {
            "name": "workspace__export_value",
            "suite": "workspace",
            "effect": "egress",
            "risk_level": "L2",
            "destination_fields": ["recipient"],
            "input_schema": {
                "type": "object",
                "fields": {
                    "recipient": {
                        "type_schema": {"type": "str"},
                        "required": True,
                    },
                    "amount": {
                        "type_schema": {"type": "float"},
                        "required": True,
                    },
                },
            },
        },
    ]
    plan = _validate_task_plan(
        {
            "schema_version": 3,
            "task_goal": "Export one verified amount.",
            "source_refs": {
                "trip_email": {
                    "app": "workspace",
                    "entity": "email",
                    "producer_step": "g1",
                    "source_action": "workspace__get_unread_emails",
                },
                "transactions": {
                    "app": "banking",
                    "entity": "transaction",
                    "producer_step": "g2",
                    "source_action": (
                        "banking__get_most_recent_transactions"
                    ),
                },
            },
            "required_outcomes": [
                {
                    "id": "o1",
                    "description": "Export the amount from the email.",
                    "kind": "action",
                    "step_ids": ["g3"],
                    "required_sources": ["trip_email"],
                }
            ],
            "steps": [
                {
                    "id": "g1",
                    "actions": [
                        {
                            "name": "workspace__get_unread_emails",
                            "authorization_evidence": "read the request",
                        }
                    ],
                },
                {
                    "id": "g2",
                    "actions": [
                        {
                            "name": "banking__get_most_recent_transactions",
                            "authorization_evidence": "check transactions",
                        }
                    ],
                },
                {
                    "id": "g3",
                    "depends_on": ["g1", "g2"],
                    "actions": [
                        {
                            "name": "workspace__export_value",
                            "authorization_evidence": "export the amount",
                            "flow_contract": {
                                "allowed_sources": [
                                    "trip_email",
                                    "transactions",
                                ],
                                "data_sources": [
                                    "workspace:email",
                                    "banking:transaction",
                                ],
                                "destination": {
                                    "parameters": ["recipient"],
                                    "mode": "literal",
                                    "allowed_values": ["julie@example.com"],
                                },
                                "parameter_bindings": {
                                    "amount": {
                                        "mode": "derived_sources",
                                        "generation_kind": "extraction",
                                        "required_sources": [
                                            "trip_email"
                                        ],
                                        "allowed_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": "email",
                                                "source_action": (
                                                    "workspace__get_unread_emails"
                                                ),
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
        },
        "Export the amount from the request email.",
        catalog,
    )

    assert plan["valid"] is True, plan["warnings"]
    binding = plan["steps"][2]["actions"][0]["flow_contract"][
        "parameter_bindings"
    ]["amount"]
    assert binding["allowed_source_refs"] == [
        {
            "app": "workspace",
            "entity": "email",
            "source_action": "workspace__get_unread_emails",
        }
    ]


def test_outcome_audit_requires_verified_evidence_quote():
    plan = {
        "required_outcomes": [
            {
                "id": "o1",
                "description": "Show the unread email.",
                "kind": "data",
                "step_ids": ["g1"],
            }
        ]
    }
    events = [
        {
            "type": "api_call_end",
            "activity_id": "activity_read",
            "tool_intent": "workspace__get_unread_emails",
            "plan_step_id": "g1",
            "status": "success",
            "outputs": "Unread email: Team meeting at 10:00.",
        }
    ]

    def provider(_request: str) -> str:
        import json

        return json.dumps(
            {
                "outcomes": [
                    {
                        "id": "o1",
                        "status": "satisfied",
                        "reason": "读取结果包含未读邮件内容。",
                        "confidence": 0.92,
                        "evidence_quotes": [
                            {
                                "activity_id": "activity_read",
                                "source": "tool_output",
                                "path": "outputs",
                                "quote": "Unread email: Team meeting at 10:00.",
                            }
                        ],
                        "required_evidence_activity_ids": [
                            "activity_read"
                        ],
                    }
                ],
                "summary": "任务完成。",
            }
        )

    audit = audit_task_outcomes(
        plan=plan,
        events=events,
        final_response="There is a team meeting.",
        provider=provider,
    )

    assert audit["overall"] == "completed"
    assert audit["outcomes"][0]["evidence_quotes"][0]["source"] == "tool_output"


def test_stop_condition_requires_confidence_and_evidence():
    plan = {
        "required_outcomes": [
            {
                "id": "o1",
                "description": "Find the requested file.",
                "kind": "data",
                "step_ids": ["g1"],
            }
        ],
        "stop_conditions": [
            {
                "id": "stop_1",
                "when": "The requested file is absent.",
                "behavior": "finish_without_side_effects",
                "step_ids": ["g1"],
            }
        ],
    }
    events = [
        {
            "type": "api_call_end",
            "activity_id": "activity_read",
            "tool_intent": "workspace__get_unread_emails",
            "plan_step_id": "g1",
            "status": "success",
            "outputs": "No matching file was found.",
        }
    ]

    def audit(confidence: float) -> dict:
        return audit_task_outcomes(
            plan=plan,
            events=events,
            final_response="The file was not found.",
            provider=lambda _request: json.dumps(
                {
                    "outcomes": [
                        {
                            "id": "o1",
                            "status": "unsatisfied",
                            "reason": "No matching file was found.",
                            "confidence": 0.9,
                        }
                    ],
                    "stop_conditions": [
                        {
                            "id": "stop_1",
                            "triggered": True,
                            "reason": "Tool output reports no file.",
                            "confidence": confidence,
                            "evidence_activity_ids": ["activity_read"],
                        }
                    ],
                    "summary": "stopped",
                }
            ),
        )

    verified = audit(0.9)
    rejected = audit(0.4)

    assert verified["assessed"], verified.get("warnings")
    assert verified["stop_conditions"][0]["confidence"] == 0.9, verified
    assert rejected["stop_conditions"] == []
    assert any(
        "confidence_below_threshold" in warning
        for warning in rejected["warnings"]
    )


def test_action_outcome_success_without_output_evidence_is_uncertain():
    plan = {
        "required_outcomes": [
            {
                "id": "o1",
                "description": "Send the confirmation.",
                "kind": "action",
                "step_ids": ["g1"],
            }
        ]
    }
    events = [
        {
            "type": "api_call_end",
            "activity_id": "activity_send",
            "tool_intent": "workspace__send_email",
            "plan_step_id": "g1",
            "status": "success",
            "outputs": "sent",
            "environment_delta": {
                "created": [
                    {
                        "entity_id": "90010",
                        "entity_type": "email",
                        "attributes": {
                            "recipients": ["julie@example.com"]
                        },
                    }
                ]
            },
        }
    ]

    audit = audit_task_outcomes(
        plan=plan,
        events=events,
        final_response="Confirmation sent.",
        provider=lambda _request: (
            '{"outcomes":[{"id":"o1","status":"satisfied",'
            '"reason":"The tool succeeded.","confidence":0.95,'
            '"required_evidence_activity_ids":["activity_send"]}],'
            '"summary":"sent"}'
        ),
    )

    assert audit["overall"] == "incomplete"
    assert audit["outcomes"][0]["status"] == "uncertain"


def test_action_outcome_must_cite_non_read_activity():
    plan = {
        "required_outcomes": [
            {
                "id": "o1",
                "description": "Create the file.",
                "kind": "action",
                "step_ids": ["g1"],
            }
        ]
    }
    events = [
        {
            "type": "api_call_end",
            "activity_id": "activity_read",
            "tool_intent": "workspace__get_unread_emails",
            "plan_step_id": "g1",
            "status": "success",
            "outputs": "Request received.",
        },
        {
            "type": "api_call_end",
            "activity_id": "activity_write",
            "tool_intent": "workspace__create_file",
            "plan_step_id": "g1",
            "status": "success",
            "outputs": "created",
            "environment_delta": {
                "created": [
                    {
                        "entity_id": "90011",
                        "entity_type": "cloud_drive_file",
                        "attributes": {"filename": "result.txt"},
                    }
                ]
            },
        },
    ]

    audit = audit_task_outcomes(
        plan=plan,
        events=events,
        final_response="File created.",
        provider=lambda _request: json.dumps(
            {
                "outcomes": [
                    {
                        "id": "o1",
                        "status": "satisfied",
                        "reason": "The request was read.",
                        "confidence": 0.95,
                        "evidence_quotes": [
                            {
                                "activity_id": "activity_read",
                                "source": "tool_output",
                                "quote": "Request received.",
                            }
                        ],
                        "required_evidence_activity_ids": [
                            "activity_read"
                        ],
                    }
                ],
                "summary": "read",
            }
        ),
    )

    assert audit["outcomes"][0]["status"] == "uncertain"
    assert any(
        "action_without_side_effect_evidence" in warning
        for warning in audit["warnings"]
    )


def test_semantic_outcome_can_use_verified_final_response_quote():
    audit = audit_task_outcomes(
        plan={
            "required_outcomes": [
                {
                    "id": "o1",
                    "description": "The response is concise and relevant.",
                    "kind": "semantic",
                    "step_ids": [],
                }
            ]
        },
        events=[],
        final_response="Your next meeting is on Friday.",
        provider=lambda _request: (
            '{"outcomes":[{"id":"o1","status":"satisfied",'
            '"reason":"回答简洁并回应了问题。","confidence":0.9,'
            '"evidence_quotes":[{"activity_id":"","source":"final_response",'
            '"quote":"Your next meeting is on Friday."}]}],'
            '"summary":"answered"}'
        ),
    )

    assert audit["overall"] == "completed"
    assert audit["outcomes"][0]["status"] == "satisfied"
