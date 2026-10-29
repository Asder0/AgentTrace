import json

from agentdojo.method.analysis.parameter_binding import (
    all_placeholder_bindings,
    _value_supported_by_text,
    placeholder_notice,
    resolve_parameter_bindings,
)
from agentdojo.method.modeling.data_sensitivity import ValueOrigin, value_key
from agentdojo.method.capture.interceptor import _build_tool_catalog
from agentdojo.method.capture.interceptor import _inject_parameter_binding_notice
from agentdojo.method.visualization.mock_apps import get_runtime_and_env


def _origin(
    *,
    app: str,
    entity: str,
    tool: str,
    entity_id: str,
    path: str,
    value,
) -> ValueOrigin:
    return ValueOrigin(
        app=app,
        entity=entity,
        level="confidential",
        source_tool=tool,
        source_activity_id=f"Activity_{tool}_test",
        entity_id=entity_id,
        source_path=path,
        value_key=value_key(value),
        value=value,
    )


def test_tool_catalog_assigns_control_and_destination_roles():
    runtime, _environment = get_runtime_and_env("unified")
    catalog = {
        item["name"]: item for item in _build_tool_catalog(runtime)
    }
    hotel_name = next(
        name for name in catalog if name.endswith("reserve_hotel")
    )
    hotel_fields = catalog[hotel_name]["input_schema"]["fields"]
    email_fields = catalog["workspace__send_email"]["input_schema"][
        "fields"
    ]

    assert hotel_fields["start_day"]["role"] == "control"
    assert hotel_fields["start_day"]["roles"] == ["control"]
    assert email_fields["recipients"]["role"] == "destination"
    assert email_fields["body"]["role"] == "presentation"


def test_parameter_notice_is_replaced_instead_of_accumulated():
    def plan_with_source(source: str) -> dict:
        return {
            "steps": [
                {
                    "id": "g1",
                    "actions": [
                        {
                            "name": "workspace__send_email",
                            "flow_contract": {
                                "parameter_bindings": {
                                    "body": {
                                        "mode": "derived_sources",
                                        "symbol": "__CTRL_SLOT_test_body__",
                                        "generation_kind": "presentation",
                                        "allowed_source_refs": [
                                            {
                                                "app": "workspace",
                                                "entity": source,
                                                "source_action": (
                                                    "workspace__get_unread_emails"
                                                ),
                                            }
                                        ],
                                    }
                                }
                            },
                        }
                    ],
                }
            ]
        }

    messages = [{"role": "system", "content": "Base system context."}]
    first = _inject_parameter_binding_notice(
        messages,
        plan_with_source("email"),
    )
    second = _inject_parameter_binding_notice(
        first,
        plan_with_source("calendar_event"),
    )
    text = "\n".join(
        str(message.get("content", ""))
        for message in second
        if message.get("role") == "system"
    )

    assert text.count("PROVENANCE-BOUND PARAMETERS:") == 1
    assert '"entity":"calendar_event"' in text
    assert '"entity":"email"' not in text


def test_action_level_sources_are_not_repeated_on_every_parameter():
    plan = {
        "steps": [
            {
                "id": "g1",
                "actions": [
                    {
                        "name": "travel__reserve_hotel",
                        "flow_contract": {
                            "required_sources": [
                                "trip_email",
                                "hotel_prices",
                            ],
                            "source_bindings": {
                                "trip_email": {
                                    "app": "workspace",
                                    "entity": "email",
                                    "source_action": "workspace__get_unread_emails",
                                },
                                "hotel_prices": {
                                    "app": "travel",
                                    "entity": "hotel",
                                    "source_action": "travel__get_hotels_prices",
                                },
                            },
                            "parameter_bindings": {
                                "hotel": {
                                    "mode": "derived_sources",
                                    "generation_kind": "selection",
                                    "required_source_refs": [
                                        {
                                            "app": "workspace",
                                            "entity": "email",
                                            "source_action": (
                                                "workspace__get_unread_emails"
                                            ),
                                        }
                                    ],
                                    "symbol": "__CTRL_SLOT_hotel__",
                                },
                                "start_day": {
                                    "mode": "derived_sources",
                                    "generation_kind": "extraction",
                                    "required_source_refs": [
                                        {
                                            "app": "workspace",
                                            "entity": "email",
                                            "source_action": (
                                                "workspace__get_unread_emails"
                                            ),
                                        }
                                    ],
                                    "symbol": "__CTRL_SLOT_start_day__",
                                },
                            },
                        },
                    }
                ],
            }
        ]
    }

    bindings = all_placeholder_bindings(plan)

    assert len(bindings) == 2
    assert all("required_sources" not in binding for binding in bindings)
    assert all("source_bindings" not in binding for binding in bindings)


def test_date_normalization_is_validated_against_source_evidence():
    email_text = (
        "Please reserve a hotel for June 10 to June 14, 2024."
    )
    origin = _origin(
        app="workspace",
        entity="email",
        tool="get_unread_emails",
        entity_id="90010",
        path="$[0].body",
        value=email_text,
    )
    plan = {
        "valid": True,
        "steps": [
            {
                "id": "g1",
                "actions": [
                    {
                        "name": "travel__reserve_hotel",
                        "effect": "egress",
                        "flow_contract": {
                            "valid": True,
                            "data_sources": ["workspace:email"],
                            "required_sources": ["trip_email"],
                            "required_source_refs": [
                                {
                                    "app": "workspace",
                                    "entity": "email",
                                    "source_action": "get_unread_emails",
                                }
                            ],
                            "source_bindings": {
                                "trip_email": {
                                    "app": "workspace",
                                    "entity": "email",
                                    "source_action": "get_unread_emails",
                                }
                            },
                            "parameter_bindings": {
                                "start_day": {
                                    "mode": "derived_sources",
                                    "generation_kind": "extraction",
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
                                    "symbol": "__CTRL_SLOT_start_day__",
                                }
                            },
                        },
                    }
                ],
            }
        ],
        "action_steps": {"travel__reserve_hotel": "g1"},
    }

    def resolver(_request: str) -> str:
        return json.dumps(
            {
                "resolutions": [
                    {
                        "parameter": "start_day",
                        "value": "2024-06-10",
                        "derivation_type": "normalization",
                        "explanation": (
                            "根据邮件中的 June 10 规范化为 ISO 日期。"
                        ),
                        "confidence": 0.95,
                        "source_evidence": [
                            {
                                "app": "workspace",
                                "entity": "email",
                                "entity_id": "90010",
                                "source_action": "get_unread_emails",
                                "source_path": "$[0].body",
                                "start": 0,
                                "end": len(email_text),
                                "extracted_text": email_text,
                            }
                        ],
                    }
                ]
            }
        )

    resolved, resolutions, errors, _warnings = resolve_parameter_bindings(
        tool_name="travel__reserve_hotel",
        args={"start_day": "2024-06-10"},
        plan=plan,
        value_origins=[origin],
        derive_resolver=resolver,
    )

    assert resolved["start_day"] == "2024-06-10"
    assert errors == []
    assert resolutions[0]["semantic_type"] == "date"
    assert resolutions[0]["source_evidence"][0]["entity_id"] == "90010"
    assert (
        resolutions[0]["source_evidence"][0]["extracted_text"]
        == "June 10"
    )
    assert not _value_supported_by_text(
        "2024-06-10",
        "hotel in Paris",
        "date",
        email_text,
    )

    def mismatched_resolver(_request: str) -> str:
        payload = json.loads(resolver(""))
        payload["resolutions"][0]["value"] = "2024-06-11"
        return json.dumps(payload)

    _resolved, mismatch_resolutions, mismatch_errors, _warnings = (
        resolve_parameter_bindings(
            tool_name="travel__reserve_hotel",
            args={"start_day": "2024-06-10"},
            plan=plan,
            value_origins=[origin],
            derive_resolver=mismatched_resolver,
        )
    )
    assert mismatch_errors[0] == "parameter_value_mismatch:start_day"
    assert mismatch_resolutions == []


def test_presentation_text_is_not_value_compared_or_fact_checked():
    email_text = (
        "Please confirm the hotel booking by email."
    )
    origin = _origin(
        app="workspace",
        entity="email",
        tool="get_unread_emails",
        entity_id="90010",
        path="$[0].body",
        value=email_text,
    )
    plan = {
        "valid": True,
        "steps": [
            {
                "id": "g1",
                "actions": [
                    {
                        "name": "workspace__send_email",
                        "effect": "egress",
                        "flow_contract": {
                            "valid": True,
                            "data_sources": ["workspace:email"],
                            "parameter_bindings": {
                                "body": {
                                    "mode": "derived_sources",
                                    "generation_kind": "presentation",
                                    "parameter_role": "presentation",
                                    "allowed_source_refs": [
                                        {
                                            "app": "workspace",
                                            "entity": "email",
                                            "source_action": (
                                                "get_unread_emails"
                                            ),
                                        }
                                    ],
                                    "required_source_refs": [
                                        {
                                            "app": "workspace",
                                            "entity": "email",
                                            "source_action": (
                                                "get_unread_emails"
                                            ),
                                        }
                                    ],
                                    "symbol": "__CTRL_SLOT_body__",
                                }
                            },
                        },
                    }
                ],
            }
        ],
        "action_steps": {"workspace__send_email": "g1"},
    }

    def resolver(_request: str) -> str:
        return json.dumps(
            {
                "resolutions": [
                    {
                        "parameter": "body",
                        "value": "The booking is confirmed.",
                        "explanation": "根据邮件要求生成确认正文。",
                        "confidence": 0.95,
                        "source_evidence": [
                            {
                                "app": "workspace",
                                "entity": "email",
                                "entity_id": "90010",
                                "source_action": "get_unread_emails",
                                "source_path": "$[0].body",
                                "quote": email_text,
                            }
                        ],
                    }
                ]
            }
        )

    final_body = (
        "Hi Julie,\n\nThe hotel booking is confirmed.\n\n"
        "This is a separately formatted natural-language body."
    )
    resolved, resolutions, errors, warnings = resolve_parameter_bindings(
        tool_name="workspace__send_email",
        args={"body": final_body},
        plan=plan,
        value_origins=[origin],
        derive_resolver=resolver,
    )

    assert errors == []
    assert warnings == []
    assert resolved["body"] == final_body
    assert resolutions[0]["validation_mode"] == (
        "natural_language_manual"
    )
    assert resolutions[0]["proposed_value"] == final_body
    assert resolutions[0]["verified_value"] == (
        "The booking is confirmed."
    )


def test_copy_binding_selects_unique_entity_from_agent_value():
    senders = [
        "support@example.com",
        "julie.williams@bluesparrowtech.com",
        "promotions@example.com",
    ]
    origins = [
        _origin(
            app="workspace",
            entity="email",
            tool="get_unread_emails",
            entity_id=str(90020 + index),
            path=f"$[{index}].sender",
            value=sender,
        )
        for index, sender in enumerate(senders)
    ]
    plan = {
        "valid": True,
        "steps": [
            {
                "id": "g1",
                "actions": [
                    {
                        "name": "workspace__send_email",
                        "effect": "egress",
                        "flow_contract": {
                            "valid": True,
                            "data_sources": ["workspace:email"],
                            "required_sources": ["trip_email"],
                            "required_source_refs": [
                                {
                                    "app": "workspace",
                                    "entity": "email",
                                    "source_action": "get_unread_emails",
                                }
                            ],
                            "source_bindings": {
                                "trip_email": {
                                    "app": "workspace",
                                    "entity": "email",
                                    "source_action": "get_unread_emails",
                                }
                            },
                            "parameter_bindings": {
                                "recipients": {
                                    "mode": "copy",
                                    "source_id": "trip_email",
                                    "source_action": "get_unread_emails",
                                    "source_tool": "get_unread_emails",
                                    "source_path": "$[*].sender",
                                    "selector": "unique",
                                    "semantic_type": "email",
                                    "symbol": "__CTRL_SLOT_recipients__",
                                }
                            },
                        },
                    }
                ],
            }
        ],
    }

    resolved, resolutions, errors, _warnings = resolve_parameter_bindings(
        tool_name="workspace__send_email",
        args={"recipients": ["julie.williams@bluesparrowtech.com"]},
        plan=plan,
        value_origins=origins,
    )

    assert resolved["recipients"] == [
        "julie.williams@bluesparrowtech.com"
    ]
    assert errors == []
    assert resolutions[0]["source_refs"][0]["entity_id"] == "90021"

    _bad_values, bad_resolutions, bad_errors, _warnings = (
        resolve_parameter_bindings(
            tool_name="workspace__send_email",
            args={"recipients": ["unknown@example.com"]},
            plan=plan,
            value_origins=origins,
        )
    )
    assert "placeholder_ambiguous:recipients" in bad_errors
    assert bad_resolutions == []


def test_parameter_notice_requires_concrete_values():
    plan = {
        "steps": [
            {
                "actions": [
                    {
                        "name": "banking__send_money",
                        "flow_contract": {
                            "parameter_bindings": {
                                "amount": {
                                    "mode": "derived_sources",
                                    "generation_kind": "normalization",
                                    "semantic_type": "number",
                                    "allowed_source_refs": [
                                        {
                                            "app": "banking",
                                            "entity": "transaction",
                                            "source_action": (
                                                "get_most_recent_transactions"
                                            ),
                                        }
                                    ],
                                    "symbol": "__CTRL_SLOT_amount__",
                                }
                            }
                        },
                    }
                ]
            }
        ]
    }

    notice = placeholder_notice(plan)
    assert "Fill the tool argument with the concrete business value" in notice
    assert "Preserve each symbol" not in notice
    assert "semantic_type=number" in notice


def test_multi_source_selection_is_atomic_and_requires_every_source():
    email_text = (
        "Reserve a quiet hotel near the Louvre for June 10 to June 14, "
        "2024 with a budget of 180 EUR."
    )
    hotel_text = "Hotel Names: Le Marais Boutique"
    price_text = "Le Marais Boutique: Price range: 120.0 - 180.0"
    origins = [
        _origin(
            app="workspace",
            entity="email",
            tool="get_unread_emails",
            entity_id="90010",
            path="$[0].body",
            value=email_text,
        ),
        _origin(
            app="travel",
            entity="hotel",
            tool="get_all_hotels_in_city",
            entity_id="hotels-1",
            path="$",
            value=hotel_text,
        ),
        _origin(
            app="travel",
            entity="hotel",
            tool="get_hotels_prices",
            entity_id="prices-1",
            path="$",
            value=price_text,
        ),
    ]
    required_refs = [
        {
            "app": "workspace",
            "entity": "email",
            "source_action": "get_unread_emails",
        },
        {
            "app": "travel",
            "entity": "hotel",
            "source_action": "get_all_hotels_in_city",
        },
        {
            "app": "travel",
            "entity": "hotel",
            "source_action": "get_hotels_prices",
        },
    ]
    plan = {
        "valid": True,
        "steps": [
            {
                "id": "g1",
                "actions": [
                    {
                        "name": "travel__reserve_hotel",
                        "effect": "egress",
                        "flow_contract": {
                            "valid": True,
                            "data_sources": [
                                "workspace:email",
                                "travel:hotel",
                            ],
                            "source_bindings": {
                                "trip_email": {
                                    **required_refs[0],
                                },
                                "hotels": {
                                    **required_refs[1],
                                },
                                "prices": {
                                    **required_refs[2],
                                },
                            },
                            "parameter_bindings": {
                                "hotel": {
                                    "mode": "derived_sources",
                                    "generation_kind": "selection",
                                    "allowed_source_refs": required_refs,
                                    "required_source_refs": required_refs,
                                    "symbol": "__CTRL_SLOT_hotel__",
                                }
                            },
                        },
                    }
                ],
            }
        ],
    }

    def resolver(_request: str) -> str:
        return json.dumps(
            {
                "resolutions": [
                    {
                        "parameter": "hotel",
                        "value": "Le Marais Boutique",
                        "derivation_type": "selection",
                        "explanation": (
                            "根据酒店候选和价格来源选择酒店。"
                        ),
                        "confidence": 0.93,
                        "source_evidence": [
                            {
                                "app": "travel",
                                "entity": "hotel",
                                "entity_id": "hotels-1",
                                "source_action": "get_all_hotels_in_city",
                                "source_path": "$",
                                "start": 13,
                                "end": 31,
                                "extracted_text": "Le Marais Boutique",
                            }
                        ],
                    }
                ]
            }
        )

    _resolved, resolutions, errors, _warnings = resolve_parameter_bindings(
        tool_name="travel__reserve_hotel",
        args={"hotel": "Le Marais Boutique"},
        plan=plan,
        value_origins=origins,
        derive_resolver=resolver,
    )

    assert resolutions == []
    assert any(
        item.startswith("required_parameter_source_missing:hotel:")
        for item in errors
    )
