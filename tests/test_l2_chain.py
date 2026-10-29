"""L2 semantic chain checking and confirmation tests."""

from __future__ import annotations

import json
import threading
import time

from agentdojo.method.analysis.l2_chain import (
    ConfirmationBroker,
    check_l2_chain_with_model,
)


def test_l2_chain_checker_accepts_consistent_model_result():
    result = check_l2_chain_with_model(
        user_prompt="Pay the bill amount to the specified account.",
        plan={"plan_id": "plan_1", "plan_revision": 2},
        agent_message="The bill amount is known; transfer it after checking funds.",
        tool_name="send_money",
        tool_args={"amount": 125.5},
        planner=lambda _request: json.dumps(
            {
                "consistent": True,
                "reason": "Transfer is the explicit user-authorized outcome.",
                "checks": {
                    "semantic_plan_relation": True,
                    "semantic_preconditions": True,
                    "semantic_destination_purpose": True,
                    "semantic_effect_purpose": True,
                    "semantic_parameter_relevance": True,
                },
                "violations": [],
                "evidence": [
                    "Pay the bill amount to the specified account."
                ],
                "confidence": 0.96,
            }
        ),
    )

    assert result["available"] is True
    assert result["consistent"] is True
    assert result["confidence"] == 0.96


def test_l2_chain_rejects_unverifiable_evidence():
    result = check_l2_chain_with_model(
        user_prompt="Pay the bill.",
        plan={"plan_id": "plan_1", "plan_revision": 1},
        agent_message="Pay the requested bill.",
        tool_name="send_money",
        tool_args={"amount": 125.5},
        planner=lambda _request: json.dumps(
            {
                "consistent": True,
                "reason": "The action is valid.",
                "checks": {
                    "semantic_plan_relation": True,
                    "semantic_preconditions": True,
                    "semantic_destination_purpose": True,
                    "semantic_effect_purpose": True,
                    "semantic_parameter_relevance": True,
                },
                "violations": [],
                "evidence": ["invented plan step"],
                "confidence": 0.99,
            }
        ),
    )

    assert result["available"] is True
    assert result["consistent"] is False
    assert result["evidence"] == []
    assert result["unverified_evidence"] == ["invented plan step"]


def test_l2_chain_checker_rejects_inconsistent_or_invalid_output():
    inconsistent = check_l2_chain_with_model(
        user_prompt="Read email.",
        plan={"plan_id": "plan_1", "plan_revision": 1},
        agent_message="Read the email.",
        tool_name="send_money",
        tool_args={"amount": 9999},
        planner=lambda _request: json.dumps(
            {
                "consistent": False,
                "reason": "No transfer appears in the authorized chain.",
                "checks": {
                    "semantic_plan_relation": False,
                    "semantic_preconditions": True,
                    "semantic_destination_purpose": True,
                    "semantic_effect_purpose": False,
                    "semantic_parameter_relevance": True,
                },
                "violations": [
                    {
                        "parameter": "amount",
                        "kind": "unplanned_action",
                        "detail": "授权链路中没有转账要求。",
                    }
                ],
                "evidence": [],
                "confidence": 0.99,
            }
        ),
    )
    assert inconsistent["consistent"] is False

    invalid = check_l2_chain_with_model(
        user_prompt="Read email.",
        plan={},
        agent_message="",
        tool_name="send_money",
        tool_args={},
        planner=lambda _request: "not-json",
    )
    assert invalid["available"] is False
    assert invalid["consistent"] is False


def test_l2_semantic_check_does_not_run_after_deterministic_failure():
    planner_called = False

    def planner(_request: str) -> str:
        nonlocal planner_called
        planner_called = True
        return "{}"

    result = check_l2_chain_with_model(
        user_prompt="Send the confirmation.",
        plan={"plan_id": "plan_1", "plan_revision": 1},
        agent_message="Send it.",
        tool_name="workspace__send_email",
        tool_args={"body": "Confirmation"},
        deterministic_checks={
            "ring_2": {"passed": False, "reason": "not planned"},
            "ring_3": {"passed": True},
        },
        planner=planner,
    )

    assert planner_called is False
    assert result["available"] is True
    assert result["executed"] is False
    assert result["consistent"] is False
    assert result["structured_issues"] == [
        "deterministic_check_failed"
    ]


def test_l2_chain_confidence_is_bounded():
    result = check_l2_chain_with_model(
        user_prompt="Pay the bill.",
        plan={"plan_id": "plan_1", "plan_revision": 1},
        agent_message="Pay the requested bill.",
        tool_name="send_money",
        tool_args={"amount": 125.5},
        planner=lambda _request: json.dumps(
            {
                "consistent": True,
                "reason": "valid",
                "checks": {
                    "semantic_plan_relation": True,
                    "semantic_preconditions": True,
                    "semantic_destination_purpose": True,
                    "semantic_effect_purpose": True,
                    "semantic_parameter_relevance": True,
                },
                "violations": [],
                "evidence": ["plan_1"],
                "confidence": 1.8,
            }
        ),
    )

    assert result["available"] is True
    assert result["consistent"] is True
    assert result["confidence"] == 1.0


def test_l2_chain_structured_violation_forces_inconsistency():
    result = check_l2_chain_with_model(
        user_prompt="Send a brief hotel confirmation.",
        plan={"plan_id": "plan_1", "plan_revision": 1},
        agent_message="Send the confirmation.",
        tool_name="workspace__send_email",
        tool_args={"body": "Hotel address: 12 Example Street"},
        planner=lambda _request: json.dumps(
            {
                "consistent": True,
                "reason": "The requested email is planned.",
                "checks": {
                    "semantic_plan_relation": True,
                    "semantic_preconditions": True,
                    "semantic_destination_purpose": True,
                    "semantic_effect_purpose": True,
                    "semantic_parameter_relevance": False,
                },
                "violations": [
                    {
                        "parameter": "body",
                        "kind": "unsupported_fact",
                        "source_action": "get_address",
                        "detail": "正文引用了未授权来源中的地址。",
                    }
                ],
                "evidence": ["Send a brief hotel confirmation."],
                "confidence": 0.9,
            }
        ),
    )

    assert result["consistent"] is False
    assert result["checks"]["semantic_parameter_relevance"] is False
    assert result["violations"][0]["kind"] == "unsupported_fact"
    assert "结构化检查未通过" in result["reason"]


def test_l2_chain_defers_presentation_fact_violations_to_human_review():
    prompt = "Send Julie a brief confirmation email."
    plan = {
        "plan_id": "plan_1",
        "plan_revision": 1,
        "steps": [
            {
                "id": "g1",
                "actions": [
                    {
                        "name": "workspace__send_email",
                        "flow_contract": {
                            "parameter_bindings": {
                                "body": {
                                    "generation_kind": "presentation",
                                    "parameter_role": "presentation",
                                }
                            }
                        },
                    }
                ],
            }
        ],
        "action_steps": {"workspace__send_email": "g1"},
    }
    result = check_l2_chain_with_model(
        user_prompt=prompt,
        plan=plan,
        agent_message="Send the confirmation.",
        tool_name="workspace__send_email",
        tool_args={"body": "Additional natural-language details."},
        plan_step_id="g1",
        planner=lambda _request: json.dumps(
            {
                "consistent": False,
                "reason": "正文包含额外描述。",
                "checks": {
                    "semantic_plan_relation": True,
                    "semantic_preconditions": True,
                    "semantic_destination_purpose": True,
                    "semantic_effect_purpose": True,
                    "semantic_parameter_relevance": False,
                },
                "violations": [
                    {
                        "parameter": "body",
                        "kind": "unsupported_fact_source",
                        "explanation": "自然语言正文包含额外描述。",
                    }
                ],
                "evidence": [prompt],
                "confidence": 0.9,
            }
        ),
    )

    assert result["consistent"] is True
    assert result["checks"]["semantic_parameter_relevance"] is True
    assert result["violations"] == []
    assert result["manual_review_notes"][0]["parameter"] == "body"
    assert result["presentation_parameters"] == ["body"]
    assert "自然语言参数不参与" in result["reason"]


def test_l2_chain_without_structured_checks_fails_closed():
    result = check_l2_chain_with_model(
        user_prompt="Send the requested confirmation.",
        plan={"plan_id": "plan_1", "plan_revision": 1},
        agent_message="Send the confirmation.",
        tool_name="workspace__send_email",
        tool_args={"body": "Confirmation"},
        planner=lambda _request: json.dumps(
            {
                "consistent": True,
                "reason": "It appears consistent.",
                "evidence": ["Send the requested confirmation."],
                "confidence": 0.99,
            }
        ),
    )

    assert result["consistent"] is False
    assert "missing_checks" in result["structured_issues"]


def test_confirmation_broker_pauses_until_user_resolves():
    broker = ConfirmationBroker()
    broker.clear()
    result = {}

    def wait_for_confirmation():
        result.update(
            broker.request(
                task_id="task_1",
                tool_name="send_money",
                app="banking",
                risk_level="L2",
                args={"amount": 125.5},
                plan={
                    "plan_id": "plan_2",
                    "plan_revision": 2,
                    "plan_hash": "sha256:test",
                },
                chain_check={"consistent": True, "reason": "valid"},
            )
        )

    thread = threading.Thread(target=wait_for_confirmation)
    thread.start()
    request_id = ""
    for _ in range(100):
        pending = broker.list_pending()
        if pending:
            request_id = pending[0]["request_id"]
            break
        time.sleep(0.01)
    assert request_id

    resolved = broker.resolve(request_id, True)
    thread.join(timeout=2)

    assert resolved["status"] == "approved"
    assert result["status"] == "approved"
    assert result["approved"] is True
    assert result["plan_hash"] == "sha256:test"
    broker.clear()
