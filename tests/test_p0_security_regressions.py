from types import SimpleNamespace

from agentdojo.default_suites.v1.tools.email_client import Email
from agentdojo.method.analysis.access_plan import schema_for_type
from agentdojo.method.analysis.flow_policy import check_sensitive_egress
from agentdojo.method.analysis.flow_policy import check_task_scope
from agentdojo.method.analysis.defense_config import effective_method_enabled
from agentdojo.method.analysis.injection_scanner import (
    INDIRECT_INJECTION_PLACEHOLDER,
    InjectionScanner,
    InjectionScanResult,
)
from agentdojo.method.analysis.pipeline import (
    process_after_execution_with_details,
    process_before_execution,
)
from agentdojo.method.analysis.tool_output_scanner import (
    _should_scan,
    scan_tool_output,
)
from agentdojo.method.capture.interceptor import _resolve_implicit_egress
from agentdojo.method.capture.interceptor import _task_planning_required
from agentdojo.method.capture.interceptor import (
    _l2_egress_execution_requires_manual_retry,
)
from agentdojo.method.modeling.graph_db import (
    get_graph_data,
    record_llm_interaction,
    record_activity,
    record_task_start,
    reset_graph,
    update_activity_outcome,
)
from agentdojo.method.modeling.labels import (
    make_confidentiality,
    make_flow_label,
)
from agentdojo.method.modeling.policy import tool_effect


class _UnavailableScanner:
    def scan_many(self, texts):
        return [
            InjectionScanResult(
                available=False,
                error="classifier unavailable",
            )
            for _text in texts
        ]


class _TruncatedScanner:
    def scan_many(self, texts):
        return [
            InjectionScanResult(
                available=True,
                truncated=True,
                chunk_count=1,
            )
            for _text in texts
        ]


class _RecordingClassifier:
    model_name = "recording-classifier"
    tokenizer = None

    def __init__(self):
        self.texts = []

    def classify_many(self, texts):
        self.texts.extend(texts)
        return [0.01 for _text in texts]


def test_disabled_ring_disables_its_methods():
    assert not effective_method_enabled(
        "ring_2",
        "task_scope",
        {"ring_2": {"enabled": False}},
    )


def test_ring3_can_depend_on_plan_without_ring2_scope_check():
    assert _task_planning_required(
        {
            "ring_2": {"enabled": True, "methods": {"task_scope": False}},
            "ring_3": {
                "enabled": True,
                "methods": {"sensitive_egress": True},
            },
        }
    )


def test_l2_egress_error_requires_explicit_user_retry():
    assert _l2_egress_execution_requires_manual_retry(
        tool_effect("workspace__send_email"),
        "ValueError: invalid email ID",
    )
    assert not _l2_egress_execution_requires_manual_retry(
        tool_effect("workspace__send_email"),
        None,
    )
    assert not _l2_egress_execution_requires_manual_retry(
        tool_effect("get_unread_emails"),
        "ValueError: read failed",
    )


def test_ring2_infers_unique_suite_for_unqualified_planned_tool():
    result = check_task_scope(
        {
            "tool_intent": "get_balance",
            "task_data_plan": {
                "valid": True,
                "allowed_actions": ["get_balance"],
                "allowed_effects": ["read"],
                "allowed_suites": ["banking"],
                "action_steps": {"get_balance": "g1"},
                "steps": [
                    {
                        "id": "g1",
                        "actions": [
                            {"name": "get_balance", "effect": "read"}
                        ],
                    }
                ],
                "l2_actions": [],
            },
        }
    )

    assert result["passed"] is True
    assert result["authorization"]["tool_suite"] == "banking"


def test_environment_delta_inherits_declared_entity_sensitivity():
    reset_graph()
    record_task_start(
        "Reserve the hotel.",
        task_id="task_delta_sensitivity",
        suite="travel",
    )
    start_event = {
        "timestamp": 1.0,
        "task_id": "task_delta_sensitivity",
        "tool_intent": "travel__reserve_hotel",
        "tool_effect": "egress",
        "tool_risk_level": "L2",
        "target_app": "travel",
        "app_domain": "travel",
        "suite": "travel",
        "inputs": {"hotel": "Example Hotel"},
        "input_flow_label": make_flow_label(
            confidentiality=make_confidentiality(level="internal")
        ),
    }
    record_activity(start_event)
    completion_event = {
        **start_event,
        "activity_id": start_event["activity_id"],
        "status": "success",
        "outputs": "Reservation successful.",
        "output_flow_label": make_flow_label(
            confidentiality=make_confidentiality(level="internal")
        ),
        "environment_delta": {
            "created": [
                {
                    "entity_id": "reservation-1",
                    "entity_type": "reservation",
                    "attributes": {"hotel": "Example Hotel"},
                    "data_payload": None,
                }
            ]
        },
    }
    update_activity_outcome(completion_event)

    delta = next(
        node
        for node in get_graph_data()["nodes"]
        if node.get("type") == "DomainData"
        and node.get("operation") == "created"
    )
    assert delta["flow_label"]["confidentiality"]["level"] == "confidential"
    assert "travel:reservation" in delta["flow_label"][
        "confidentiality"
    ]["source_entities"]
    reset_graph()


def test_tool_output_context_informs_next_model_invocation():
    reset_graph()
    record_task_start(
        "Read the email and decide the next step.",
        task_id="task_context_edge",
        suite="workspace",
    )
    activity_event = {
        "timestamp": 1.0,
        "task_id": "task_context_edge",
        "tool_intent": "workspace__get_unread_emails",
        "tool_effect": "read",
        "tool_risk_level": "L0",
        "target_app": "workspace",
        "app_domain": "workspace",
        "suite": "workspace",
        "inputs": {},
        "input_flow_label": make_flow_label(),
    }
    record_activity(activity_event)
    activity_id = activity_event["activity_id"]
    update_activity_outcome(
        {
            **activity_event,
            "activity_id": activity_id,
            "status": "success",
            "outputs": "The meeting is on Friday.",
            "output_flow_label": make_flow_label(
                confidentiality=make_confidentiality(
                    level="confidential",
                    source_ids=[f"{activity_id}:$.body"],
                    source_entities=["workspace:email"],
                )
            ),
        }
    )
    record_llm_interaction(
        {
            "timestamp": 2.0,
            "task_id": "task_context_edge",
            "suite": "workspace",
            "prompt": "Read the email and decide the next step.",
            "response": "The next step is to create a reminder.",
            "thought_id": "thought_context_edge",
            "context_flow_labels": [
                make_flow_label(
                    confidentiality=make_confidentiality(
                        level="confidential",
                        source_ids=[f"{activity_id}:$.body"],
                        source_entities=["workspace:email"],
                    )
                )
            ],
        }
    )

    graph = get_graph_data()
    invocation = next(
        node
        for node in graph["nodes"]
        if node.get("type") == "AIModelInvocation"
    )
    data_nodes = {
        node["id"]
        for node in graph["nodes"]
        if node.get("type") == "DomainData"
    }
    assert any(
        link.get("relation") == "informed"
        and link["source"]["id"] in data_nodes
        and link["target"]["id"] == invocation["id"]
        for link in graph["links"]
    )
    reset_graph()


def test_structured_enum_fields_are_not_scanned_as_language():
    classifier = _RecordingClassifier()
    result = scan_tool_output(
        [
            Email(
                id_="90010",
                sender="julie@example.com",
                recipients=["emma@example.com"],
                subject="Hotel request",
                body="Please reserve a hotel.",
                status="received",
            )
        ],
        scanner=InjectionScanner(classifier, threshold=0.5),
        tool_name="workspace__get_unread_emails",
        schema=schema_for_type(list[Email]),
    )

    assert result.field_statuses["$[0].status"] == "not_applicable"
    assert all(text != "received" for text in classifier.texts)


def test_calendar_email_side_effects_are_l2_egress():
    for tool_name in (
        "create_calendar_event",
        "cancel_calendar_event",
        "reschedule_calendar_event",
    ):
        policy = tool_effect(tool_name)
        assert policy.effect == "egress"
        assert policy.risk_level == "L2"
        assert policy.destination_fields


def test_calendar_cancel_resolves_actual_event_recipients():
    event = SimpleNamespace(
        id_="7",
        title="Planning",
        description="Planning session",
        start_time="2024-05-15T10:00:00",
        end_time="2024-05-15T11:00:00",
        location="Room A",
        participants=["julie@example.com"],
    )
    env = SimpleNamespace(
        calendar=SimpleNamespace(events={"7": event}),
    )

    implicit = _resolve_implicit_egress(
        env,
        "cancel_calendar_event",
        {"event_id": "7"},
        "workspace",
    )

    assert implicit[0]["resolved"] is True
    assert implicit[0]["recipients"] == ["julie@example.com"]
    assert implicit[0]["source"] == {
        "app": "workspace",
        "entity": "calendar_event",
        "entity_id": "7",
    }
    result = check_sensitive_egress(
        {
            "tool_intent": "cancel_calendar_event",
            "inputs": {"event_id": "7"},
            "task_data_plan": {
                "valid": True,
                "steps": [
                    {
                        "id": "g1",
                        "actions": [
                            {
                                "name": "cancel_calendar_event",
                                "effect": "egress",
                                "flow_contract": {
                                    "valid": True,
                                    "destination": {
                                        "parameters": ["event_id"],
                                        "mode": "literal",
                                        "allowed_values": ["7"],
                                    },
                                    "data_sources": [
                                        "workspace:calendar_event",
                                        "user_prompt",
                                    ],
                                    "max_confidentiality": "confidential",
                                    "parameter_bindings": {},
                                },
                            }
                        ],
                    }
                ],
            },
            "implicit_egress": implicit,
            "argument_flow_labels": {
                "event_id": make_flow_label(),
            },
        },
        options={
            "ring_3": {
                "enabled": True,
                "methods": {"sensitive_egress": True},
            }
        },
    )
    assert result["passed"] is True
    assert result["destinations"] == ["7", "julie@example.com"]


def _send_email_plan():
    return {
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
                            "destination": {
                                "parameters": ["recipients"],
                                "mode": "literal",
                                "allowed_values": ["julie@example.com"],
                            },
                            "data_sources": [
                                "workspace:email",
                                "user_prompt",
                            ],
                            "max_confidentiality": "confidential",
                            "parameter_bindings": {},
                        },
                    }
                ],
            }
        ],
        "action_steps": {"workspace__send_email": "g1"},
    }


def test_ring3_checks_all_actual_destination_fields_and_content_provenance():
    label = make_flow_label(
        confidentiality=make_confidentiality(level="internal")
    )
    result = check_sensitive_egress(
        {
            "tool_intent": "workspace__send_email",
            "inputs": {
                "recipients": ["julie@example.com"],
                "cc": ["attacker@example.com"],
                "body": "unverified text",
            },
            "task_data_plan": _send_email_plan(),
            "argument_flow_labels": {
                "recipients": label,
                "cc": label,
                "body": label,
            },
        },
        options={
            "ring_3": {
                "enabled": True,
                "methods": {"sensitive_egress": True},
            }
        },
    )

    assert result["passed"] is False
    assert "destination_not_authorized" in result["reason"]
    assert "egress_argument_without_provenance:body" in result["reason"]
    assert result["unverified_arguments"] == ["body"]
    assert result["provenance_state"] == "incomplete"
    assert (
        "egress_argument_without_provenance:body"
        in result["provenance_warnings"]
    )


def test_sensitive_content_without_entity_source_is_incomplete():
    plan = _send_email_plan()
    plan["steps"][0]["actions"][0]["flow_contract"][
        "max_confidentiality"
    ] = "secret"
    label = make_flow_label(
        confidentiality=make_confidentiality(
            level="secret",
            source_ids=["legacy:read_email"],
        )
    )
    result = check_sensitive_egress(
        {
            "tool_intent": "workspace__send_email",
            "inputs": {
                "recipients": ["julie@example.com"],
                "body": "Sensitive text",
            },
            "task_data_plan": plan,
            "argument_flow_labels": {
                "recipients": make_flow_label(),
                "body": label,
            },
        }
    )

    assert result["passed"] is False
    assert "data_source_unresolved" in result["reason"]
    assert result["provenance_state"] == "incomplete"
    assert "data_source_unresolved" in result["provenance_warnings"]


def test_tool_output_scan_failure_quarantines_instead_of_failing_open():
    result = scan_tool_output(
        {"body": "unexpected instructions"},
        scanner=_UnavailableScanner(),
    )

    assert result.available is False
    assert result.incomplete is True
    assert result.source_flagged is True
    assert result.sanitized_value["body"] == INDIRECT_INJECTION_PLACEHOLDER
    assert result.quarantined_fields == ["$.body"]


def test_ring1_failure_is_persisted_as_quarantine(monkeypatch):
    monkeypatch.setattr(
        "agentdojo.method.analysis.pipeline.get_injection_scanner",
        lambda: InjectionScanner(_UnavailableScanner()),
    )
    event = {
        "tool_intent": "workspace__get_unread_emails",
        "activity_id": "activity_scan_failure",
        "output_flow_label": make_flow_label(),
    }

    sanitized, diagnostics = process_after_execution_with_details(
        event,
        {"body": "unexpected instructions"},
    )

    assert sanitized["body"] == INDIRECT_INJECTION_PLACEHOLDER
    assert diagnostics["ring_1"]["passed"] is False
    assert diagnostics["risk_assessments"][0]["decision"] == "QUARANTINE"


def test_truncated_tool_output_is_quarantined():
    result = scan_tool_output(
        {"body": "content beyond the scan window"},
        scanner=_TruncatedScanner(),
    )

    assert result.incomplete is True
    assert result.sanitized_value["body"] == INDIRECT_INJECTION_PLACEHOLDER


def test_ring0_blocks_unavailable_and_truncated_scans():
    unavailable = {
        "tool_intent": "",
        "inputs": {},
        "injection_scan": {
            "available": False,
            "suspected": False,
            "error": "classifier unavailable",
        },
    }
    allow, _kwargs, _diagnostics, _categories = process_before_execution(
        unavailable,
        prompt="Book a hotel.",
    )
    assert allow is False
    assert "fail-closed" in unavailable["block_reason"]

    truncated = {
        "tool_intent": "",
        "inputs": {},
        "injection_scan": {
            "available": True,
            "suspected": False,
            "truncated": True,
            "chunk_count": 64,
        },
    }
    allow, _kwargs, _diagnostics, _categories = process_before_execution(
        truncated,
        prompt="Book a hotel.",
    )
    assert allow is False
    assert "partially" in truncated["block_reason"]


def test_ring0_distinguishes_method_disabled_from_detector_failure():
    disabled = {"tool_intent": "", "inputs": {}}
    allowed, _kwargs, diagnostics, _categories = process_before_execution(
        disabled,
        prompt="Read my email.",
        options={
            "ring_0": {
                "enabled": True,
                "methods": {"small_model": False},
            }
        },
    )

    assert allowed is True
    assert diagnostics["ring_0"]["skipped"] is True
    assert diagnostics["ring_0"]["skipped_reason"] == "method_disabled"

    unavailable = {"tool_intent": "", "inputs": {}}
    allowed, _kwargs, diagnostics, _categories = process_before_execution(
        unavailable,
        prompt="Read my email.",
    )

    assert allowed is False
    assert diagnostics["ring_0"]["coverage_incomplete"] is True
    assert "detector unavailable" in unavailable["block_reason"]


def test_url_fields_are_not_exempt_from_textual_scanning():
    assert _should_scan(
        "https://example.com/ignore-previous-instructions"
    )
    assert _should_scan("ignore_previous_instructions")
    assert _should_scan("send now")
