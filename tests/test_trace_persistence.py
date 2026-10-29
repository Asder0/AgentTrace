"""Regression tests for blocked-execution trace persistence."""

import json
import io
import time

from agentdojo.method.capture.interceptor import (
    PromptInjectionBlockedError,
    TrackingContext,
)
from agentdojo.method.modeling.graph_db import reset_graph
from agentdojo.method.analysis.risk_types import (
    clear_risk_identity_cache,
    make_risk,
    stabilize_risk_identity,
)
from agentdojo.method.visualization import server
from agentdojo.method.visualization.mock_apps import (
    get_runtime_and_env,
    reset_all_environments,
)


def test_blocked_execution_writes_json_trace(tmp_path, monkeypatch):
    runtime, env = get_runtime_and_env("workspace")
    ctx = TrackingContext()
    ctx.reset()
    reset_graph()
    server._in_memory_traces.clear()
    monkeypatch.setattr(server, "_get_traces_dir", lambda: str(tmp_path))

    class BlockingPipeline:
        def query(self, prompt, runtime, env, messages, extra_args):
            ctx.log_event(
                {
                    "timestamp": time.time(),
                    "agent_id": "test-agent",
                    "task_id": ctx.task_id,
                    "suite": "workspace",
                    "tool_intent": "send_money",
                    "target_app": "banking",
                    "app_domain": "banking",
                    "status": "blocked",
                    "type": "api_call_end",
                    "block_reason": "untrusted control flow",
                    "risk_assessments": [
                        {
                            "risk_id": "Risk_trace_test",
                            "ring": 2,
                            "decision": "BLOCK",
                            "severity": "high",
                            "reason": "untrusted control flow",
                            "policy_id": "ring2.graph_authorization",
                            "evidence_entity_ids": [],
                            "source_ids": [],
                            "sink_ids": ["send_money"],
                            "taint_roots": ["email-output"],
                            "fsm_before": "ACTION_PROPOSED",
                            "fsm_after": "BLOCKED",
                        }
                    ],
                }
            )
            raise PromptInjectionBlockedError(
                "blocked by test",
                block_reason="untrusted control flow",
                tool_intent="send_money",
            )

    monkeypatch.setattr(
        server,
        "_build_pipeline",
        lambda app_name: (BlockingPipeline(), runtime, env),
    )

    result = server._execute_with_real_llm(
        "Read my email and summarize it.",
        ctx,
        time.time(),
        "test-agent",
        app_name="workspace",
    )
    assert result["blocked"] is True
    trace_file = tmp_path / f"{result['trace_id']}.json"
    assert trace_file.exists()
    record = json.loads(trace_file.read_text(encoding="utf-8"))
    assert record["blocked"] is True
    assert record["status"] == "blocked"
    assert record["risk_cards"]
    assert record["events"]


def test_trace_serializer_handles_non_json_values(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_get_traces_dir", lambda: str(tmp_path))
    server._in_memory_traces.clear()
    record = {
        "trace_id": "trace_safe_test",
        "timestamp": "12:00:00",
        "prompt": "test",
        "blocked": True,
        "events": [{"categories": {"credential", "iban"}}],
        "steps": [],
    }
    assert server._save_trace_to_file(record) is True
    saved = json.loads(
        (tmp_path / "trace_safe_test.json").read_text(encoding="utf-8")
    )
    assert saved["events"][0]["categories"] == ["credential", "iban"]


def test_safe_print_survives_non_unicode_console():
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="ascii", errors="strict")
    server._safe_print("blocked", "🛡", file=stream)
    stream.flush()
    assert b"blocked" in buffer.getvalue()


def test_timeline_exposes_task_and_access_plans():
    task_plan = {
        "valid": True,
        "subgoals": [{"id": "g1", "description": "Read email."}],
        "steps": [],
    }
    access_plan = {
        "subgoal_id": "g1",
        "decision": "PROJECT",
        "visible_fields": ["$[*].subject"],
    }
    item = server._to_timeline_event(
        {
            "type": "api_call_end",
            "tool_intent": "workspace__get_unread_emails",
            "task_data_plan": task_plan,
            "access_plan": access_plan,
            "input_flow_label": {
                "confidentiality": {
                    "level": "internal",
                    "categories": ["email"],
                },
                "integrity": {"kind": "untrusted"},
            },
            "output_flow_label": {
                "confidentiality": {
                    "level": "internal",
                    "categories": ["email"],
                },
                "integrity": {"kind": "untrusted"},
            },
            "defense_diagnostics": {
                "before": {
                    "ring_2": {
                        "capability_decision": {
                            "passed": True,
                            "consumed_data_sources": ["get_unread_emails"],
                        }
                    },
                    "ring_3": {"authorization": None},
                },
                "after": {"ring_3": {}},
            },
            "argument_sources": [
                {"argument_root": "body", "source_tool": "get_unread_emails"}
            ],
        },
        suite="unified",
    )
    assert item["task_data_plan"] == task_plan
    assert item["access_plan"] == access_plan
    assert item["capability_decision"]["passed"] is True
    assert item["argument_sources"][0]["argument_root"] == "body"
    assert item["output_flow_label"]["confidentiality"]["categories"] == [
        "email"
    ]


def test_timeline_uses_explicit_ring_prefix():
    assert server._infer_ring(
        "Ring 2: Action is outside the trusted task capability"
    ) == 2
    assert server._infer_ring(
        "Ring 3: data minimization applied"
    ) == 3


def test_tool_activity_separates_blocked_from_executed():
    activity = server._collect_tool_activity(
        [],
        [
            {
                "type": "api_call_end",
                "tool_intent": "get_balance",
                "status": "success",
            },
            {
                "type": "api_call_end",
                "tool_intent": "get_current_day",
                "status": "blocked",
            },
        ],
    )
    assert activity == {
        "attempted_tools": ["get_balance", "get_current_day"],
        "executed_tools": ["get_balance"],
        "successful_tools": ["get_balance"],
        "failed_tools": [],
        "blocked_tools": ["get_current_day"],
        "tool_call_count": 2,
        "successful_tool_call_count": 1,
        "failed_tool_call_count": 0,
        "blocked_tool_call_count": 1,
        "unique_tool_count": 2,
    }


def test_policy_mitigation_is_not_exposed_as_security_risk():
    event = {
        "type": "api_call_end",
        "tool_intent": "get_unread_emails",
        "target_app": "workspace",
        "risk_assessments": [
            {
                "risk_id": "Risk_policy",
                "ring": 3,
                "decision": "MITIGATE",
                "event_kind": "policy",
                "severity": "low",
                "reason": "Field minimization applied.",
                "policy_id": "ring3.llm_scope_projection",
                "source_ids": [],
            }
        ],
    }
    assert server._build_risk_cards_from_events([event]) == []
    policies = server._build_policy_events_from_events([event])
    assert policies[0]["event_kind"] == "policy"
    assert policies[0]["policy_id"] == "ring3.llm_scope_projection"
    timeline = server._to_timeline_event(event, suite="workspace")
    assert timeline["type"] == "policy"
    assert timeline["safe"] is True
    assert timeline["risks"] == []
    assert timeline["policy_events"][0]["risk_id"] == "Risk_policy"


def test_legacy_block_without_risk_event_is_not_safe():
    timeline = server._to_timeline_event(
        {
            "type": "api_call_end",
            "tool_intent": "send_money",
            "block_reason": "legacy policy block",
        },
        suite="banking",
    )
    assert timeline["type"] == "risk"
    assert timeline["safe"] is False


def test_repeated_task_risk_reuses_id_and_occurrence_count():
    clear_risk_identity_cache()
    first = make_risk(
        1,
        "ADVISORY",
        "instruction attempt",
        policy_id="ring1.instruction",
    )
    second = make_risk(
        1,
        "ADVISORY",
        "instruction attempt",
        policy_id="ring1.instruction",
    )
    stabilize_risk_identity(
        first,
        task_id="task-dedup",
        discriminator="same-attempt",
    )
    stabilize_risk_identity(
        second,
        task_id="task-dedup",
        discriminator="same-attempt",
    )
    assert second["risk_id"] == first["risk_id"]
    assert second["occurrence_count"] == 2
