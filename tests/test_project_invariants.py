import inspect
import json
from pathlib import Path

import pytest

from agentdojo.method.analysis.risk_types import make_risk
from agentdojo.method.capture import interceptor
from agentdojo.method.modeling.graph_db import (
    get_graph_data,
    normalize_graph_semantics,
    record_activity,
    record_risk_assessments,
    record_task_start,
    reset_graph,
    transition_state,
)
from agentdojo.method.visualization import server

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCAL_COMMAND_DOCS = [
    "README.md",
    "start_guide.md",
    "TESTING_GUIDE.md",
    "method.md",
    "docs/development.md",
    "docs/concepts/appworld_task_migration.md",
    "docs/testing/curated_security_scenarios.md",
    "docs/testing/cross_app_security_metrics.md",
    "CLAUDE.md",
]


@pytest.mark.parametrize("relative_path", LOCAL_COMMAND_DOCS)
def test_local_commands_use_conda_agent(relative_path: str) -> None:
    text = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")

    assert "conda activate agent" in text
    assert ".venv\\Scripts\\python.exe" not in text
    assert ".venv/Scripts/python.exe" not in text
    assert "C:\\Users\\86534\\.conda\\envs\\agent" not in text


def test_server_defaults_to_loopback_without_cors():
    source = (
        REPOSITORY_ROOT
        / "src"
        / "agentdojo"
        / "method"
        / "visualization"
        / "server.py"
    ).read_text(encoding="utf-8")
    signature = inspect.signature(server.start_server)

    assert signature.parameters["host"].default == "127.0.0.1"
    assert signature.parameters["debug"].default is False
    assert "CORS(app)" not in source


def test_cross_origin_requests_are_rejected():
    client = server.app.test_client()

    response = client.get(
        "/api/status",
        headers={"Origin": "https://evil.example"},
    )
    preflight = client.options(
        "/api/reset",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    mutation = client.post(
        "/api/config/defense",
        json={"enabled": True},
        headers={"Origin": "https://evil.example"},
    )

    assert "Access-Control-Allow-Origin" not in response.headers
    assert preflight.status_code == 403
    assert mutation.status_code == 403


def test_foreign_host_is_rejected():
    response = server.app.test_client().get(
        "/api/status",
        headers={"Host": "attacker.example"},
    )

    assert response.status_code == 403


def test_frontend_is_served_with_security_headers():
    response = server.app.test_client().get("/")

    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers[
        "Content-Security-Policy"
    ]


def test_llm_config_rejects_markup_model_names():
    response = server.app.test_client().post(
        "/api/config/llm",
        json={
            "provider": "deepseek",
            "model": '" autofocus onfocus="alert(1)',
            "api_key": "test-only",
        },
    )

    assert response.status_code == 400
    error = response.get_json()["error"]
    assert error["code"] == "invalid_request"
    assert error["request_id"].startswith("req_")
    assert error["retryable"] is False


def test_unknown_server_errors_do_not_leak_internal_details(
    monkeypatch,
):
    def fail_graph():
        raise RuntimeError("C:\\private\\secret.txt")

    monkeypatch.setattr(server, "get_graph_data", fail_graph)
    response = server.app.test_client().get("/api/graph")

    assert response.status_code == 500
    assert "C:\\private" not in response.get_data(as_text=True)
    error = response.get_json()["error"]
    assert error["code"] == "internal_error"
    assert error["request_id"].startswith("req_")
    assert error["retryable"] is True
    assert response.headers["X-Request-ID"] == error["request_id"]


def test_frontend_uses_same_origin_api_and_escapes_model():
    api_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "api.js"
    ).read_text(encoding="utf-8")
    console_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "console.js"
    ).read_text(encoding="utf-8")

    assert "BASE_URL: '/api'" in api_source
    assert 'value="${modelValue}"' in console_source


def test_unsafe_html_sinks_are_escaped_or_sanitized():
    main_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "main.js"
    ).read_text(encoding="utf-8")
    status_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "status-panel.js"
    ).read_text(encoding="utf-8")
    risk_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "risk-panel.js"
    ).read_text(encoding="utf-8")
    graph_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "graph.js"
    ).read_text(encoding="utf-8")
    console_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "console.js"
    ).read_text(encoding="utf-8")

    assert "errorEl.innerHTML" not in main_source
    assert "window.location.protocol === 'file:'" in main_source
    assert "${f.name}" not in status_source
    assert "attentionKey.replace(" in risk_source
    assert ".replace(/[^a-z0-9_-]/g, '') || 'unknown'" in graph_source
    assert 'const safeRing = this._escape(ring)' in console_source
    assert 'const safeMethod = this._escape(method)' in console_source


def test_api_client_uses_structured_errors():
    api_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "api.js"
    ).read_text(encoding="utf-8")

    assert "class ApiError extends Error" in api_source
    assert "window.ApiError" not in api_source
    assert "async _request(" in api_source
    assert "structured?.request_id" in api_source
    console_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "console.js"
    ).read_text(encoding="utf-8")
    main_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "main.js"
    ).read_text(encoding="utf-8")
    assert "API.formatError(" in console_source
    assert "API.formatError(" in main_source
    assert "result.error" not in console_source


def test_risk_cards_do_not_nest_interactive_controls_in_button_role():
    risk_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "risk-panel.js"
    ).read_text(encoding="utf-8")

    assert '<article class="risk-card' in risk_source
    assert 'role="button"' not in risk_source
    assert 'aria-labelledby="risk-title-' in risk_source
    assert 'aria-controls="graph-container"' in risk_source
    assert "aria-pressed=\"${selected ? 'true' : 'false'}\"" in risk_source
    assert "container.addEventListener('keydown'" not in risk_source


def test_documentation_uses_same_origin_frontend():
    for relative_path in ("README.md", "start_guide.md", "method.md"):
        text = (REPOSITORY_ROOT / relative_path).read_text(
            encoding="utf-8"
        )
        assert "http://127.0.0.1:5000/" in text
        assert "Start-Process .\\frontend\\index.html" not in text
        assert "start frontend/index.html" not in text
        assert "xdg-open frontend/index.html" not in text


def test_documentation_matches_runtime_contract():
    readme = (REPOSITORY_ROOT / "README.md").read_text(
        encoding="utf-8"
    )
    method = (REPOSITORY_ROOT / "method.md").read_text(
        encoding="utf-8"
    )
    explain = (REPOSITORY_ROOT / "explain.md").read_text(
        encoding="utf-8"
    )

    for name in (
        "AGENTDOJO_PI_MODEL_PATH",
        "AGENTDOJO_DIRECT_PI_MODEL_PATH",
        "AGENTDOJO_FALLBACK_PI_MODEL_PATH",
        "AGENTDOJO_GLINER_MODEL_PATH",
        "AGENTDOJO_DEBUG",
        "AGENTDOJO_USE_RELOADER",
        "AGENTDOJO_ATTACK_SCENARIOS_PER_SUITE",
        "LOCAL_LLM_PORT",
    ):
        assert name in readme
        assert name in method

    assert "任务审计摘要" not in readme
    assert "triggered_by" in explain
    assert "applies_to_sink" in explain
    assert "29 个 `/api` 路由" in explain
    assert "旧 Trace Schema" in readme
    assert "读取和回放时自动归一化" in readme


def test_ring0_risk_is_linked_to_prompt():
    reset_graph()
    try:
        started = record_task_start(
            "Summarize the report.",
            task_id="task_ring0_graph",
            suite="workspace",
        )
        risk = make_risk(
            0,
            "MITIGATE",
            "Direct prompt injection was quarantined.",
            event_kind="security",
            policy_id="ring0.direct_user_instruction",
            fsm_before="CONTEXT_READY",
            fsm_after="SANITIZED",
        )
        interceptor._attach_ring0_prompt_source(
            [risk],
            started["prompt_entity_id"],
        )
        record_risk_assessments(
            {
                "timestamp": 1.0,
                "task_id": "task_ring0_graph",
                "suite": "workspace",
                "app_domain": "system",
            },
            [risk],
        )

        graph = get_graph_data()
        assert any(
            link["source"]["id"] == started["prompt_entity_id"]
            and link["target"]["id"] == risk["risk_id"]
            and link["relation"] == "triggered_by"
            for link in graph["links"]
        )
        assert not any(
            link.get("relation") == "source_of"
            and link["target"]["id"]
            == started["prompt_entity_id"]
            for link in graph["links"]
        )
    finally:
        reset_graph()


def test_only_task_scope_states_are_terminal():
    reset_graph()
    try:
        record_task_start(
            "Read the report.",
            task_id="task_terminal_scope",
            suite="workspace",
        )
        activity_state = transition_state(
            activity_id="Activity_terminal_test",
            state_name="FAILED",
            suffix="activity",
        )
        task_state = transition_state(
            activity_id=None,
            state_name="INCOMPLETE",
            scope="task",
            suffix="outcome",
        )
        graph = get_graph_data()
        nodes = {node["id"]: node for node in graph["nodes"]}

        assert nodes[activity_state]["terminal"] is False
        assert nodes[task_state]["terminal"] is True
    finally:
        reset_graph()


def test_only_ring3_risks_use_leak_sink_relation():
    reset_graph()
    try:
        record_task_start(
            "Send the payment.",
            task_id="task_sink_relation",
            suite="banking",
        )
        activity_event = {
            "timestamp": 1.0,
            "task_id": "task_sink_relation",
            "tool_intent": "send_money",
            "tool_effect": "egress",
            "tool_risk_level": "L2",
            "target_app": "banking",
            "app_domain": "banking",
            "suite": "banking",
            "inputs": {"amount": 10},
        }
        record_activity(activity_event)
        l2_risk = make_risk(
            2,
            "HOLD",
            "L2 confirmation.",
            event_kind="policy",
            policy_id="ring2.l2_confirmation",
            activity_id=activity_event["activity_id"],
            sink_ids=["send_money"],
        )
        egress_risk = make_risk(
            3,
            "ADVISORY",
            "Sensitive egress.",
            event_kind="security",
            policy_id="ring3.sensitive_egress",
            activity_id=activity_event["activity_id"],
            sink_ids=["send_money"],
        )
        record_risk_assessments(
            {
                "activity_id": activity_event["activity_id"],
                "timestamp": 2.0,
                "task_id": "task_sink_relation",
                "suite": "banking",
                "app_domain": "banking",
            },
            [l2_risk, egress_risk],
        )

        graph = get_graph_data()
        l2_relations = {
            link["relation"]
            for link in graph["links"]
            if link["source"]["id"] == l2_risk["risk_id"]
        }
        egress_relations = {
            link["relation"]
            for link in graph["links"]
            if link["source"]["id"] == egress_risk["risk_id"]
        }

        assert "applies_to_sink" in l2_relations
        assert "leak_sink" not in l2_relations
        assert "leak_sink" in egress_relations
    finally:
        reset_graph()


def test_graph_layout_places_unattached_auxiliary_nodes():
    graph_source = (
        REPOSITORY_ROOT / "frontend" / "js" / "graph.js"
    ).read_text(encoding="utf-8")

    assert "link.relation === 'triggered_by'" in graph_source
    assert "if (leftoverData.length > 0)" in graph_source
    assert "if (rows.length === 0 && leftoverData.length > 0)" not in graph_source


def test_saved_trace_graphs_are_normalized_on_read():
    trace_path = (
        REPOSITORY_ROOT
        / "src"
        / "workfolder"
        / "traces"
        / "trace_9896dd8d.json"
    )
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    server._normalize_trace_graph(trace)
    graph = trace["graph"]
    nodes = {node["id"]: node for node in graph["nodes"]}
    links = graph["links"]

    ring0 = next(
        node
        for node in graph["nodes"]
        if node.get("policy_id")
        == "ring0.direct_user_instruction"
    )
    prompt = next(
        node for node in graph["nodes"]
        if node.get("type") == "Prompt"
    )
    assert any(
        link["source"]["id"] == prompt["id"]
        and link["target"]["id"] == ring0["id"]
        and link["relation"] == "triggered_by"
        for link in links
    )
    assert all(
        node.get("terminal") is False
        for node in nodes.values()
        if node.get("type") == "TaskState"
        and node.get("scope") != "task"
    )
    assert not any(
        link.get("relation") == "source_of"
        for link in links
    )
    l2_ids = {
        node["id"]
        for node in nodes.values()
        if node.get("policy_id") == "ring2.l2_confirmation"
    }
    l2_relations = {
        link["relation"]
        for link in links
        if link["source"]["id"] in l2_ids
    }
    assert "applies_to_sink" in l2_relations
    assert "leak_sink" not in l2_relations
    assert (
        trace["graph_summary"]["total_edges"]
        == len(graph["links"])
    )
    assert (
        trace["graph_summary"]["edge_types"]["triggered_by"]
        >= 1
    )

    terminal_trace = json.loads(
        (
            REPOSITORY_ROOT
            / "src"
            / "workfolder"
            / "traces"
            / "trace_ec69a29a.json"
        ).read_text(encoding="utf-8")
    )
    server._normalize_trace_graph(terminal_trace)
    assert all(
        node.get("terminal") is False
        for node in terminal_trace["graph"]["nodes"]
        if node.get("type") == "TaskState"
        and node.get("scope") != "task"
    )

    legacy_source_trace = json.loads(
        (
            REPOSITORY_ROOT
            / "src"
            / "workfolder"
            / "traces"
            / "trace_f226b2e8.json"
        ).read_text(encoding="utf-8")
    )
    normalize_graph_semantics(legacy_source_trace["graph"])
    assert not any(
        link.get("relation") == "source_of"
        for link in legacy_source_trace["graph"]["links"]
    )
