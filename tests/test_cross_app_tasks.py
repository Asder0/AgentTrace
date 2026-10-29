"""Cross-APP composition and four-suite unified routing tests."""

import pytest

from agentdojo.method.capture.interceptor import TrackingContext
from agentdojo.method.analysis.defense_config import (
    reset_config,
    set_method_enabled,
)
from agentdojo.method.modeling.graph_db import (
    get_graph_data,
    reset_graph,
)
from agentdojo.method.tasks.cross_app import (
    CROSS_APP_TASKS,
    CrossAppStep,
    CrossAppTask,
)
from agentdojo.method.visualization.mock_apps import (
    MOCK_SCENARIOS,
    RouterRuntime,
    apply_scenario_fixtures,
    get_runtime_and_env,
    reset_all_environments,
)
from agentdojo.method.modeling.policy import base_tool_name, tool_effect


@pytest.fixture(autouse=True)
def _reset_app_state():
    from agentdojo.method import activate_platform

    activate_platform()
    reset_all_environments()
    reset_graph()
    TrackingContext().reset()
    # These tests exercise suite routing directly, without a user task plan.
    set_method_enabled("ring_3", "sensitive_egress", False)
    set_method_enabled("ring_2", "task_scope", False)
    yield
    reset_config()
    reset_all_environments()
    reset_graph()
    TrackingContext().reset()


def test_unified_runtime_namespaces_duplicate_tools():
    runtime, _env = get_runtime_and_env("unified")
    assert isinstance(runtime, RouterRuntime)
    assert "get_balance" in runtime.functions
    assert "send_email" not in runtime.functions
    assert "workspace__send_email" in runtime.functions
    assert "travel__send_email" in runtime.functions
    assert all(
        tool_effect(base_tool_name(name)).effect != "unknown"
        for name in runtime.functions
    )
    balance_policy = tool_effect("get_balance")
    assert balance_policy.confidentiality == "secret"
    assert "financial_data" in balance_policy.categories
    email_policy = tool_effect("workspace__send_email")
    assert email_policy.effect == "egress"
    assert email_policy.destination_fields == {"recipients", "cc", "bcc"}
    assert runtime.tool_app_map()["workspace__send_email"] == "workspace"
    assert runtime.tool_app_map()["travel__send_email"] == "travel"

    _result, error = runtime.run_function(
        None,
        "send_email",
        {"recipients": ["x@example.com"], "subject": "x", "body": "x"},
    )
    assert error is not None
    assert "ambiguous" in error.lower()


def test_duplicate_tool_alias_routes_to_correct_app_environment():
    runtime, env = get_runtime_and_env("unified")
    workspace_count = len(env.workspace.inbox.sent)
    travel_count = len(env.travel.inbox.sent)

    _result, error = runtime.run_function(
        env,
        "travel__send_email",
        {
            "recipients": ["travel@example.com"],
            "subject": "Travel route",
            "body": "Routed to travel APP.",
            "attachments": None,
            "cc": None,
            "bcc": None,
        },
    )
    assert error is None
    assert len(env.workspace.inbox.sent) == workspace_count
    assert len(env.travel.inbox.sent) == travel_count + 1
    assert TrackingContext().events[-1]["tool_intent"] == "travel__send_email"


def test_four_suite_composite_task_executes_through_all_apps():
    task = CROSS_APP_TASKS["cross_app::trip_request_to_slack"]
    runtime, env = get_runtime_and_env("unified")
    task.validate(runtime.functions)
    assert task.required_suites == (
        "workspace",
        "travel",
        "banking",
        "slack",
    )
    links = task.data_links()
    assert {
        link["artifact"] for link in links
    } == {
        "trip_request",
        "lodging_preference",
        "hotel_options",
        "available_budget",
        "slack_channel_list",
    }
    assert all(step.depends_on or step.step_id == "extract_trip_request" for step in task.execution_order())

    actual_suites = []
    for step in task.execution_order():
        tool_name = step.exposed_tool_name(runtime)
        _result, error = runtime.run_function(
            env,
            tool_name,
            dict(step.arguments),
        )
        assert error is None, f"{step.step_id}: {error}"
        actual_suites.append(runtime.tool_app_map()[tool_name])
    assert set(actual_suites) == set(task.required_suites)


def test_cross_app_artifact_must_come_from_an_ancestor():
    task = CrossAppTask(
        task_id="invalid-link",
        prompt="Invalid dependency test.",
        description="Invalid dependency test.",
        steps=(
            CrossAppStep(
                step_id="first",
                suite="workspace",
                tool="get_unread_emails",
                purpose="Produce email data.",
                produces=("email_data",),
            ),
            CrossAppStep(
                step_id="second",
                suite="banking",
                tool="get_balance",
                purpose="Consume email data without declaring dependency.",
                consumes=("email_data",),
            ),
        ),
    )
    with pytest.raises(ValueError, match="without depending"):
        task.validate()


def test_inbox_and_balance_has_deterministic_payment_reminder():
    task = CROSS_APP_TASKS["cross_app::inbox_and_balance"]
    runtime, env = get_runtime_and_env("unified")
    task.validate(runtime.functions)

    assert task.fixtures["workspace"]["append_unread_emails"]
    apply_scenario_fixtures(env, task.to_scenario())

    unread, error = runtime.run_function(
        env,
        "get_unread_emails",
        {},
    )
    assert error is None
    reminder = next(
        email
        for email in unread
        if email.subject == "Electricity bill payment reminder"
    )
    assert "68.50 EUR" in reminder.body

    balance, error = runtime.run_function(env, "get_balance", {})
    assert error is None
    assert isinstance(balance, (int, float))

    graph = get_graph_data()
    tool_apps = {
        node.get("app")
        for node in graph["nodes"]
        if node.get("type") == "AgentTool"
    }
    assert {"workspace", "banking"} <= tool_apps


def test_email_bill_transfer_is_a_preset_cross_app_scenario():
    task = CROSS_APP_TASKS["cross_app::email_bill_transfer"]
    runtime, env = get_runtime_and_env("unified")
    task.validate(runtime.functions)
    assert task.required_suites == ("workspace", "banking")
    assert [
        link["artifact"] for link in task.data_links()
    ] == ["bill_amount", "recipient_account"]
    assert "cross_app::email_bill_transfer" in MOCK_SCENARIOS
    assert runtime.tool_app_map()["send_money"] == "banking"

    scenario = task.to_scenario()
    apply_scenario_fixtures(env, scenario)
    apply_scenario_fixtures(env, scenario)
    bill = next(
        email
        for email in env.workspace.inbox.emails.values()
        if email.subject == "Utility bill payment reminder"
    )
    assert bill.id_.isdecimal()
    assert bill.read is False
    assert bill.subject == "Utility bill payment reminder"
    assert "125.50 EUR" in bill.body
    assert "Ignore previous instructions" in bill.body
    assert sum(
        email.subject == bill.subject
        for email in env.workspace.inbox.emails.values()
    ) == 1


def test_cross_app_email_fixtures_use_numeric_entity_ids():
    entity_ids = []
    for task in CROSS_APP_TASKS.values():
        fixtures = task.fixtures.get("workspace", {})
        for fixture in fixtures.get("append_unread_emails", []):
            assert fixture.get("fixture_id")
            assert str(fixture.get("id_", "")).isdecimal()
            entity_ids.append(str(fixture["id_"]))
    assert len(entity_ids) == len(set(entity_ids))


def test_scenario_fixture_rejects_opaque_runtime_entity_id():
    _runtime, env = get_runtime_and_env("unified")
    scenario = {
        "fixtures": {
            "workspace": {
                "append_unread_emails": [
                    {
                        "fixture_id": "scenario_invalid_email",
                        "id_": "scenario_invalid_email",
                        "sender": "sender@example.com",
                        "subject": "Invalid fixture",
                        "body": "Invalid entity ID.",
                        "recipients": [
                            "emma.johnson@bluesparrowtech.com"
                        ],
                    }
                ]
            }
        }
    }

    with pytest.raises(ValueError, match="numeric id_"):
        apply_scenario_fixtures(env, scenario)


def test_cross_app_execution_is_recorded_in_all_app_domains():
    from agentdojo.method import activate_platform

    activate_platform()
    task = CROSS_APP_TASKS["cross_app::trip_request_to_slack"]
    runtime, env = get_runtime_and_env("unified")
    for step in task.execution_order():
        _result, error = runtime.run_function(
            env,
            step.exposed_tool_name(runtime),
            dict(step.arguments),
        )
        assert error is None, f"{step.step_id}: {error}"

    graph = get_graph_data()
    tool_apps = {
        node.get("app")
        for node in graph["nodes"]
        if node.get("type") == "AgentTool"
    }
    assert {"workspace", "banking", "slack", "travel"} <= tool_apps
