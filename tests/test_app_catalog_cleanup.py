"""Regression tests for centralized APP metadata and capture filtering."""

from agentdojo.method.capture.environment_snapshot import EnvironmentSnapshotParser
from agentdojo.method.capture.environment_snapshot import snapshot_environment
from agentdojo.method.capture.interceptor import _infer_app_from_function
from agentdojo.method.app_domains import domain_for_tool
from agentdojo.method.capture.interceptor import _build_tool_catalog
from agentdojo.method.modeling.data_sensitivity import has_entity
from agentdojo.method.modeling.data_sensitivity import (
    ENTITY_ALIASES,
    ENVIRONMENT_ONLY_ENTITIES,
    canonical_entity_name,
    sensitivity_catalog,
    tool_output_entity,
)
from agentdojo.method.modeling.policy import tool_effect
from agentdojo.method.visualization.mock_apps import get_runtime_and_env


def test_tool_app_resolution_uses_central_catalog():
    assert domain_for_tool("send_direct_message") == "slack"
    assert domain_for_tool("send_email", "travel") == "travel"
    assert _infer_app_from_function("send_direct_message") == "slack"
    assert _infer_app_from_function("unregistered_tool") == "unknown"


def test_environment_capture_preserves_provenance_fields():
    parser = EnvironmentSnapshotParser(source_app="workspace")
    entities = parser._extract_domain_entities(
        {
            "inbox": [
                {
                    "id": "mail-1",
                    "paid": True,
                    "timestamp": "2026-10-23",
                    "selected": True,
                }
            ]
        }
    )

    assert len(entities) == 1
    assert entities[0].entity_type == "inbox"
    assert entities[0].attributes == {
        "id": "mail-1",
        "paid": True,
        "timestamp": "2026-10-23",
    }


def test_human_declared_tool_risk_levels():
    assert tool_effect("get_balance").risk_level == "L0"
    assert tool_effect("create_calendar_event").risk_level == "L2"
    assert tool_effect("create_calendar_event").effect == "egress"
    assert tool_effect("delete_email").risk_level == "L2"
    assert tool_effect("send_money").risk_level == "L2"


def test_tool_security_fields_match_runtime_input_schema():
    runtime, _environment = get_runtime_and_env("unified")
    catalog = {
        item["name"]: item for item in _build_tool_catalog(runtime)
    }
    mismatches = []
    for name, metadata in catalog.items():
        policy = tool_effect(name)
        fields = set(metadata["input_schema"].get("fields", {}))
        declared = (
            set(policy.parameter_roles)
            | policy.control_fields
            | policy.destination_fields
            | policy.content_fields
            | set(policy.authoritative_parameters)
        )
        missing = sorted(declared - fields)
        if missing:
            mismatches.append((name, missing))

    assert mismatches == []
    assert catalog["get_all_hotels_in_city"]["output_entity"] == "hotel"
    assert catalog["reserve_hotel"]["output_entity"] == "reservation"
    assert catalog["workspace__send_email"]["output_entity"] == "email"


def test_every_snapshot_entity_type_has_a_sensitivity_level():
    runtime, environment = get_runtime_and_env("unified")
    del runtime
    missing = []
    for app_name in ("workspace", "banking", "slack", "travel"):
        snapshot = snapshot_environment(getattr(environment, app_name))
        parser = EnvironmentSnapshotParser(source_app=app_name)
        for entity in parser._extract_domain_entities(snapshot):
            if not has_entity(app_name, entity.entity_type):
                missing.append((app_name, entity.entity_type))

    assert missing == []


def test_planner_catalog_separates_environment_aliases():
    catalog = sensitivity_catalog()

    assert canonical_entity_name("travel", "hotels") == "hotel"
    assert "hotel" in catalog["travel"]
    assert "hotels" not in catalog["travel"]
    assert all(
        has_entity(app, canonical)
        for app, aliases in ENTITY_ALIASES.items()
        for canonical in aliases.values()
    )
    assert all(
        entity not in catalog[app]
        for app, entities in ENVIRONMENT_ONLY_ENTITIES.items()
        for entity in entities
    )


def test_side_effect_tools_declare_provenance_output_entities():
    assert tool_output_entity("reserve_hotel") == "reservation"
    assert tool_output_entity("reserve_restaurant") == "reservation"
    assert tool_output_entity("reserve_car_rental") == "reservation"
    assert tool_output_entity("send_money") == "transaction"
    assert tool_output_entity("send_email") == "email"
