"""Declarative tool security metadata and source trust policy."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any, Iterable

from ..app_domains import APP_DOMAINS
from .labels import make_confidentiality, minimum_level_for_categories

SUITE_NAMES = set(APP_DOMAINS)
_SPEC_CACHE: dict[str, Any] | None = None


@dataclass(frozen=True)
class ToolEffectPolicy:
    """Declared security semantics for one AgentDojo tool."""

    name: str
    effect: str
    risk_level: str = "L2"
    control_fields: set[str] = field(default_factory=set)
    destination_fields: set[str] = field(default_factory=set)
    content_fields: set[str] = field(default_factory=set)
    parameter_roles: dict[str, str] = field(default_factory=dict)
    semantic_types: dict[str, str] = field(default_factory=dict)
    implicit_egress: tuple[dict[str, Any], ...] = ()
    authoritative_parameters: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )
    confidentiality: str = "internal"
    categories: set[str] = field(default_factory=set)

    @property
    def egress(self) -> bool:
        return self.effect == "egress"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "effect": self.effect,
            "risk_level": self.risk_level,
            "control_fields": sorted(self.control_fields),
            "destination_fields": sorted(self.destination_fields),
            "content_fields": sorted(self.content_fields),
            "parameter_roles": dict(self.parameter_roles),
            "semantic_types": dict(self.semantic_types),
            "implicit_egress": [
                dict(item) for item in self.implicit_egress
            ],
            "authoritative_parameters": {
                key: dict(value)
                for key, value in self.authoritative_parameters.items()
            },
            "confidentiality": self.confidentiality,
            "categories": sorted(self.categories),
            "egress": self.egress,
        }


def _load_specs() -> dict[str, Any]:
    global _SPEC_CACHE
    if _SPEC_CACHE is None:
        _SPEC_CACHE = json.loads(
            files("agentdojo.method.modeling")
            .joinpath("tool_security.json")
            .read_text(encoding="utf-8")
        )
    return _SPEC_CACHE


def reload_tool_security_specs() -> None:
    global _SPEC_CACHE
    _SPEC_CACHE = None


def security_thresholds() -> dict[str, Any]:
    """Return declarative confidence thresholds and system limits."""
    raw = _load_specs().get("thresholds", {})
    return json.loads(json.dumps(raw)) if isinstance(raw, dict) else {}


def source_policy() -> dict[str, Any]:
    raw = _load_specs().get("source_kinds", {})
    return json.loads(json.dumps(raw)) if isinstance(raw, dict) else {}


TRUSTED_SOURCE_KINDS = set(source_policy().get("trusted", []))
EXTERNAL_SOURCE_KINDS = set(source_policy().get("external", []))
SOURCE_LEVELS = dict(source_policy().get("levels", {}))


def split_qualified_tool_name(tool_name: str) -> tuple[str | None, str]:
    """Split ``suite__tool`` aliases while preserving ordinary tool names."""
    name = str(tool_name or "")
    if "__" not in name:
        return None, name
    suite, base = name.split("__", 1)
    if suite in SUITE_NAMES and base:
        return suite, base
    return None, name


def base_tool_name(tool_name: str) -> str:
    return split_qualified_tool_name(tool_name)[1]


def tool_effect(tool_name: str) -> ToolEffectPolicy:
    """Resolve explicitly declared tool metadata; unknown tools fail closed."""
    name = base_tool_name(tool_name)
    specs = _load_specs()
    raw = (specs.get("tools") or {}).get(name)
    if not isinstance(raw, dict):
        return ToolEffectPolicy(name=name, effect="unknown")
    profile_name = str(raw.get("profile", ""))
    profile = (specs.get("profiles") or {}).get(profile_name, {})
    if not isinstance(profile, dict):
        profile = {}

    def merged_list(key: str) -> set[str]:
        base_values = profile.get(key, [])
        tool_values = raw.get(key, [])
        values = [
            *(base_values if isinstance(base_values, list) else []),
            *(tool_values if isinstance(tool_values, list) else []),
        ]
        return {str(value) for value in values if value}

    effect = str(profile.get("effect") or raw.get("effect") or "unknown")
    risk_level = str(
        raw.get("risk_level")
        or profile.get("risk_level")
        or "L2"
    ).upper()
    if risk_level not in {"L0", "L1", "L2"}:
        risk_level = "L2"
    confidentiality = str(
        raw.get("confidentiality")
        or profile.get("confidentiality")
        or "internal"
    )
    return ToolEffectPolicy(
        name=name,
        effect=effect,
        risk_level=risk_level,
        control_fields=merged_list("control_fields"),
        destination_fields=merged_list("destination_fields"),
        content_fields=merged_list("content_fields"),
        parameter_roles={
            str(parameter): str(role)
            for parameter, role in (
                raw.get("parameter_roles", {}) or {}
            ).items()
            if str(role).strip()
        },
        semantic_types={
            str(parameter): str(value_type)
            for parameter, value_type in (
                raw.get("semantic_types", {}) or {}
            ).items()
            if str(value_type).strip()
        },
        implicit_egress=tuple(
            dict(item)
            for item in (raw.get("implicit_egress", []) or [])
            if isinstance(item, dict)
        ),
        authoritative_parameters={
            str(parameter): dict(spec)
            for parameter, spec in (
                raw.get("authoritative_parameters", {}) or {}
            ).items()
            if isinstance(spec, dict)
        },
        confidentiality=confidentiality,
        categories=merged_list("categories"),
    )


def is_read_tool(tool_name: str) -> bool:
    return tool_effect(tool_name).effect == "read"


def is_egress_tool(tool_name: str) -> bool:
    return tool_effect(tool_name).egress


def source_confidentiality(
    source_kind: str,
    content: Any = "",
    *,
    source_id: str = "",
    declared_level: str | None = None,
    categories: Iterable[str] = (),
) -> dict[str, Any]:
    """Build a confidentiality label from declared source metadata."""
    level = declared_level or SOURCE_LEVELS.get(source_kind, "secret")
    return make_confidentiality(
        level=level,
        categories=categories,
        source_ids=[source_id] if source_id else (),
    )


def category_required_level(categories: Iterable[str]) -> str:
    return minimum_level_for_categories(categories)


def sensitive_categories_in(value: Any) -> set[str]:
    """Content-based sensitive categories are intentionally unsupported."""
    return set()
