"""Human-defined sensitivity labels for original APP data entities.

This module deliberately does not infer sensitivity from values or parse free
text into synthetic fields. Labels belong to the original workspace, banking,
Slack and travel data entities.
"""

from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from importlib.resources import files
from typing import Any, Iterable, Mapping

from pydantic import BaseModel

from .labels import (
    CATEGORY_MIN_LEVEL,
    CONFIDENTIALITY_LEVELS,
    aggregate_flow_labels,
    make_confidentiality,
    make_flow_label,
    make_injection,
    make_integrity,
)
from .policy import base_tool_name


def _load_policy() -> dict[str, Any]:
    text = files("agentdojo.method.modeling").joinpath(
        "data_sensitivity.json"
    ).read_text(encoding="utf-8")
    value = json.loads(text)
    return value if isinstance(value, dict) else {}


_POLICY = _load_policy()
DEFAULT_LEVEL = str(_POLICY.get("default_level", "secret")).lower()
APP_LEVELS: dict[str, dict[str, str]] = {
    str(app): {
        str(entity): str(level).lower()
        for entity, level in entities.items()
    }
    for app, entities in (_POLICY.get("apps") or {}).items()
    if isinstance(entities, Mapping)
}
TOOL_OUTPUT_ENTITIES: dict[str, str] = {
    str(tool): str(entity)
    for tool, entity in (_POLICY.get("tool_output_entities") or {}).items()
    if tool and entity
}
def _snake_case(name: str) -> str:
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", str(name or "")).lower()
    return re.sub(r"[^a-z0-9_]+", "_", value).strip("_")


ENVIRONMENT_ONLY_ENTITIES: dict[str, set[str]] = {
    str(app): {
        _snake_case(str(entity))
        for entity in entities
    }
    for app, entities in (
        _POLICY.get("environment_only_entities") or {}
    ).items()
    if isinstance(entities, list)
}
ENTITY_ALIASES: dict[str, dict[str, str]] = {
    str(app): {
        _snake_case(str(alias)): _snake_case(str(entity))
        for alias, entity in aliases.items()
    }
    for app, aliases in (_POLICY.get("entity_aliases") or {}).items()
    if isinstance(aliases, Mapping)
}


def configured_apps() -> set[str]:
    return set(APP_LEVELS)


def sensitivity_catalog() -> dict[str, dict[str, str]]:
    """Return the human-maintained APP entity label catalog."""
    return {
        app: {
            entity: level
            for entity, level in entities.items()
            if entity
            not in ENVIRONMENT_ONLY_ENTITIES.get(app, set())
        }
        for app, entities in APP_LEVELS.items()
    }


def normalized_entity_name(value: Any) -> str:
    if isinstance(value, type):
        return _snake_case(value.__name__)
    if value is not None:
        return _snake_case(value.__class__.__name__)
    return ""


def canonical_entity_name(app: str, entity: str) -> str:
    """Resolve an environment container name to its canonical entity."""
    suite = str(app or "").lower()
    name = _snake_case(entity)
    return ENTITY_ALIASES.get(suite, {}).get(name, name)


def entity_level(app: str, entity: str) -> str:
    suite = str(app or "").lower()
    name = canonical_entity_name(suite, entity)
    candidate = APP_LEVELS.get(suite, {}).get(name, DEFAULT_LEVEL)
    return (
        candidate
        if candidate in CONFIDENTIALITY_LEVELS
        else DEFAULT_LEVEL
    )


def has_entity(app: str, entity: str) -> bool:
    suite = str(app or "").lower()
    name = _snake_case(entity)
    canonical = canonical_entity_name(suite, name)
    entities = APP_LEVELS.get(suite, {})
    return name in entities or canonical in entities


def entity_source(app: str, entity: str) -> str:
    suite = str(app or "unknown").lower()
    return f"{suite}:{canonical_entity_name(suite, entity)}"


def parse_entity_source(value: str) -> tuple[str, str] | None:
    text = str(value or "").strip().lower()
    if text in {"user_prompt", "system_prompt"}:
        return "system", text
    if ":" not in text:
        return None
    app, entity = text.split(":", 1)
    if not app or not entity:
        return None
    return app, entity


def source_level(value: str) -> str:
    parsed = parse_entity_source(value)
    if parsed is None:
        return DEFAULT_LEVEL
    app, entity = parsed
    if entity in {"user_prompt", "system_prompt"}:
        return "internal"
    return entity_level(app, entity)


def max_source_level(sources: Iterable[str]) -> str:
    level = "public"
    for source in sources:
        candidate = source_level(source)
        if CONFIDENTIALITY_LEVELS.get(candidate, 3) > CONFIDENTIALITY_LEVELS[level]:
            level = candidate
    return level


def tool_output_entity(tool_name: str) -> str:
    return TOOL_OUTPUT_ENTITIES.get(base_tool_name(tool_name), "")


@dataclass(frozen=True)
class ValueOrigin:
    app: str
    entity: str
    level: str
    source_tool: str
    source_activity_id: str
    entity_id: str
    source_path: str
    value_key: str
    value: Any
    label: dict[str, Any] = field(default_factory=dict)
    container_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        injection = self.label.get("injection", {})
        return {
            "source_app": self.app,
            "source_entity": self.entity,
            "source": entity_source(self.app, self.entity),
            "confidentiality": self.level,
            "source_tool": self.source_tool,
            "source_activity_id": self.source_activity_id,
            "source_entity_id": self.entity_id,
            "source_path": self.source_path,
            "source_key": self.container_key,
            "source_risk": bool(
                isinstance(injection, Mapping)
                and (
                    injection.get("source_flagged")
                    or injection.get("risky_entities")
                )
            ),
            "risky_entities": list(
                injection.get("risky_entities", [])
                if isinstance(injection, Mapping)
                else []
            ),
        }


def value_key(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        try:
            normalized = Decimal(str(value)).normalize()
            return format(normalized, "f")
        except (InvalidOperation, ValueError):
            return str(value)
    return str(value).strip()


def _walk_values(
    value: Any,
    *,
    app: str,
    source_tool: str,
    activity_id: str,
    path: str,
    inherited_entity: str,
    inherited_entity_id: str,
    fallback_level: str,
    fallback_categories: Iterable[str],
    risky_entities: set[str],
    inherited_label: Mapping[str, Any] | None = None,
    container_key: str = "",
) -> list[ValueOrigin]:
    records: list[ValueOrigin] = []
    if isinstance(value, BaseModel):
        dumped = value.model_dump(mode="json")
        entity = canonical_entity_name(
            app,
            normalized_entity_name(value) or inherited_entity,
        )
        entity_id = inherited_entity_id or next(
            (
                str(dumped.get(key))
                for key in ("id_", "id", "entity_id", "email_id", "file_id")
                if dumped.get(key) not in (None, "")
            ),
            "",
        )
        if not entity_id:
            entity_id = hashlib.sha256(
                json.dumps(
                    dumped,
                    sort_keys=True,
                    ensure_ascii=False,
                    default=str,
                ).encode("utf-8")
            ).hexdigest()[:12]
        for key, child in dumped.items():
            records.extend(
                _walk_values(
                    child,
                    app=app,
                    source_tool=source_tool,
                    activity_id=activity_id,
                    path=f"{path}.{key}",
                    inherited_entity=entity or inherited_entity,
                    inherited_entity_id=entity_id,
                    fallback_level=fallback_level,
                    fallback_categories=fallback_categories,
                    risky_entities=risky_entities,
                    inherited_label=inherited_label,
                    container_key=str(key),
                )
            )
        return records
    if isinstance(value, Mapping):
        nested_entity_id = inherited_entity_id or next(
            (
                str(value.get(key))
                for key in ("id_", "id", "entity_id", "email_id", "file_id")
                if value.get(key) not in (None, "")
            ),
            "",
        )
        for key, child in value.items():
            records.extend(
                _walk_values(
                    child,
                    app=app,
                    source_tool=source_tool,
                    activity_id=activity_id,
                    path=f"{path}.{key}",
                    inherited_entity=inherited_entity,
                    inherited_entity_id=nested_entity_id,
                    fallback_level=fallback_level,
                    fallback_categories=fallback_categories,
                    risky_entities=risky_entities,
                    inherited_label=inherited_label,
                    container_key=str(key),
                )
            )
        return records
    if isinstance(value, (list, tuple, set)):
        for index, child in enumerate(value):
            records.extend(
                _walk_values(
                    child,
                    app=app,
                    source_tool=source_tool,
                    activity_id=activity_id,
                    path=f"{path}[{index}]",
                    inherited_entity=inherited_entity,
                    inherited_entity_id=inherited_entity_id,
                    fallback_level=fallback_level,
                    fallback_categories=fallback_categories,
                    risky_entities=risky_entities,
                    inherited_label=inherited_label,
                    container_key=container_key,
                )
            )
        return records
    key = value_key(value)
    if not key:
        return records
    entity = canonical_entity_name(
        app,
        inherited_entity or tool_output_entity(source_tool) or "unknown",
    )
    entity_id = inherited_entity_id or hashlib.sha256(
        f"{source_tool}\0{path}\0{key}".encode("utf-8")
    ).hexdigest()[:12]
    level = (
        entity_level(app, entity)
        if entity != "unknown"
        else fallback_level
    )
    source_entity = entity_source(app, entity) if entity != "unknown" else ""
    direct_risk = next(
        (
            risk_entity
            for risk_entity in risky_entities
            if path == risk_entity or path.startswith(f"{risk_entity}.")
            or path.startswith(f"{risk_entity}[")
        ),
        "",
    )
    origin_label = make_flow_label(
        confidentiality=make_confidentiality(
            level=level,
            categories=(
                [
                    *(
                        [entity]
                        if entity != "unknown"
                        and entity in CATEGORY_MIN_LEVEL
                        else []
                    ),
                    *fallback_categories,
                ]
            ),
            source_ids=[f"{activity_id}:{path}"],
            source_entities=[source_entity] if source_entity else [],
        ),
        integrity=make_integrity(
            kind="untrusted",
            taint_roots=[source_entity or f"{activity_id}:{path}"],
        ),
        injection=make_injection(
            source_flagged=bool(direct_risk),
            risky_entities=[direct_risk] if direct_risk else [],
            flagged_fields=[path] if direct_risk else [],
        ),
        data_influence=True,
        control_influence=True,
    )
    if inherited_label:
        origin_label = aggregate_flow_labels(
            [origin_label, inherited_label],
            generated=True,
            control_influence=True,
        )
    records.append(
        ValueOrigin(
            app=app,
            entity=entity,
            level=str(
                origin_label.get("confidentiality", {}).get("level", level)
            ),
            source_tool=source_tool,
            source_activity_id=activity_id,
            entity_id=entity_id,
            source_path=path,
            value_key=key,
            value=value,
            label=origin_label,
            container_key=container_key,
        )
    )
    return records


def collect_value_origins(
    result: Any,
    *,
    app: str,
    source_tool: str,
    activity_id: str,
    fallback_level: str = "secret",
    risky_entities: Iterable[str] = (),
    inherited_label: Mapping[str, Any] | None = None,
    fallback_categories: Iterable[str] = (),
) -> list[ValueOrigin]:
    """Index scalar leaves under their original APP entity label."""
    return _walk_values(
        result,
        app=app,
        source_tool=source_tool,
        activity_id=activity_id,
        path="$",
        inherited_entity=tool_output_entity(source_tool),
        inherited_entity_id="",
        fallback_level=fallback_level,
        fallback_categories=tuple(fallback_categories),
        risky_entities=set(risky_entities),
        inherited_label=inherited_label,
    )


def index_value_origins(
    origins: Iterable[ValueOrigin],
) -> dict[str, list[ValueOrigin]]:
    index: dict[str, list[ValueOrigin]] = {}
    for origin in origins:
        index.setdefault(origin.value_key, []).append(origin)
    return index


def origins_for_value(
    index: Mapping[str, list[ValueOrigin]],
    value: Any,
) -> list[ValueOrigin]:
    return list(index.get(value_key(value), []))


def origins_for_entity_refs(
    origins: Iterable[ValueOrigin],
    source_refs: Iterable[Mapping[str, Any]],
) -> tuple[list[ValueOrigin], list[dict[str, Any]]]:
    """Resolve model-reported source refs against sanitized entity records."""
    materialised = list(origins)
    matched: list[ValueOrigin] = []
    invalid: list[dict[str, Any]] = []
    for raw_ref in source_refs:
        if not isinstance(raw_ref, Mapping):
            invalid.append({"source_ref": "", "reason": "invalid_reference"})
            continue
        app = str(raw_ref.get("app", "")).lower()
        entity = canonical_entity_name(
            app,
            str(raw_ref.get("entity", "")),
        )
        entity_id = str(raw_ref.get("entity_id", ""))
        source_action = str(
            raw_ref.get("source_action", raw_ref.get("source_tool", ""))
        )
        candidates = [
            origin
            for origin in materialised
            if origin.app.lower() == app
            and _snake_case(origin.entity) == entity
            and origin.entity_id == entity_id
            and (
                not source_action
                or origin.source_tool == source_action
                or base_tool_name(origin.source_tool)
                == base_tool_name(source_action)
            )
        ]
        if not candidates:
            invalid.append(
                {
                    "source_ref": f"{app}:{entity}:{entity_id}",
                    "reason": "source_entity_not_found",
                }
            )
            continue
        matched.extend(candidates)
    return matched, invalid


def label_for_origins(
    origins: Iterable[ValueOrigin],
    *,
    fallback: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    materialised = list(origins)
    if not materialised:
        return dict(fallback or make_confidentiality())
    level = max(
        (origin.level for origin in materialised),
        key=lambda item: CONFIDENTIALITY_LEVELS.get(item, 3),
        default=DEFAULT_LEVEL,
    )
    categories = {
        category
        for origin in materialised
        for category in (
            origin.label.get("confidentiality", {}) or {}
        ).get("categories", [])
        if category
    }
    source_ids = {
        source_id
        for origin in materialised
        for source_id in (
            origin.label.get("confidentiality", {}) or {}
        ).get("source_ids", [])
        if source_id
    }
    source_entities = {
        entity_source(origin.app, origin.entity)
        for origin in materialised
        if origin.entity and origin.entity != "unknown"
    }
    return make_confidentiality(
        level=level,
        categories=categories,
        source_ids=source_ids,
        source_entities=source_entities,
    )


def flow_label_for_origins(
    origins: Iterable[ValueOrigin],
    *,
    fallback: Mapping[str, Any] | None = None,
    control_influence: bool = True,
) -> dict[str, Any]:
    materialised = list(origins)
    if not materialised:
        return dict(fallback or make_flow_label())
    return aggregate_flow_labels(
        [origin.label for origin in materialised],
        generated=True,
        control_influence=control_influence,
    )
