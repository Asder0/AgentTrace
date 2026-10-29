"""Information-flow labels for provenance entities and activities.

Confidentiality and integrity are propagated deterministically from declared
source metadata. Security code never infers sensitive categories from content
keywords.
"""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, Iterable, Mapping, Optional

CONFIDENTIALITY_LEVELS = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "secret": 3,
}

INTEGRITY_KINDS = {"trusted", "untrusted", "tainted"}

_POLICY_TEXT = files("agentdojo.method.modeling").joinpath(
    "tool_security.json"
).read_text(encoding="utf-8")
_POLICY = json.loads(_POLICY_TEXT)
CATEGORY_MIN_LEVEL = dict(_POLICY.get("category_min_level", {}))
_THRESHOLDS = _POLICY.get("thresholds", {})
UNKNOWN_CATEGORY_LEVEL = str(
    _THRESHOLDS.get("unknown_category_level", "secret")
).lower()
UNKNOWN_SOURCE_INTEGRITY = str(
    _THRESHOLDS.get("unknown_source_integrity", "untrusted")
).lower()
_SOURCE_POLICY = _POLICY.get("source_kinds", {})
_TRUSTED_SOURCE_KINDS = {
    str(item) for item in _SOURCE_POLICY.get("trusted", []) if item
}
_EXTERNAL_SOURCE_KINDS = {
    str(item) for item in _SOURCE_POLICY.get("external", []) if item
}
_SOURCE_LEVELS = {
    str(source): str(level).lower()
    for source, level in (_SOURCE_POLICY.get("levels", {}) or {}).items()
    if str(level).lower() in CONFIDENTIALITY_LEVELS
}


def _normalise_level(level: str | None) -> str:
    value = str(level or "public").lower()
    if value in CONFIDENTIALITY_LEVELS:
        return value
    return "secret"


def detect_categories(content: Any, key: str = "") -> set[str]:
    """Compatibility hook for explicitly declared categories.

    Content text is never inspected. Categories must come from tool/field
    metadata or a task plan.
    """
    return set()


def minimum_level_for_categories(categories: Iterable[str]) -> str:
    level = "public"
    for category in categories:
        candidate = CATEGORY_MIN_LEVEL.get(
            str(category),
            UNKNOWN_CATEGORY_LEVEL,
        )
        if candidate not in CONFIDENTIALITY_LEVELS:
            candidate = UNKNOWN_CATEGORY_LEVEL
        if CONFIDENTIALITY_LEVELS[candidate] > CONFIDENTIALITY_LEVELS[level]:
            level = candidate
    return level


def make_confidentiality(
    *,
    level: str = "internal",
    categories: Iterable[str] = (),
    source_ids: Iterable[str] = (),
    source_entities: Iterable[str] = (),
) -> dict[str, Any]:
    cats = {str(item) for item in categories if item}
    resolved = _normalise_level(level)
    required = minimum_level_for_categories(cats)
    if CONFIDENTIALITY_LEVELS[required] > CONFIDENTIALITY_LEVELS[resolved]:
        resolved = required
    return {
        "level": resolved,
        "categories": sorted(cats),
        "source_ids": _unique(source_ids),
        "source_entities": _unique(source_entities),
    }


def make_integrity(
    *,
    kind: str = "trusted",
    taint_roots: Iterable[str] = (),
) -> dict[str, Any]:
    resolved = str(kind or "trusted").lower()
    if resolved not in INTEGRITY_KINDS:
        resolved = "untrusted"
    roots = _unique(taint_roots)
    if resolved == "trusted" and roots:
        resolved = "untrusted"
    if resolved != "trusted" and not roots:
        roots = ["unknown_untrusted_source"]
    return {"kind": resolved, "taint_roots": roots}


def make_injection(
    *,
    source_flagged: bool = False,
    max_score: float = 0.0,
    detector: str = "",
    field_statuses: Optional[Mapping[str, str]] = None,
    evidence_refs: Iterable[str] = (),
    available: bool = True,
    flagged_fields: Iterable[str] = (),
    quarantined_fields: Iterable[str] = (),
    unscanned_fields: Iterable[str] = (),
    risky_entities: Iterable[str] = (),
    incomplete: bool = False,
) -> dict[str, Any]:
    return {
        "source_flagged": bool(source_flagged),
        "max_score": max(0.0, min(1.0, float(max_score or 0.0))),
        "detector": str(detector or ""),
        "field_statuses": dict(field_statuses or {}),
        "evidence_refs": _unique(evidence_refs),
        "available": bool(available),
        "flagged_fields": _unique(flagged_fields),
        "quarantined_fields": _unique(quarantined_fields),
        "unscanned_fields": _unique(unscanned_fields),
        "risky_entities": _unique(risky_entities),
        "incomplete": bool(incomplete),
    }


def make_flow_label(
    *,
    confidentiality: Optional[Mapping[str, Any]] = None,
    integrity: Optional[Mapping[str, Any]] = None,
    injection: Optional[Mapping[str, Any]] = None,
    data_influence: bool = True,
    control_influence: bool = False,
) -> dict[str, Any]:
    return {
        "confidentiality": dict(
            confidentiality
            or make_confidentiality(
                level="public",
                categories=(),
                source_ids=(),
            )
        ),
        "integrity": dict(
            integrity or make_integrity(kind="trusted", taint_roots=())
        ),
        "injection": dict(injection or make_injection()),
        "influence": {
            "data": bool(data_influence),
            "control": bool(control_influence),
        },
    }


def join_confidentiality(
    labels: Iterable[Mapping[str, Any] | None],
) -> dict[str, Any]:
    level = "public"
    categories: set[str] = set()
    source_ids: list[str] = []
    source_entities: list[str] = []
    for label in labels:
        if not label:
            continue
        conf = label.get("confidentiality", label)
        if not isinstance(conf, Mapping):
            continue
        candidate = _normalise_level(str(conf.get("level", "public")))
        if CONFIDENTIALITY_LEVELS[candidate] > CONFIDENTIALITY_LEVELS[level]:
            level = candidate
        categories.update(
            str(item) for item in conf.get("categories", []) if item
        )
        source_ids.extend(
            str(item) for item in conf.get("source_ids", []) if item
        )
        source_entities.extend(
            str(item) for item in conf.get("source_entities", []) if item
        )
    required = minimum_level_for_categories(categories)
    if CONFIDENTIALITY_LEVELS[required] > CONFIDENTIALITY_LEVELS[level]:
        level = required
    return {
        "level": level,
        "categories": sorted(categories),
        "source_ids": _unique(source_ids),
        "source_entities": _unique(source_entities),
    }


def join_integrity(
    labels: Iterable[Mapping[str, Any] | None],
    *,
    generated: bool = False,
    taint_roots: Iterable[str] = (),
) -> dict[str, Any]:
    """Join source-integrity labels.

    ``tainted`` is no longer assigned merely because a response was generated
    from external data. External provenance remains ``untrusted``; injection
    suspicion is tracked separately by the ``injection`` label plane.
    """
    roots: list[str] = list(taint_roots)
    saw_untrusted = False
    for label in labels:
        if not label:
            continue
        integ = label.get("integrity", label)
        if not isinstance(integ, Mapping):
            continue
        kind = str(integ.get("kind", "trusted")).lower()
        saw_untrusted = saw_untrusted or (
            kind not in INTEGRITY_KINDS
            or kind in {"untrusted", "tainted"}
            or bool(integ.get("taint_roots"))
        )
        roots.extend(
            str(item) for item in integ.get("taint_roots", []) if item
        )
    if saw_untrusted:
        return make_integrity(
            kind="untrusted",
            taint_roots=roots,
        )
    return make_integrity(kind="trusted", taint_roots=())


def join_injection(
    labels: Iterable[Mapping[str, Any] | None],
) -> dict[str, Any]:
    source_flagged = False
    max_score = 0.0
    detectors: list[str] = []
    field_statuses: dict[str, str] = {}
    evidence_refs: list[str] = []
    flagged_fields: list[str] = []
    quarantined_fields: list[str] = []
    unscanned_fields: list[str] = []
    risky_entities: list[str] = []
    available = True
    incomplete = False
    for label in labels:
        if not label:
            continue
        injection = label.get("injection")
        if not isinstance(injection, Mapping):
            continue
        source_flagged = source_flagged or bool(
            injection.get("source_flagged", False)
        )
        max_score = max(max_score, float(injection.get("max_score", 0.0) or 0.0))
        if injection.get("detector"):
            detectors.append(str(injection["detector"]))
        statuses = injection.get("field_statuses")
        if isinstance(statuses, Mapping):
            field_statuses.update(
                {str(key): str(value) for key, value in statuses.items()}
            )
        evidence_refs.extend(
            str(item) for item in injection.get("evidence_refs", []) if item
        )
        flagged_fields.extend(
            str(item) for item in injection.get("flagged_fields", []) if item
        )
        quarantined_fields.extend(
            str(item) for item in injection.get("quarantined_fields", []) if item
        )
        unscanned_fields.extend(
            str(item) for item in injection.get("unscanned_fields", []) if item
        )
        risky_entities.extend(
            str(item) for item in injection.get("risky_entities", []) if item
        )
        available = available and bool(injection.get("available", True))
        incomplete = incomplete or bool(injection.get("incomplete", False))
    return make_injection(
        source_flagged=source_flagged,
        max_score=max_score,
        detector=detectors[-1] if detectors else "",
        field_statuses=field_statuses,
        evidence_refs=evidence_refs,
        available=available,
        flagged_fields=flagged_fields,
        quarantined_fields=quarantined_fields,
        unscanned_fields=unscanned_fields,
        risky_entities=risky_entities,
        incomplete=incomplete,
    )


def aggregate_flow_labels(
    labels: Iterable[Mapping[str, Any] | None],
    *,
    generated: bool = False,
    control_influence: bool = False,
) -> dict[str, Any]:
    materialised = [label for label in labels if isinstance(label, Mapping)]
    data_influence = any(
        bool((label.get("influence") or {}).get("data", True))
        for label in materialised
    )
    control = control_influence or any(
        bool((label.get("influence") or {}).get("control", False))
        for label in materialised
    )
    return make_flow_label(
        confidentiality=join_confidentiality(materialised),
        integrity=join_integrity(materialised, generated=generated),
        injection=join_injection(materialised),
        data_influence=data_influence,
        control_influence=control,
    )


def derive_flow_label(
    parents: Iterable[Mapping[str, Any] | None],
    *,
    source_kind: str,
    content: Any,
    source_id: str,
    control_influence: bool = False,
) -> dict[str, Any]:
    parent_labels = [label for label in parents if isinstance(label, Mapping)]
    generated = source_kind in {"agent", "activity", "sanitized"}
    source_untrusted = not generated and (
        source_kind in _EXTERNAL_SOURCE_KINDS
        or source_kind not in _TRUSTED_SOURCE_KINDS
    )
    conf = join_confidentiality(parent_labels)
    source_level = _SOURCE_LEVELS.get(str(source_kind), "secret")
    level = max(
        (
            str(conf.get("level", "public")),
            source_level,
        ),
        key=lambda item: CONFIDENTIALITY_LEVELS.get(
            item,
            CONFIDENTIALITY_LEVELS["secret"],
        ),
    )
    conf = make_confidentiality(
        level=level,
        categories=conf.get("categories", []),
        source_ids=[*conf.get("source_ids", []), source_id],
        source_entities=conf.get("source_entities", []),
    )
    if generated:
        integ = join_integrity(parent_labels, generated=True)
        if source_untrusted:
            integ = make_integrity(kind="tainted", taint_roots=[source_id])
    elif source_untrusted:
        integ = make_integrity(
            kind=UNKNOWN_SOURCE_INTEGRITY,
            taint_roots=[source_id],
        )
    else:
        integ = make_integrity(kind="trusted", taint_roots=())
    return make_flow_label(
        confidentiality=conf,
        integrity=integ,
        injection=join_injection(parent_labels),
        data_influence=True,
        control_influence=control_influence,
    )


def is_tainted(label: Mapping[str, Any] | None) -> bool:
    if not isinstance(label, Mapping):
        return False
    kind = str((label.get("integrity") or {}).get("kind", "trusted")).lower()
    return kind not in INTEGRITY_KINDS or kind in {"untrusted", "tainted"}


def is_confidential(label: Mapping[str, Any] | None) -> bool:
    if not isinstance(label, Mapping):
        return False
    level = str(
        (label.get("confidentiality") or {}).get("level", "public")
    ).lower()
    return (
        CONFIDENTIALITY_LEVELS.get(level, 0)
        >= CONFIDENTIALITY_LEVELS["confidential"]
    )


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result
