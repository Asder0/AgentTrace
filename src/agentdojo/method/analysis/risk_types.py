"""Shared risk assessment types for all four rings."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..modeling.policy import security_thresholds


DECISION_PASS = "PASS"
DECISION_ADVISORY = "ADVISORY"
DECISION_MITIGATE = "MITIGATE"
DECISION_QUARANTINE = "QUARANTINE"
DECISION_HOLD = "HOLD"
DECISION_BLOCK = "BLOCK"

DECISION_TO_STATE = {
    DECISION_PASS: "ADMITTED",
    DECISION_ADVISORY: "ADMITTED",
    DECISION_MITIGATE: "SANITIZED",
    DECISION_QUARANTINE: "QUARANTINED",
    DECISION_HOLD: "HELD",
    DECISION_BLOCK: "BLOCKED",
}

MAX_RISK_EVIDENCE = int(
    security_thresholds().get("max_risk_evidence", 50)
)
_TASK_RISK_IDENTITIES: dict[tuple[str, int, str, str], dict[str, Any]] = {}


def _limited_unique(values: Iterable[Any], limit: int = MAX_RISK_EVIDENCE) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if value))[:limit]


def stabilize_risk_identity(
    risk: dict[str, Any],
    *,
    task_id: str | None,
    discriminator: str,
) -> dict[str, Any]:
    """Reuse a risk ID for repeated observations of the same task condition."""
    if not task_id:
        risk.setdefault("occurrence_count", 1)
        return risk
    digest = hashlib.sha256(str(discriminator).encode("utf-8")).hexdigest()
    key = (
        str(task_id),
        int(risk.get("ring", 0)),
        str(risk.get("policy_id", "")),
        digest,
    )
    existing = _TASK_RISK_IDENTITIES.get(key)
    if existing is None:
        existing = {
            "risk_id": risk["risk_id"],
            "occurrence_count": 0,
        }
        _TASK_RISK_IDENTITIES[key] = existing
    existing["occurrence_count"] += 1
    risk["risk_id"] = existing["risk_id"]
    risk["occurrence_count"] = existing["occurrence_count"]
    risk["observation_key"] = digest
    return risk


def clear_risk_identity_cache() -> None:
    _TASK_RISK_IDENTITIES.clear()


@dataclass
class RiskAssessment:
    ring: int
    decision: str
    reason: str
    event_kind: str = "security"
    severity: str = "medium"
    policy_id: str = ""
    confidence: float | None = None
    activity_id: str | None = None
    evidence_entity_ids: list[str] = field(default_factory=list)
    evidence_edge_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    sink_ids: list[str] = field(default_factory=list)
    taint_roots: list[str] = field(default_factory=list)
    fsm_before: str | None = None
    fsm_after: str | None = None
    risk_id: str = field(default_factory=lambda: f"Risk_{uuid.uuid4().hex[:10]}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_id": self.risk_id,
            "ring": int(self.ring),
            "decision": self.decision,
            "reason": self.reason,
            "event_kind": self.event_kind,
            "severity": self.severity,
            "policy_id": self.policy_id,
            "confidence": self.confidence,
            "activity_id": self.activity_id,
            "evidence_entity_ids": list(self.evidence_entity_ids),
            "evidence_edge_ids": list(self.evidence_edge_ids),
            "source_ids": list(self.source_ids),
            "sink_ids": list(self.sink_ids),
            "taint_roots": list(self.taint_roots),
            "fsm_before": self.fsm_before,
            "fsm_after": self.fsm_after
            or DECISION_TO_STATE.get(self.decision, "ADMITTED"),
        }


def make_risk(
    ring: int,
    decision: str,
    reason: str,
    *,
    event_kind: str | None = None,
    severity: str = "medium",
    policy_id: str = "",
    activity_id: str | None = None,
    evidence_entity_ids: Iterable[str] = (),
    evidence_edge_ids: Iterable[str] = (),
    source_ids: Iterable[str] = (),
    sink_ids: Iterable[str] = (),
    taint_roots: Iterable[str] = (),
    fsm_before: str | None = None,
    fsm_after: str | None = None,
    confidence: float | None = None,
) -> dict[str, Any]:
    evidence_list = list(evidence_entity_ids)
    source_list = list(source_ids)
    sink_list = list(sink_ids)
    taint_list = list(taint_roots)
    risk = RiskAssessment(
        ring=ring,
        decision=decision,
        reason=reason,
        event_kind=(
            event_kind
            or ("policy" if decision == DECISION_MITIGATE else "security")
        ),
        severity=severity,
        policy_id=policy_id,
        confidence=confidence,
        activity_id=activity_id,
        evidence_entity_ids=_limited_unique(evidence_list),
        evidence_edge_ids=_limited_unique(evidence_edge_ids),
        source_ids=_limited_unique(source_list),
        sink_ids=_limited_unique(sink_list),
        taint_roots=_limited_unique(taint_list),
        fsm_before=fsm_before,
        fsm_after=fsm_after,
    ).to_dict()
    risk["evidence_total"] = {
        "entities": len(evidence_list),
        "sources": len(source_list),
        "taint_roots": len(taint_list),
    }
    risk["evidence_truncated"] = any(
        total > MAX_RISK_EVIDENCE
        for total in (
            len(evidence_list),
            len(source_list),
            len(taint_list),
        )
    )
    return risk


def add_risk_to_event(event: dict[str, Any], risk: dict[str, Any] | None) -> None:
    if not risk:
        return
    risks = event.setdefault("risk_assessments", [])
    if all(item.get("risk_id") != risk.get("risk_id") for item in risks):
        risks.append(risk)


def worst_decision(risks: Iterable[dict[str, Any]]) -> str:
    order = {
        DECISION_PASS: 0,
        DECISION_ADVISORY: 1,
        DECISION_MITIGATE: 2,
        DECISION_HOLD: 3,
        DECISION_QUARANTINE: 4,
        DECISION_BLOCK: 5,
    }
    return max(
        (str(risk.get("decision", DECISION_PASS)) for risk in risks),
        key=lambda decision: order.get(decision, 0),
        default=DECISION_PASS,
    )
