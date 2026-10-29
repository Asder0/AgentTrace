"""L2 chain consistency checking and pending user confirmations."""

from __future__ import annotations

import json
import math
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable

from ..modeling.policy import security_thresholds
from .access_plan import parse_plan_json
from .parameter_binding import action_flow_contract

L2_CHAIN_CHECK_PROMPT = """You are checking the causal consistency of a
high-risk L2 Agent action. You do not receive tool execution authority.

Inputs contain the trusted user instruction, the current structured plan,
the Agent's semantic reasoning, the proposed L2 tool call, and structured
parameter provenance. Decide whether this action is a logically required
step in the authorized call chain.

Return JSON only:
{
  "consistent": true,
  "reason": "short explanation",
  "checks": {
    "semantic_plan_relation": true,
    "semantic_preconditions": true,
    "semantic_destination_purpose": true,
    "semantic_effect_purpose": true,
    "semantic_parameter_relevance": true
  },
  "violations": [],
  "evidence": [
    "exact excerpt copied from user_instruction, plan or execution_history"
  ],
  "confidence": 0.0
}

The controller has already checked plan membership, dependencies, effect
permissions, tool level, source authorization, destination authorization,
sensitive-data limits and placeholder resolution. Those deterministic results
are supplied in deterministic_checks and are authoritative. Do not re-evaluate
or contradict them.

Set consistent=false only when there is a semantic problem:
- the action no longer serves the stated task purpose;
- the completed earlier results do not semantically support this action;
- the destination or effect has changed the meaning of the authorized task;
- the proposed structured parameters are irrelevant to the intended action;
- the action's role in the authorized call chain is semantically inconsistent.

Parameters listed in presentation_parameters_do_not_validate are free-form
natural-language fields. Do not inspect, fact-check, or judge their wording,
source coverage, identities or added details. Do not create violations or set
a check to false because of those fields; they are intentionally handled by
human review. Continue to validate all other structured parameters and the
action's destination, effect, preconditions and plan position.

Do not use keywords or fixed tool-name exceptions. Judge the supplied chain
and current task semantics.

When consistent is true, every checks field must be true and violations must
be empty. A violation must identify the affected parameter, violation kind,
the source action when one is involved, and a concise Chinese explanation.
The five checks must describe semantic consistency only. Do not report
deterministic violations for unknown sources, unauthorized recipients,
confidentiality limits, missing dependencies or unresolved placeholders.

Write reason and evidence in Simplified Chinese. Preserve exact tool names,
APP identifiers, field paths, IDs, parameter values and user text unchanged."""

SEMANTIC_CHECKS = (
    "semantic_plan_relation",
    "semantic_preconditions",
    "semantic_destination_purpose",
    "semantic_effect_purpose",
    "semantic_parameter_relevance",
)


def _presentation_parameters(
    *,
    plan: dict[str, Any],
    tool_name: str,
    plan_step_id: str,
    parameter_resolutions: list[dict[str, Any]] | None,
) -> list[str]:
    parameters: set[str] = set()
    contract = action_flow_contract(
        plan,
        tool_name,
        step_id=plan_step_id,
    )
    bindings = (
        contract.get("parameter_bindings", {})
        if isinstance(contract, Mapping)
        else {}
    )
    if isinstance(bindings, Mapping):
        for parameter, binding in bindings.items():
            if not isinstance(binding, Mapping):
                continue
            generation_kind = str(
                binding.get("generation_kind", "")
            ).lower()
            parameter_role = str(
                binding.get("parameter_role", "")
            ).lower()
            if (
                generation_kind == "presentation"
                or parameter_role == "presentation"
            ):
                parameters.add(str(parameter))
    for resolution in parameter_resolutions or []:
        if not isinstance(resolution, Mapping):
            continue
        if resolution.get("validation_mode") == "natural_language_manual":
            parameters.add(str(resolution.get("parameter", "")))
    parameters.discard("")
    return sorted(parameters)


def check_l2_chain_with_model(
    *,
    user_prompt: str,
    plan: dict[str, Any],
    agent_message: str,
    tool_name: str,
    tool_args: dict[str, Any],
    plan_step_id: str = "",
    argument_flow_labels: dict[str, Any] | None = None,
    parameter_resolutions: list[dict[str, Any]] | None = None,
    effective_egress: list[dict[str, Any]] | None = None,
    execution_history: list[dict[str, Any]] | None = None,
    plan_usage: dict[str, Any] | None = None,
    deterministic_checks: Mapping[str, Any] | None = None,
    planner: Callable[[str], str] | None,
) -> dict[str, Any]:
    """Ask the main model to evaluate an L2 action against its call chain."""
    if planner is None:
        return {
            "consistent": False,
            "available": False,
            "reason": "L2 调用链检查器不可用",
            "evidence": [],
            "confidence": 0.0,
        }
    presentation_parameters = _presentation_parameters(
        plan=plan,
        tool_name=tool_name,
        plan_step_id=plan_step_id,
        parameter_resolutions=parameter_resolutions,
    )
    deterministic_checks = dict(deterministic_checks or {})
    ring_2_check = deterministic_checks.get("ring_2")
    ring_3_check = deterministic_checks.get("ring_3")
    if (
        isinstance(ring_2_check, Mapping)
        and ring_2_check.get("passed") is False
    ) or (
        isinstance(ring_3_check, Mapping)
        and ring_3_check.get("passed") is False
    ):
        return {
            "consistent": False,
            "available": True,
            "executed": False,
            "deterministic_passed": False,
            "reason": "确定性授权检查未通过，L2 语义检查未执行。",
            "checks": {},
            "violations": [],
            "manual_review_notes": [],
            "presentation_parameters": presentation_parameters,
            "structured_issues": ["deterministic_check_failed"],
            "evidence": [],
            "confidence": 0.0,
        }
    check_input = {
        "user_instruction": user_prompt,
        "plan": plan,
        "agent_semantic_plan": agent_message,
        "proposed_l2_call": {
            "name": tool_name,
            "arguments": tool_args,
            "plan_step_id": plan_step_id,
        },
        "parameter_flow_labels": argument_flow_labels or {},
        "parameter_resolutions": parameter_resolutions or [],
        "effective_egress": effective_egress or [],
        "execution_history": execution_history or [],
        "plan_usage": plan_usage or {},
        "presentation_parameters_do_not_validate": presentation_parameters,
        "deterministic_checks": deterministic_checks,
    }
    request = (
        L2_CHAIN_CHECK_PROMPT
        + "\n\nCHAIN_CHECK_INPUT:\n"
        + json.dumps(
            check_input,
            ensure_ascii=False,
            indent=2,
            default=str,
        )
    )
    try:
        raw = parse_plan_json(planner(request))
        confidence = float(raw.get("confidence", 0.0) or 0.0)
        if not math.isfinite(confidence):
            raise ValueError("L2 chain confidence must be finite")
        confidence = min(1.0, max(0.0, confidence))
        minimum = float(
            security_thresholds().get(
                "l2_chain_min_confidence",
                0.65,
            )
        )
        consistent = bool(raw.get("consistent", False))
        reason = str(raw.get("reason", ""))
        required_checks = SEMANTIC_CHECKS
        raw_checks = raw.get("checks")
        checks: dict[str, bool] = {}
        structured_issues: list[str] = []
        if not isinstance(raw_checks, Mapping):
            structured_issues.append("missing_checks")
            checks = {name: False for name in required_checks}
        else:
            for name in required_checks:
                value = raw_checks.get(name)
                checks[name] = value is True
                if value is not True:
                    structured_issues.append(f"check_failed:{name}")

        raw_violations = raw.get("violations", [])
        violations: list[dict[str, Any]] = []
        manual_review_notes: list[dict[str, Any]] = []
        presentation_parameter_set = set(presentation_parameters)
        if not isinstance(raw_violations, list):
            structured_issues.append("invalid_violations")
        else:
            for item in raw_violations:
                if not isinstance(item, Mapping):
                    structured_issues.append("invalid_violation")
                    continue
                normalized = {
                    str(key): value
                    for key, value in item.items()
                }
                if not normalized.get("parameter") or not normalized.get(
                    "kind"
                ):
                    structured_issues.append("incomplete_violation")
                if str(normalized.get("parameter", "")) in (
                    presentation_parameter_set
                ):
                    manual_review_notes.append(normalized)
                else:
                    violations.append(normalized)
        evidence = [
            str(item).strip()
            for item in raw.get("evidence", [])
            if str(item).strip()
        ]

        def string_leaves(value: Any) -> list[str]:
            if isinstance(value, dict):
                return [
                    item
                    for child in value.values()
                    for item in string_leaves(child)
                ]
            if isinstance(value, (list, tuple, set)):
                return [
                    item
                    for child in value
                    for item in string_leaves(child)
                ]
            if value is None:
                return []
            return [str(value)]

        available_evidence = "\n".join(
            string_leaves(check_input)
        ).casefold()
        verified_evidence = [
            item
            for item in evidence
            if item.casefold() in available_evidence
        ]
        other_failed_checks = [
            issue
            for issue in structured_issues
            if issue != "check_failed:semantic_parameter_relevance"
        ]
        presentation_only_override = (
            bool(manual_review_notes)
            and not violations
            and not other_failed_checks
            and all(
                checks.get(name, False)
                for name in required_checks
                if name != "semantic_parameter_relevance"
            )
        )
        if presentation_only_override:
            checks["semantic_parameter_relevance"] = True
            structured_issues = [
                issue
                for issue in structured_issues
                if issue != "check_failed:semantic_parameter_relevance"
            ]
            consistent = True
            if not verified_evidence and user_prompt:
                verified_evidence.append(user_prompt)
            reason = (
                reason
                + "（自然语言参数不参与 L2 事实与来源覆盖判定，"
                "相关内容已转入人工核对。）"
            )
        if consistent and (structured_issues or violations):
            consistent = False
            reason = (
                reason
                + "（结构化检查未通过："
                + ", ".join(
                    [
                        *structured_issues,
                        *(
                            [
                                f"violation:{item.get('parameter', '-')}:"
                                f"{item.get('kind', '-')}"
                                for item in violations
                            ]
                        ),
                    ]
                )
                + "）"
            )
        if consistent and not verified_evidence:
            consistent = False
            reason = reason + "（未提供可核验的链证据，已阻断。）"
        if consistent and confidence < minimum:
            consistent = False
            reason = (
                reason
                + (
                    f"（判定置信度 {confidence:.2f} 低于阈值 "
                    f"{minimum:.2f}，已阻断）"
                )
            )
        return {
            "consistent": consistent,
            "available": True,
            "reason": reason,
            "checks": checks,
            "violations": violations,
            "manual_review_notes": manual_review_notes,
            "presentation_parameters": presentation_parameters,
            "structured_issues": structured_issues,
            "evidence": verified_evidence,
            "unverified_evidence": [
                item
                for item in evidence
                if item not in verified_evidence
            ],
            "confidence": confidence,
        }
    except Exception as exc:
        return {
            "consistent": False,
            "available": False,
            "reason": f"L2 调用链检查失败：{exc}",
            "evidence": [],
            "confidence": 0.0,
        }


@dataclass
class PendingConfirmation:
    request_id: str
    task_id: str
    tool_name: str
    app: str
    risk_level: str
    args: dict[str, Any]
    plan_id: str
    plan_revision: int
    plan_hash: str
    chain_check: dict[str, Any]
    created_at: float
    expires_at: float | None
    status: str = "pending"
    approved: bool | None = None
    flow_check: dict[str, Any] = field(default_factory=dict)
    event: threading.Event = field(default_factory=threading.Event, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "task_id": self.task_id,
            "tool_name": self.tool_name,
            "app": self.app,
            "risk_level": self.risk_level,
            "args": dict(self.args),
            "plan_id": self.plan_id,
            "plan_revision": self.plan_revision,
            "plan_hash": self.plan_hash,
            "chain_check": dict(self.chain_check),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "approved": self.approved,
            "flow_check": dict(self.flow_check),
        }


class ConfirmationBroker:
    """Thread-safe L2 confirmation bridge used by Flask and the Agent thread."""

    _instance: "ConfirmationBroker | None" = None
    _lock = threading.Lock()

    def __new__(cls) -> "ConfirmationBroker":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._pending = {}
                cls._instance._pending_lock = threading.Lock()
            return cls._instance

    def request(
        self,
        *,
        task_id: str,
        tool_name: str,
        app: str,
        risk_level: str,
        args: dict[str, Any],
        plan: dict[str, Any],
        chain_check: dict[str, Any],
        flow_check: dict[str, Any] | None = None,
        on_pending: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        now = time.time()
        pending = PendingConfirmation(
            request_id=f"confirm_{uuid.uuid4().hex[:12]}",
            task_id=task_id,
            tool_name=tool_name,
            app=app,
            risk_level=risk_level,
            args=dict(args),
            plan_id=str(plan.get("plan_id", "")),
            plan_revision=int(plan.get("plan_revision", 1) or 1),
            plan_hash=str(plan.get("plan_hash", "")),
            chain_check=dict(chain_check),
            flow_check=dict(flow_check or {}),
            created_at=now,
            expires_at=None,
        )
        with self._pending_lock:
            self._pending[pending.request_id] = pending
        if on_pending is not None:
            on_pending(pending.to_dict())
        pending.event.wait()
        with self._pending_lock:
            result = pending.to_dict()
            self._pending.pop(pending.request_id, None)
        return result

    def resolve(self, request_id: str, approved: bool) -> dict[str, Any] | None:
        with self._pending_lock:
            pending = self._pending.get(str(request_id))
            if pending is None or pending.status != "pending":
                return None
            pending.approved = bool(approved)
            pending.status = "approved" if approved else "rejected"
            pending.event.set()
            return pending.to_dict()

    def list_pending(self) -> list[dict[str, Any]]:
        with self._pending_lock:
            result = []
            for pending in self._pending.values():
                if pending.status == "pending":
                    result.append(pending.to_dict())
            return result

    def clear(self) -> None:
        with self._pending_lock:
            for pending in self._pending.values():
                pending.status = "cancelled"
                pending.approved = False
                pending.event.set()
            self._pending.clear()
