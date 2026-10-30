"""Runtime policy pipeline for traceable cross-APP Agent execution.

The pipeline deliberately keeps only three runtime concerns:

* Ring 0: optional direct-user prompt classification;
* Ring 1: report untrusted data that influences control arguments;
* Ring 2: verify the action against a task-scoped capability;
* Ring 3: verify final egress arguments against action-local flow contracts.

Raw tool outputs are not rewritten. Data capture and provenance remain the
source of truth; risks are attached to the activity and rendered by the graph.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from ..modeling.data_sensitivity import tool_output_entity
from .data_access import action_data_access
from .defense_config import (
    direct_injection_mode,
    effective_method_enabled,
    effective_ring_enabled,
)
from .flow_policy import (
    check_sensitive_egress,
    check_task_scope,
    check_untrusted_control,
)
from .injection_scanner import (
    get_injection_scanner,
    redact_injection_chunks_with_metrics,
)
from .prompt_injection import check_prompt_for_injection_with_details
from .risk_types import (
    DECISION_ADVISORY,
    DECISION_BLOCK,
    DECISION_MITIGATE,
    DECISION_QUARANTINE,
    add_risk_to_event,
    make_risk,
    stabilize_risk_identity,
)
from .tool_output_scanner import scan_tool_output


def _skipped_diagnostics(ring: str, reason: str = "ring_disabled") -> dict:
    return {
        "passed": True,
        "skipped": True,
        "skipped_reason": reason,
        "ring": ring,
    }


def validate_call_event(event: Dict[str, Any]) -> None:
    """Compatibility hook used by external loggers."""
    return None


def _append_risk(
    event: Dict[str, Any],
    diagnostics: Dict[str, Any],
    risk: dict[str, Any],
    *,
    discriminator: str,
) -> None:
    stabilize_risk_identity(
        risk,
        task_id=event.get("task_id"),
        discriminator=discriminator,
    )
    add_risk_to_event(event, risk)
    diagnostics.setdefault("risk_assessments", []).append(risk)


def process_before_execution(
    event: Dict[str, Any],
    prompt: str | None = None,
    options: dict | None = None,
) -> Tuple[bool, Dict[str, Any], Dict[str, Any], set]:
    """Run prompt, provenance-scope and sensitive-egress checks.

    The fourth return value is retained for backward compatibility. Data
    categories are now carried by flow labels and task plans instead of a
    legacy category set inferred from text.
    """
    kwargs = event.get("inputs", {})
    diagnostics: Dict[str, Any] = {
        "ring_0": {},
        "ring_1": {},
        "ring_2": {},
        "ring_3": {},
        "risk_assessments": [],
    }

    if (
        prompt is not None
        and effective_ring_enabled("ring_0", options)
        and not effective_method_enabled("ring_0", "small_model", options)
    ):
        diagnostics["ring_0"] = _skipped_diagnostics(
            "ring_0",
            "method_disabled",
        )
        prompt = None

    if prompt is not None:
        if effective_ring_enabled("ring_0", options):
            details = check_prompt_for_injection_with_details(
                prompt,
                options=options,
                scan_result=event.get("injection_scan"),
                judge_result=(
                    event.get("injection_judge")
                    if effective_method_enabled(
                        "ring_0", "small_model", options
                    )
                    else None
                ),
            )
            diagnostics["ring_0"] = details
            mode = direct_injection_mode(options)
            detector_unavailable = (
                details.get("detection_method")
                in {
                    "small_model_unavailable",
                    "main_llm_uncertain",
                }
            )
            scanner_incomplete = bool(
                details.get("scanner_truncated", False)
            )
            detected = (
                not details.get("passed", True)
                and details.get("detection_method")
                in {
                    "small_model_span",
                    "small_model_chunked",
                    "main_llm_judge",
                }
            )
            details["mode"] = mode
            details["raw_prompt"] = prompt
            sanitized_prompt = prompt
            risk_decision = None
            if detector_unavailable or scanner_incomplete:
                risk_decision = DECISION_BLOCK
                details["coverage_incomplete"] = True
            elif detected:
                if mode == "quarantine":
                    sanitized_prompt, quarantine_metrics = (
                        redact_injection_chunks_with_metrics(
                        prompt,
                        event.get("injection_scan") or {},
                        )
                    )
                    residual_scan = get_injection_scanner().scan(
                        sanitized_prompt
                    )
                    quarantine_metrics.update(
                        {
                            "sanitized_rescan_available": (
                                residual_scan.available
                            ),
                            "sanitized_rescan_score": residual_scan.score,
                            "sanitized_residual_suspected": (
                                residual_scan.suspected
                            ),
                            "sanitized_rescan_unavailable": (
                                not residual_scan.available
                            ),
                        }
                    )
                    event.setdefault("injection_scan", {})[
                        "quarantine_metrics"
                    ] = quarantine_metrics
                    details["quarantine_metrics"] = quarantine_metrics
                    if residual_scan.suspected or not residual_scan.available:
                        risk_decision = DECISION_BLOCK
                        details["sanitized_residual_suspected"] = (
                            residual_scan.suspected
                        )
                        details["sanitized_rescan_unavailable"] = (
                            not residual_scan.available
                        )
                    details["sanitized_prompt"] = sanitized_prompt
                    details["prompt_modified"] = sanitized_prompt != prompt
                    if (
                        int(
                            quarantine_metrics.get(
                                "invalid_spans_total",
                                0,
                            )
                            or 0
                        )
                        > 0
                        or not quarantine_metrics.get(
                            "all_flagged_spans_replaced",
                            False,
                        )
                    ):
                        risk_decision = DECISION_BLOCK
                        details["quarantine_incomplete"] = True
                    if risk_decision is None:
                        if int(
                            quarantine_metrics.get(
                                "uncovered_characters",
                                1,
                            )
                            or 0
                        ) == 0:
                            risk_decision = DECISION_BLOCK
                            details["quarantine_empty"] = True
                        else:
                            risk_decision = DECISION_MITIGATE
                elif mode == "advisory":
                    risk_decision = DECISION_ADVISORY
                else:
                    risk_decision = DECISION_BLOCK

            if risk_decision is not None:
                risk = make_risk(
                    0,
                    risk_decision,
                    (
                        "The direct-injection detector is unavailable or "
                        "uncertain in fail-closed mode."
                        if detector_unavailable
                        else (
                            "The direct prompt was not fully scanned; "
                            "execution was blocked to avoid unscanned input."
                            if scanner_incomplete
                            else (
                                "Direct prompt injection chunks were replaced "
                                "before Agent invocation."
                                if risk_decision == DECISION_MITIGATE
                                else (
                                    "Prompt injection detected; no usable task "
                                    "remained after quarantine."
                                    if details.get("quarantine_empty")
                                    else (
                                        "Prompt contains instruction "
                                        "manipulation; advisory mode preserved "
                                        "the raw prompt."
                                        if risk_decision == DECISION_ADVISORY
                                        else "Direct prompt injection detected."
                                    )
                                )
                            )
                        )
                    ),
                    severity="high" if risk_decision == DECISION_BLOCK else "medium",
                    event_kind="security",
                    policy_id="ring0.direct_user_instruction",
                    confidence=details.get("safety_score"),
                    fsm_before="CONTEXT_READY",
                    fsm_after=(
                        "BLOCKED"
                        if risk_decision == DECISION_BLOCK
                        else (
                            "SANITIZED"
                            if risk_decision == DECISION_MITIGATE
                            else "ADMITTED"
                        )
                    ),
                )
                _append_risk(
                    event,
                    diagnostics,
                    risk,
                    discriminator=f"ring0:{prompt}",
                )
                if risk_decision == DECISION_BLOCK:
                    event["block_reason"] = (
                        "Ring 0: injection detector unavailable or "
                        "uncertain in fail-closed mode."
                        if detector_unavailable
                        else (
                            "Ring 0: the direct prompt was only partially "
                            "scanned."
                            if scanner_incomplete
                            else (
                                "Ring 0: no usable task remained after prompt "
                                "quarantine."
                                if details.get("quarantine_empty")
                                else "Ring 0: direct prompt injection detected."
                            )
                        )
                    )
                    return False, kwargs, diagnostics, set()
                if risk_decision == DECISION_MITIGATE:
                    event["sanitized_prompt"] = sanitized_prompt
        else:
            diagnostics["ring_0"] = _skipped_diagnostics("ring_0")

    ring1 = check_untrusted_control(event, options=options)
    diagnostics["ring_1"] = ring1
    if ring1.get("risk"):
        _append_risk(
            event,
            diagnostics,
            ring1["risk"],
            discriminator=(
                f"ring1:{event.get('tool_intent', '')}:"
                f"{','.join(ring1.get('control_arguments', []))}"
            ),
        )

    ring2 = check_task_scope(event, options=options)
    diagnostics["ring_2"] = ring2
    if ring2.get("risk"):
        _append_risk(
            event,
            diagnostics,
            ring2["risk"],
            discriminator=(
                f"ring2:{event.get('tool_intent', '')}:"
                f"{ring2.get('reason', '')}"
            ),
        )
    if not ring2.get("passed", True):
        event["block_reason"] = (
            (ring2.get("risk") or {}).get("reason")
            or f"Ring 2 blocked {event.get('tool_intent', 'tool')}: "
            f"{ring2.get('reason', 'policy check failed')}."
        )
        return False, kwargs, diagnostics, set()

    ring3 = check_sensitive_egress(event, options=options)
    diagnostics["ring_3"] = ring3
    if ring3.get("risk"):
        _append_risk(
            event,
            diagnostics,
            ring3["risk"],
            discriminator=(
                f"ring3:{event.get('tool_intent', '')}:"
                f"{ring3.get('reason', '')}"
            ),
        )
    if not ring3.get("passed", True):
        event["block_reason"] = (
            (ring3.get("risk") or {}).get("reason")
            or f"Ring 3 blocked {event.get('tool_intent', 'tool')}: "
            f"{ring3.get('reason', 'flow check failed')}."
        )
        return False, kwargs, diagnostics, set()

    return True, kwargs, diagnostics, set()


def process_after_execution(
    event_complete: Dict[str, Any],
    result: Any,
    nec_data: set | None = None,
    intent_data: set | None = None,
    options: dict | None = None,
    isolated_reader=None,
) -> Any:
    """Apply Ring 1 quarantine without exposing the full audit view."""
    final_result, _diagnostics = process_after_execution_with_details(
        event_complete,
        result,
        nec_data=nec_data,
        intent_data=intent_data,
        options=options,
        isolated_reader=isolated_reader,
    )
    return final_result


def process_after_execution_with_details(
    event_complete: Dict[str, Any],
    result: Any,
    nec_data: set | None = None,
    intent_data: set | None = None,
    options: dict | None = None,
    isolated_reader=None,
) -> Tuple[Any, Dict[str, Any]]:
    """Scan tool output, quarantine suspicious chunks, and retain audit raw data."""
    diagnostics = {
        "ring_1": {
            "passed": True,
            "executed": False,
            "mode": "label_only",
            "output_integrity": (
                ((event_complete.get("output_flow_label") or {}).get(
                    "integrity"
                ) or {})
            ),
        },
        "ring_3": {
            "passed": True,
            "executed": False,
            "mode": "sink_policy_only",
        },
        "risk_assessments": [],
    }
    if not effective_ring_enabled("ring_1", options):
        diagnostics["ring_1"] = _skipped_diagnostics("ring_1")
        return result, diagnostics
    if not effective_method_enabled("ring_1", "chunk_scanner", options):
        diagnostics["ring_1"] = {
            "passed": True,
            "executed": False,
            "mode": "disabled",
            "skipped_reason": "chunk_scanner_disabled",
        }
        return result, diagnostics

    tool_name = str(event_complete.get("tool_intent", ""))
    access_contract = action_data_access(
        event_complete.get("task_data_plan"),
        tool_name,
        str(event_complete.get("plan_step_id", "")),
    )
    output_app = (
        str(access_contract.get("app", ""))
        if isinstance(access_contract, dict)
        else ""
    ) or str(
        event_complete.get("target_app")
        or event_complete.get("app_domain")
        or ""
    )
    output_entity = (
        str(access_contract.get("entity", ""))
        if isinstance(access_contract, dict)
        else ""
    ) or tool_output_entity(tool_name)
    scan = scan_tool_output(
        result,
        scanner=get_injection_scanner(),
        tool_name=tool_name,
        schema=(
            event_complete.get("output_schema")
            if isinstance(event_complete.get("output_schema"), dict)
            else None
        ),
        app=output_app,
        entity=output_entity,
    )
    diagnostics["ring_1"] = {
        "passed": scan.available,
        "executed": True,
        "mode": "chunk_scanner_quarantine",
        "scan_scope": "natural_language_only",
        **scan.to_dict(),
    }
    event_complete["injection_scan"] = scan.to_dict()

    output_label = event_complete.get("output_flow_label")
    if not isinstance(output_label, dict):
        output_label = {}
    output_label = dict(output_label)
    output_label["injection"] = scan.information_flow()
    event_complete["output_flow_label"] = output_label

    if scan.source_flagged:
        scan_failed = not scan.available or scan.incomplete
        decision = (
            DECISION_QUARANTINE
            if scan_failed
            else DECISION_MITIGATE
        )
        risk = make_risk(
            1,
            decision,
            (
                (
                    "Tool output could not be scanned completely and was "
                    "quarantined before the next Agent reasoning step. "
                )
                if scan_failed
                else (
                    "Indirect prompt injection content was detected and "
                    "quarantined before the next Agent reasoning step. "
                )
            )
            + (
                "Affected fields: "
                f"{', '.join(scan.flagged_fields)}."
            ),
            severity=(
                "high"
                if scan_failed or scan.max_score >= 0.8
                else "medium"
            ),
            event_kind="security",
            policy_id="ring1.indirect_prompt_injection",
            activity_id=event_complete.get("activity_id"),
            source_ids=scan.evidence_refs,
            taint_roots=scan.evidence_refs,
            sink_ids=[str(event_complete.get("tool_intent", ""))],
            fsm_before="OUTPUT_OBSERVED",
            fsm_after=(
                "QUARANTINED"
                if decision == DECISION_QUARANTINE
                else "SANITIZED"
            ),
            confidence=scan.max_score,
        )
        _append_risk(
            event_complete,
            diagnostics,
            risk,
            discriminator=(
                f"ring1-scan:{event_complete.get('tool_intent', '')}:"
                f"{','.join(scan.flagged_fields)}"
            ),
        )
    return (
        scan.sanitized_value if scan.changed else result,
        diagnostics,
    )
