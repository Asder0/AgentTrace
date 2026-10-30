"""PROV + FSM provenance graph for AgentDojo.

The graph intentionally keeps two planes in the same directed multigraph:

* PROV facts describe data provenance and information-flow labels;
* FSM nodes describe task control state and risk-driven transitions.

NetworkX is used as an in-process graph store. The public API remains small so
the storage backend can later be replaced by Neo4j without changing capture or
analysis code.
"""

from __future__ import annotations

import copy
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

import networkx as nx

from ..app_domains import domain_for_tool
from .data_sensitivity import entity_level, entity_source
from .labels import (
    aggregate_flow_labels,
    derive_flow_label,
    make_confidentiality,
    make_flow_label,
    make_integrity,
)
from .policy import split_qualified_tool_name, tool_effect


class KnowledgeGraph:
    """Singleton in-memory PROV/FSM graph."""

    _instance: Optional["KnowledgeGraph"] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                instance = super().__new__(cls)
                instance.G = nx.MultiDiGraph()
                instance.agent_node = "AIAgent_Default"
                instance.G.add_node(
                    instance.agent_node,
                    type="AIAgent",
                    label="AgentDojo Agent",
                    app="system",
                    flow_label=make_flow_label(
                        confidentiality=make_confidentiality(level="internal"),
                        integrity=make_integrity(kind="trusted"),
                    ),
                )
                instance.last_invocation_id = None
                instance.last_invocation_label = None
                instance.current_state_id = None
                instance.task_id = None
                instance.suite = None
                instance.prompt_entity_id = None
                instance.activity_input_ids = {}
                cls._instance = instance
        return cls._instance


def _unique(values):
    return list(dict.fromkeys(str(value) for value in values if value))


def _make_label(node_type: str, content: str, max_len: int = 120) -> str:
    if not content:
        return node_type
    text = str(content)
    return text if len(text) <= max_len else f"{text[:max_len - 1]}…"


def _make_tool_label(tool_intent: str, tool_description: str = "") -> str:
    return tool_intent


def _infer_app_from_function_name(function_name: str) -> str:
    return domain_for_tool(function_name) or "unknown"



def _add_edge(
    G: nx.MultiDiGraph,
    source: str,
    target: str,
    relation: str,
    **attrs: Any,
) -> None:
    """Add an idempotent typed parallel edge."""
    if source not in G:
        G.add_node(source, type="Unknown")
    if target not in G:
        G.add_node(target, type="Unknown")
    if G.has_edge(source, target):
        for edge_data in G.get_edge_data(source, target, default={}).values():
            if edge_data.get("relation") == relation:
                return
    G.add_edge(source, target, relation=relation, **attrs)


def _state_id(task_id: str, name: str, suffix: str = "") -> str:
    token = f"{task_id}_{name}_{suffix}".strip("_")
    return f"TaskState_{token}"


def reset_graph(
    *,
    task_id: Optional[str] = None,
    suite: Optional[str] = None,
) -> KnowledgeGraph:
    """Reset all singleton graph state at a task boundary."""
    kg = KnowledgeGraph()
    kg.G.clear()
    kg.G.add_node(
        kg.agent_node,
        type="AIAgent",
        label="AgentDojo Agent",
        app="system",
        flow_label=make_flow_label(
            confidentiality=make_confidentiality(level="internal"),
            integrity=make_integrity(kind="trusted"),
        ),
    )
    kg.last_invocation_id = None
    kg.last_invocation_label = None
    kg.current_state_id = None
    kg.task_id = task_id
    kg.suite = suite
    kg.prompt_entity_id = None
    kg.activity_input_ids = {}
    return kg


def _find_or_create_prompt_node(
    G: nx.MultiDiGraph,
    prompt_text: str,
    timestamp: float,
) -> str:
    """Find the user-anchor prompt node for the current task."""
    kg = KnowledgeGraph()
    if kg.prompt_entity_id and kg.prompt_entity_id in G:
        return kg.prompt_entity_id

    for node_id, attrs in G.nodes(data=True):
        if attrs.get("type") == "Prompt" and attrs.get("content") == prompt_text:
            kg.prompt_entity_id = node_id
            return node_id

    prompt_id = f"Prompt_{uuid.uuid4().hex[:8]}"
    kg.G.add_node(
        prompt_id,
        type="Prompt",
        label=_make_label("User instruction", prompt_text),
        content=prompt_text,
        prompt=prompt_text,
        principal="user",
        app="system",
        suite=kg.suite,
        task_id=kg.task_id,
        timestamp=timestamp,
        flow_label=make_flow_label(
            confidentiality=make_confidentiality(
                level="internal",
                source_ids=[prompt_id],
                source_entities=["user_prompt"],
            ),
            integrity=make_integrity(kind="trusted"),
            data_influence=True,
            control_influence=True,
        ),
    )
    _add_edge(kg.G, prompt_id, kg.agent_node, "wasAttributedTo")
    kg.prompt_entity_id = prompt_id
    return prompt_id


def ensure_task_state(
    *,
    prompt: Optional[str] = None,
    task_id: Optional[str] = None,
    suite: Optional[str] = None,
) -> str:
    """Ensure the current task, prompt entity, and initial FSM state exist."""
    kg = KnowledgeGraph()
    if kg.task_id is None:
        kg.task_id = task_id or f"task_{uuid.uuid4().hex[:8]}"
    if kg.suite is None and suite:
        kg.suite = suite

    if prompt:
        _find_or_create_prompt_node(kg.G, prompt, 0.0)

    if kg.current_state_id is None:
        state_id = _state_id(kg.task_id, "INPUT_RECEIVED")
        kg.G.add_node(
            state_id,
            type="TaskState",
            state="INPUT_RECEIVED",
            label="Input received",
            app="system",
            suite=kg.suite,
            task_id=kg.task_id,
            scope="task",
        )
        _add_edge(kg.G, kg.agent_node, state_id, "hasState")
        if kg.prompt_entity_id:
            _add_edge(kg.G, state_id, kg.prompt_entity_id, "contains")
        kg.current_state_id = state_id
    return kg.current_state_id


def transition_state(
    *,
    activity_id: Optional[str],
    state_name: str,
    reason: str = "",
    risk_ids: Optional[List[str]] = None,
    suffix: Optional[str] = None,
    scope: Optional[str] = None,
) -> str:
    """Create an FSM state and link it from the current state/activity."""
    kg = KnowledgeGraph()
    ensure_task_state()
    from_state = kg.current_state_id
    state_id = _state_id(
        kg.task_id or "task",
        state_name,
        suffix or uuid.uuid4().hex[:6],
    )
    kg.G.add_node(
        state_id,
        type="TaskState",
        state=state_name,
        label=state_name.replace("_", " ").title(),
        reason=reason,
        risk_ids=list(risk_ids or []),
        app="system",
        suite=kg.suite,
        task_id=kg.task_id,
        scope=scope or ("task" if activity_id is None else "activity"),
        terminal=state_name
        in {
            "COMPLETED",
            "BLOCKED",
            "QUARANTINED",
            "FAILED",
            "CANCELLED",
            "INCOMPLETE",
        },
    )
    if from_state:
        _add_edge(kg.G, from_state, state_id, "stateTransition")
    if activity_id:
        _add_edge(
            kg.G,
            from_state or kg.agent_node,
            activity_id,
            "transition_from",
        )
        _add_edge(kg.G, activity_id, state_id, "transition_to")
    kg.current_state_id = state_id
    return state_id


def finalize_task_outcome(
    *,
    outcome: str,
    reason: str = "",
    summary: str = "",
    task_id: Optional[str] = None,
    suite: Optional[str] = None,
    plan: Optional[Dict[str, Any]] = None,
    executed_tools: Optional[List[str]] = None,
    successful_tools: Optional[List[str]] = None,
    failed_tools: Optional[List[str]] = None,
    blocked_tools: Optional[List[str]] = None,
    tool_call_count: int = 0,
    successful_tool_call_count: int = 0,
    failed_tool_call_count: int = 0,
    blocked_tool_call_count: int = 0,
    completion_audit: Optional[Dict[str, Any]] = None,
    finished_at: Optional[float] = None,
) -> Dict[str, Any]:
    """Record one terminal task state after the Agent pipeline returns."""
    kg = KnowledgeGraph()
    ensure_task_state(task_id=task_id, suite=suite)
    state_name = str(outcome or "FAILED").upper()
    if state_name not in {"COMPLETED", "BLOCKED", "FAILED", "CANCELLED", "INCOMPLETE"}:
        state_name = "FAILED"

    current = kg.G.nodes.get(kg.current_state_id, {})
    if (
        current.get("terminal")
        and current.get("scope") == "task"
        and current.get("state") == state_name
    ):
        state_id = str(kg.current_state_id)
    else:
        state_id = transition_state(
            activity_id=None,
            state_name=state_name,
            reason=reason,
            suffix="outcome",
            scope="task",
        )

    finished = time.time() if finished_at is None else float(finished_at)
    plan_data = plan if isinstance(plan, dict) else {}
    task_state = kg.G.nodes[state_id]
    task_state.update(
        label=f"Task {state_name.replace('_', ' ').title()}",
        scope="task",
        terminal=True,
        outcome=state_name,
        outcome_summary=str(summary or ""),
        finished_at=finished,
        task_id=kg.task_id,
        suite=kg.suite,
        plan_id=str(plan_data.get("plan_id", "")),
        plan_revision=int(plan_data.get("plan_revision", 1) or 1),
        plan_hash=str(plan_data.get("plan_hash", "")),
        executed_tools=_unique(executed_tools or []),
        successful_tools=_unique(successful_tools or executed_tools or []),
        failed_tools=_unique(failed_tools or []),
        blocked_tools=_unique(blocked_tools or []),
        tool_call_count=max(0, int(tool_call_count or 0)),
        successful_tool_call_count=max(
            0,
            int(successful_tool_call_count or 0),
        ),
        failed_tool_call_count=max(
            0,
            int(failed_tool_call_count or 0),
        ),
        blocked_tool_call_count=max(
            0,
            int(blocked_tool_call_count or 0),
        ),
        completion_audit=copy.deepcopy(completion_audit or {}),
    )
    return {
        "id": state_id,
        "state": state_name,
        "terminal": True,
        "scope": "task",
        "reason": reason,
        "summary": str(summary or ""),
        "finished_at": finished,
        "plan_id": task_state["plan_id"],
        "plan_revision": task_state["plan_revision"],
        "plan_hash": task_state["plan_hash"],
        "executed_tools": list(task_state["executed_tools"]),
        "successful_tools": list(task_state["successful_tools"]),
        "failed_tools": list(task_state["failed_tools"]),
        "blocked_tools": list(task_state["blocked_tools"]),
        "tool_call_count": task_state["tool_call_count"],
        "successful_tool_call_count": task_state[
            "successful_tool_call_count"
        ],
        "failed_tool_call_count": task_state["failed_tool_call_count"],
        "blocked_tool_call_count": task_state["blocked_tool_call_count"],
        "completion_audit": copy.deepcopy(
            task_state["completion_audit"]
        ),
    }


def record_task_start(
    prompt: str,
    *,
    task_id: Optional[str] = None,
    suite: Optional[str] = None,
) -> Dict[str, str]:
    """Reset the graph and register the trusted user authorization anchor."""
    resolved_task_id = task_id or f"task_{uuid.uuid4().hex[:8]}"
    kg = reset_graph(task_id=resolved_task_id, suite=suite)
    ensure_task_state(prompt=prompt, task_id=resolved_task_id, suite=suite)
    state_id = transition_state(
        activity_id=None,
        state_name="CONTEXT_READY",
        reason="trusted user prompt registered",
        suffix="context",
    )
    return {
        "task_id": resolved_task_id,
        "prompt_entity_id": str(kg.prompt_entity_id),
        "state_id": state_id,
    }


def record_llm_interaction(event: Dict[str, Any]) -> None:
    """Record an LLM activity and full-context information-flow label."""
    kg = KnowledgeGraph()
    G = kg.G
    ensure_task_state(
        prompt=event.get("prompt"),
        task_id=event.get("task_id"),
        suite=event.get("suite"),
    )

    prompt_text = str(event.get("prompt", "") or "")
    thought_id = event.get("thought_id", uuid.uuid4().hex[:8])
    invocation_id = f"AIModelInvocation_{thought_id}"
    event["invocation_id"] = invocation_id
    prompt_id = _find_or_create_prompt_node(G, prompt_text, event["timestamp"])
    if prompt_id in G:
        G.nodes[prompt_id]["raw_prompt"] = event.get(
            "raw_prompt", prompt_text
        )
        G.nodes[prompt_id]["prompt_modified"] = bool(
            event.get("prompt_modified", False)
        )
    prompt_label = G.nodes[prompt_id].get("flow_label") or make_flow_label()
    context_labels = [
        prompt_label,
        *[label for label in event.get("context_flow_labels", []) if label],
    ]
    flow_label = event.get("flow_label") or aggregate_flow_labels(
        context_labels,
        generated=True,
        control_influence=True,
    )

    G.add_node(
        invocation_id,
        type="AIModelInvocation",
        label=_make_label("LLM reasoning", prompt_text),
        prompt=prompt_text,
        raw_prompt=event.get("raw_prompt", prompt_text),
        prompt_modified=bool(event.get("prompt_modified", False)),
        response=event.get("response", ""),
        timestamp=event["timestamp"],
        app="system",
        suite=event.get("suite", kg.suite),
        task_id=event.get("task_id", kg.task_id),
        context_messages=copy.deepcopy(event.get("context_messages", [])),
        plan_updates=copy.deepcopy(event.get("plan_updates", [])),
        plan_update_warnings=list(
            event.get("plan_update_warnings", [])
        ),
        flow_label=flow_label,
    )
    _add_edge(G, prompt_id, invocation_id, "informed")
    _add_edge(G, invocation_id, prompt_id, "used")
    for label in event.get("context_flow_labels", []) or []:
        if not isinstance(label, dict):
            continue
        confidentiality = label.get("confidentiality")
        source_ids = (
            confidentiality.get("source_ids", [])
            if isinstance(confidentiality, dict)
            else []
        )
        for source_id in source_ids:
            source_activity_id = str(source_id).split(":", 1)[0]
            if source_activity_id not in G:
                continue
            for candidate_id, candidate in G.nodes(data=True):
                if (
                    candidate.get("type") != "DomainData"
                    or candidate.get("task_id")
                    != event.get("task_id", kg.task_id)
                ):
                    continue
                if any(
                    edge.get("relation") == "produces"
                    for edge in G.get_edge_data(
                        source_activity_id,
                        candidate_id,
                        default={},
                    ).values()
                ):
                    _add_edge(
                        G,
                        candidate_id,
                        invocation_id,
                        "informed",
                    )
    agent_id = event.get("agent_id", kg.agent_node)
    _add_edge(G, invocation_id, agent_id, "belongsTo")
    _add_edge(G, invocation_id, agent_id, "wasAssociatedWith")

    kg.last_invocation_id = invocation_id
    kg.last_invocation_label = flow_label
    transition_state(
        activity_id=invocation_id,
        state_name="CONTEXT_READY",
        reason="LLM context evaluated",
        suffix=thought_id,
    )


def _resolve_invocation_id(kg: KnowledgeGraph, event: Dict[str, Any]) -> Optional[str]:
    value = event.get("wasInformedBy")
    if value:
        invocation_id = (
            str(value)
            if str(value).startswith("AIModelInvocation_")
            else f"AIModelInvocation_{value}"
        )
        return invocation_id if invocation_id in kg.G else None
    return kg.last_invocation_id


def record_activity(event: Dict[str, Any]) -> None:
    """Record a proposed tool activity and its input entities."""
    kg = KnowledgeGraph()
    G = kg.G
    ensure_task_state(
        prompt=event.get("thought_prompt"),
        task_id=event.get("task_id"),
        suite=event.get("suite"),
    )

    tool_intent = event["tool_intent"]
    qualified_suite, base_tool = split_qualified_tool_name(tool_intent)
    activity_id = f"Activity_{tool_intent}_{uuid.uuid4().hex[:8]}"
    event["activity_id"] = activity_id
    invocation_id = _resolve_invocation_id(kg, event)
    parent_labels: List[dict[str, Any]] = []
    if invocation_id:
        parent_labels.append(
            G.nodes[invocation_id].get("flow_label")
            or kg.last_invocation_label
            or make_flow_label()
        )
    if kg.prompt_entity_id in G:
        parent_labels.append(G.nodes[kg.prompt_entity_id].get("flow_label") or {})

    activity_label = event.get("flow_label") or aggregate_flow_labels(
        parent_labels,
        generated=True,
        control_influence=True,
    )
    effect_policy = tool_effect(base_tool)
    G.add_node(
        activity_id,
        type="AgentTool",
        label=_make_tool_label(tool_intent, event.get("tool_description", "")),
        app=event.get("app_domain") or event.get("target_app", "unknown"),
        module=event.get("target_app", "unknown"),
        suite=qualified_suite or event.get("suite", kg.suite),
        tool_alias=tool_intent if tool_intent != base_tool else None,
        tool_base_name=base_tool,
        task_id=event.get("task_id", kg.task_id),
        inputs=str(event.get("inputs", {})),
        original_inputs=copy.deepcopy(event.get("original_inputs", {})),
        timestamp=event["timestamp"],
        wasInformedBy=event.get("wasInformedBy"),
        flow_label=activity_label,
        effect=event.get("tool_effect", effect_policy.effect),
        tool_risk_level=event.get(
            "tool_risk_level",
            effect_policy.risk_level,
        ),
        access_plan=copy.deepcopy(event.get("access_plan")),
        task_data_plan=copy.deepcopy(event.get("task_data_plan")),
        flow_contract=copy.deepcopy(event.get("flow_contract")),
        subgoal_id=(
            event.get("access_plan", {}).get("subgoal_id")
            if isinstance(event.get("access_plan"), dict)
            else None
        ),
        argument_sources=copy.deepcopy(event.get("argument_sources", [])),
        argument_flow_labels=copy.deepcopy(
            event.get("argument_flow_labels", {})
        ),
        parameter_resolutions=copy.deepcopy(
            event.get("parameter_resolutions", [])
        ),
        parameter_resolution_errors=list(
            event.get("parameter_resolution_errors", [])
        ),
        parameter_resolution_warnings=list(
            event.get("parameter_resolution_warnings", [])
        ),
        control_fields=sorted(effect_policy.control_fields),
        content_fields=sorted(effect_policy.content_fields),
        egress=effect_policy.egress,
        executed=False,
    )
    agent_id = event.get("agent_id", kg.agent_node)
    _add_edge(G, activity_id, agent_id, "belongsTo")
    _add_edge(G, activity_id, agent_id, "wasAssociatedWith")

    if event.get("tool_effect") == "egress" or effect_policy.egress:
        sink_id = f"EgressSink_{tool_intent}"
        G.add_node(
            sink_id,
            type="EgressSink",
            label=tool_intent,
            app=event.get("app_domain") or event.get("target_app", "unknown"),
            suite=event.get("suite", kg.suite),
            task_id=event.get("task_id", kg.task_id),
            sink_kind="external",
        )
        _add_edge(G, activity_id, sink_id, "egress_to")

    inputs = event.get("inputs") or {}
    input_ids: List[str] = []
    if inputs:
        input_entity_id = f"Entity_Input_{uuid.uuid4().hex[:8]}"
        input_ids.append(input_entity_id)
        input_label = event.get("input_flow_label") or derive_flow_label(
            parent_labels,
            source_kind="agent",
            content=inputs,
            source_id=input_entity_id,
            control_influence=True,
        )
        G.add_node(
            input_entity_id,
            type="DomainData",
            label=_make_label("Tool inputs", str(inputs)),
            content=str(inputs),
            source_app=event.get("target_app", "unknown"),
            app=event.get("app_domain") or event.get("target_app", "unknown"),
            module=event.get("target_app", "unknown"),
            suite=event.get("suite", kg.suite),
            task_id=event.get("task_id", kg.task_id),
            operation="input",
            field_path="tool.inputs",
            flow_label=input_label,
        )
        if invocation_id:
            _add_edge(G, invocation_id, input_entity_id, "informed")
            _add_edge(G, input_entity_id, invocation_id, "wasGeneratedBy")
        _add_edge(G, activity_id, input_entity_id, "used")
    elif invocation_id:
        _add_edge(G, invocation_id, activity_id, "informed")

    if invocation_id:
        _add_edge(G, activity_id, invocation_id, "wasInformedBy")
    kg.activity_input_ids[activity_id] = input_ids
    transition_state(
        activity_id=activity_id,
        state_name="ACTION_PROPOSED",
        reason="tool call received",
        suffix=activity_id.rsplit("_", 1)[-1],
    )


def _find_activity(kg: KnowledgeGraph, event: Dict[str, Any]) -> Optional[str]:
    activity_id = event.get("activity_id")
    if activity_id and activity_id in kg.G:
        return str(activity_id)
    informed_by = event.get("wasInformedBy")
    if informed_by:
        candidates = [
            node_id
            for node_id, attrs in kg.G.nodes(data=True)
            if attrs.get("type") == "AgentTool"
            and attrs.get("wasInformedBy") == informed_by
        ]
        if candidates:
            return candidates[-1]
    return None


def _raw_output_text(event: Dict[str, Any]) -> Optional[str]:
    value = event.get("outputs")
    if value in (None, ""):
        return None
    return value if isinstance(value, str) else str(value)


def update_activity_outcome(event: Dict[str, Any]) -> None:
    """Attach an activity outcome, derived entities, risks, and FSM state."""
    kg = KnowledgeGraph()
    G = kg.G
    activity_id = _find_activity(kg, event)
    if not activity_id:
        return
    if event.get("_graph_outcome_recorded"):
        return
    event["_graph_outcome_recorded"] = True
    activity = G.nodes[activity_id]
    status = str(event.get("status", "success"))
    activity["status"] = status
    # update_activity_outcome is only used after the tool function has run.
    # Ring-1 quarantine therefore records an executed-but-not-admitted output.
    activity["executed"] = True
    if event.get("block_reason"):
        activity["blocked"] = status == "blocked"
        activity["block_reason"] = event["block_reason"]
    for key in (
        "l2_chain_check",
        "l2_confirmation",
        "tool_risk_level",
        "inputs",
        "original_inputs",
        "ring3_check",
        "ring2_check",
        "requirement_audit",
        "requirement_decision",
        "data_access_check",
        "injection_scan",
        "flow_contract",
        "argument_flow_labels",
        "argument_sources",
        "parameter_resolutions",
        "parameter_resolution_errors",
        "parameter_resolution_warnings",
        "implicit_egress",
        "execution_rollback",
    ):
        if key in event:
            activity[key] = copy.deepcopy(event.get(key))

    input_ids = kg.activity_input_ids.get(activity_id, [])
    input_labels = [
        G.nodes[node_id].get("flow_label") for node_id in input_ids if node_id in G
    ]
    activity_label = activity.get("flow_label") or make_flow_label()
    output_label = event.get("output_flow_label") or derive_flow_label(
        [activity_label, *input_labels],
        source_kind="tool_output",
        content=event.get("outputs", ""),
        source_id=activity_id,
    )

    output_ids: List[str] = []
    source_evidence_ids: List[str] = []
    raw_output = _raw_output_text(event)
    if raw_output is not None:
        output_entity_id = f"Entity_Output_{uuid.uuid4().hex[:8]}"
        output_ids.append(output_entity_id)
        source_evidence_ids.append(output_entity_id)
        G.add_node(
            output_entity_id,
            type="DomainData",
            label="",
            content=raw_output,
            status=status,
            source_app=event.get("target_app", "unknown"),
            app=event.get("app_domain") or event.get("target_app", "unknown"),
            module=event.get("target_app", "unknown"),
            suite=event.get("suite", kg.suite),
            task_id=event.get("task_id", kg.task_id),
            operation="output",
            field_path="tool.output",
            admitted=not bool(
                event.get("redaction_applied")
                or event.get("quarantined")
                or status == "blocked"
            ),
            flow_label=output_label,
        )
        _add_edge(G, activity_id, output_entity_id, "produces")
        _add_edge(G, output_entity_id, activity_id, "wasGeneratedBy")
        for input_id in input_ids:
            if input_id in G:
                _add_edge(
                    G,
                    output_entity_id,
                    input_id,
                    "wasDerivedFrom",
                    influence="content",
                )

        sanitized_text = event.get("sanitized_output")
        if (
            isinstance(sanitized_text, str)
            and sanitized_text != raw_output
        ):
            sanitized_id = f"Entity_Sanitized_{uuid.uuid4().hex[:8]}"
            output_ids.append(sanitized_id)
            source_evidence_ids.append(sanitized_id)
            sanitized_label = derive_flow_label(
                [output_label],
                source_kind="sanitized",
                content=sanitized_text,
                source_id=sanitized_id,
            )
            G.add_node(
                sanitized_id,
                type="DomainData",
                label="Sanitized tool result",
                content=sanitized_text,
                status="sanitized",
                source_app=event.get("target_app", "unknown"),
                app=event.get("app_domain") or event.get("target_app", "unknown"),
                module=event.get("target_app", "unknown"),
                suite=event.get("suite", kg.suite),
                task_id=event.get("task_id", kg.task_id),
                operation="output_sanitized",
                field_path="tool.output.sanitized",
                admitted=True,
                redacted=True,
                flow_label=sanitized_label,
            )
            _add_edge(G, activity_id, sanitized_id, "produces")
            _add_edge(G, sanitized_id, output_entity_id, "wasDerivedFrom")

    env_delta = event.get("environment_delta") or {}
    for operation in ("created", "updated", "deleted"):
        for entity_info in env_delta.get(operation, []):
            if isinstance(entity_info, str):
                entity_name = entity_info
                entity_type = "unknown"
                attributes = {}
                data_payload = None
            else:
                entity_name = entity_info.get("entity_id", "unknown")
                entity_type = entity_info.get("entity_type", "unknown")
                attributes = entity_info.get("attributes", {})
                data_payload = entity_info.get("data_payload")
            delta_id = f"Entity_Delta_{uuid.uuid4().hex[:8]}"
            content = data_payload or attributes or entity_name
            delta_label = entity_info.get("flow_label") if isinstance(entity_info, dict) else None
            if not delta_label:
                delta_label = derive_flow_label(
                    [output_label, *input_labels],
                    source_kind="tool_output",
                    content=content,
                    source_id=delta_id,
                )
            delta_app = str(
                event.get("app_domain")
                or event.get("target_app")
                or "unknown"
            )
            delta_entity = str(entity_type or "unknown")
            delta_label = aggregate_flow_labels(
                [
                    delta_label,
                    make_flow_label(
                        confidentiality=make_confidentiality(
                            level=entity_level(
                                delta_app,
                                delta_entity,
                            ),
                            source_entities=[
                                entity_source(
                                    delta_app,
                                    delta_entity,
                                )
                            ],
                        ),
                        integrity=make_integrity(
                            kind="untrusted",
                            taint_roots=[
                                entity_source(
                                    delta_app,
                                    delta_entity,
                                )
                            ],
                        ),
                        control_influence=True,
                    ),
                ],
                generated=True,
                control_influence=True,
            )
            G.add_node(
                delta_id,
                type="DomainData",
                label=f"{operation.title()} {entity_type}: {entity_name}",
                content=str(content),
                source_app=event.get("target_app", "unknown"),
                app=event.get("app_domain") or event.get("target_app", "unknown"),
                module=event.get("target_app", "unknown"),
                suite=event.get("suite", kg.suite),
                task_id=event.get("task_id", kg.task_id),
                operation=operation,
                entity_id=entity_name,
                entity_type=entity_type,
                attributes=attributes,
                flow_label=delta_label,
            )
            _add_edge(G, activity_id, delta_id, "produces")
            _add_edge(G, delta_id, activity_id, "wasGeneratedBy")
            for input_id in input_ids:
                if input_id in G:
                    _add_edge(G, delta_id, input_id, "wasDerivedFrom")
            output_ids.append(delta_id)

    risks = event.get("risk_assessments", [])
    if source_evidence_ids:
        for risk in risks:
            if risk.get("policy_id") != "ring1.indirect_prompt_injection":
                continue
            risk["evidence_entity_ids"] = _unique(
                [
                    *risk.get("evidence_entity_ids", []),
                    *source_evidence_ids,
                ]
            )
            risk["evidence_total"] = {
                "entities": len(risk["evidence_entity_ids"]),
                "sources": len(_unique(risk.get("source_ids", []))),
                "taint_roots": len(
                    _unique(risk.get("taint_roots", []))
                ),
            }
    record_risk_assessments(event, risks)
    state_name = "ADMITTED"
    if any(risk.get("decision") == "QUARANTINE" for risk in risks):
        state_name = "QUARANTINED"
    elif status == "blocked":
        state_name = "BLOCKED"
    elif event.get("redaction_applied"):
        state_name = "SANITIZED"
    elif status == "error":
        state_name = "FAILED"
    transition_state(
        activity_id=activity_id,
        state_name=state_name,
        reason=event.get("block_reason", ""),
        risk_ids=[risk.get("risk_id", "") for risk in risks],
        suffix=activity_id.rsplit("_", 1)[-1],
    )


def record_risk_assessments(
    event: Dict[str, Any],
    risks: Optional[List[Dict[str, Any]]] = None,
) -> List[str]:
    """Attach risk events to graph nodes and FSM states."""
    kg = KnowledgeGraph()
    G = kg.G
    risks = risks if risks is not None else event.get("risk_assessments", [])
    activity_id = event.get("activity_id")
    risk_ids: List[str] = []
    for risk in risks:
        risk_id = str(risk.get("risk_id") or f"Risk_{uuid.uuid4().hex[:10]}")
        risk["risk_id"] = risk_id
        risk_ids.append(risk_id)
        event_kind = str(risk.get("event_kind", "security"))
        node_type = (
            "PolicyEvent" if event_kind == "policy" else "RiskEvent"
        )
        G.add_node(
            risk_id,
            type=node_type,
            ring=int(risk.get("ring", 0)),
            decision=str(risk.get("decision", "ADVISORY")),
            event_kind=event_kind,
            severity=str(risk.get("severity", "medium")),
            reason=str(risk.get("reason", "")),
            policy_id=str(risk.get("policy_id", "")),
            label=f"Ring {risk.get('ring', 0)}: {risk.get('decision', 'RISK')}",
            app="system",
            suite=kg.suite,
            task_id=kg.task_id,
            flow_label=make_flow_label(
                confidentiality=make_confidentiality(level="public"),
                integrity=make_integrity(kind="trusted"),
                data_influence=False,
                control_influence=False,
            ),
            **{
                key: copy.deepcopy(value)
                for key, value in risk.items()
                if key
                not in {
                    "ring",
                    "decision",
                    "severity",
                    "reason",
                    "policy_id",
                    "risk_id",
                    "event_kind",
                }
            },
        )
        if activity_id and activity_id in G:
            relation = "policy_of" if event_kind == "policy" else "risk_of"
            _add_edge(G, risk_id, activity_id, relation)
            id_field = "policy_ids" if event_kind == "policy" else "risk_ids"
            G.nodes[activity_id].setdefault(id_field, []).append(risk_id)
            if event_kind == "security":
                G.nodes[activity_id]["risk_decision"] = risk.get("decision")
        for entity_id in risk.get("evidence_entity_ids", []):
            if entity_id in G:
                _add_edge(G, risk_id, entity_id, "risk_evidence")
                _add_edge(G, risk_id, entity_id, "source_of")
        for source_id in risk.get("source_ids", []):
            if source_id in G:
                _add_edge(G, risk_id, source_id, "source_of")
        for sink_id in risk.get("sink_ids", []):
            if sink_id in G:
                _add_edge(G, risk_id, sink_id, "leak_sink")
            else:
                graph_sink_id = f"EgressSink_{sink_id}"
                if graph_sink_id in G:
                    _add_edge(G, risk_id, graph_sink_id, "leak_sink")
    if risk_ids and activity_id in G:
        for id_field in ("risk_ids", "policy_ids"):
            if id_field in G.nodes[activity_id]:
                G.nodes[activity_id][id_field] = _unique(
                    G.nodes[activity_id][id_field]
                )
    return risk_ids


def mark_activity_blocked(event: Dict[str, Any]) -> None:
    """Mark an activity canceled before execution without inventing output."""
    kg = KnowledgeGraph()
    activity_id = _find_activity(kg, event)
    if not activity_id:
        return
    activity = kg.G.nodes[activity_id]
    activity["blocked"] = True
    activity["status"] = "blocked"
    activity["executed"] = False
    activity["block_reason"] = event.get("block_reason", "")
    for key in (
        "l2_chain_check",
        "l2_confirmation",
        "tool_risk_level",
        "inputs",
        "original_inputs",
        "ring3_check",
        "ring2_check",
        "requirement_audit",
        "requirement_decision",
        "data_access_check",
        "injection_scan",
        "flow_contract",
        "argument_flow_labels",
        "argument_sources",
        "parameter_resolutions",
        "parameter_resolution_errors",
        "parameter_resolution_warnings",
    ):
        if key in event:
            activity[key] = copy.deepcopy(event.get(key))
    record_risk_assessments(event)
    transition_state(
        activity_id=activity_id,
        state_name="BLOCKED",
        reason=activity["block_reason"],
        risk_ids=[
            risk.get("risk_id", "") for risk in event.get("risk_assessments", [])
        ],
        suffix=activity_id.rsplit("_", 1)[-1],
    )


def mark_activity_denied(event: Dict[str, Any]) -> None:
    """Record a denied tool call without terminating the overall task."""
    kg = KnowledgeGraph()
    activity_id = _find_activity(kg, event)
    if not activity_id:
        return
    activity = kg.G.nodes[activity_id]
    activity["blocked"] = True
    activity["denied"] = True
    activity["status"] = "blocked"
    activity["executed"] = False
    activity["block_reason"] = event.get("block_reason", "")
    for key in (
        "l2_chain_check",
        "l2_confirmation",
        "tool_risk_level",
        "inputs",
        "original_inputs",
        "ring3_check",
        "ring2_check",
        "data_access_check",
        "injection_scan",
        "flow_contract",
        "argument_flow_labels",
        "argument_sources",
        "parameter_resolutions",
        "parameter_resolution_errors",
        "parameter_resolution_warnings",
    ):
        if key in event:
            activity[key] = copy.deepcopy(event.get(key))
    record_risk_assessments(event)
    transition_state(
        activity_id=activity_id,
        state_name="ADVISED",
        reason=activity["block_reason"],
        risk_ids=[
            risk.get("risk_id", "")
            for risk in event.get("risk_assessments", [])
        ],
        suffix=f"denied_{activity_id.rsplit('_', 1)[-1]}",
        scope="activity",
    )


def record_human_authorization(
    activity_id: str,
    confirmation: Dict[str, Any],
) -> str | None:
    """Create or update a persistent human-authorization node."""
    kg = KnowledgeGraph()
    G = kg.G
    if not activity_id or activity_id not in G:
        return None
    request_id = str(confirmation.get("request_id", "") or "")
    if not request_id:
        return None
    node_id = f"HumanAuthorization_{request_id}"
    status = str(confirmation.get("status", "pending"))
    confirmation_kind = str(
        confirmation.get("confirmation_kind", "l2_action")
        or "l2_action"
    )
    G.add_node(
        node_id,
        type="HumanAuthorization",
        label=(
            "Sensitive-data exposure authorization: "
            if confirmation_kind == "sensitive_data_exposure"
            else (
                "任务要求决策："
                if confirmation_kind == "requirement_resolution"
                else "Human authorization: "
            )
        )
        + (
            {
                "pending": "待处理",
                "resolved": "已处理",
                "cancelled": "已取消",
            }.get(status, status)
            if confirmation_kind == "requirement_resolution"
            else status
        ),
        request_id=request_id,
        status=status,
        confirmation_kind=confirmation_kind,
        approved=confirmation.get("approved"),
        tool_name=str(confirmation.get("tool_name", "")),
        risk_level=str(confirmation.get("risk_level", "L2")),
        args=copy.deepcopy(confirmation.get("args", {})),
        plan_id=str(confirmation.get("plan_id", "")),
        plan_revision=int(confirmation.get("plan_revision", 1) or 1),
        plan_hash=str(confirmation.get("plan_hash", "")),
        chain_check=copy.deepcopy(confirmation.get("chain_check", {})),
        flow_check=copy.deepcopy(confirmation.get("flow_check", {})),
        decision_kind=str(
            confirmation.get("decision_kind", "approve_reject")
        ),
        options=copy.deepcopy(confirmation.get("options", [])),
        payload=copy.deepcopy(confirmation.get("payload", {})),
        decision=copy.deepcopy(confirmation.get("decision")),
        decision_hash=str(confirmation.get("decision_hash", "")),
        created_at=confirmation.get("created_at"),
        expires_at=confirmation.get("expires_at"),
        app=str(confirmation.get("app", "system") or "system"),
        suite=kg.suite,
        task_id=kg.task_id,
        flow_label=make_flow_label(
            confidentiality=make_confidentiality(level="internal"),
            integrity=make_integrity(kind="trusted"),
            data_influence=True,
            control_influence=True,
        ),
    )
    _add_edge(G, node_id, activity_id, "authorizes")
    activity = G.nodes[activity_id]
    activity["l2_confirmation"] = copy.deepcopy(confirmation)
    activity["authorization_status"] = status
    activity["human_authorization_id"] = node_id
    if status == "pending":
        transition_state(
            activity_id=activity_id,
            state_name="HELD",
            reason=(
                "Sensitive APP data is awaiting explicit exposure "
                "authorization."
                if confirmation_kind == "sensitive_data_exposure"
                else (
                    "The task has an unresolved business requirement "
                    "that requires an explicit user decision."
                    if confirmation_kind == "requirement_resolution"
                    else "L2 action is awaiting explicit human authorization."
                )
            ),
            suffix=f"auth_{request_id}",
        )
    return node_id


def get_graph_data() -> Dict[str, Any]:
    """Serialize the graph for the D3 visualization layer."""
    kg = KnowledgeGraph()
    try:
        data = nx.node_link_data(kg.G, edges="links")
    except TypeError:
        data = nx.node_link_data(kg.G)
    for link in data.get("links", []):
        if isinstance(link.get("source"), str):
            link["source"] = {"id": link["source"]}
        if isinstance(link.get("target"), str):
            link["target"] = {"id": link["target"]}

    for node in data.get("nodes", []):
        if "source_app" in node and "app" not in node:
            node["app"] = node["source_app"]
        if "app" not in node:
            node["app"] = (
                "system"
                if node.get("type") in {
                    "AIAgent",
                    "Prompt",
                    "AIModelInvocation",
                    "TaskState",
                    "RiskEvent",
                    "PolicyEvent",
                }
                else "unknown"
            )
    return data


def get_graph_summary() -> Dict[str, Any]:
    """Return small graph counters used by status and audit views."""
    kg = KnowledgeGraph()
    G = kg.G
    node_types: Dict[str, int] = {}
    edge_types: Dict[str, int] = {}
    confidentiality: Dict[str, int] = {}
    integrity: Dict[str, int] = {}
    risk_decisions: Dict[str, int] = {}
    policy_decisions: Dict[str, int] = {}
    event_kinds: Dict[str, int] = {}
    for _, attrs in G.nodes(data=True):
        node_type = str(attrs.get("type", "unknown"))
        node_types[node_type] = node_types.get(node_type, 0) + 1
        label = attrs.get("flow_label") or {}
        conf_level = (label.get("confidentiality") or {}).get("level")
        integ_kind = (label.get("integrity") or {}).get("kind")
        if conf_level:
            confidentiality[conf_level] = confidentiality.get(conf_level, 0) + 1
        if integ_kind:
            integrity[integ_kind] = integrity.get(integ_kind, 0) + 1
        if node_type == "RiskEvent":
            decision = str(attrs.get("decision", "unknown"))
            risk_decisions[decision] = risk_decisions.get(decision, 0) + 1
            event_kind = str(attrs.get("event_kind", "security"))
            event_kinds[event_kind] = event_kinds.get(event_kind, 0) + 1
        elif node_type == "PolicyEvent":
            decision = str(attrs.get("decision", "unknown"))
            policy_decisions[decision] = (
                policy_decisions.get(decision, 0) + 1
            )
            event_kinds["policy"] = event_kinds.get("policy", 0) + 1
    for _, _, attrs in G.edges(data=True):
        relation = str(attrs.get("relation", "unknown"))
        edge_types[relation] = edge_types.get(relation, 0) + 1
    current_state = (
        G.nodes.get(kg.current_state_id, {}) or {}
        if kg.current_state_id
        else {}
    )
    return {
        "task_id": kg.task_id,
        "state": current_state.get("state"),
        "terminal": bool(current_state.get("terminal", False)),
        "state_scope": current_state.get("scope"),
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "node_types": node_types,
        "edge_types": edge_types,
        "confidentiality": confidentiality,
        "integrity": integrity,
        "risk_decisions": risk_decisions,
        "policy_decisions": policy_decisions,
        "event_kinds": event_kinds,
    }


__all__ = [
    "KnowledgeGraph",
    "ensure_task_state",
    "finalize_task_outcome",
    "mark_activity_blocked",
    "mark_activity_denied",
    "record_human_authorization",
    "record_activity",
    "record_llm_interaction",
    "record_risk_assessments",
    "record_task_start",
    "reset_graph",
    "transition_state",
    "update_activity_outcome",
    "get_graph_data",
    "get_graph_summary",
]
