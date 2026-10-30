"""
Capture Layer: AOP-based interceptors for AgentDojo.
Provides:
1. Tool call interception (API-level)
2. LLM reasoning context capture (Thought/Action)
3. Environment state semantic parsing (pre/post snapshots)
4. wasInformedBy relationship binding between LLM reasoning and tool calls
"""

import copy
import functools
import hashlib
import json
import sys
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field as dataclass_field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from agentdojo.types import ChatSystemMessage, text_content_block_from_string

from ..analysis.data_access import (
    action_data_access,
    project_agent_exposure,
    resolve_resource_parameter_resolutions,
)
from ..analysis.defense_config import (
    effective_method_enabled,
    effective_ring_enabled,
    get_config,
)
from ..analysis.injection_scanner import (
    SECURITY_PLACEHOLDER_NOTICE,
    contains_security_placeholder,
)
from ..analysis.parameter_binding import (
    PLACEHOLDER_NOTICE_PREFIX,
    action_flow_contract,
    placeholder_notice,
    resolve_parameter_bindings,
)
from ..analysis.pipeline import (
    process_after_execution_with_details,
    process_before_execution,
)
from ..analysis.risk_types import (
    DECISION_BLOCK,
    DECISION_HOLD,
    DECISION_MITIGATE,
    make_risk,
)
from ..app_domains import domain_for_tool
from ..modeling.data_sensitivity import (
    ValueOrigin,
    collect_value_origins,
    entity_level,
    entity_source,
    field_level,
    field_policy,
    field_sensitivity_catalog,
    flow_label_for_origins,
    index_value_origins,
    max_source_level,
    normalize_data_path,
    origins_for_entity_refs,
    tool_output_entity,
)
from ..modeling.graph_db import (
    mark_activity_denied,
    record_task_start,
    update_activity_outcome,
)
from ..modeling.labels import (
    CONFIDENTIALITY_LEVELS,
    aggregate_flow_labels,
    derive_flow_label,
    join_confidentiality,
    make_confidentiality,
    make_flow_label,
    make_injection,
    make_integrity,
)
from ..modeling.sensitive_ner import elevate_policy_for_content
from ..modeling.policy import (
    base_tool_name,
    split_qualified_tool_name,
    tool_effect,
)
from .environment_snapshot import snapshot_environment

# 防御开关（全局，默认开启）
# 关闭后，Analysis Pipeline 的 4 个 Ring 将全部跳过
_defense_enabled = True
_EXPOSED_TOOL_NAME: ContextVar[Optional[str]] = ContextVar(
    "agentdojo_exposed_tool_name",
    default=None,
)


def _task_planning_required(options: Mapping[str, Any] | None = None) -> bool:
    """Return whether either plan consumer currently needs a task contract."""
    return bool(
        (
            effective_ring_enabled("ring_2", options)
            and effective_method_enabled("ring_2", "task_scope", options)
        )
        or (
            effective_ring_enabled("ring_3", options)
            and effective_method_enabled(
                "ring_3",
                "sensitive_egress",
                options,
            )
        )
    )


class PromptInjectionBlockedError(Exception):
    """当防御系统检测到提示注入并阻断工具调用时抛出的异常。
    
    此异常会中断 AgentPipeline 的执行循环，避免 LLM 陷入循环尝试。
    """
    def __init__(self, message: str, block_reason: str = "", tool_intent: str = ""):
        self.block_reason = block_reason
        self.tool_intent = tool_intent
        super().__init__(message)


class TaskStoppedError(Exception):
    """Raised when a structured task stop condition is satisfied."""

    def __init__(self, message: str, stop_reason: str = ""):
        self.stop_reason = stop_reason
        super().__init__(message)


def _l2_egress_execution_requires_manual_retry(effect: Any, error: Any) -> bool:
    """Never let the agent silently repeat a failed L2 external side effect."""
    return bool(
        error
        and getattr(effect, "effect", "") == "egress"
        and getattr(effect, "risk_level", "") == "L2"
    )


@dataclass
class ReasoningContext:
    """Captures the LLM's reasoning (Thought) and decision (Action) for a single step."""
    thought_id: str
    prompt: str  # The prompt sent to the LLM
    response: str  # The LLM's response (thought + action)
    tool_calls: List[Dict[str, Any]] = dataclass_field(default_factory=list)  # Tool calls decided by this reasoning
    timestamp: float = 0.0
    flow_label: Dict[str, Any] = dataclass_field(default_factory=dict)
    context_messages: List[Dict[str, Any]] = dataclass_field(default_factory=list)


class TrackingContext:
    """
    Singleton context that tracks all events across the Agent's execution.
    Maintains the causal chain: LLM Thought -> Tool Calls -> Environment Changes.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(TrackingContext, cls).__new__(cls, *args, **kwargs)
            cls._instance.events: List[Dict[str, Any]] = []
            cls._instance.current_agent_id: str = "AIAgent_Default"
            cls._instance.reasoning_history: List[ReasoningContext] = []
            cls._instance.current_reasoning: Optional[ReasoningContext] = None
            cls._instance.last_environment: Any = None  # Snapshot of environment before current tool call
            cls._instance.task_id: Optional[str] = None
            cls._instance.suite: Optional[str] = None
            cls._instance.user_prompt: Optional[str] = None
            cls._instance.prompt_entity_id: Optional[str] = None
            cls._instance.task_started: bool = False
            cls._instance.task_data_plan_provider: Optional[Callable[[str], str]] = None
            cls._instance.task_data_plan: Optional[Dict[str, Any]] = None
            cls._instance.plan_usage: Dict[str, Any] = {}
            cls._instance.tool_output_labels: Dict[str, Dict[str, Any]] = {}
            cls._instance.message_flow_labels: Dict[str, Dict[str, Any]] = {}
            cls._instance.tool_value_origins: List[ValueOrigin] = []
            cls._instance.tool_value_index: Dict[str, List[ValueOrigin]] = {}
            cls._instance.sensitive_reference_values: Dict[
                str,
                Dict[str, Any],
            ] = {}
            cls._instance.partial_messages: List[Any] = []
        return cls._instance

    def start_task(self, prompt: str, suite: Optional[str] = None) -> None:
        """Start a clean task and persist the trusted user anchor."""
        resolved_suite = suite or self.suite
        from ..analysis.risk_types import clear_risk_identity_cache

        clear_risk_identity_cache()
        self.events = []
        self.task_data_plan = None
        self.plan_usage = {}
        self.tool_output_labels = {}
        self.message_flow_labels = {}
        self.tool_value_origins = []
        self.tool_value_index = {}
        self.sensitive_reference_values = {}
        self.partial_messages = []
        self.reasoning_history = []
        self.current_reasoning = None
        self.last_environment = None
        self.task_id = f"task_{uuid.uuid4().hex[:10]}"
        self.suite = resolved_suite
        self.user_prompt = prompt
        result = record_task_start(
            prompt,
            task_id=self.task_id,
            suite=resolved_suite,
        )
        self.prompt_entity_id = result["prompt_entity_id"]
        self.task_started = True

    def ensure_task(
        self,
        prompt: Optional[str] = None,
        suite: Optional[str] = None,
    ) -> None:
        if not self.task_started:
            self.start_task(prompt or "", suite=suite)
        elif suite:
            app_domains = {"workspace", "banking", "slack", "travel"}
            if not self.suite:
                self.suite = suite
            elif (
                self.suite in app_domains
                and suite in app_domains
                and self.suite != suite
            ):
                self.suite = "unified"
            from ..modeling.graph_db import KnowledgeGraph

            KnowledgeGraph().suite = self.suite

    def set_suite(self, suite: Optional[str]) -> None:
        self.suite = suite or self.suite

    def reset(self) -> None:
        from ..analysis.risk_types import clear_risk_identity_cache

        clear_risk_identity_cache()
        self.events = []
        self.reasoning_history = []
        self.current_reasoning = None
        self.last_environment = None
        self.task_id = None
        self.suite = None
        self.user_prompt = None
        self.prompt_entity_id = None
        self.task_started = False
        self.task_data_plan_provider = None
        self.task_data_plan = None
        self.plan_usage = {}
        self.tool_output_labels = {}
        self.message_flow_labels = {}
        self.tool_value_origins = []
        self.tool_value_index = {}
        self.sensitive_reference_values = {}
        self.partial_messages = []

    def log_event(self, event: Dict[str, Any]):
        """Log an event and pass it to the Analysis Pipeline."""
        self.events.append(event)
        from ..analysis.pipeline import validate_call_event
        validate_call_event(event)

    def set_reasoning_context(
        self,
        prompt: str,
        response: str,
        timestamp: float,
        *,
        flow_label: Optional[Dict[str, Any]] = None,
        context_messages: Optional[List[Dict[str, Any]]] = None,
    ):
        """
        Record the LLM's reasoning context (Thought/Action).
        This creates a new ReasoningContext that subsequent tool calls will be linked to.
        """
        reasoning = ReasoningContext(
            thought_id=f"thought_{uuid.uuid4().hex[:8]}",
            prompt=prompt,
            response=response,
            timestamp=timestamp,
            flow_label=dict(flow_label or {}),
            context_messages=list(context_messages or []),
        )
        self.current_reasoning = reasoning
        self.reasoning_history.append(reasoning)

    def link_tool_call_to_reasoning(self, tool_call_event: Dict[str, Any]):
        """
        Link a tool call to the current reasoning context (wasInformedBy).
        """
        if self.current_reasoning is not None:
            self.current_reasoning.tool_calls.append(tool_call_event)
            tool_call_event["wasInformedBy"] = self.current_reasoning.thought_id
            tool_call_event["thought_prompt"] = self.current_reasoning.prompt
            tool_call_event["thought_response"] = self.current_reasoning.response


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for block in content:
            if isinstance(block, dict):
                value = block.get("content", block.get("text", ""))
                if value:
                    parts.append(str(value))
            elif block is not None:
                parts.append(str(block))
        return "\n".join(parts)
    return str(content)


def _message_content_text(message: Any) -> str:
    """Return the text carried by a chat message, excluding role metadata."""
    if not isinstance(message, dict):
        return ""
    return _content_to_text(message.get("content", ""))


def _plan_step_for_action(
    plan: Any,
    action_name: str,
    plan_usage: Optional[Mapping[str, Any]] = None,
) -> str:
    """Resolve a recorded tool call to its structured plan step."""
    if not isinstance(plan, dict):
        return ""
    matching_steps: list[str] = []
    for step in plan.get("steps", []):
        if not isinstance(step, Mapping):
            continue
        for action in step.get("actions", []):
            if not isinstance(action, Mapping):
                continue
            candidate = str(action.get("name", ""))
            if (
                candidate == action_name
                or (
                    "__" not in candidate
                    and "__" not in action_name
                    and base_tool_name(candidate)
                    == base_tool_name(action_name)
                )
            ):
                matching_steps.append(str(step.get("id", "")))
    if not matching_steps:
        return ""
    attempt_count = 0
    if isinstance(plan_usage, Mapping):
        attempt_count = sum(
            1
            for item in plan_usage.get("action_results", [])
            if isinstance(item, Mapping)
            and item.get("status") == "success"
            and item.get("has_result_evidence", True)
            and (
                str(item.get("action", "")) == action_name
                or (
                    "__" not in str(item.get("action", ""))
                    and "__" not in action_name
                    and base_tool_name(str(item.get("action", "")))
                    == base_tool_name(action_name)
                )
            )
        )
    return matching_steps[min(attempt_count, len(matching_steps) - 1)]


def _result_has_action_evidence(
    result: Any,
    *,
    error: Optional[str],
    effect: str,
    environment_changed: bool = False,
) -> bool:
    """Require an observable result before marking a step as completed."""
    if error:
        return False
    if effect in {"write", "privilege", "egress"}:
        if environment_changed:
            return True
        if result is None:
            return False
    if result is None:
        return False
    if isinstance(result, bool):
        return result
    if isinstance(result, (list, tuple, set, dict)):
        return bool(result)
    if isinstance(result, str):
        return result.strip() not in {"", "[]", "{}", "null", "None"}
    return True


def _restore_environment(
    environment: Any,
    snapshot: Any,
) -> bool:
    """Restore an in-place mutable environment after a failed tool call."""
    if environment is None or snapshot is None:
        return False
    if not hasattr(environment, "__dict__") or not hasattr(snapshot, "__dict__"):
        return False
    try:
        environment.__dict__.clear()
        environment.__dict__.update(copy.deepcopy(snapshot.__dict__))
        return True
    except Exception:
        return False


def _refresh_completed_plan_steps(
    ctx: "TrackingContext",
    *,
    step_id: str,
    action_name: str,
    result: Any,
    error: Optional[str],
    effect: str,
    environment_delta: Optional[Mapping[str, Any]] = None,
) -> None:
    """Record action evidence and complete a step only after all required actions."""
    plan = ctx.task_data_plan
    if not step_id or not isinstance(plan, dict):
        return
    action_results = ctx.plan_usage.setdefault("action_results", [])
    action_results.append(
        {
            "step_id": step_id,
            "action": action_name,
            "status": "error" if error else "success",
            "has_result_evidence": _result_has_action_evidence(
                result,
                error=error,
                effect=effect,
                environment_changed=bool(environment_delta),
            ),
            "error": error or "",
        }
    )
    step = next(
        (
            item
            for item in plan.get("steps", [])
            if isinstance(item, dict) and str(item.get("id")) == step_id
        ),
        None,
    )
    if step is None:
        return
    required_actions = [
        str(action.get("name"))
        for action in step.get("actions", [])
        if isinstance(action, dict)
        and action.get("name")
        and action.get("necessity") != "fallback"
    ]
    evidenced_actions = {
        str(item.get("action"))
        for item in action_results
        if str(item.get("step_id")) == step_id
        and item.get("status") == "success"
        and item.get("has_result_evidence")
    }

    def evidenced(required_action: str) -> bool:
        return any(
            candidate == required_action
            or (
                "__" not in candidate
                and "__" not in required_action
                and base_tool_name(candidate)
                == base_tool_name(required_action)
            )
            for candidate in evidenced_actions
        )

    completed = ctx.plan_usage.setdefault("completed_steps", [])
    if required_actions and all(evidenced(action) for action in required_actions):
        if step_id not in completed:
            completed.append(step_id)
    elif step_id in completed:
        completed.remove(step_id)


def _record_successful_planned_action(
    ctx: "TrackingContext",
    action_name: str,
) -> None:
    """Consume an L2 grant only after the tool returns without error."""
    if not isinstance(ctx.plan_usage, dict):
        return
    counts = ctx.plan_usage.setdefault("planned_action_counts", {})
    if not isinstance(counts, dict):
        counts = {}
        ctx.plan_usage["planned_action_counts"] = counts
    counts[action_name] = int(counts.get(action_name, 0) or 0) + 1


def _stop_condition_steps_terminal(
    plan: dict[str, Any],
    stop_condition: Mapping[str, Any],
    plan_usage: Mapping[str, Any],
) -> bool:
    """Return whether every step needed to evaluate a stop has finished."""
    raw_step_ids = stop_condition.get("step_ids", [])
    if not isinstance(raw_step_ids, list):
        return False
    step_ids = [str(item) for item in raw_step_ids if str(item).strip()]
    if not step_ids:
        return False
    results = plan_usage.get("action_results", [])
    if not isinstance(results, list):
        return False
    attempted_by_step: dict[str, set[str]] = {}
    for result in results:
        if not isinstance(result, Mapping):
            continue
        step_id = str(result.get("step_id") or "")
        action_name = str(result.get("action") or "")
        if step_id and action_name and result.get("status") in {
            "success",
            "error",
        }:
            attempted_by_step.setdefault(step_id, set()).add(action_name)
    steps = {
        str(step.get("id")): step
        for step in plan.get("steps", [])
        if isinstance(step, Mapping) and step.get("id")
    }

    def same_action(left: str, right: str) -> bool:
        return left == right or (
            "__" not in left
            and "__" not in right
            and base_tool_name(left) == base_tool_name(right)
        )

    for step_id in step_ids:
        step = steps.get(step_id)
        if not isinstance(step, Mapping):
            return False
        required_actions = [
            str(action.get("name"))
            for action in step.get("actions", [])
            if isinstance(action, Mapping)
            and action.get("name")
            and action.get("necessity") != "fallback"
        ]
        if not required_actions:
            return False
        attempted = attempted_by_step.get(step_id, set())
        if not all(
            any(same_action(action, candidate) for candidate in attempted)
            for action in required_actions
        ):
            return False
    return True


def _serialize_messages(messages: Sequence[Any]) -> List[Dict[str, Any]]:
    """Serialize the actual chat context without losing message provenance."""
    serialized: List[Dict[str, Any]] = []
    for index, message in enumerate(messages or []):
        if isinstance(message, dict):
            role = str(message.get("role", "unknown"))
            content = _content_to_text(message.get("content", ""))
            tool_call = message.get("tool_call")
            tool_name = ""
            tool_call_id = message.get("tool_call_id")
            if tool_call is not None:
                tool_name = str(getattr(tool_call, "function", "") or "")
            elif isinstance(message.get("tool_calls"), list):
                tool_names = []
                for call in message["tool_calls"]:
                    names = getattr(call, "function", None)
                    if names:
                        tool_names.append(str(names))
                tool_name = ",".join(tool_names)
            serialized.append(
                {
                    "index": index,
                    "role": role,
                    "content": content,
                    "content_hash": hashlib.sha256(
                        content.encode("utf-8", errors="replace")
                    ).hexdigest()[:16],
                    "tool_name": tool_name,
                    "tool_call_id": tool_call_id,
                }
            )
        else:
            serialized.append(
                {
                    "index": index,
                    "role": "unknown",
                    "content": str(message),
                    "content_hash": hashlib.sha256(
                        str(message).encode("utf-8", errors="replace")
                    ).hexdigest()[:16],
                }
            )
    return serialized


def _extract_tool_calls(messages: Sequence[Any]) -> List[Dict[str, Any]]:
    """Extract assistant tool calls without changing provider objects."""
    if not messages:
        return []
    last = messages[-1]
    if not isinstance(last, dict) or last.get("role") != "assistant":
        return []
    calls = last.get("tool_calls") or []
    if not isinstance(calls, (list, tuple)):
        return []
    result: List[Dict[str, Any]] = []
    for call in calls:
        if isinstance(call, dict):
            function = call.get("function", "")
            if isinstance(function, dict):
                function = function.get("name", "")
            name = str(function or "")
            args = call.get("args") or call.get("arguments") or {}
        else:
            name = str(getattr(call, "function", "") or "")
            args = getattr(call, "args", {}) or {}
        if name:
            result.append(
                {
                    "name": name,
                    "args": dict(args) if isinstance(args, dict) else {},
                }
            )
    return result


def _has_unplanned_tool_call(
    plan: Dict[str, Any] | None,
    tool_calls: Sequence[Dict[str, Any]],
) -> bool:
    """Return whether any proposed call is outside the current action scope."""
    if not isinstance(plan, dict):
        return False
    allowed = [
        str(item)
        for item in plan.get("allowed_actions", [])
        if item
    ]

    def planned(call_name: str) -> bool:
        for allowed_name in allowed:
            if call_name == allowed_name:
                return True
            if (
                "__" not in call_name
                and "__" not in allowed_name
                and base_tool_name(call_name) == base_tool_name(allowed_name)
            ):
                return True
        return False

    return any(
        not planned(str(call.get("name", "")))
        for call in tool_calls
        if call.get("name")
    )


def _replace_user_prompt_text(
    messages: Sequence[Any],
    original: str,
    sanitized: str,
) -> Sequence[Any]:
    """Replace only matching user text blocks before invoking the Agent LLM."""
    if original == sanitized:
        return messages

    def replace_content(content: Any) -> Any:
        if isinstance(content, str):
            return content.replace(original, sanitized)
        if isinstance(content, list):
            updated = []
            for block in content:
                if isinstance(block, dict):
                    child = dict(block)
                    for key in ("content", "text"):
                        value = child.get(key)
                        if isinstance(value, str):
                            child[key] = value.replace(original, sanitized)
                    updated.append(child)
                else:
                    updated.append(block)
            return updated
        return content

    replaced = []
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "user":
            child = dict(message)
            child["content"] = replace_content(child.get("content", ""))
            replaced.append(child)
        else:
            replaced.append(message)
    return replaced


def _inject_security_placeholder_notice(messages: Sequence[Any]) -> Sequence[Any]:
    """Add a trusted system-level explanation when sanitized content is present."""
    if not any(
        contains_security_placeholder(_message_content_text(message))
        for message in messages
        if isinstance(message, dict)
    ):
        return messages

    for index, message in enumerate(messages):
        if not isinstance(message, dict) or message.get("role") != "system":
            continue
        if SECURITY_PLACEHOLDER_NOTICE in _message_content_text(message):
            return messages
        updated = dict(message)
        content = updated.get("content", [])
        if isinstance(content, list):
            updated["content"] = [
                *content,
                text_content_block_from_string(
                    "\n\n" + SECURITY_PLACEHOLDER_NOTICE
                ),
            ]
        else:
            updated["content"] = (
                _content_to_text(content)
                + "\n\n"
                + SECURITY_PLACEHOLDER_NOTICE
            )
        result = list(messages)
        result[index] = updated
        return result

    return [
        ChatSystemMessage(
            role="system",
            content=[
                text_content_block_from_string(SECURITY_PLACEHOLDER_NOTICE)
            ],
        ),
        *messages,
    ]


def _inject_parameter_binding_notice(
    messages: Sequence[Any],
    plan: Optional[Dict[str, Any]],
) -> Sequence[Any]:
    """Explain controller-owned provenance constraints to the Agent."""
    notice = placeholder_notice(plan)
    retained = [
        message
        for message in messages
        if not (
            isinstance(message, dict)
            and message.get("role") == "system"
            and _message_content_text(message)
            .strip()
            .startswith(PLACEHOLDER_NOTICE_PREFIX)
        )
    ]
    if not notice:
        return retained
    return [
        ChatSystemMessage(
            role="system",
            content=[text_content_block_from_string(notice)],
        ),
        *retained,
    ]


def _inject_task_plan_notice(
    messages: Sequence[Any],
    plan: Optional[Dict[str, Any]],
) -> Sequence[Any]:
    """Inject the latest controller-owned plan and remove stale versions."""
    from ..analysis.data_need import (
        TASK_PLAN_NOTICE_PREFIX,
        task_plan_notice,
    )

    notice = task_plan_notice(plan)
    retained = [
        message
        for message in messages
        if not (
            isinstance(message, dict)
            and message.get("role") == "system"
            and _message_content_text(message)
            .strip()
            .startswith(TASK_PLAN_NOTICE_PREFIX)
        )
    ]
    if not notice:
        return retained
    return [
        ChatSystemMessage(
            role="system",
            content=[text_content_block_from_string(notice)],
        ),
        *retained,
    ]


def _argument_flow_labels(
    inputs: Dict[str, Any],
    *,
    value_index: Dict[str, List[ValueOrigin]],
    parameter_resolutions: Sequence[Dict[str, Any]],
    destination_parameters: set[str] | None = None,
) -> tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    labels: Dict[str, Dict[str, Any]] = {}
    sources: List[Dict[str, Any]] = []
    destination_parameters = destination_parameters or set()
    all_origins = [
        origin
        for records in value_index.values()
        for origin in records
    ]
    resolution_by_parameter = {
        str(item.get("parameter", "")): item
        for item in parameter_resolutions
        if isinstance(item, dict)
    }
    for name, value in inputs.items():
        resolution = resolution_by_parameter.get(str(name), {})
        source_refs = [
            item
            for item in resolution.get("source_refs", [])
            if isinstance(item, dict)
        ]
        if any(
            str(item.get("source_kind", "")).lower() == "user_prompt"
            for item in source_refs
        ):
            labels[str(name)] = make_flow_label(
                confidentiality=make_confidentiality(
                    level="internal",
                    source_entities=["user_prompt"],
                ),
                data_influence=True,
                control_influence=True,
            )
            sources.append(
                {
                    "argument_root": str(name),
                    "source_kind": "user_prompt",
                    "source_app": "system",
                    "source_entity": "user_prompt",
                    "source": "user_prompt",
                    "source_risk": False,
                    "risky_entities": [],
                }
            )
            continue

        resolved_origins, _invalid = origins_for_entity_refs(
            all_origins,
            source_refs,
        )
        source_paths = {
            str(item)
            for item in resolution.get("source_paths", [])
            if item
        }
        if source_paths:
            resolved_origins = [
                origin
                for origin in resolved_origins
                if origin.source_path in source_paths
            ]
        origins = resolved_origins
        if origins:
            labels[str(name)] = flow_label_for_origins(
                origins,
                control_influence=True,
            )
        else:
            provenance_refs = [
                item
                for item in resolution.get("provenance_refs", [])
                if isinstance(item, dict)
            ]
            if provenance_refs:
                confidentiality = join_confidentiality(
                    [
                        make_confidentiality(
                            level=str(
                                item.get("confidentiality", "secret")
                            ),
                            categories=item.get("categories", []),
                            source_ids=[
                                f"{item.get('activity_id', '')}:"
                                f"{item.get('source_path', '')}"
                            ],
                            source_entities=[
                                f"{item.get('app', '')}:"
                                f"{item.get('entity', '')}"
                            ],
                        )
                        for item in provenance_refs
                    ]
                )
                labels[str(name)] = make_flow_label(
                    confidentiality=confidentiality,
                    integrity=make_integrity(kind="trusted"),
                    data_influence=True,
                    control_influence=True,
                )
                for item in provenance_refs:
                    sources.append(
                        {
                            "argument_root": str(name),
                            "source_kind": "tool_output",
                            "source_app": str(item.get("app", "")),
                            "source_entity": str(
                                item.get("entity", "")
                            ),
                            "source": (
                                f"{item.get('app', '')}:"
                                f"{item.get('entity', '')}"
                            ),
                            "source_path": str(
                                item.get("source_path", "")
                            ),
                            "source_risk": False,
                            "risky_entities": [],
                        }
                    )
            else:
                from_user = str(name) in destination_parameters
                labels[str(name)] = make_flow_label(
                    confidentiality=make_confidentiality(
                        level="internal",
                        source_entities=(
                            ["user_prompt"] if from_user else []
                        ),
                    ),
                    integrity=make_integrity(kind="trusted"),
                    data_influence=True,
                    control_influence=True,
                )
            if not provenance_refs and from_user:
                sources.append(
                    {
                        "argument_root": str(name),
                        "source_kind": "user_prompt",
                        "source_app": "system",
                        "source_entity": "user_prompt",
                        "source": "user_prompt",
                        "source_risk": False,
                        "risky_entities": [],
                    }
                )
            elif not provenance_refs:
                sources.append(
                    {
                        "argument_root": str(name),
                        "source_kind": "agent_literal",
                        "source_app": "system",
                        "source_entity": "agent",
                        "source": "agent",
                        "source_risk": False,
                        "risky_entities": [],
                    }
                )
        for origin in origins:
            item = origin.to_dict()
            item["argument_root"] = str(name)
            sources.append(item)
    return labels, sources


def _context_flow_labels(
    context: Sequence[Dict[str, Any]],
    task_id: str,
    tool_output_labels: Optional[Dict[str, Dict[str, Any]]] = None,
    message_flow_labels: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    labels: List[Dict[str, Any]] = []
    for message in context:
        role = message.get("role")
        if role in {"system", "user", "assistant"}:
            source_kind = "system_prompt" if role == "system" else "user_prompt"
            if role == "assistant":
                source_kind = "agent"
        else:
            source_kind = "tool_output"
        cached_label = None
        if source_kind == "tool_output":
            cached_label = (tool_output_labels or {}).get(
                str(message.get("content_hash", ""))
            )
            if cached_label is None and message.get("tool_name"):
                cached_label = (tool_output_labels or {}).get(
                    f"tool:{message.get('tool_name')}"
                )
        elif source_kind == "agent":
            cached_label = (message_flow_labels or {}).get(
                str(message.get("content_hash", ""))
            )
        if cached_label is not None:
            labels.append(dict(cached_label))
            continue
        fallback_label = derive_flow_label(
            [],
            source_kind=source_kind,
            content=message.get("content", ""),
            source_id=f"{task_id}:{role}:{message.get('index')}",
            control_influence=role in {"system", "user"},
        )
        if source_kind == "tool_output":
            tool_name = str(message.get("tool_name") or "")
            policy = tool_effect(tool_name)
            entity = tool_output_entity(tool_name)
            suite = (
                tool_name.split("__", 1)[0]
                if "__" in tool_name
                else (domain_for_tool(tool_name) or "")
            )
            entity_level_value = (
                entity_level(suite, entity)
                if suite and entity
                else "public"
            )
            policy_level = (
                policy.confidentiality
                if policy.effect != "unknown"
                else "secret"
            )
            fallback_label["confidentiality"] = join_confidentiality(
                [
                    make_confidentiality(
                        level=entity_level_value,
                        source_entities=(
                            [entity_source(suite, entity)]
                            if suite and entity
                            else []
                        ),
                    ),
                    make_confidentiality(
                        level=policy_level,
                        categories=policy.categories,
                    ),
                ]
            )
        if (
            role in {"user", "tool"}
            and contains_security_placeholder(
                str(message.get("content") or "")
            )
        ):
            fallback_label["injection"] = make_injection(
                source_flagged=True,
                evidence_refs=[
                    f"context:{task_id}:{message.get('index')}"
                ],
                flagged_fields=["$"],
                quarantined_fields=["$"],
                risky_entities=["$"],
            )
        labels.append(fallback_label)
    return labels


def _infer_suite_from_environment(environment: Any) -> Optional[str]:
    """Infer the active AgentDojo suite without importing task-suite modules."""
    if environment is None:
        return None
    name = type(environment).__name__.lower()
    for suite in ("banking", "workspace", "slack", "travel"):
        if suite in name:
            return suite
    return None


def _apply_schema_semantic_types(
    schema: dict[str, Any],
    semantic_types: Mapping[str, str],
) -> dict[str, Any]:
    """Attach declarative semantic types to structured output schema paths."""
    result = copy.deepcopy(schema)
    for raw_path, raw_semantic_type in semantic_types.items():
        path = str(raw_path or "")
        semantic_type = str(raw_semantic_type or "").strip()
        if not path.startswith("$") or not semantic_type:
            continue
        node: Any = result
        rest = path[1:]
        valid = True
        while rest:
            if rest.startswith("[*]"):
                if not isinstance(node, dict):
                    valid = False
                    break
                node = node.setdefault("items", {})
                rest = rest[3:]
            elif rest.startswith("."):
                name, separator, tail = rest[1:].partition(".")
                if not name or not isinstance(node, dict):
                    valid = False
                    break
                fields = node.setdefault("fields", {})
                if not isinstance(fields, dict):
                    valid = False
                    break
                field_schema = fields.setdefault(name, {})
                if not isinstance(field_schema, dict):
                    valid = False
                    break
                node = field_schema.setdefault("type_schema", {})
                rest = (
                    f".{tail}"
                    if separator
                    else tail
                )
            else:
                valid = False
                break
        if valid and isinstance(node, dict):
            node["semantic_type"] = semantic_type
    return result


def _build_tool_catalog(runtime: Any) -> List[Dict[str, Any]]:
    """Describe available tools for task-level planning without data values."""
    functions = getattr(runtime, "functions", {}) or {}
    if not isinstance(functions, dict):
        return []
    from ..analysis.access_plan import schema_for_type

    field_catalog = field_sensitivity_catalog()
    tool_app_map = {}
    if hasattr(runtime, "tool_app_map"):
        try:
            tool_app_map = runtime.tool_app_map() or {}
        except Exception:
            tool_app_map = {}
    catalog = []
    for name, function in functions.items():
        parameters = getattr(function, "parameters", None)
        policy = tool_effect(str(name))
        qualified_suite, base_name = split_qualified_tool_name(str(name))
        tool_suite = (
            qualified_suite
            or str(tool_app_map.get(str(name), "") or "")
            or domain_for_tool(base_name)
            or ""
        )
        output_entity = tool_output_entity(str(name))
        output_entity_policies = (
            field_catalog.get(tool_suite, {}).get(output_entity, {})
        )
        input_schema = (
            schema_for_type(parameters)
            if parameters is not None
            else {"type": "unknown"}
        )
        role_sets: dict[str, set[str]] = {
            field_name: {"control"}
            for field_name in policy.control_fields
        }
        for field_name in policy.content_fields:
            role_sets.setdefault(field_name, set()).add("presentation")
        for field_name in policy.destination_fields:
            role_sets.setdefault(field_name, set()).add("destination")
        for field_name in policy.authoritative_parameters:
            role_sets.setdefault(field_name, set()).add("control")
        for field_name, role in policy.parameter_roles.items():
            role_sets.setdefault(field_name, set()).add(str(role))
        parameter_roles: dict[str, str] = {}
        for field_name, roles in role_sets.items():
            if field_name in policy.parameter_roles:
                parameter_roles[field_name] = policy.parameter_roles[
                    field_name
                ]
            elif "destination" in roles:
                parameter_roles[field_name] = "destination"
            elif "value" in roles:
                parameter_roles[field_name] = "value"
            elif "control" in roles:
                parameter_roles[field_name] = "control"
            elif "presentation" in roles:
                parameter_roles[field_name] = "presentation"
            else:
                parameter_roles[field_name] = "input"
        schema_fields = input_schema.get("fields", {})
        if isinstance(schema_fields, dict):
            for field_name, field_schema in schema_fields.items():
                if isinstance(field_schema, dict):
                    field_schema["role"] = parameter_roles.get(
                        str(field_name),
                        "input",
                    )
                    field_schema["roles"] = sorted(
                        role_sets.get(str(field_name), {"input"})
                    )
                    if field_name in policy.semantic_types:
                        field_schema["semantic_type"] = policy.semantic_types[
                            str(field_name)
                        ]
        output_schema = _apply_schema_semantic_types(
            schema_for_type(getattr(function, "return_type", None)),
            policy.output_semantic_types,
        )
        catalog.append(
            {
                "name": str(name),
                "suite": tool_suite,
                "description": str(
                    getattr(function, "description", "") or ""
                )[:1000],
                "effect": policy.effect,
                "risk_level": policy.risk_level,
                "confidentiality": policy.confidentiality,
                "categories": sorted(policy.categories),
                "control_fields": sorted(policy.control_fields),
                "resource_fields": sorted(policy.resource_fields),
                "destination_fields": sorted(policy.destination_fields),
                "content_fields": sorted(policy.content_fields),
                "parameter_roles": parameter_roles,
                "implicit_egress": [
                    dict(item) for item in policy.implicit_egress
                ],
                "authoritative_parameters": {
                    key: dict(value)
                    for key, value in policy.authoritative_parameters.items()
                },
                "dynamic_entity_map": bool(
                    policy.dynamic_entity_map
                ),
                "content_detection": bool(
                    policy.content_detection
                ),
                "input_schema": input_schema,
                "output_schema": output_schema,
                "output_entity": output_entity,
                "output_entity_fields": sorted(
                    output_entity_policies.keys()
                ),
                "output_entity_field_levels": {
                    path: str(policy.get("level", "secret")).lower()
                    for path, policy in output_entity_policies.items()
                },
            }
        )
    return catalog


def capture_llm_interaction(func: Callable):
    """
    Interceptor for LLM query methods.
    Captures the prompt sent to the LLM and the response (Thought/Action).
    Binds the reasoning context for subsequent tool calls.
    
    This should wrap BasePipelineElement.query() methods that call LLMs.
    """
    @functools.wraps(func)
    def wrapper(self, query: str, runtime: Any, env: Any = None, 
                messages: Sequence[Any] = [], extra_args: dict = {}) -> Tuple:
        start_time = time.time()
        ctx = TrackingContext()
        current_options = get_config()
        ctx.ensure_task(query, suite=_infer_suite_from_environment(env))
        if ctx.task_data_plan_provider is None:
            try:
                from ..analysis.data_need import make_pipeline_task_planner

                ctx.task_data_plan_provider = make_pipeline_task_planner(self)
            except Exception:
                ctx.task_data_plan_provider = None
        prompt = query
        raw_context_messages = _serialize_messages(messages)
        ctx.partial_messages = list(messages)

        _ring0_diagnostics = {}
        risk_assessments: List[Dict[str, Any]] = []
        injection_scan = None
        if (
            _defense_enabled
            and effective_ring_enabled("ring_0", current_options)
            and effective_method_enabled(
                "ring_0",
                "small_model",
                current_options,
            )
        ):
            from ..analysis.injection_scanner import get_injection_scanner

            scan = get_injection_scanner().scan(prompt)
            injection_scan = scan.to_dict()
            injection_scan["evidence_spans"] = [
                chunk.text[:300] for chunk in scan.chunks[:8]
            ]
        if _defense_enabled:
            llm_event = {
                "timestamp": start_time,
                "type": "llm_interaction",
                "prompt": prompt,
                "task_id": ctx.task_id,
                "suite": ctx.suite,
                "injection_scan": injection_scan,
            }
            allow, _, defense_diagnostics, _ = process_before_execution(
                llm_event,
                prompt=prompt,
                options=current_options,
            )
            _ring0_diagnostics = defense_diagnostics.get("ring_0", {})
            risk_assessments = list(llm_event.get("risk_assessments", []))
            if not allow:
                block_reason = llm_event.get('block_reason', "Ring 0: Prompt injection detected in user input.")
                risk = make_risk(
                    0,
                    DECISION_BLOCK,
                    block_reason,
                    severity="high",
                    policy_id="ring0.user_input.injection",
                    source_ids=[ctx.prompt_entity_id or "user_prompt"],
                    fsm_before="CONTEXT_READY",
                    fsm_after="BLOCKED",
                )
                llm_event["risk_assessments"] = [risk]
                from ..modeling.graph_db import record_risk_assessments, transition_state
                record_risk_assessments(llm_event, [risk])
                transition_state(
                    activity_id=None,
                    state_name="BLOCKED",
                    reason=block_reason,
                    risk_ids=[risk["risk_id"]],
                    suffix="ring0",
                )
                ctx.log_event(llm_event)
                raise PromptInjectionBlockedError(
                    "Prompt contains injection instructions.",
                    block_reason=block_reason,
                    tool_intent="",
                )
            effective_prompt = str(
                _ring0_diagnostics.get("sanitized_prompt", prompt)
            )
            effective_messages = _replace_user_prompt_text(
                messages,
                prompt,
                effective_prompt,
            )
            effective_messages = _inject_security_placeholder_notice(
                effective_messages
            )
            context_messages = _serialize_messages(effective_messages)
            context_labels = _context_flow_labels(
                context_messages,
                ctx.task_id or "task",
                ctx.tool_output_labels,
                ctx.message_flow_labels,
            )
            context_flow_label = aggregate_flow_labels(
                context_labels,
                generated=True,
                control_influence=True,
            )
            if (
                _task_planning_required(current_options)
                and ctx.task_data_plan is None
            ):
                from ..analysis.data_need import generate_task_data_plan

                ctx.task_data_plan = generate_task_data_plan(
                    effective_prompt,
                    ctx.task_data_plan_provider,
                    available_tools=_build_tool_catalog(runtime),
                )
                ctx.plan_usage = {
                    "planned_action_counts": {},
                    "completed_steps": [],
                }
                llm_event["task_data_plan"] = ctx.task_data_plan
            if ctx.task_data_plan is not None:
                effective_messages = _inject_parameter_binding_notice(
                    effective_messages,
                    ctx.task_data_plan,
                )
                effective_messages = _inject_task_plan_notice(
                    effective_messages,
                    ctx.task_data_plan,
                )
                context_messages = _serialize_messages(effective_messages)
                context_labels = _context_flow_labels(
                    context_messages,
                    ctx.task_id or "task",
                    ctx.tool_output_labels,
                    ctx.message_flow_labels,
                )
                context_flow_label = aggregate_flow_labels(
                    context_labels,
                    generated=True,
                    control_influence=True,
                )
        else:
            effective_prompt = prompt
            effective_messages = _inject_security_placeholder_notice(messages)
            context_messages = raw_context_messages
            context_labels = _context_flow_labels(
                context_messages,
                ctx.task_id or "task",
                ctx.tool_output_labels,
                ctx.message_flow_labels,
            )
            context_flow_label = aggregate_flow_labels(
                context_labels,
                generated=True,
                control_influence=True,
            )

        result = func(
            self,
            effective_prompt,
            runtime,
            env,
            effective_messages,
            extra_args,
        )
        response_text = ""
        final_response_audit: Optional[Dict[str, Any]] = None
        plan_updates: List[Dict[str, Any]] = []
        plan_update_warnings: List[str] = []
        if len(result) >= 4:
            updated_messages = result[3]
            ctx.partial_messages = list(updated_messages or [])
            if updated_messages and len(updated_messages) > 0:
                last_msg = updated_messages[-1]
                if isinstance(last_msg, dict):
                    content = last_msg.get("content", "")
                    response_text = _content_to_text(content)
                tool_calls = _extract_tool_calls(updated_messages)
                if (
                    not tool_calls
                    and response_text
                    and isinstance(ctx.task_data_plan, dict)
                    and ctx.task_data_plan_provider is not None
                ):
                    from ..analysis.outcome_audit import (
                        audit_final_response_claims,
                    )

                    final_response_audit = audit_final_response_claims(
                        user_prompt=effective_prompt,
                        plan=ctx.task_data_plan,
                        events=ctx.events,
                        final_response=response_text,
                        provider=ctx.task_data_plan_provider,
                    )
                    ctx.plan_usage["final_response_audit"] = (
                        final_response_audit
                    )
                    if (
                        final_response_audit.get("applicable")
                        and not final_response_audit.get("safe")
                    ):
                        corrected_response = str(
                            final_response_audit.get(
                                "corrected_response"
                            )
                            or ""
                        ).strip()
                        if not corrected_response:
                            corrected_response = (
                                "任务执行流程已结束，但最终回答包含未通过"
                                "证据校验的表述，已停止展示原文。请查看"
                                "完成审计和溯源图谱。"
                            )
                        corrected_audit = audit_final_response_claims(
                            user_prompt=effective_prompt,
                            plan=ctx.task_data_plan,
                            events=ctx.events,
                            final_response=corrected_response,
                            provider=ctx.task_data_plan_provider,
                        )
                        ctx.plan_usage[
                            "final_response_correction_audit"
                        ] = corrected_audit
                        if (
                            corrected_audit.get("applicable")
                            and not corrected_audit.get("safe")
                        ):
                            corrected_response = (
                                "任务执行流程已结束，但修正后的回答仍未通过"
                                "证据校验，已停止展示文本。请查看完成审计和"
                                "溯源图谱。"
                            )
                        response_text = corrected_response
                        if isinstance(last_msg, dict):
                            last_msg["content"] = [
                                text_content_block_from_string(
                                    corrected_response
                                )
                            ]
                if (
                    tool_calls
                    and isinstance(ctx.task_data_plan, dict)
                    and ctx.task_data_plan.get("stop_conditions")
                    and ctx.events
                    and not ctx.task_data_plan.get("execution_stop")
                    and ctx.task_data_plan_provider is not None
                ):
                    from ..analysis.outcome_audit import audit_task_outcomes

                    stop_assessment = audit_task_outcomes(
                        plan=ctx.task_data_plan,
                        events=ctx.events,
                        final_response=response_text,
                        provider=ctx.task_data_plan_provider,
                    )
                    triggered_stops = stop_assessment.get(
                        "stop_conditions",
                        [],
                    )
                    terminal_stops = []
                    deferred_stops = []
                    for item in triggered_stops:
                        if not item.get("step_ids"):
                            continue
                        if _stop_condition_steps_terminal(
                            ctx.task_data_plan,
                            item,
                            ctx.plan_usage,
                        ):
                            terminal_stops.append(item)
                        else:
                            deferred_stops.append(item)
                    triggered_stops = terminal_stops
                    if deferred_stops:
                        ctx.plan_usage["deferred_stop_conditions"] = (
                            deferred_stops
                        )
                    else:
                        ctx.plan_usage.pop(
                            "deferred_stop_conditions",
                            None,
                        )
                    if triggered_stops:
                        stop_record = {
                            **triggered_stops[0],
                            "assessment": stop_assessment,
                        }
                        from ..analysis.data_need import _finalize_plan

                        stopped_plan = copy.deepcopy(ctx.task_data_plan)
                        stopped_plan["parent_plan_id"] = str(
                            stopped_plan.get("plan_id", "")
                        )
                        stopped_plan["plan_revision"] = int(
                            stopped_plan.get("plan_revision", 1) or 1
                        ) + 1
                        stopped_plan["execution_stop"] = stop_record
                        stopped_plan.setdefault(
                            "runtime_updates",
                            [],
                        ).append(
                            stop_update := {
                                "revision": stopped_plan["plan_revision"],
                                "operation": "stop_task",
                                "stop_condition_id": stop_record.get("id", ""),
                                "reason": stop_record.get("reason", ""),
                                "trigger": "structured_outcome_audit",
                            }
                        )
                        ctx.task_data_plan = _finalize_plan(stopped_plan)
                        ctx.plan_usage["execution_stop"] = stop_record
                        plan_updates.append(stop_update)
                if (
                    tool_calls
                    and ctx.task_data_plan is not None
                    and not ctx.task_data_plan.get("execution_stop")
                    and effective_method_enabled(
                        "ring_2",
                        "task_scope",
                        current_options,
                    )
                    and _has_unplanned_tool_call(
                        ctx.task_data_plan,
                        tool_calls,
                    )
                ):
                    from ..analysis.data_need import (
                        compile_runtime_scope_update,
                        generate_runtime_plan_update,
                    )

                    catalog = _build_tool_catalog(runtime)
                    (
                        updated_plan,
                        plan_updates,
                        plan_update_warnings,
                    ) = generate_runtime_plan_update(
                        effective_prompt,
                        ctx.task_data_plan,
                        response_text,
                        tool_calls,
                        ctx.task_data_plan_provider,
                        catalog,
                        execution_context=context_messages,
                    )
                    if updated_plan is not None:
                        ctx.task_data_plan = updated_plan
                    (
                        ctx.task_data_plan,
                        scope_updates,
                        scope_warnings,
                    ) = compile_runtime_scope_update(
                        ctx.task_data_plan,
                        tool_calls,
                        catalog,
                        completed_steps=list(
                            (
                                ctx.plan_usage.get(
                                    "completed_steps",
                                    [],
                                )
                                if isinstance(ctx.plan_usage, dict)
                                else []
                            )
                        ),
                        reason=response_text,
                    )
                    plan_updates.extend(scope_updates)
                    plan_update_warnings.extend(scope_warnings)

        response_label = derive_flow_label(
            [context_flow_label],
            source_kind="agent",
            content=response_text,
            source_id=f"response:{uuid.uuid4().hex[:8]}",
            control_influence=True,
        )
        ctx.set_reasoning_context(
            effective_prompt,
            response_text,
            start_time,
            flow_label=response_label,
            context_messages=context_messages,
        )
        response_hash = hashlib.sha256(
            response_text.encode("utf-8", errors="replace")
        ).hexdigest()[:16]
        ctx.message_flow_labels[response_hash] = copy.deepcopy(
            response_label
        )

        llm_event = {
            "timestamp": start_time,
            "agent_id": ctx.current_agent_id,
            "type": "llm_interaction",
            "prompt": effective_prompt,
            "raw_prompt": prompt,
            "prompt_modified": effective_prompt != prompt,
            "response": response_text,
            "task_id": ctx.task_id,
            "suite": ctx.suite,
            "thought_id": ctx.current_reasoning.thought_id if ctx.current_reasoning else None,
            "context_messages": context_messages,
            "raw_context_messages": raw_context_messages,
            "context_flow_labels": context_labels,
            "flow_label": response_label,
            "risk_assessments": risk_assessments,
            "injection_scan": injection_scan,
            "plan_updates": plan_updates,
            "plan_update_warnings": plan_update_warnings,
            "final_response_audit": (
                final_response_audit
            ),
            "task_data_plan": (
                ctx.task_data_plan
                if _task_planning_required(current_options)
                else None
            ),
            "defense_diagnostics": {
                "before": {"ring_0": _ring0_diagnostics},
            },
        }
        ctx.log_event(llm_event)
        
        # Record to graph DB
        from ..modeling.graph_db import record_llm_interaction, record_risk_assessments
        record_llm_interaction(llm_event)
        if llm_event.get("risk_assessments"):
            record_risk_assessments(llm_event, llm_event["risk_assessments"])

        return result
    
    return wrapper


def _get_function_description(runtime: Any, function_name: str) -> str:
    """从 FunctionsRuntime 中获取函数的语义描述（docstring 短描述）。
    
    利用原版 agentdojo 的 Function.description 属性，
    无需任何硬编码映射。
    
    Args:
        runtime: FunctionsRuntime 实例
        function_name: 函数名（如 "send_email"）
    
    Returns:
        语义描述（如 "Sends an email with the given body to the given address"）
    """
    try:
        func_obj = runtime.functions.get(function_name)
        if func_obj and hasattr(func_obj, 'description') and func_obj.description:
            return func_obj.description
    except Exception:
        pass
    return function_name


def _infer_app_from_function(function_name: str) -> str:
    """根据函数名推断所属 APP。
    
    利用原版 agentdojo 工具函数的命名约定：
    - send_email, get_unread_emails → email
    - get_balance, send_money → banking
    - create_calendar_event, get_current_day → calendar
    - list_files, create_file → cloud_drive
    - read_file → file_reader
    - get_user_info, update_password → user_account
    
    如果无法推断，返回 "unknown"。
    """
    qualified_suite, base_name = split_qualified_tool_name(function_name)
    return domain_for_tool(base_name, qualified_suite) or "unknown"


def _get_attribute_path(value: Any, path: str) -> Any:
    current = value
    for part in str(path or "").split("."):
        if not part:
            continue
        if isinstance(current, Mapping):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
        if current is None:
            return None
    return current


def _resolve_implicit_egress(
    env: Any,
    tool_name: str,
    inputs: Mapping[str, Any],
    app: str,
) -> list[dict[str, Any]]:
    """Resolve declared resource-backed external receivers and payloads."""
    def flat_values(value: Any) -> list[Any]:
        if isinstance(value, Mapping):
            return [
                child
                for item in value.values()
                for child in flat_values(item)
            ]
        if isinstance(value, list | tuple | set):
            return [
                child
                for item in value
                for child in flat_values(item)
            ]
        return [] if value in (None, "") else [value]

    def input_resource_ids(
        spec: Mapping[str, Any],
    ) -> tuple[list[str], bool]:
        parameter = str(spec.get("id_parameter", ""))
        raw = inputs.get(parameter)
        mode = str(spec.get("id_mode", "scalar")).lower()
        id_field = str(spec.get("id_field", "")).strip()
        type_field = str(spec.get("item_type_field", "")).strip()
        type_value = str(spec.get("item_type_value", "")).strip()
        if mode != "collection":
            value = (
                _get_attribute_path(raw, id_field)
                if id_field and isinstance(raw, Mapping)
                else raw
            )
            return [str(item) for item in flat_values(value)], False
        if raw is None:
            return [], False
        if not isinstance(raw, list | tuple):
            return [], True
        ids: list[str] = []
        invalid = False
        for item in raw:
            if type_field and isinstance(item, Mapping):
                type_matches = (
                    str(item.get(type_field, "")) == type_value
                )
                id_present = bool(
                    id_field
                    and _get_attribute_path(item, id_field)
                    not in (None, "")
                )
                if not type_matches and not id_present:
                    continue
            value = (
                _get_attribute_path(item, id_field)
                if id_field
                else item
            )
            values = [str(child) for child in flat_values(value)]
            if values:
                ids.extend(values)
            else:
                invalid = True
        return list(dict.fromkeys(ids)), invalid

    resolved: list[dict[str, Any]] = []
    for spec in tool_effect(tool_name).implicit_egress:
        resource_ids, invalid_input = input_resource_ids(spec)
        if invalid_input:
            resolved.append(
                {
                    "resolved": False,
                    "resource_id": "",
                    "id_parameter": str(
                        spec.get("id_parameter", "")
                    ),
                    "error": "implicit_egress_input_invalid",
                }
            )
        if not resource_ids:
            continue
        collection = _get_attribute_path(
            env,
            str(spec.get("resource_path", "")),
        )
        for resource_id in resource_ids:
            resource = None
            if isinstance(collection, Mapping):
                resource = collection.get(resource_id)
            elif isinstance(collection, list | tuple):
                resource = next(
                    (
                        item
                        for item in collection
                        if str(
                            getattr(
                                item,
                                "id_",
                                item.get("id_", "")
                                if isinstance(item, Mapping)
                                else "",
                            )
                        )
                        == resource_id
                    ),
                    None,
                )
            if hasattr(resource, "model_dump"):
                resource = resource.model_dump(mode="json")
            elif resource is not None and hasattr(resource, "__dict__"):
                resource = copy.deepcopy(vars(resource))
            if not isinstance(resource, Mapping):
                resolved.append(
                    {
                        "resolved": False,
                        "resource_id": resource_id,
                        "id_parameter": str(
                            spec.get("id_parameter", "")
                        ),
                        "error": "implicit_egress_resource_not_found",
                    }
                )
                continue
            recipient_field = str(spec.get("recipient_field", ""))
            content_fields = [
                str(item)
                for item in spec.get("content_fields", [])
                if str(item) in resource
            ]
            recipient_values = flat_values(
                resource.get(recipient_field)
            )
            for parameter in spec.get("recipient_parameters", []):
                recipient_values.extend(
                    flat_values(inputs.get(str(parameter)))
                )
            recipients = sorted(
                {
                    str(item)
                    for item in recipient_values
                    if item
                }
            )
            entity = str(spec.get("entity", "unknown"))
            source_entity = entity_source(app, entity)
            field_policies: dict[str, dict[str, Any]] = {}
            try:
                for field in content_fields:
                    field_policies[field] = elevate_policy_for_content(
                        field_policy(
                            app,
                            entity,
                            f"$.{field}",
                        ),
                        resource.get(field),
                    )
            except Exception as exc:
                resolved.append(
                    {
                        "resolved": False,
                        "resource_id": resource_id,
                        "id_parameter": str(
                            spec.get("id_parameter", "")
                        ),
                        "error": (
                            "implicit_egress_sensitivity_unavailable:"
                            f"{exc}"
                        ),
                    }
                )
                continue
            field_levels = {
                field: str(
                    policy.get(
                        "level",
                        field_level(app, entity, f"$.{field}"),
                    )
                )
                for field, policy in field_policies.items()
            }
            level = max(
                field_levels.values(),
                key=lambda item: CONFIDENTIALITY_LEVELS.get(item, 3),
                default=entity_level(app, entity),
            )
            categories = sorted(
                {
                    str(category)
                    for policy in field_policies.values()
                    for category in policy.get("categories", [])
                }
            )
            resolved.append(
                {
                    "resolved": bool(recipients),
                    "resource_id": resource_id,
                    "id_parameter": str(
                        spec.get("id_parameter", "")
                    ),
                    "recipients": recipients,
                    "recipient_field": recipient_field,
                    "content": {
                        field: copy.deepcopy(resource.get(field))
                        for field in content_fields
                    },
                    "content_field_levels": field_levels,
                    "content_field_policies": field_policies,
                    "source": {
                        "app": app,
                        "entity": entity,
                        "entity_id": resource_id,
                    },
                    "flow_label": make_flow_label(
                        confidentiality=make_confidentiality(
                            level=level,
                            categories=categories,
                            source_ids=[
                                f"implicit_egress:{resource_id}"
                            ],
                            source_entities=[source_entity],
                        ),
                        integrity=make_integrity(
                            kind="untrusted",
                            taint_roots=[source_entity],
                        ),
                        data_influence=True,
                        control_influence=True,
                    ),
                }
            )
    return resolved

    # 已知的 APP 前缀映射
    
    # 回退：尝试从函数名的第一个下划线前的部分推断
        # 常见前缀映射


def capture_tool_call(func: Callable):
    """
    Interceptor for FunctionsRuntime.run_function.
    Captures input, output, identifies Target APP.
    Links tool calls to the current LLM reasoning context (wasInformedBy).
    Performs pre/post environment state semantic parsing.
    
    关键改进：
    - 利用 FunctionsRuntime.functions[].description 获取语义标签（无需硬编码）
    - 利用函数名推断 target_app（无需硬编码）
    """
    @functools.wraps(func)
    def wrapper(self, env: Any, function: str, kwargs: Dict[str, Any], 
                raise_on_error: bool = False) -> Tuple[Any, Optional[str]]:
        start_time = time.time()
        
        ctx = TrackingContext()
        call_suite = _infer_suite_from_environment(env)
        ctx.ensure_task(suite=call_suite)
        tracked_function = _EXPOSED_TOOL_NAME.get() or function
        if (
            isinstance(ctx.task_data_plan, dict)
            and ctx.task_data_plan.get("execution_stop")
        ):
            stop = ctx.task_data_plan.get("execution_stop")
            stop_reason = (
                str(stop.get("reason") or "")
                if isinstance(stop, dict)
                else "A structured task stop condition was satisfied."
            )
            raise TaskStoppedError(
                f"Task stopped before executing {tracked_function!r}.",
                stop_reason=stop_reason,
            )
        
        # AgentDojo environments are mutated in place. Persist a canonical copy
        # before execution so semantic deltas remain observable.
        pre_environment = snapshot_environment(env)
        
        # 从 FunctionsRuntime 获取语义描述（原版 Function.description）
        tool_description = _get_function_description(self, function)
        
        # 推断 Target APP
        qualified_suite, base_function = split_qualified_tool_name(
            tracked_function
        )
        target_app = _infer_app_from_function(tracked_function)
        effect = tool_effect(base_function)
        current_options = get_config()
        flow_user_prompt = (
            ctx.current_reasoning.prompt
            if ctx.current_reasoning and ctx.current_reasoning.prompt
            else ctx.user_prompt
        ) or ""
        plan_step_id = _plan_step_for_action(
            ctx.task_data_plan,
            tracked_function,
            ctx.plan_usage,
        )
        original_inputs = copy.deepcopy(dict(kwargs))
        parameter_resolutions: List[Dict[str, Any]] = []
        parameter_resolution_errors: List[str] = []
        parameter_resolution_warnings: List[str] = []
        if ctx.task_data_plan is not None:
            (
                resolved_kwargs,
                parameter_resolutions,
                parameter_resolution_errors,
                parameter_resolution_warnings,
            ) = resolve_parameter_bindings(
                tool_name=tracked_function,
                args=dict(kwargs),
                plan=ctx.task_data_plan,
                step_id=plan_step_id,
                value_origins=ctx.tool_value_origins,
                derive_resolver=ctx.task_data_plan_provider,
                user_prompt=flow_user_prompt,
                context_messages=(
                    ctx.current_reasoning.context_messages
                    if ctx.current_reasoning
                    else []
                ),
                sensitive_references=ctx.sensitive_reference_values,
            )
            kwargs = resolved_kwargs
            resolved_parameters = {
                str(item.get("parameter", ""))
                for item in parameter_resolutions
                if isinstance(item, dict)
            }
            for resolution in resolve_resource_parameter_resolutions(
                ctx.task_data_plan,
                tracked_function,
                plan_step_id,
                dict(kwargs),
                ctx.tool_value_index,
            ):
                if (
                    str(resolution.get("parameter", ""))
                    not in resolved_parameters
                ):
                    parameter_resolutions.append(resolution)
        argument_sources: List[Dict[str, Any]] = []
        argument_source_error = ";".join(parameter_resolution_errors)
        task_plan_active = (
            ctx.task_data_plan
            if _task_planning_required(current_options)
            else None
        )
        flow_contract = action_flow_contract(
            ctx.task_data_plan,
            tracked_function,
            step_id=plan_step_id,
        )
        destination_parameters = {
            str(item)
            for item in (
                ((flow_contract or {}).get("destination") or {}).get(
                    "parameters",
                    [],
                )
                if isinstance(flow_contract, dict)
                else []
            )
            if item
        }
        argument_flow_labels, argument_sources = _argument_flow_labels(
            dict(kwargs),
            value_index=ctx.tool_value_index,
            parameter_resolutions=parameter_resolutions,
            destination_parameters=destination_parameters,
        )
        output_inherited_label = (
            aggregate_flow_labels(
                argument_flow_labels.values(),
                generated=True,
                control_influence=True,
            )
            if argument_flow_labels
            else None
        )
        input_flow_label = output_inherited_label or make_flow_label(
            confidentiality=make_confidentiality(level="internal"),
            integrity=make_integrity(kind="trusted"),
            data_influence=True,
            control_influence=True,
        )
        app_domain = (
            qualified_suite
            or call_suite
            or (
                target_app
                if target_app in {"banking", "workspace", "slack", "travel"}
                else ""
            )
            or ctx.suite
            or "unknown"
        )
        implicit_egress = _resolve_implicit_egress(
            env,
            tracked_function,
            kwargs,
            app_domain,
        )
        
        event_record = {
            "timestamp": start_time,
            "agent_id": ctx.current_agent_id,
            "task_id": ctx.task_id,
            "suite": call_suite or ctx.suite,
            "tool_intent": tracked_function,
            "tool_base_name": base_function,
            "tool_suite": qualified_suite,
            "tool_description": tool_description,  # 语义描述，用于生成友好标签
            "target_app": target_app,
            "app_domain": app_domain,
            "tool_effect": effect.effect,
            "tool_risk_level": effect.risk_level,
            "task_data_plan": task_plan_active,
            "plan_step_id": plan_step_id,
            "flow_contract": flow_contract,
            "plan_usage": ctx.plan_usage,
            "access_plan": None,
            "argument_sources": argument_sources,
            "argument_source_error": argument_source_error,
            "argument_flow_labels": argument_flow_labels,
            "parameter_resolutions": parameter_resolutions,
            "parameter_resolution_errors": parameter_resolution_errors,
            "parameter_resolution_warnings": parameter_resolution_warnings,
            "implicit_egress": implicit_egress,
            "original_inputs": original_inputs,
            "inputs": kwargs,
            "input_flow_label": input_flow_label,
            "thought": ctx.current_reasoning.response if ctx.current_reasoning else None,
            "thought_prompt": ctx.current_reasoning.prompt if ctx.current_reasoning else None,
            "type": "api_call_start"
        }

        
        # Link this tool call to the current reasoning context (wasInformedBy)
        ctx.link_tool_call_to_reasoning(event_record)
        if not event_record.get("thought_prompt") and ctx.user_prompt:
            event_record["thought_prompt"] = ctx.user_prompt
        
        # Graph construction hook (Modeling Layer)
        from ..modeling.graph_db import record_activity
        record_activity(event_record)
        
        # Analyze input (Auditing Layer Pipeline) before execution
        # Ring 3 uses the final resolved egress arguments below.
        # 检查全局防御开关，关闭时跳过所有 Analysis Pipeline
        # 从 ctx 获取用户原始 prompt，传递给 Ring 0 和 Ring 2
        user_prompt = (
            ctx.current_reasoning.prompt
            if ctx.current_reasoning and ctx.current_reasoning.prompt
            else ctx.user_prompt
        )
        requirement_audit: Optional[Dict[str, Any]] = None
        if (
            effect.risk_level == "L2"
            and isinstance(ctx.task_data_plan, dict)
            and ctx.task_data_plan_provider is not None
        ):
            from ..analysis.requirement_audit import (
                audit_requirements,
                apply_requirement_decision,
                requirement_resolution_options,
                record_requirement_audit,
            )

            requirement_audit = audit_requirements(
                user_prompt=user_prompt or "",
                plan=ctx.task_data_plan,
                proposed_tool=tracked_function,
                proposed_args=dict(kwargs),
                events=ctx.events,
                available_tools=_build_tool_catalog(self),
                provider=ctx.task_data_plan_provider,
            )
            ctx.task_data_plan = record_requirement_audit(
                ctx.task_data_plan,
                requirement_audit,
            )
            task_plan_active = ctx.task_data_plan
            event_record["task_data_plan"] = task_plan_active
            event_record["requirement_audit"] = requirement_audit
        defense_diagnostics = {"ring_2": {}, "ring_3": {}}
        intended_data_categories = set()
        requirement_failed = bool(
            requirement_audit is not None
            and not requirement_audit.get("passed")
        )
        requirement_decision: Optional[Dict[str, Any]] = None
        requirement_decision_applied = False
        if requirement_failed:
            allow = False
            modified_kwargs = kwargs
            unmet_requirements = [
                item
                for item in requirement_audit.get(
                    "unmet_requirements",
                    [],
                )
                if isinstance(item, Mapping)
            ]
            recommended_reads = list(
                requirement_audit.get("recommended_reads", [])
            )
            if unmet_requirements and not recommended_reads:
                from ..analysis.l2_chain import ConfirmationBroker
                from ..modeling.graph_db import record_human_authorization

                options = requirement_resolution_options(
                    requirement_audit
                )
                requirement_field_sources = [
                    {
                        "parameter": "requirement",
                        "source_activity_id": activity_id,
                        "source_action": "",
                        "source_path": "",
                    }
                    for requirement in unmet_requirements
                    for activity_id in requirement.get(
                        "source_activity_ids",
                        [],
                    )
                    if str(activity_id).strip()
                ]
                requirement_decision = ConfirmationBroker().request(
                    task_id=ctx.task_id or "",
                    tool_name=tracked_function,
                    app=app_domain,
                    risk_level=effect.risk_level,
                    args=dict(kwargs),
                    plan=ctx.task_data_plan or {},
                    chain_check={
                        "requirement_audit": requirement_audit,
                    },
                    flow_check={
                        "field_sources": requirement_field_sources,
                    },
                    confirmation_kind="requirement_resolution",
                    decision_kind="requirement_resolution",
                    options=options,
                    payload={
                        "requirements": requirement_audit.get(
                            "requirements",
                            [],
                        ),
                        "unmet_requirements": unmet_requirements,
                        "summary": requirement_audit.get("summary", ""),
                        "warnings": requirement_audit.get(
                            "warnings",
                            [],
                        ),
                    },
                    on_pending=lambda pending: record_human_authorization(
                        str(event_record.get("activity_id", "")),
                        pending,
                    ),
                )
                record_human_authorization(
                    str(event_record.get("activity_id", "")),
                    requirement_decision,
                )
                event_record["requirement_decision"] = (
                    requirement_decision
                )
                decision = requirement_decision.get("decision")
                current_plan_hash = str(
                    (ctx.task_data_plan or {}).get("plan_hash") or ""
                )
                approved_plan_hash = str(
                    requirement_decision.get("plan_hash") or ""
                )
                if (
                    current_plan_hash
                    and approved_plan_hash
                    and current_plan_hash != approved_plan_hash
                ):
                    requirement_decision["application_error"] = (
                        "requirement_decision_plan_stale"
                    )
                elif isinstance(decision, Mapping):
                    try:
                        ctx.task_data_plan = apply_requirement_decision(
                            ctx.task_data_plan or {},
                            decision,
                            request_id=str(
                                requirement_decision.get("request_id") or ""
                            ),
                            decision_hash=str(
                                requirement_decision.get("decision_hash")
                                or ""
                            ),
                        )
                        task_plan_active = ctx.task_data_plan
                        event_record["task_data_plan"] = task_plan_active
                        requirement_decision_applied = True
                    except (TypeError, ValueError) as exc:
                        requirement_decision["application_error"] = str(exc)
            defense_diagnostics["ring_2"] = {
                "passed": False,
                "requirement_audit": requirement_audit,
            }
            event_record["ring2_check"] = copy.deepcopy(
                defense_diagnostics["ring_2"]
            )
            event_record["ring3_check"] = {}
        elif _defense_enabled:
            allow, modified_kwargs, defense_diagnostics, intended_data_categories = process_before_execution(
                event_record, prompt=None, options=get_config()
            )
            event_record["ring3_check"] = copy.deepcopy(
                defense_diagnostics.get("ring_3", {})
            )
            event_record["ring2_check"] = copy.deepcopy(
                defense_diagnostics.get("ring_2", {})
            )
            if requirement_audit is not None:
                defense_diagnostics["ring_2"][
                    "requirement_audit"
                ] = requirement_audit
        else:
            allow, modified_kwargs = True, kwargs

        if requirement_audit is not None and not requirement_audit.get(
            "passed"
        ):
            unmet_ids = [
                str(item.get("id") or "")
                for item in requirement_audit.get(
                    "unmet_requirements",
                    [],
                )
                if isinstance(item, Mapping) and item.get("id")
            ]
            event_record["block_reason"] = (
                "Ring 2：L2 动作未通过任务要求覆盖检查；"
                f"未满足要求={unmet_ids}。"
            )
            risk = make_risk(
                2,
                DECISION_BLOCK,
                event_record["block_reason"],
                severity="high",
                event_kind="policy",
                policy_id="ring2.requirement_coverage",
                activity_id=event_record.get("activity_id"),
                sink_ids=[tracked_function],
                fsm_before="ACTION_PROPOSED",
                fsm_after="BLOCKED",
                confidence=requirement_audit.get("confidence"),
            )
            event_record.setdefault("risk_assessments", []).append(risk)

        if (
            allow
            and _defense_enabled
            and defense_diagnostics.get("ring_2", {}).get(
                "confirmation_required"
            )
        ):
            ring2_deterministic = defense_diagnostics.get(
                "ring_2",
                {},
            )
            confirmation_kind = str(
                ring2_deterministic.get(
                    "confirmation_kind",
                    "l2_action",
                )
            )
            from ..analysis.l2_chain import (
                ConfirmationBroker,
                check_l2_chain_with_model,
                confirmation_matches_request,
            )

            if confirmation_kind == "sensitive_data_exposure":
                exposure_check = dict(
                    ring2_deterministic.get("exposure_check", {})
                )
                chain_check = {
                    "consistent": True,
                    "available": True,
                    "executed": False,
                    "kind": "sensitive_data_exposure",
                    "reason": (
                        "敏感字段读取计划已通过确定性字段、资源和任务范围"
                        "检查，等待用户授权后再交给 Agent。"
                    ),
                    "checks": {},
                    "violations": [],
                    "evidence": [
                        field
                        for field in exposure_check.get(
                            "inspection_fields",
                            [],
                        )
                        if field
                    ],
                    "confidence": 1.0,
                    "exposure_check": exposure_check,
                }
            else:
                chain_check = check_l2_chain_with_model(
                    user_prompt=user_prompt or "",
                    plan=ctx.task_data_plan or {},
                    agent_message=(
                        ctx.current_reasoning.response
                        if ctx.current_reasoning
                        else ""
                    ),
                    tool_name=tracked_function,
                    tool_args=dict(kwargs),
                    plan_step_id=plan_step_id,
                    argument_flow_labels=argument_flow_labels,
                    parameter_resolutions=parameter_resolutions,
                    effective_egress=implicit_egress,
                    execution_history=[
                        {
                            "tool": called.get("tool_intent", ""),
                            "status": called.get("status", ""),
                            "risk_level": called.get(
                                "tool_risk_level",
                                "",
                            ),
                        }
                        for called in ctx.events
                        if called.get("type") == "api_call_end"
                    ],
                    plan_usage=ctx.plan_usage,
                    execution_context=(
                        ctx.current_reasoning.context_messages
                        if ctx.current_reasoning
                        else []
                    ),
                    deterministic_checks={
                        "ring_2": {
                            key: ring2_deterministic.get(key)
                            for key in (
                                "passed",
                                "reason",
                                "matched_step",
                                "effect",
                                "risk_level",
                                "confirmation_required",
                                "data_access",
                                "resource_access",
                                "resource_access_failures",
                            )
                        },
                        "ring_3": {
                            key: defense_diagnostics.get(
                                "ring_3",
                                {},
                            ).get(key)
                            for key in (
                                "passed",
                                "reason",
                                "destination_state",
                                "destinations",
                                "data_sources",
                                "provenance_ancestors",
                                "provenance_state",
                                "confidentiality",
                                "max_confidentiality",
                            )
                        },
                    },
                    planner=ctx.task_data_plan_provider,
                )
            event_record["l2_chain_check"] = chain_check
            defense_diagnostics["ring_2"]["chain_check"] = chain_check
            if not chain_check.get("consistent"):
                allow = False
                event_record["block_reason"] = (
                    "Ring 2: L2 action is inconsistent with the "
                    "authorized call chain."
                )
                risk = make_risk(
                    2,
                    DECISION_BLOCK,
                    event_record["block_reason"],
                    severity="high",
                    event_kind="security",
                    policy_id="ring2.l2_chain_inconsistent",
                    activity_id=event_record.get("activity_id"),
                    sink_ids=[tracked_function],
                    fsm_before="ACTION_PROPOSED",
                    fsm_after="BLOCKED",
                    confidence=chain_check.get("confidence"),
                )
                event_record.setdefault("risk_assessments", []).append(risk)
            else:
                from ..modeling.graph_db import record_human_authorization

                confirmation = ConfirmationBroker().request(
                    task_id=ctx.task_id or "",
                    tool_name=tracked_function,
                    app=app_domain,
                    risk_level=effect.risk_level,
                    args=dict(kwargs),
                    plan=ctx.task_data_plan or {},
                    chain_check=chain_check,
                    flow_check=event_record.get("ring3_check", {}),
                    confirmation_kind=confirmation_kind,
                    on_pending=lambda pending: record_human_authorization(
                        str(event_record.get("activity_id", "")),
                        pending,
                    ),
                )
                record_human_authorization(
                    str(event_record.get("activity_id", "")),
                    confirmation,
                )
                event_record["l2_confirmation"] = confirmation
                defense_diagnostics["ring_2"][
                    "confirmation"
                ] = confirmation
                confirmation_current, confirmation_mismatches = (
                    confirmation_matches_request(
                        confirmation,
                        tool_name=tracked_function,
                        arguments=dict(kwargs),
                        plan=ctx.task_data_plan or {},
                    )
                )
                defense_diagnostics["ring_2"][
                    "confirmation_binding"
                ] = {
                    "matched": confirmation_current,
                    "mismatches": confirmation_mismatches,
                }
                if (
                    confirmation.get("status") == "approved"
                    and not confirmation_current
                ):
                    allow = False
                    event_record["block_reason"] = (
                        "Ring 2: approval no longer matches the current "
                        "plan, tool or arguments."
                    )
                    risk = make_risk(
                        2,
                        DECISION_BLOCK,
                        event_record["block_reason"],
                        severity="high",
                        event_kind="security",
                        policy_id=(
                            "ring2.sensitive_data_exposure_stale"
                            if confirmation_kind
                            == "sensitive_data_exposure"
                            else "ring2.l2_confirmation_stale"
                        ),
                        activity_id=event_record.get("activity_id"),
                        sink_ids=[tracked_function],
                        fsm_before="HELD",
                        fsm_after="BLOCKED",
                    )
                    risk["confirmation_mismatches"] = (
                        confirmation_mismatches
                    )
                    event_record.setdefault(
                        "risk_assessments",
                        [],
                    ).append(risk)
                elif confirmation.get("status") != "approved":
                    allow = False
                    event_record["block_reason"] = (
                        (
                            "Ring 2: sensitive data exposure was not "
                            "approved by the user."
                        )
                        if confirmation_kind
                        == "sensitive_data_exposure"
                        else (
                            "Ring 2: L2 action was not approved by the user."
                        )
                    )
                    risk = make_risk(
                        2,
                        DECISION_BLOCK,
                        event_record["block_reason"],
                        severity="high",
                        event_kind="policy",
                        policy_id=(
                            "ring2.sensitive_data_exposure_rejected"
                            if confirmation_kind
                            == "sensitive_data_exposure"
                            else "ring2.l2_confirmation_rejected"
                        ),
                        activity_id=event_record.get("activity_id"),
                        sink_ids=[tracked_function],
                        fsm_before="HELD",
                        fsm_after="BLOCKED",
                    )
                    event_record.setdefault("risk_assessments", []).append(risk)

        if not allow:
            # 记录阻断事件到 TrackingContext，以便前端展示风险卡片和 defense_audit
            end_time = time.time()
            block_reason = event_record.get('block_reason', 'Ring 2: Action inconsistent with user intent (possible injection influence).')
            blocked_event = {
                "timestamp": end_time,
                "agent_id": ctx.current_agent_id,
                "task_id": ctx.task_id,
                "suite": call_suite or ctx.suite,
                "tool_intent": tracked_function,
                "tool_base_name": base_function,
                "tool_suite": qualified_suite,
                "target_app": target_app,
                "app_domain": app_domain,
                "tool_effect": effect.effect,
                "tool_risk_level": effect.risk_level,
                "task_data_plan": task_plan_active,
                "plan_step_id": plan_step_id,
                "flow_contract": event_record.get("flow_contract"),
                "access_plan": None,
                "argument_sources": argument_sources,
                "argument_source_error": argument_source_error,
                "argument_flow_labels": argument_flow_labels,
                "parameter_resolutions": parameter_resolutions,
                "parameter_resolution_errors": parameter_resolution_errors,
                "parameter_resolution_warnings": parameter_resolution_warnings,
                "implicit_egress": implicit_egress,
                "original_inputs": original_inputs,
                "inputs": kwargs,
                "input_flow_label": input_flow_label,
                "status": "blocked",
                "outputs": None,
                "error": None,
                "type": "api_call_end",
                "wasInformedBy": event_record.get("wasInformedBy"),
                "thought": event_record.get("thought"),
                "thought_prompt": event_record.get("thought_prompt"),
                "activity_id": event_record.get("activity_id"),
                "environment_delta": None,
                "execution_rollback": False,
                "block_reason": block_reason,
                "l2_chain_check": event_record.get("l2_chain_check"),
                "l2_confirmation": event_record.get("l2_confirmation"),
                "ring3_check": event_record.get("ring3_check"),
                "ring2_check": event_record.get("ring2_check"),
                "requirement_audit": event_record.get(
                    "requirement_audit"
                ),
                "requirement_decision": event_record.get(
                    "requirement_decision"
                ),
                "risk_assessments": event_record.get("risk_assessments", []),
                "defense_diagnostics": {
                    "before": defense_diagnostics,
                    "after": {"ring_3": {}, "ring_1": {}},
                },
            }
            ctx.log_event(blocked_event)
            mark_activity_denied(blocked_event)
            requirement_audit = event_record.get("requirement_audit")
            requirement_decision = event_record.get(
                "requirement_decision"
            )
            if isinstance(requirement_decision, Mapping):
                selected_decision = requirement_decision.get(
                    "decision"
                )
                decision_name = (
                    str(selected_decision.get("decision") or "")
                    if isinstance(selected_decision, Mapping)
                    else ""
                )
                if (
                    requirement_decision_applied
                    and decision_name != "cancel_task"
                ):
                    denial_message = (
                        "RequirementDecisionApplied: the user explicitly "
                        f"resolved the unmet requirements with {decision_name}. "
                        "The current L2 call was not executed. Replan from the "
                        "new plan revision, re-run requirement coverage and "
                        "then request the normal L2 confirmation."
                    )
                else:
                    denial_message = (
                        "RequirementDecisionCancelled: the user did not "
                        "accept the unresolved business requirement. The "
                        "current L2 call was not executed. Stop and report "
                        "the cancelled requirement."
                    )
            elif isinstance(requirement_audit, Mapping):
                reads = list(
                    requirement_audit.get("recommended_reads", [])
                )
                denial_message = (
                    "RequirementCoverageDenied: "
                    f"{block_reason} The tool was not executed. "
                    "Before retrying this L2 action, gather the required "
                    "evidence with the recommended allowed L0/L1 reads: "
                    + json.dumps(
                        reads,
                        ensure_ascii=False,
                        default=str,
                    )
                    + ". Do not retry a conflicting or unverifiable "
                    "requirement; report it to the user instead."
                )
            else:
                denial_message = (
                    f"RingPolicyDenied: {block_reason} The tool was not "
                    "executed. Do not retry this rejected call. Continue the "
                    "task using only planned and authorized tools, or report "
                    "the missing capability."
                )
            if raise_on_error:
                raise PromptInjectionBlockedError(
                    (
                        f"Tool call '{tracked_function}' was blocked by "
                        "the Ring defense pipeline."
                    ),
                    block_reason=block_reason,
                    tool_intent=tracked_function,
                )
            return "", denial_message
        
        # Tool functions mutate the environment in place. Keep a rollback copy
        # so an exception cannot commit a partially completed side effect.
        try:
            execution_snapshot = copy.deepcopy(env)
        except Exception:
            execution_snapshot = None
        try:
            result, error = func(
                self,
                env,
                function,
                modified_kwargs,
                raise_on_error,
            )
        except Exception as exc:
            _restore_environment(env, execution_snapshot)
            failure_event = {
                **copy.deepcopy(event_record),
                "timestamp": time.time(),
                "status": "error",
                "outputs": None,
                "error": f"{type(exc).__name__}: {exc}",
                "type": "api_call_end",
                "environment_delta": None,
                "defense_diagnostics": {
                    "before": defense_diagnostics,
                    "after": {"ring_3": {}, "ring_1": {}},
                },
            }
            ctx.log_event(failure_event)
            update_activity_outcome(failure_event)
            raise
        rollback_applied = False
        if error:
            rollback_applied = _restore_environment(env, execution_snapshot)
        end_time = time.time()
        raw_domain_snapshot = None
        if result is not None and not error:
            try:
                raw_domain_snapshot = str(result)
            except Exception:
                raw_domain_snapshot = "Unserializable Result"
        data_access_check: dict[str, Any] = {
            "passed": True,
            "reason": "not_applicable",
            "withheld_fields": [],
            "opaque_fields": [],
        }
        agent_result = result
        if (
            _defense_enabled
            and not error
            and isinstance(ctx.task_data_plan, dict)
            and effective_ring_enabled("ring_2", get_config())
            and effective_method_enabled(
                "ring_2",
                "task_scope",
                get_config(),
            )
        ):
            access_contract = action_data_access(
                ctx.task_data_plan,
                tracked_function,
                str(plan_step_id),
            )
            if access_contract is None:
                data_access_check = {
                    "passed": False,
                    "reason": "data_access_contract_unavailable",
                    "withheld_fields": [],
                    "opaque_fields": [],
                }
            else:
                agent_result, data_access_check = project_agent_exposure(
                    result,
                    access_contract,
                    activity_id=str(
                        event_record.get("activity_id", "")
                    ),
                )
                visible_patterns = {
                    normalize_data_path(str(item))
                    for item in access_contract.get(
                        "visible_fields",
                        [],
                    )
                    if str(item).strip()
                }

                def requested_for_analysis(path: str) -> bool:
                    normalized = normalize_data_path(path)
                    return any(
                        normalized == pattern
                        or normalized.startswith(f"{pattern}.")
                        or normalized.startswith(f"{pattern}[")
                        for pattern in visible_patterns
                    )

                runtime_hidden = list(
                    data_access_check.get(
                        "runtime_hidden_sensitive_fields",
                        [],
                    )
                )
                requested_runtime_hidden = [
                    path
                    for path in runtime_hidden
                    if requested_for_analysis(path)
                ]
                if requested_runtime_hidden:
                    from ..analysis.l2_chain import (
                        ConfirmationBroker,
                        confirmation_matches_request,
                        stable_arguments_hash,
                    )
                    from ..modeling.graph_db import (
                        record_human_authorization,
                    )

                    visible_policies = data_access_check.get(
                        "runtime_sensitive_policies",
                        {},
                    )
                    actual_levels = [
                        str(
                            (
                                visible_policies.get(path)
                                if isinstance(visible_policies, Mapping)
                                else {}
                            ).get("level", "secret")
                        )
                        for path in requested_runtime_hidden
                    ]
                    authorized_level = max(
                        actual_levels,
                        key=lambda item: CONFIDENTIALITY_LEVELS.get(
                            item,
                            3,
                        ),
                        default="secret",
                    )
                    exposure_check = {
                        "phase": "post_execution_runtime_detection",
                        "action": tracked_function,
                        "inspection_fields": requested_runtime_hidden,
                        "opaque_fields": list(
                            access_contract.get(
                                "opaque_fields",
                                [],
                            )
                        ),
                        "previous_max_exposure_level": str(
                            access_contract.get(
                                "max_exposure_level",
                                "internal",
                            )
                        ),
                        "max_exposure_level": authorized_level,
                        "field_policies": copy.deepcopy(
                            {
                                path: visible_policies.get(path, {})
                                for path in requested_runtime_hidden
                            }
                        ),
                    }
                    chain_check = {
                        "consistent": True,
                        "available": True,
                        "executed": False,
                        "kind": "sensitive_data_exposure",
                        "reason": (
                            "读取结果中的自然语言内容被检测为高于原计划"
                            "暴露上限；该字段属于任务声明的待分析字段，"
                            "等待用户授权后再交给 Agent。"
                        ),
                        "checks": {},
                        "violations": [],
                        "evidence": requested_runtime_hidden,
                        "confidence": 1.0,
                        "exposure_check": exposure_check,
                    }
                    runtime_hold = make_risk(
                        2,
                        DECISION_HOLD,
                        (
                            "读取结果中的自然语言内容超出计划暴露上限，"
                            "需要用户授权后才能交给 Agent。"
                        ),
                        severity="high",
                        event_kind="policy",
                        policy_id=(
                            "ring2.sensitive_data_exposure_confirmation"
                        ),
                        activity_id=event_record.get("activity_id"),
                        source_ids=requested_runtime_hidden,
                        sink_ids=[tracked_function],
                        fsm_before="OUTPUT_OBSERVED",
                        fsm_after="HELD",
                        confidence=1.0,
                    )
                    runtime_hold["phase"] = (
                        "post_execution_runtime_detection"
                    )
                    runtime_hold["exposure_fields"] = list(
                        requested_runtime_hidden
                    )
                    runtime_hold["occurrence_count"] = 1
                    event_record.setdefault(
                        "risk_assessments",
                        [],
                    ).append(runtime_hold)
                    confirmation = ConfirmationBroker().request(
                        task_id=ctx.task_id or "",
                        tool_name=tracked_function,
                        app=app_domain,
                        risk_level="sensitive_data",
                        args=dict(kwargs),
                        plan=ctx.task_data_plan or {},
                        chain_check=chain_check,
                        flow_check={
                            "passed": True,
                            "reason": (
                                "runtime_sensitive_content_requires_"
                                "authorization"
                            ),
                            "exposure_check": exposure_check,
                        },
                        confirmation_kind="sensitive_data_exposure",
                        on_pending=lambda pending: (
                            record_human_authorization(
                                str(
                                    event_record.get(
                                        "activity_id",
                                        "",
                                    )
                                ),
                                pending,
                            )
                        ),
                    )
                    (
                        confirmation_current,
                        confirmation_mismatches,
                    ) = confirmation_matches_request(
                        confirmation,
                        tool_name=tracked_function,
                        arguments=dict(kwargs),
                        plan=ctx.task_data_plan or {},
                    )
                    record_human_authorization(
                        str(event_record.get("activity_id", "")),
                        confirmation,
                    )
                    event_record[
                        "runtime_exposure_confirmation"
                    ] = confirmation
                    event_record["l2_confirmation"] = confirmation
                    data_access_check[
                        "runtime_exposure_authorization"
                    ] = {
                        "status": confirmation.get("status"),
                        "request_id": confirmation.get("request_id"),
                        "fields": requested_runtime_hidden,
                        "max_exposure_level": authorized_level,
                        "args_hash": stable_arguments_hash(kwargs),
                        "confirmation_current": confirmation_current,
                        "confirmation_mismatches": confirmation_mismatches,
                    }
                    if (
                        confirmation.get("status") == "approved"
                        and confirmation_current
                    ):
                        authorized_contract = copy.deepcopy(
                            access_contract
                        )
                        authorized_contract[
                            "max_exposure_level"
                        ] = authorized_level
                        agent_result, data_access_check = (
                            project_agent_exposure(
                                result,
                                authorized_contract,
                                activity_id=str(
                                    event_record.get(
                                        "activity_id",
                                        "",
                                    )
                                ),
                            )
                        )
                        data_access_check[
                            "runtime_exposure_authorization"
                        ] = {
                            "status": "approved",
                            "request_id": confirmation.get(
                                "request_id"
                            ),
                            "fields": requested_runtime_hidden,
                            "max_exposure_level": authorized_level,
                        }
                    elif (
                        confirmation.get("status") == "approved"
                        and not confirmation_current
                    ):
                        stale = make_risk(
                            2,
                            DECISION_MITIGATE,
                            (
                                "The user approved exposure, but the plan "
                                "or arguments changed while the request was "
                                "pending; the sensitive fields remain hidden."
                            ),
                            severity="medium",
                            event_kind="policy",
                            policy_id=(
                                "ring2.sensitive_data_exposure_stale"
                            ),
                            activity_id=event_record.get(
                                "activity_id"
                            ),
                            source_ids=requested_runtime_hidden,
                            sink_ids=[tracked_function],
                            fsm_before="HELD",
                            fsm_after="SANITIZED",
                        )
                        stale["confirmation_mismatches"] = (
                            confirmation_mismatches
                        )
                        event_record.setdefault(
                            "risk_assessments",
                            [],
                        ).append(stale)
                    elif confirmation.get("status") == "rejected":
                        rejection = make_risk(
                            2,
                            DECISION_MITIGATE,
                            (
                                "The user rejected exposure of runtime-"
                                "detected sensitive content; the affected "
                                "fields remain hidden from the Agent."
                            ),
                            severity="medium",
                            event_kind="policy",
                            policy_id=(
                                "ring2.sensitive_data_exposure_rejected"
                            ),
                            activity_id=event_record.get(
                                "activity_id"
                            ),
                            source_ids=requested_runtime_hidden,
                            sink_ids=[tracked_function],
                            fsm_before="OUTPUT_OBSERVED",
                            fsm_after="SANITIZED",
                        )
                        event_record.setdefault(
                            "risk_assessments",
                            [],
                        ).append(rejection)
                ctx.sensitive_reference_values.update(
                    data_access_check.pop(
                        "_sensitive_references",
                        {},
                    )
                )
                if data_access_check.get(
                    "runtime_hidden_sensitive_fields"
                ):
                    risk = make_risk(
                        2,
                        DECISION_MITIGATE,
                        (
                            "Content-derived sensitivity exceeded the "
                            f"tool-output exposure limit for {tracked_function}; "
                            "the affected fields were withheld."
                        ),
                        severity="medium",
                        event_kind="policy",
                        policy_id="ring2.sensitive_field_withheld",
                        activity_id=event_record.get("activity_id"),
                        source_ids=data_access_check.get(
                            "runtime_hidden_sensitive_fields",
                            [],
                        ),
                        sink_ids=[tracked_function],
                        fsm_before="OUTPUT_OBSERVED",
                        fsm_after="SANITIZED",
                    )
                    event_record.setdefault(
                        "risk_assessments",
                        [],
                    ).append(risk)
            if not data_access_check.get("passed", False):
                block_reason = (
                    "Ring 2 data-exposure policy could not authorize the "
                    f"read result for {tracked_function}: "
                    f"{data_access_check.get('reason', 'unknown')}."
                )
                blocked_event = {
                    **copy.deepcopy(event_record),
                    "timestamp": end_time,
                    "status": "blocked",
                    "outputs": None,
                    "error": None,
                    "type": "api_call_end",
                    "environment_delta": None,
                    "block_reason": block_reason,
                    "data_access_check": data_access_check,
                }
                risk = make_risk(
                    2,
                    DECISION_BLOCK,
                    block_reason,
                    severity="high",
                    event_kind="security",
                    policy_id="ring2.data_exposure_blocked",
                    activity_id=event_record.get("activity_id"),
                    sink_ids=[tracked_function],
                    fsm_before="OUTPUT_OBSERVED",
                    fsm_after="BLOCKED",
                )
                blocked_event.setdefault(
                    "risk_assessments",
                    [],
                ).append(risk)
                ctx.log_event(blocked_event)
                update_activity_outcome(blocked_event)
                raise PromptInjectionBlockedError(
                    block_reason,
                    block_reason=block_reason,
                    tool_intent=tracked_function,
                )
        
        # Post execution semantic extraction/snapshot
        out_domain_snapshot = None
        if agent_result is not None and not error:
            try:
                out_domain_snapshot = str(agent_result)
            except Exception:
                out_domain_snapshot = "Unserializable Result"
        output_origins: List[ValueOrigin] = []
        if agent_result is not None and not error:
            output_origins = collect_value_origins(
                agent_result,
                app=app_domain,
                source_tool=tracked_function,
                activity_id=str(event_record.get("activity_id", "")),
                fallback_level=effect.confidentiality,
                fallback_categories=effect.categories,
                inherited_label=output_inherited_label,
                dynamic_mapping_policy_paths=data_access_check.get(
                    "dynamic_mapping_policy_paths",
                    [],
                ),
                content_detection=data_access_check.get(
                    "content_detection",
                    True,
                ),
            )
        output_source_entities = sorted(
            {
                entity_source(origin.app, origin.entity)
                for origin in output_origins
                if origin.entity != "unknown"
            }
        )
        
        # Compute environment delta (semantic diff between pre and post states)
        environment_delta = None
        try:
            from .environment_snapshot import parse_environment_delta
            delta = parse_environment_delta(pre_environment, env, source_app=target_app)
            if delta.created or delta.updated or delta.deleted:
                # 存储完整的 entity 信息（含 entity_type, attributes, data_payload）
                environment_delta = {
                    "created": [
                        {
                            "entity_id": e.entity_id,
                            "entity_type": e.entity_type,
                            "attributes": e.attributes,
                            "data_payload": e.data_payload,
                        }
                        for e in delta.created
                    ],
                    "updated": [
                        {
                            "entity_id": e.entity_id,
                            "entity_type": e.entity_type,
                            "attributes": e.attributes,
                            "data_payload": e.data_payload,
                        }
                        for e in delta.updated
                    ],
                    "deleted": [
                        {
                            "entity_id": e.entity_id,
                            "entity_type": e.entity_type,
                            "attributes": e.attributes,
                            "data_payload": e.data_payload,
                        }
                        for e in delta.deleted
                    ],
                    "accessed": [
                        {
                            "entity_id": e.entity_id,
                            "entity_type": e.entity_type,
                            "attributes": e.attributes,
                            "data_payload": e.data_payload,
                        }
                        for e in delta.accessed
                    ],
                }
        except Exception:
            pass  # Environment parsing is best-effort

        if isinstance(ctx.task_data_plan, dict):
            _refresh_completed_plan_steps(
                ctx,
                step_id=plan_step_id,
                action_name=tracked_function,
                result=result,
                error=error,
                effect=effect.effect,
                environment_delta=environment_delta,
            )
        if not error:
            _record_successful_planned_action(ctx, tracked_function)

        output_flow_label = derive_flow_label(
            [output_inherited_label] if output_inherited_label else [],
            source_kind="tool_output",
            content=out_domain_snapshot or "",
            source_id=event_record.get("activity_id", function),
        )
        confidentiality_parents = [
            output_flow_label.get("confidentiality"),
            make_confidentiality(
                level=effect.confidentiality,
                categories=effect.categories,
                source_ids=[event_record.get("activity_id", function)],
            ),
        ]
        if output_source_entities:
            confidentiality_parents.append(
                make_confidentiality(
                    level=max_source_level(output_source_entities),
                    source_ids=[event_record.get("activity_id", function)],
                    source_entities=output_source_entities,
                )
            )
        output_flow_label["confidentiality"] = join_confidentiality(
            confidentiality_parents
        )
        output_content_hash = hashlib.sha256(
            (out_domain_snapshot or "").encode("utf-8", errors="replace")
        ).hexdigest()[:16]
        ctx.tool_output_labels[output_content_hash] = dict(output_flow_label)
        ctx.tool_output_labels[f"tool:{tracked_function}"] = dict(
            output_flow_label
        )
        output_schema: Dict[str, Any] = {}
        try:
            from ..analysis.access_plan import schema_for_type

            function_obj = getattr(self, "functions", {}).get(function)
            if function_obj is not None:
                output_schema = schema_for_type(
                    getattr(function_obj, "return_type", None)
                )
                output_schema = _apply_schema_semantic_types(
                    output_schema,
                    effect.output_semantic_types,
                )
        except Exception:
            output_schema = {}
        event_complete = {
            "timestamp": end_time,
            "agent_id": ctx.current_agent_id,
            "task_id": ctx.task_id,
            "suite": call_suite or ctx.suite,
            "tool_intent": tracked_function,
            "tool_base_name": base_function,
            "tool_suite": qualified_suite,
            "target_app": target_app,
            "app_domain": app_domain,
            "tool_effect": effect.effect,
            "tool_risk_level": effect.risk_level,
            "task_data_plan": task_plan_active,
            "plan_step_id": plan_step_id,
            "flow_contract": event_record.get("flow_contract"),
            "access_plan": None,
            "argument_sources": argument_sources,
            "argument_source_error": argument_source_error,
            "argument_flow_labels": argument_flow_labels,
            "parameter_resolutions": parameter_resolutions,
            "parameter_resolution_errors": parameter_resolution_errors,
            "parameter_resolution_warnings": parameter_resolution_warnings,
            "implicit_egress": implicit_egress,
            "original_inputs": original_inputs,
            "inputs": copy.deepcopy(kwargs),
            "status": "success" if not error else "error",
            "outputs": out_domain_snapshot,
            "error": error,
            "execution_uncertain": (
                _l2_egress_execution_requires_manual_retry(effect, error)
            ),
            "execution_rollback": rollback_applied,
            "type": "api_call_end",
            "wasInformedBy": event_record.get("wasInformedBy"),
            "activity_id": event_record.get("activity_id"),
            "environment_delta": environment_delta,
            "thought_prompt": user_prompt,
            "thought": event_record.get("thought"),
            "task_context_available": bool(
                ctx.user_prompt
                or (
                    ctx.current_reasoning
                    and ctx.current_reasoning.prompt
                )
            ),
            "input_flow_label": event_record.get("input_flow_label", {}),
            "output_flow_label": output_flow_label,
            "output_schema": output_schema,
            "l2_chain_check": event_record.get("l2_chain_check"),
            "l2_confirmation": event_record.get("l2_confirmation"),
            "ring3_check": event_record.get("ring3_check"),
            "ring2_check": event_record.get("ring2_check"),
            "requirement_audit": event_record.get("requirement_audit"),
            "requirement_decision": event_record.get(
                "requirement_decision"
            ),
            "data_access_check": data_access_check,
            "raw_output_snapshot": raw_domain_snapshot,
            "risk_assessments": list(event_record.get("risk_assessments", [])),
        }
        
        # Post-execution validation and Ring 1 output quarantine.
        # 检查全局防御开关，关闭时跳过所有 Analysis Pipeline
        after_diagnostics = {"ring_3": {}, "ring_1": {}}
        try:
            if _defense_enabled:
                final_result, after_diagnostics = process_after_execution_with_details(
                    event_complete, agent_result,
                    intent_data=intended_data_categories,
                    options=get_config(),
                )
            else:
                final_result = agent_result
            if final_result is not None and not error:
                ring1_diagnostics = (
                    after_diagnostics.get("ring_1", {})
                    if isinstance(after_diagnostics, dict)
                    else {}
                )
                admitted_origins = collect_value_origins(
                    final_result,
                    app=app_domain,
                    source_tool=tracked_function,
                    activity_id=str(event_record.get("activity_id", "")),
                    fallback_level=effect.confidentiality,
                    fallback_categories=effect.categories,
                    risky_entities=ring1_diagnostics.get(
                        "risky_entities", []
                    ),
                    inherited_label=output_inherited_label,
                    dynamic_mapping_policy_paths=data_access_check.get(
                        "dynamic_mapping_policy_paths",
                        [],
                    ),
                    content_detection=data_access_check.get(
                        "content_detection",
                        True,
                    ),
                )
                ctx.tool_value_origins.extend(admitted_origins)
                for key, records in index_value_origins(
                    admitted_origins
                ).items():
                    ctx.tool_value_index.setdefault(key, []).extend(records)
            for risk in after_diagnostics.get("risk_assessments", []):
                if all(
                    item.get("risk_id") != risk.get("risk_id")
                    for item in event_complete.setdefault("risk_assessments", [])
                ):
                    event_complete["risk_assessments"].append(risk)
            ctx.tool_output_labels[output_content_hash] = dict(
                event_complete.get("output_flow_label") or {}
            )
            ctx.tool_output_labels[f"tool:{tracked_function}"] = dict(
                event_complete.get("output_flow_label") or {}
            )
            try:
                sanitized_output = (
                    final_result
                    if isinstance(final_result, str)
                    else str(final_result)
                )
            except Exception:
                sanitized_output = None
            if (
                sanitized_output is not None
                and out_domain_snapshot is not None
                and sanitized_output != out_domain_snapshot
            ):
                event_complete["sanitized_output"] = sanitized_output
                event_complete["redaction_applied"] = True
            if sanitized_output is not None:
                sanitized_hash = hashlib.sha256(
                    sanitized_output.encode("utf-8", errors="replace")
                ).hexdigest()[:16]
                ctx.tool_output_labels[sanitized_hash] = dict(
                    event_complete.get("output_flow_label") or {}
                )
                try:
                    from agentdojo.agent_pipeline.tool_execution import (
                        tool_result_to_str,
                    )

                    formatted_output = tool_result_to_str(final_result)
                    formatted_hash = hashlib.sha256(
                        formatted_output.encode(
                            "utf-8",
                            errors="replace",
                        )
                    ).hexdigest()[:16]
                    ctx.tool_output_labels[formatted_hash] = dict(
                        event_complete.get("output_flow_label") or {}
                    )
                except Exception:
                    pass
        except PromptInjectionBlockedError:
            # Ring 1 检测到提示注入，记录阻断事件后重新抛出异常
            event_complete["status"] = "blocked"
            event_complete["block_reason"] = "Ring 1: Indirect prompt injection detected in tool output."
            event_complete["quarantined"] = True
            # 从 event_complete 中提取 pipeline 保存的诊断信息（异常中断后恢复 ring1/ring3）
            ring1_diag = event_complete.pop("_ring1_diagnostics", {})
            ring3_diag = event_complete.pop("_ring3_diagnostics", {})
            if ring1_diag:
                after_diagnostics["ring_1"] = ring1_diag
            if ring3_diag:
                after_diagnostics["ring_3"] = ring3_diag
            event_complete["defense_diagnostics"] = {
                "before": defense_diagnostics,
                "after": after_diagnostics,
            }
            for risk in after_diagnostics.get("risk_assessments", []):
                if all(
                    item.get("risk_id") != risk.get("risk_id")
                    for item in event_complete.setdefault("risk_assessments", [])
                ):
                    event_complete["risk_assessments"].append(risk)
            ctx.log_event(event_complete)
            update_activity_outcome(event_complete)
            raise
        
        # Update Graph with outcome (移到 try 块之后，避免阻断时重复创建输出节点)
        update_activity_outcome(event_complete)
        
        # Attach defense diagnostics to the event for trace file collection
        event_complete["defense_diagnostics"] = {
            "before": defense_diagnostics,
            "after": after_diagnostics,
        }
        
        # Log the complete event (including defense diagnostics) to TrackingContext
        ctx.log_event(event_complete)

        if event_complete["execution_uncertain"]:
            raise TaskStoppedError(
                (
                    f"L2 egress tool {tracked_function!r} failed. "
                    "Automatic retry is disabled; a new explicit user "
                    "instruction and authorization are required."
                ),
                stop_reason="l2_egress_execution_uncertain",
            )

        return final_result, error

    return wrapper


def enable_tracking():
    """
    Patches the FunctionsRuntime class in AgentDojo to use the capture_tool_call wrapper.
    Also patches LLM query methods to capture reasoning context.
    """
    import agentdojo.functions_runtime as functions_runtime
    
    # Patch FunctionsRuntime.run_function
    if not hasattr(functions_runtime.FunctionsRuntime.run_function, "__wrapped__"):
        original_run_function = functions_runtime.FunctionsRuntime.run_function
        functions_runtime.FunctionsRuntime.run_function = capture_tool_call(original_run_function)
        print("Data Flow Tracking enabled: FunctionsRuntime.run_function intercepted.")

    _patch_init_query()
    # Patch LLM query methods to capture reasoning context
    _patch_llm_query_methods()


def _patch_init_query():
    """Start a new task when the initial user message is inserted."""
    module = sys.modules.get("agentdojo.agent_pipeline.basic_elements")
    if module is None:
        try:
            from agentdojo.agent_pipeline import basic_elements as module
        except ImportError:
            return
    init_cls = getattr(module, "InitQuery", None)
    if init_cls is None or hasattr(init_cls.query, "__wrapped__"):
        return
    original_query = init_cls.query

    @functools.wraps(original_query)
    def wrapped(self, query, runtime, env=None, messages=(), extra_args=None):
        is_initial_context = not messages or (
            len(messages) == 1 and messages[0].get("role") == "system"
        )
        if is_initial_context:
            TrackingContext().start_task(
                query,
                suite=_infer_suite_from_environment(env),
            )
        return original_query(
            self,
            query,
            runtime,
            env,
            messages,
            extra_args or {},
        )

    init_cls.query = wrapped


def _patch_llm_query_methods():
    """
    Attempt to patch LLM query methods in the agent pipeline.
    This wraps the query() method of LLM pipeline elements to capture reasoning context.
    
    Only already-imported provider modules are patched. This avoids importing
    optional SDKs (for example Cohere/tokenizers) merely because the auditing
    platform is activated in a runtime-only test.
    """
    import inspect

    patched_count = 0
    prefix = "agentdojo.agent_pipeline.llms."
    for module_name, submod in list(sys.modules.items()):
        if not module_name.startswith(prefix) or submod is None:
            continue
        for name, cls in inspect.getmembers(submod, inspect.isclass):
            if hasattr(cls, 'query') and name.endswith('LLM'):
                original_query = cls.query
                if not hasattr(original_query, "__wrapped__"):
                    cls.query = capture_llm_interaction(original_query)
                    patched_count += 1

    if patched_count > 0:
        print(f"Data Flow Tracking enabled: {patched_count} LLM query methods intercepted.")
    else:
        print(
            "Data Flow Tracking: no provider module was loaded yet; "
            "LLM capture will be unavailable until activate_platform() "
            "is called after importing the agent pipeline."
        )
