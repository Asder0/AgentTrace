"""
Orchestrates the 4 rings of the Defense Pipeline.
Focuses on detecting indirect prompt injection in tool outputs,
rather than blindly blocking operation sequences.

Ring 0: Prompt Injection Detection — Detects injection in initial user prompt
Ring 1: Prompt Injection Detection — Detects malicious instructions in tool outputs
Ring 2: Intent Consistency Check — Verifies LLM actions align with user's original task
Ring 3: DOE (Data Over-Exposure) — Redacts sensitive data from outputs
"""
from typing import Dict, Any, Tuple, Set
from .prompt_injection import check_prompt_for_injection, check_prompt_for_injection_with_details
from .skillprobe_topology import check_tool_output_for_injection, check_tool_output_for_injection_with_details
from .fides_ifc import check_intent_consistency, check_intent_consistency_with_details
from .agentraft_doe import apply_doe_mitigation, apply_doe_mitigation_with_details
from .model_utils import extract_necessary_categories, extract_intended_categories


def validate_call_event(event: Dict[str, Any]):
    """
    Generic validation, can be used by external loggers.
    """
    pass


def process_before_execution(
    event: Dict[str, Any],
    prompt: str = None,
) -> Tuple[bool, Dict[str, Any], Dict[str, Any], set]:
    """
    Ring 0 & Ring 2 execution logic.
    
    Ring 0: Prompt Injection Detection — Detects injection in user prompt (LLM 前)
    Ring 2: Intent Consistency Check — Verifies LLM actions align with user's original task
    
    Also extracts D_int (intended data categories) for use by Ring 3 DOE.
    
    Ring 0 最先执行，因为 prompt 注入直接威胁初始安全边界。
    如果 prompt 本身包含注入指令，后续所有检查都无意义。
    
    Args:
        event: 工具调用事件字典（用于 Ring 2 意图一致性检查）
        prompt: 用户输入的 prompt 文本（用于 Ring 0 注入检测）
                如果为 None，则跳过 Ring 0（工具调用场景）
    
    Returns (Allowed, Modified_Kwargs, Diagnostics, Intended_Data_Categories)
    """
    kwargs = event.get('inputs', {})
    diagnostics = {"ring_0": {}, "ring_2": {}}
    intended_data_categories: set = set()
    
    # Ring 0: Prompt Injection Detection (LLM 前，最先执行)
    # 检测用户输入的 prompt 是否包含注入指令
    if prompt is not None:
        ring0_details = check_prompt_for_injection_with_details(prompt)
        diagnostics["ring_0"] = ring0_details
        
        # Extract D_int from user prompt (for Ring 3 DOE)
        intended_data_categories = extract_intended_categories(prompt)
        
        if not ring0_details["passed"]:
            event['block_reason'] = "Ring 0: Prompt injection detected in user input."
            return False, kwargs, diagnostics, intended_data_categories
    
    # Ring 2: Intent Consistency Check
    # Verifies that the LLM's action is consistent with the user's original task
    ring2_details = check_intent_consistency_with_details(event)
    diagnostics["ring_2"] = ring2_details
    
    # If Ring 2 has user intent text, also extract D_int
    user_intent = ring2_details.get("user_intent", "")
    if user_intent:
        intended_data_categories = intended_data_categories | extract_intended_categories(user_intent)
    
    if not ring2_details["passed"]:
        event['block_reason'] = "FIDES IFC: Action inconsistent with user intent (possible injection influence)."
        return False, kwargs, diagnostics, intended_data_categories
    
    return True, kwargs, diagnostics, intended_data_categories


def process_after_execution(
    event_complete: Dict[str, Any],
    result: Any,
    nec_data: set = None,
    intent_data: set = None,
) -> Any:
    """
    Ring 1 & 3 execution logic.

    Ring 3: DOE (Data Over-Exposure) mitigation — Redacts sensitive data from outputs
            respecting D_nec (tool-necessary) and D_int (user-intended) categories.
    Ring 1: Checks if the tool output contains malicious instructions

    All rings execute regardless of previous ring results, but if Ring 1 detects
    injection, the final result is replaced with a block message.
    """
    # Ring 3: DOE (Data Over-Exposure) mitigation — run first so sanitized data
    # is available even if Ring 1 blocks
    if nec_data is None:
        nec_data = extract_necessary_categories(event_complete.get("tool_intent", ""))
    if intent_data is None:
        thought_prompt = event_complete.get("thought_prompt", "")
        intent_data = extract_intended_categories(thought_prompt)

    sanitized_result = apply_doe_mitigation(
        event_complete, result, nec_data=nec_data, intent_data=intent_data
    )

    # Ring 1: Prompt Injection Detection in tool outputs
    tool_output = event_complete.get('outputs', '')
    if tool_output and not check_tool_output_for_injection(tool_output):
        # Injection detected — return safe placeholder (same as original agentdojo's approach)
        return "<Data omitted because a prompt injection was detected>"

    return sanitized_result


def process_after_execution_with_details(
    event_complete: Dict[str, Any],
    result: Any,
    nec_data: set = None,
    intent_data: set = None,
) -> Tuple[Any, Dict[str, Any]]:
    """
    Ring 1 & 3 execution logic with detailed diagnostics for audit tracing.

    Args:
        event_complete: Tool call event with metadata.
        result: The tool output to sanitize.
        nec_data: D_nec — data categories necessary for the tool's function.
        intent_data: D_int — data categories the user intended to access.

    Returns (Final_Result, Diagnostics)
    """
    diagnostics = {"ring_3": {}, "ring_1": {}}

    # Compute D_nec and D_int if not provided
    if nec_data is None:
        nec_data = extract_necessary_categories(event_complete.get("tool_intent", ""))
    if intent_data is None:
        thought_prompt = event_complete.get("thought_prompt", "")
        intent_data = extract_intended_categories(thought_prompt)

    # Ring 3: DOE (Data Over-Exposure) mitigation with context
    ring3_details = apply_doe_mitigation_with_details(
        event_complete, result, nec_data=nec_data, intent_data=intent_data
    )
    diagnostics["ring_3"] = ring3_details
    sanitized_result = ring3_details["sanitized_result"]

    # Ring 1: Prompt Injection Detection in tool outputs
    tool_output = event_complete.get('outputs', '')
    ring1_details = check_tool_output_for_injection_with_details(tool_output)
    diagnostics["ring_1"] = ring1_details

    if tool_output and not ring1_details["passed"]:
        # 在 event_complete 中设置 block_reason，以便前端展示风险卡片
        event_complete["block_reason"] = "Ring 1: Indirect prompt injection detected in tool output."
        # 将完整的诊断信息附加到 event_complete，确保 interceptor 能捕获到
        # 同时保存 ring_1 和 ring_3，避免异常中断导致诊断数据丢失
        event_complete["_ring1_diagnostics"] = ring1_details
        event_complete["_ring3_diagnostics"] = ring3_details
        # 抛出异常中断 AgentPipeline 执行循环，避免 LLM 继续尝试其他工具调用
        from ..capture.interceptor import PromptInjectionBlockedError
        raise PromptInjectionBlockedError(
            f"Tool output contains prompt injection.",
            block_reason="Ring 1: Indirect prompt injection detected in tool output.",
            tool_intent=event_complete.get('tool_intent', ''),
        )

    return sanitized_result, diagnostics
