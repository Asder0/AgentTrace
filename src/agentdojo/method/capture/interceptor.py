"""
Capture Layer: AOP-based interceptors for AgentDojo.
Provides:
1. Tool call interception (API-level)
2. LLM reasoning context capture (Thought/Action)
3. Environment state semantic parsing (pre/post snapshots)
4. wasInformedBy relationship binding between LLM reasoning and tool calls
"""

import time
import functools
import json
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Sequence
from dataclasses import dataclass, field

from ..analysis.pipeline import process_before_execution, process_after_execution, process_after_execution_with_details

# 防御开关（全局，默认开启）
# 关闭后，Analysis Pipeline 的 4 个 Ring 将全部跳过
_defense_enabled = True


class PromptInjectionBlockedError(Exception):
    """当防御系统检测到提示注入并阻断工具调用时抛出的异常。
    
    此异常会中断 AgentPipeline 的执行循环，避免 LLM 陷入循环尝试。
    """
    def __init__(self, message: str, block_reason: str = "", tool_intent: str = ""):
        self.block_reason = block_reason
        self.tool_intent = tool_intent
        super().__init__(message)


@dataclass
class ReasoningContext:
    """Captures the LLM's reasoning (Thought) and decision (Action) for a single step."""
    thought_id: str
    prompt: str  # The prompt sent to the LLM
    response: str  # The LLM's response (thought + action)
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)  # Tool calls decided by this reasoning
    timestamp: float = 0.0


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
        return cls._instance

    def log_event(self, event: Dict[str, Any]):
        """Log an event and pass it to the Analysis Pipeline."""
        self.events.append(event)
        from ..analysis.pipeline import validate_call_event
        validate_call_event(event)

    def set_reasoning_context(self, prompt: str, response: str, timestamp: float):
        """
        Record the LLM's reasoning context (Thought/Action).
        This creates a new ReasoningContext that subsequent tool calls will be linked to.
        """
        reasoning = ReasoningContext(
            thought_id=f"thought_{uuid.uuid4().hex[:8]}",
            prompt=prompt,
            response=response,
            timestamp=timestamp,
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
        
        # Capture the prompt (last user message or system message + query)
        # Use the raw query as prompt (it's the user's input)
        prompt = query
        
        # Ring 0: Check prompt for injection before LLM invocation
        # 通过 pipeline.py 统一编排，Ring 0 最先执行
        # 保存结果以便后续持久化到 TrackingContext（供前端 defense_audit 展示）
        _ring0_diagnostics = {}
        if _defense_enabled:
            # 构造一个最小 event 用于 pipeline 统一编排
            # 注意：这里没有工具调用，所以 event 只包含 prompt 相关信息
            llm_event = {
                "timestamp": start_time,
                "type": "llm_interaction",
                "prompt": prompt,
            }
            allow, _, defense_diagnostics, _ = process_before_execution(llm_event, prompt=prompt)
            _ring0_diagnostics = defense_diagnostics.get("ring_0", {})
            if not allow:
                block_reason = llm_event.get('block_reason', "Ring 0: Prompt injection detected in user input.")
                raise PromptInjectionBlockedError(
                    f"Prompt contains injection instructions.",
                    block_reason=block_reason,
                    tool_intent="",
                )
        
        # Execute the LLM call
        result = func(self, query, runtime, env, messages, extra_args)
        
        end_time = time.time()
        
        # Extract the response from the result
        # result is (query, runtime, env, messages, extra_args)
        response_text = ""
        tool_calls_info = []
        if len(result) >= 4:
            updated_messages = result[3]
            if updated_messages and len(updated_messages) > 0:
                last_msg = updated_messages[-1]
                if isinstance(last_msg, dict):
                    # Extract text content from ContentBlock list format
                    # e.g. [{"type": "text", "content": "..."}]
                    content = last_msg.get("content", "")
                    if isinstance(content, list):
                        text_parts = []
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                text_parts.append(block.get("content", ""))
                        response_text = "\n".join(text_parts)
                    elif isinstance(content, str):
                        response_text = content
                    
                    # Extract tool calls from the assistant message
                    tool_calls = last_msg.get("tool_calls", [])
                    if tool_calls:
                        for tc in tool_calls:
                            if isinstance(tc, dict):
                                tool_calls_info.append({
                                    "function": tc.get("function", ""),
                                    "args": tc.get("args", {}),
                                })

        
        # Record the reasoning context
        ctx = TrackingContext()
        ctx.set_reasoning_context(prompt, response_text, start_time)
        
        # Log the LLM interaction event (include Ring 0 diagnostics for defense_audit)
        llm_event = {
            "timestamp": start_time,
            "agent_id": ctx.current_agent_id,
            "type": "llm_interaction",
            "prompt": prompt,
            "response": response_text,
            "thought_id": ctx.current_reasoning.thought_id if ctx.current_reasoning else None,
            "defense_diagnostics": {
                "before": {"ring_0": _ring0_diagnostics},
            },
        }
        ctx.log_event(llm_event)
        
        # Record to graph DB
        from ..modeling.graph_db import record_llm_interaction
        record_llm_interaction(llm_event)
        
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
    # 已知的 APP 前缀映射
    app_prefixes = {
        'email': ['send_email', 'get_unread_emails', 'get_sent_emails', 'get_received_emails',
                  'get_draft_emails', 'search_emails', 'search_contacts', 'delete_email'],
        'calendar': ['get_current_day', 'get_day_calendar_events', 'search_calendar_events',
                     'create_calendar_event', 'cancel_calendar_event', 'reschedule_calendar_event',
                     'add_calendar_event_participants'],
        'cloud_drive': ['list_files', 'create_file', 'delete_file', 'get_file_by_id',
                        'search_files', 'search_files_by_filename', 'append_to_file', 'share_file'],
        'banking': ['get_balance', 'get_iban', 'send_money', 'schedule_transaction',
                    'update_scheduled_transaction', 'get_most_recent_transactions',
                    'get_scheduled_transactions'],
        'file_reader': ['read_file'],
        'user_account': ['get_user_info', 'update_password', 'update_user_info'],
    }
    
    for app, prefixes in app_prefixes.items():
        if function_name in prefixes:
            return app
    
    # 回退：尝试从函数名的第一个下划线前的部分推断
    if '_' in function_name:
        prefix = function_name.split('_')[0]
        # 常见前缀映射
        prefix_map = {
            'get': 'unknown',
            'send': 'email',
            'search': 'email',
            'create': 'calendar',
            'delete': 'cloud_drive',
            'list': 'cloud_drive',
            'update': 'user_account',
            'schedule': 'banking',
            'reschedule': 'calendar',
            'cancel': 'calendar',
            'add': 'calendar',
            'append': 'cloud_drive',
            'share': 'cloud_drive',
        }
        return prefix_map.get(prefix, 'unknown')
    
    return 'unknown'


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
        
        # Save pre-execution environment snapshot
        pre_environment = env
        
        # 从 FunctionsRuntime 获取语义描述（原版 Function.description）
        tool_description = _get_function_description(self, function)
        
        # 推断 Target APP
        target_app = _infer_app_from_function(function)
        
        event_record = {
            "timestamp": start_time,
            "agent_id": ctx.current_agent_id,
            "tool_intent": function,
            "tool_description": tool_description,  # 语义描述，用于生成友好标签
            "target_app": target_app,
            "inputs": kwargs,
            "thought": ctx.current_reasoning.response if ctx.current_reasoning else None,
            "thought_prompt": ctx.current_reasoning.prompt if ctx.current_reasoning else None,
            "type": "api_call_start"
        }

        
        # Link this tool call to the current reasoning context (wasInformedBy)
        ctx.link_tool_call_to_reasoning(event_record)
        
        # Graph construction hook (Modeling Layer)
        from ..modeling.graph_db import record_activity
        record_activity(event_record)
        
        # Analyze input (Auditing Layer Pipeline) before execution
        # Also extracts D_int (intended data categories) for Ring 3 DOE
        # 检查全局防御开关，关闭时跳过所有 Analysis Pipeline
        # 从 ctx 获取用户原始 prompt，传递给 Ring 0 和 Ring 2
        user_prompt = ctx.current_reasoning.prompt if ctx.current_reasoning else None
        defense_diagnostics = {"ring_2": {}}
        intended_data_categories = set()
        if _defense_enabled:
            allow, modified_kwargs, defense_diagnostics, intended_data_categories = process_before_execution(
                event_record, prompt=user_prompt
            )
        else:
            allow, modified_kwargs = True, kwargs
        
        if not allow:
            # 记录阻断事件到 TrackingContext，以便前端展示风险卡片和 defense_audit
            end_time = time.time()
            block_reason = event_record.get('block_reason', 'Ring 2: Action inconsistent with user intent (possible injection influence).')
            blocked_event = {
                "timestamp": end_time,
                "agent_id": ctx.current_agent_id,
                "tool_intent": function,
                "target_app": target_app,
                "status": "blocked",
                "outputs": "<Data omitted because a prompt injection was detected>",
                "error": None,
                "type": "api_call_end",
                "wasInformedBy": event_record.get("wasInformedBy"),
                "activity_id": event_record.get("activity_id"),  # 传递 activity_id 用于图谱精确匹配
                "environment_delta": None,
                "block_reason": block_reason,
                "defense_diagnostics": {
                    "before": defense_diagnostics,
                    "after": {"ring_3": {}, "ring_1": {}},
                },
            }
            ctx.log_event(blocked_event)
            
            # 也在图谱中记录阻断的节点，以便前端统计阻断数
            from ..modeling.graph_db import update_activity_outcome
            # 给 event_record 添加 blocked 标记
            event_record["blocked"] = True
            event_record["block_reason"] = block_reason
            update_activity_outcome(blocked_event)
            
            # 抛出异常中断 AgentPipeline 执行循环，避免 LLM 陷入循环尝试
            raise PromptInjectionBlockedError(
                f"Tool call '{function}' was blocked: prompt injection detected.",
                block_reason=block_reason,
                tool_intent=function,
            )
        
        # Execute actual function
        result, error = func(self, env, function, modified_kwargs, raise_on_error)
        
        end_time = time.time()
        
        # Post execution semantic extraction/snapshot
        out_domain_snapshot = None
        if result is not None and not error:
            try:
                out_domain_snapshot = str(result)
            except Exception:
                out_domain_snapshot = "Unserializable Result"
        
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
        
        event_complete = {
            "timestamp": end_time,
            "tool_intent": function,
            "target_app": target_app,
            "status": "success" if not error else "error",
            "outputs": out_domain_snapshot,
            "error": error,
            "type": "api_call_end",
            "wasInformedBy": event_record.get("wasInformedBy"),
            "activity_id": event_record.get("activity_id"),  # 传递 activity_id 用于图谱精确匹配
            "environment_delta": environment_delta,
        }
        
        # Post-execution validation (AgentRaft DOE + prompt injection detection)
        # Pass D_int (intended data categories) from before-execution analysis
        # 检查全局防御开关，关闭时跳过所有 Analysis Pipeline
        after_diagnostics = {"ring_3": {}, "ring_1": {}}
        try:
            if _defense_enabled:
                final_result, after_diagnostics = process_after_execution_with_details(
                    event_complete, result,
                    intent_data=intended_data_categories,
                )
            else:
                final_result = result
        except PromptInjectionBlockedError:
            # Ring 1 检测到提示注入，记录阻断事件后重新抛出异常
            event_complete["status"] = "blocked"
            event_complete["block_reason"] = "Ring 1: Indirect prompt injection detected in tool output."
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
            ctx.log_event(event_complete)
            # 更新图谱中的节点状态为 blocked
            event_complete["blocked"] = True
            from ..modeling.graph_db import update_activity_outcome
            update_activity_outcome(event_complete)
            raise
        
        # Update Graph with outcome (移到 try 块之后，避免阻断时重复创建输出节点)
        from ..modeling.graph_db import update_activity_outcome
        update_activity_outcome(event_complete)
        
        # Attach defense diagnostics to the event for trace file collection
        event_complete["defense_diagnostics"] = {
            "before": defense_diagnostics,
            "after": after_diagnostics,
        }
        
        # Log the complete event (including defense diagnostics) to TrackingContext
        ctx.log_event(event_complete)
        
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
    
    # Patch LLM query methods to capture reasoning context
    _patch_llm_query_methods()


def _patch_llm_query_methods():
    """
    Attempt to patch LLM query methods in the agent pipeline.
    This wraps the query() method of LLM pipeline elements to capture reasoning context.
    
    Note: agentdojo.agent_pipeline.llms is a package (not a module), so we must
    traverse its submodules to find LLM classes.
    """
    import agentdojo.agent_pipeline.llms as llms_pkg
    import importlib
    import inspect
    
    patched_count = 0
    # Traverse all submodules of the llms package
    for attr_name in dir(llms_pkg):
        if attr_name.startswith('_'):
            continue
        submodule = getattr(llms_pkg, attr_name)
        if not hasattr(submodule, '__file__'):
            continue
        # Import the submodule to ensure it's loaded
        try:
            full_name = f"agentdojo.agent_pipeline.llms.{attr_name}"
            submod = importlib.import_module(full_name)
        except (ImportError, TypeError):
            continue
        
        # Find LLM classes in this submodule
        for name, cls in inspect.getmembers(submod, inspect.isclass):
            if hasattr(cls, 'query') and name.endswith('LLM'):
                original_query = cls.query
                if not hasattr(original_query, "__wrapped__"):
                    cls.query = capture_llm_interaction(original_query)
                    patched_count += 1
    
    if patched_count > 0:
        print(f"Data Flow Tracking enabled: {patched_count} LLM query methods intercepted.")
    else:
        print("Warning: No LLM query methods were patched.")

