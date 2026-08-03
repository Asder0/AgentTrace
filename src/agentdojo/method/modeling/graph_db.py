"""
Modeling Layer: FSM ⊕ PROV fused knowledge graph.
Uses NetworkX for in-memory prototyping (replaceable with Neo4j).

Implements:
- PROV-AGENT core entities: AIAgent, AIModelInvocation, AgentTool, Prompt, DomainData
- PROV relationships: used, wasGeneratedBy, wasInformedBy, wasAttributedTo
- FSM state machine: State (DomainData) -> Transition (AgentTool) -> State (DomainData)

节点命名优化（v2）：
- 使用友好的 label 替代原始 ID 展示
- 合并 Thought 节点到 AIModelInvocation
- Entity_Delta 改为更直观的命名

边方向优化（v2）：
- informed: Prompt → AIModelInvocation（Prompt 通知 LLM）
- informed: AIModelInvocation → AgentTool（LLM 决策通知工具调用）
- used: AgentTool → DomainData(Input)（工具使用输入数据）
- produces: AgentTool → DomainData(Output)（工具产生输出数据）
- belongsTo: AgentTool → AIAgent（工具归属于 Agent）
"""

import networkx as nx
import uuid
import threading
from typing import Any, Dict, List, Optional


class KnowledgeGraph:
    """
    Singleton mimicking Neo4j Graph DB holding PROV-AGENT AND FSM structures.
    Uses NetworkX for easy memory prototyping without external dependencies.
    
    Node types:
    - AIAgent: The AI agent entity
    - AIModelInvocation: A specific LLM reasoning step (Thought/Action)
    - AgentTool: A tool call (FSM Transition)
    - Prompt: The prompt sent to the LLM
    - DomainData: A data entity (FSM State)
    
    Edge types (v2 - 优化方向与命名):
    - belongsTo: AgentTool → AIAgent（工具归属于 Agent）
    - informed: Prompt → AIModelInvocation（Prompt 通知 LLM 推理）
    - informed: AIModelInvocation → AgentTool（LLM 推理通知工具调用）
    - used: AgentTool → DomainData(Input)（工具使用输入数据）
    - produces: AgentTool → DomainData(Output)（工具产生输出数据）
    - wasDerivedFrom: Entity → Entity（数据派生）
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(KnowledgeGraph, cls).__new__(cls, *args, **kwargs)
                cls._instance.G = nx.DiGraph()
                # PROV Core Entities
                cls._instance.agent_node = "AIAgent_Default"
                cls._instance.G.add_node(
                    cls._instance.agent_node, 
                    type="AIAgent", 
                    label="AgentDojo Agent"
                )
                # Track the last AIModelInvocation for wasInformedBy linking
                cls._instance.last_invocation_id: Optional[str] = None
        return cls._instance


def _make_label(node_type: str, content: str, max_len: int = 120) -> str:
    """生成友好的节点显示标签。"""
    if not content:
        return node_type
    text = content if len(content) <= max_len else content[:max_len-2] + '…'
    return text


def _make_tool_label(tool_intent: str, tool_description: str = "") -> str:
    """生成工具调用节点标签，直接使用函数名。"""
    return tool_intent


def _infer_app_from_function_name(function_name: str) -> str:
    """根据函数名推断所属 APP（与 interceptor.py 中的 _infer_app_from_function 保持一致）。"""
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
    return 'unknown'


def _find_or_create_prompt_node(G: nx.DiGraph, prompt_text: str, timestamp: float) -> str:
    """查找是否已有相同内容的 Prompt 节点，有则复用，无则创建。
    
    避免同一用户指令的多次 LLM 推理创建多个内容相同的 Prompt 节点。
    """
    for node_id, attr in G.nodes(data=True):
        if attr.get('type') == 'Prompt' and attr.get('content') == prompt_text:
            return node_id
    # 未找到，创建新的 Prompt 节点
    prompt_id = f"Prompt_{uuid.uuid4().hex[:8]}"
    G.add_node(
        prompt_id,
        type="Prompt",
        label=_make_label('用户指令', prompt_text),
        content=prompt_text,
        timestamp=timestamp,
    )
    return prompt_id


def record_llm_interaction(event: Dict[str, Any]):
    """
    Records an LLM interaction as an AIModelInvocation node.
    
    v2 优化：
    - 友好的 label：从 prompt 中提取摘要
    - 边方向修正：Prompt → informed → AIModelInvocation
    - 合并 Thought 概念到 AIModelInvocation（不再单独创建 Thought 节点）
    - 复用相同内容的 Prompt 节点，避免重复
    """
    kg = KnowledgeGraph()
    G = kg.G
    
    prompt_text = event.get('prompt', '')
    thought_id = event.get('thought_id', uuid.uuid4().hex[:8])
    invocation_id = f"AIModelInvocation_{thought_id}"
    event['invocation_id'] = invocation_id
    
    # Node: AIModelInvocation — 使用友好的 label
    G.add_node(
        invocation_id,
        type="AIModelInvocation",
        label=_make_label('LLM 推理', prompt_text),
        prompt=prompt_text,
        response=event.get('response', ''),
        timestamp=event['timestamp'],
    )
    
    # Node: Prompt — 复用相同内容的 Prompt 节点
    prompt_id = _find_or_create_prompt_node(G, prompt_text, event['timestamp'])
    
    # Edge v2: Prompt → informed → AIModelInvocation
    # 语义：Prompt（用户指令）通知/触发了 LLM 推理
    G.add_edge(prompt_id, invocation_id, relation="informed")
    
    # Edge v2: AIModelInvocation → belongsTo → AIAgent
    # 语义：LLM 推理归属于 AI Agent
    agent_id = event.get('agent_id', kg.agent_node)
    G.add_edge(invocation_id, agent_id, relation="belongsTo")
    
    # Store as last invocation for subsequent tool calls to link to
    kg.last_invocation_id = invocation_id


def record_activity(event: Dict[str, Any]):
    """
    Records an incoming API interception as a new AgentTool node.
    
    v2 优化：
    - 友好的 label
    - 边方向修正：AIModelInvocation → informed → AgentTool
    - 不再创建单独的 Thought 节点（合并到 AIModelInvocation）
    """
    kg = KnowledgeGraph()
    G = kg.G
    
    tool_intent = event['tool_intent']
    activity_id = f"Activity_{tool_intent}_{uuid.uuid4().hex[:8]}"
    event['activity_id'] = activity_id
    
    # Node: AgentTool — 使用语义丰富的 label
    tool_description = event.get('tool_description', '')
    tool_label = _make_tool_label(tool_intent, tool_description)
    G.add_node(
        activity_id,
        type="AgentTool",
        label=tool_label,
        app=event['target_app'],
        inputs=str(event['inputs']),
        timestamp=event['timestamp'],
        wasInformedBy=event.get('wasInformedBy'),
    )
    
    # Edge v2: AgentTool → belongsTo → AIAgent
    agent_id = event.get('agent_id', kg.agent_node)
    G.add_edge(activity_id, agent_id, relation="belongsTo")
    
    # 确定 LLM 推理节点 ID
    was_informed_by = event.get('wasInformedBy')
    if was_informed_by:
        if was_informed_by.startswith("AIModelInvocation_"):
            invocation_id = was_informed_by
        else:
            invocation_id = f"AIModelInvocation_{was_informed_by}"
        if not G.has_node(invocation_id):
            invocation_id = None
    else:
        invocation_id = kg.last_invocation_id if kg.last_invocation_id else None
    
    if event['inputs']:
        # 有输入参数时：
        # LLM推理节点 → informed → 输入参数节点 → used → 工具函数节点
        input_entity_id = f"Entity_Input_{uuid.uuid4().hex[:8]}"
        G.add_node(
            input_entity_id,
            type="DomainData",
            label=_make_label('输入数据', str(event['inputs'])),
            content=str(event['inputs']),
            source_app=event.get('target_app', 'unknown'),
            operation="input",
        )
        # LLM推理节点 → informed → 输入参数节点
        if invocation_id:
            G.add_edge(invocation_id, input_entity_id, relation="informed")
        # 输入参数节点 → used → 工具函数节点
        G.add_edge(input_entity_id, activity_id, relation="used")
    else:
        # 无输入参数时：LLM推理节点 → informed → 工具函数节点
        if invocation_id:
            G.add_edge(invocation_id, activity_id, relation="informed")


def update_activity_outcome(event: Dict[str, Any]):
    """
    Records the result/snapshot of the executed Action into the Graph.
    
    v2 优化：
    - 友好的 label
    - 边方向修正：AgentTool → produces → DomainData(Output)
    - Entity_Delta 改为更直观的命名
    - 使用 activity_id 精确匹配 AgentTool 节点，避免模糊匹配
    """
    kg = KnowledgeGraph()
    G = kg.G
    
    # 优先使用 activity_id 精确匹配（由 record_activity 生成并保存到 event 中）
    activity_id = event.get('activity_id', '')
    if activity_id and G.has_node(activity_id):
        best_activity = activity_id
    else:
        # 回退：通过 wasInformedBy 精确匹配
        was_informed_by = event.get('wasInformedBy')
        if was_informed_by:
            activities = [
                n for n, attr in G.nodes(data=True) 
                if attr.get('type') == 'AgentTool' and attr.get('wasInformedBy') == was_informed_by
            ]
            if activities:
                best_activity = activities[-1]
            else:
                return
        else:
            return
    
    # 如果事件被阻断，在节点上设置 blocked 标记
    if event.get('status') == 'blocked':
        # 如果节点已经有 blocked 标记，说明 update_activity_outcome 已被调用过
        # 避免重复创建输出节点（Ring 1 阻断时会被调用两次）
        if G.nodes[best_activity].get('blocked'):
            return
        G.nodes[best_activity]['blocked'] = True
        G.nodes[best_activity]['block_reason'] = event.get('block_reason', 'Unknown')
    
    # Record output as a new Domain Data (FSM State)
    if event.get('outputs'):
        output_entity_id = f"Entity_Output_{uuid.uuid4().hex[:8]}"
        G.add_node(
            output_entity_id,
            type="DomainData",
            label='',
            content=event['outputs'],
            status=event['status'],
            source_app=event.get('target_app', 'unknown'),
            operation="output",
        )
        # Edge: 工具函数节点 → produces → 输出结果节点
        # 语义：工具函数执行后产生输出数据
        G.add_edge(best_activity, output_entity_id, relation="produces")
    
    # Record environment delta entities (v2 - 丰富信息)
    env_delta = event.get('environment_delta')
    if env_delta:
        for entity_info in env_delta.get('created', []):
            # entity_info 可能是字符串（旧格式兼容）或字典（新格式）
            if isinstance(entity_info, str):
                entity_id = entity_info
                entity_type = "unknown"
                attributes = {}
                data_payload = None
            else:
                entity_id = entity_info.get('entity_id', 'unknown')
                entity_type = entity_info.get('entity_type', 'unknown')
                attributes = entity_info.get('attributes', {})
                data_payload = entity_info.get('data_payload')
            
            delta_entity_id = f"Entity_Delta_{uuid.uuid4().hex[:8]}"
            
            # 生成更有意义的标签
            type_icons = {
                'email': '📧',
                'file': '📄',
                'contact': '👤',
                'transaction': '💰',
                'calendar_event': '📅',
                'travel_booking': '✈️',
                'unknown': '📝',
            }
            icon = type_icons.get(entity_type, '📝')
            
            # 从 attributes 中提取关键信息生成描述
            attr_summary = ""
            if attributes:
                # 取前 2 个非空属性值作为描述
                vals = [str(v) for v in attributes.values() if v is not None and v != '']
                if vals:
                    attr_summary = ": " + ", ".join(vals[:2])
            
            # 如果有 data_payload，优先使用
            display_content = data_payload or attr_summary or entity_id
            
            G.add_node(
                delta_entity_id,
                type="DomainData",
                label=f"{icon} 创建 {entity_type}: {entity_id.split(':')[-1][:20]}",
                content=display_content,
                source_app=event.get('target_app', 'unknown'),
                operation="created",
                entity_type=entity_type,
                attributes=attributes,
            )
            G.add_edge(best_activity, delta_entity_id, relation="produces")
        
        for entity_info in env_delta.get('updated', []):
            if isinstance(entity_info, str):
                entity_id = entity_info
                entity_type = "unknown"
                attributes = {}
                data_payload = None
            else:
                entity_id = entity_info.get('entity_id', 'unknown')
                entity_type = entity_info.get('entity_type', 'unknown')
                attributes = entity_info.get('attributes', {})
                data_payload = entity_info.get('data_payload')
            
            delta_entity_id = f"Entity_Delta_{uuid.uuid4().hex[:8]}"
            
            type_icons = {
                'email': '📧',
                'file': '📄',
                'contact': '👤',
                'transaction': '💰',
                'calendar_event': '📅',
                'travel_booking': '✈️',
                'unknown': '📝',
            }
            icon = type_icons.get(entity_type, '📝')
            
            attr_summary = ""
            if attributes:
                vals = [str(v) for v in attributes.values() if v is not None and v != '']
                if vals:
                    attr_summary = ": " + ", ".join(vals[:2])
            
            display_content = data_payload or attr_summary or entity_id
            
            G.add_node(
                delta_entity_id,
                type="DomainData",
                label=f"{icon} 更新 {entity_type}: {entity_id.split(':')[-1][:20]}",
                content=display_content,
                source_app=event.get('target_app', 'unknown'),
                operation="updated",
                entity_type=entity_type,
                attributes=attributes,
            )
            G.add_edge(best_activity, delta_entity_id, relation="produces")


def get_graph_data() -> Dict[str, Any]:
    """
    Returns graph representation for the Visualization Dashboard.
    Serializes to JSON-friendly Dict.
    
    Uses edges='links' to match the 'links' key expected by the frontend D3.js.
    Also converts source/target from strings to {id: string} objects for D3 force layout.
    """
    kg = KnowledgeGraph()
    data = nx.node_link_data(kg.G, edges='links')
    
    # Convert source/target from strings to {id: string} objects for D3 force layout
    # D3's forceLink().id(d => d.id) expects source/target to be node references
    for link in data.get('links', []):
        if isinstance(link.get('source'), str):
            link['source'] = {'id': link['source']}
        if isinstance(link.get('target'), str):
            link['target'] = {'id': link['target']}
    
    # 统一 app 字段：将 source_app 映射到 app，并为没有 app 的节点推断
    for node in data.get('nodes', []):
        # 如果有 source_app，统一为 app
        if 'source_app' in node and 'app' not in node:
            node['app'] = node['source_app']
        # 如果既没有 app 也没有 source_app，根据节点类型推断
        if 'app' not in node:
            ntype = node.get('type', '')
            if ntype == 'AIAgent':
                node['app'] = 'system'
            elif ntype == 'AIModelInvocation':
                node['app'] = 'system'
            elif ntype == 'Prompt':
                node['app'] = 'system'
            elif ntype == 'AgentTool':
                # 尝试从关联的边推断 app
                node['app'] = 'unknown'
            elif ntype == 'DomainData':
                node['app'] = 'unknown'
            else:
                node['app'] = 'unknown'
    
    return data


def get_graph_summary() -> Dict[str, Any]:
    """
    Returns a summary of the graph for quick analysis.
    """
    kg = KnowledgeGraph()
    G = kg.G
    
    node_types = {}
    edge_types = {}
    
    for _, attr in G.nodes(data=True):
        ntype = attr.get('type', 'unknown')
        node_types[ntype] = node_types.get(ntype, 0) + 1
    
    for _, _, attr in G.edges(data=True):
        etype = attr.get('relation', 'unknown')
        edge_types[etype] = edge_types.get(etype, 0) + 1
    
    return {
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "node_types": node_types,
        "edge_types": edge_types,
    }
