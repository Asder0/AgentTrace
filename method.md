# AgentDojo 防御监控平台文档 (Method Layer)

## 概述

`src/agentdojo/method/` 目录实现了一套**四层防御监控架构**，用于追踪、分析和防御 AI Agent 在执行工具调用过程中的安全风险。该机制通过**面向切面编程（AOP）** 拦截 Agent 的所有工具调用和 LLM 推理，在调用前后执行多层安全检查，并结合**知识图谱建模**和**可视化仪表盘**提供完整的可观测性。

此外，`src/agentdojo/method/visualization/` 还包含一个完整的 **Flask API 服务器** 和 **跨 APP 路由 Runtime**，配合 `frontend/` 目录下的 **D3.js 前端可视化平台**，提供实时数据流追踪、风险审计和交互式拓扑图展示。

### 核心设计理念

- **非侵入式**：通过猴子补丁（Monkey Patching）在运行时动态注入，无需修改 Agent 原有代码
- **多层防御**：四层架构各司其职，Analysis 层内部 4-Ring 管道提供纵深防御
- **可观测性**：全量追踪 + 知识图谱溯源 + 可视化仪表盘
- **优雅降级**：所有 ML 模型均支持懒加载，不可用时自动降级为规则/正则回退
- **跨 APP 路由**：RouterRuntime 统一路由 workspace + banking 工具调用，模拟真实微服务架构
- **实时可视化**：Flask API + D3.js 前端提供实时数据流拓扑图、事件时间线和风险审计

---

## 一、防御系统 vs 原 AgentDojo 平台

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        AgentDojo 原平台架构                                 │
│                                                                            │
│  ┌──────────────┐    ┌──────────────────────────────┐    ┌──────────────┐  │
│  │ benchmark.py │───▶│       AgentPipeline          │───▶│  TaskSuite   │  │
│  │ (入口脚本)    │    │                              │    │  (评估套件)   │  │
│  └──────────────┘    │  ┌────────────────────────┐  │    └──────────────┘  │
│                      │  │  LLM (推理引擎)          │  │                     │
│                      │  │  · GoogleLLM            │  │                     │
│                      │  │  · OpenAILLM            │  │                     │
│                      │  │  · AnthropicLLM         │  │                     │
│                      │  │  · LocalLLM             │  │                     │
│                      │  └───────────┬────────────┘  │                     │
│                      │              │ 返回工具调用决策 │                     │
│                      │              ▼                │                     │
│                      │  ┌────────────────────────┐  │                     │
│                      │  │   FunctionsRuntime     │  │                     │
│                      │  │   (工具执行引擎)        │  │                     │
│                      │  │   · run_function()     │  │                     │
│                      │  │   · 注册/管理工具       │  │                     │
│                      │  └────────────────────────┘  │                     │
│                      └──────────────────────────────┘                     │
│                                                                            │
│  ════════════════════════════════════════════════════════════════════════  │
│                                                                            │
│              防御监控系统（method/）的切入方式（AOP 面向切面编程）            │
│                                                                            │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  activate_platform() → enable_tracking()                          │    │
│  │                                                                    │    │
│  │  猴子补丁 ①: FunctionsRuntime.run_function                         │    │
│  │    → 被 capture_tool_call 装饰器包装                                │    │
│  │    → 在工具调用前后插入：                                           │    │
│  │      前置: 环境快照 → 图谱记录 → Ring 0 → Ring 2                    │    │
│  │      后置: 环境增量 → 图谱更新 → Ring 3 → Ring 1                    │    │
│  │                                                                    │    │
│  │  猴子补丁 ②: LLM.query 方法（遍历 llms 包所有子模块）                 │    │
│  │    → 被 capture_llm_interaction 包装                                │    │
│  │    → 在 LLM 推理前后插入：                                          │    │
│  │      前置: 记录 Prompt                                              │    │
│  │      后置: 提取 Response → 创建 ReasoningContext → 图谱记录          │    │
│  │                                                                    │    │
│  │  关键特性：                                                          │    │
│  │  · 非侵入式：无需修改 AgentPipeline / FunctionsRuntime 原有代码       │    │
│  │  · 运行时注入：在 activate_platform() 调用时动态生效                  │    │
│  │  · 可开关：_defense_enabled 全局变量控制 Analysis Pipeline 启停      │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 二、四层防御监控架构总览

```
┌─────────────────────────────────────────────────────────────────────┐
│                       四层防御监控架构                                │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │               Capture Layer (AOP 拦截层)                      │   │
│  │  ┌─────────────────────┐  ┌──────────────────────────────┐  │   │
│  │  │  interceptor.py     │  │  environment_snapshot.py     │  │   │
│  │  │  · 工具调用拦截      │  │  · 环境状态语义解析           │  │   │
│  │  │  · LLM 推理捕获      │  │  · 增量计算 (created/        │  │   │
│  │  │  · wasInformedBy 绑定│  │    updated/deleted/accessed) │  │   │
│  │  │  · TrackingContext   │  │  · 语义噪声过滤              │  │   │
│  │  └─────────────────────┘  └──────────────────────────────┘  │   │
│  └──────────────────────┬──────────────────────────────────────┘   │
│                         │                                          │
│                         ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              Modeling Layer (知识图谱建模层)                   │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │  graph_db.py                                         │   │   │
│  │  │  · PROV + FSM 融合有向图 (NetworkX)                   │   │   │
│  │  │  · 节点: AIAgent / AIModelInvocation / AgentTool /   │   │   │
│  │  │         Prompt / DomainData                           │   │   │
│  │  │  · 边: informed / used / produces / belongsTo         │   │   │
│  │  │  · 语义化标签 (emoji + 中文描述)                       │   │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  └──────────────────────┬──────────────────────────────────────┘   │
│                         │                                          │
│                         ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              Analysis Layer (4-Ring 审计管道)                  │   │
│  │                                                               │   │
│  │   ┌──────────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────┐ │   │
│  │   │ Ring 0:      │  │ Ring 1:      │  │ Ring 2:  │  │ Ring 3:  │ │   │
│  │   │ Prompt Inj.  │  │ Prompt Inj.  │  │ Intent   │  │ DOE      │ │   │
│  │   │ (LLM 前)     │  │ (后置)       │  │Consistency│  │ 数据脱敏  │ │   │
│  │   └──────────────┘  └──────────────┘  └──────────┘  └──────────┘ │   │
│  │                                                               │   │
│  │   ┌──────────────────────────────────────────────────────┐    │   │
│  │   │  model_utils.py (模型管理)                            │    │   │
│  │   │  · PI Detector: protectai/deberta-v3-base-prompt-    │    │   │
│  │   │    injection-v2 (Ring 0 & Ring 1 共用)               │    │   │
│  │   │  · Sentence Encoder: all-MiniLM-L6-v2 (Ring 2)      │    │   │
│  │   │  · NER Pipeline: dslim/bert-base-NER (Ring 3)       │    │   │
│  │   │  · 所有模型懒加载 + 自动降级                           │    │   │
│  │   └──────────────────────────────────────────────────────┘    │   │
│  └──────────────────────┬──────────────────────────────────────┘   │
│                         │                                          │
│                         ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │            Visualization Layer (可视化层)                     │   │
│  │                                                               │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │  dashboard.py (控制台可视化)                          │   │   │
│  │  │  · InconPreter 风险卡片                               │   │   │
│  │  │  · DataShield 隐私营养标签                             │   │   │
│  │  │  · 图谱 JSON 导出                                     │   │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  │                                                               │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │  server.py (Flask API 服务器)                         │   │   │
│  │  │  · REST API 端点 (15+)                               │   │   │
│  │  │  · LLM 配置管理                                      │   │   │
│  │  │  · 防御开关控制                                      │   │   │
│  │  │  · AgentPipeline 执行引擎                             │   │   │
│  │  │  · 追踪记录持久化                                    │   │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  │                                                               │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │  mock_apps.py (跨 APP 路由 Runtime)                   │   │   │
│  │  │  · RouterRuntime: 工具名 → APP 路由                   │   │   │
│  │  │  · UnifiedEnvironment: 统一环境                       │   │   │
│  │  │  · 原版 TaskSuite 加载                                │   │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  │                                                               │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │  frontend/ (D3.js 前端可视化平台)                     │   │   │
│  │  │  · 实时数据流拓扑图 (graph.js)                        │   │   │
│  │  │  · 事件时间线 (timeline.js)                           │   │   │
│  │  │  · 风险卡片面板 (risk-panel.js)                       │   │   │
│  │  │  · 操作控制台 (console.js)                            │   │   │
│  │  │  · 系统状态面板 (status-panel.js)                     │   │   │
│  │  │  · 指令流转追踪 (trace-panel.js)                      │   │   │
│  │  │  · API 通信 (api.js)                                 │   │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 三、Capture Layer — AOP 拦截层

**文件**: `src/agentdojo/method/capture/interceptor.py`, `environment_snapshot.py`

### 3.1 核心机制

通过**猴子补丁（Monkey Patching）** 技术，在运行时动态替换 `FunctionsRuntime.run_function` 方法，使其被 `capture_tool_call` 装饰器包装。同时遍历 `agentdojo.agent_pipeline.llms` 包的所有子模块，拦截 LLM 类的 `query` 方法以捕获推理上下文。

```python
def enable_tracking():
    import agentdojo.functions_runtime as functions_runtime
    
    # 拦截工具调用
    if not hasattr(functions_runtime.FunctionsRuntime.run_function, "__wrapped__"):
        original = functions_runtime.FunctionsRuntime.run_function
        functions_runtime.FunctionsRuntime.run_function = capture_tool_call(original)
    
    # 拦截 LLM 推理（遍历 llms 包的所有子模块）
    _patch_llm_query_methods()
```

### 3.2 拦截流程

```
LLM 推理捕获 (capture_llm_interaction)
  │
  ├─ 1. 记录 Prompt（用户查询）
  ├─ 2. 执行 LLM 调用
  ├─ 3. 提取 Response（Thought + Action）
  ├─ 4. 创建 ReasoningContext（thought_id, prompt, response）
  ├─ 5. 记录 LLM 事件到 TrackingContext
  └─ 6. 记录到知识图谱 (record_llm_interaction)

工具调用拦截 (capture_tool_call)
  │
  ├─ 前置阶段
  │  ├─ 1. 保存执行前环境快照
  │  ├─ 2. 获取工具语义描述 (Function.description)
  │  ├─ 3. 推断目标 APP (target_app)
  │  ├─ 4. 构建 event_record
  │  ├─ 5. 绑定 wasInformedBy（链接到当前 LLM 推理）
  │  ├─ 6. 记录到知识图谱 (record_activity)
  │  ├─ 7. 执行 Analysis Pipeline 前置检查
│  │    └─ Ring 2 (意图一致性)
  │  └─ 8. 如果阻断，返回错误
  │
  ├─ 执行阶段
  │  └─ 调用原始 run_function
  │
  └─ 后置阶段
     ├─ 1. 提取输出结果
     ├─ 2. 计算环境增量 (EnvironmentDelta)
     ├─ 3. 更新知识图谱 (update_activity_outcome)
     └─ 4. 执行 Analysis Pipeline 后置检查
          └─ Ring 3 (DOE 脱敏) → Ring 1 (注入检测)
```

### 3.3 TrackingContext 单例

使用单例模式维护全局的追踪上下文：

| 属性 | 类型 | 说明 |
|------|------|------|
| `events` | `List[Dict]` | 事件列表 |
| `current_agent_id` | `str` | 当前 Agent ID（默认 `"AIAgent_Default"`） |
| `reasoning_history` | `List[ReasoningContext]` | 推理历史（Thought/Action 序列） |
| `current_reasoning` | `Optional[ReasoningContext]` | 当前推理上下文 |
| `last_environment` | `Any` | 执行前的环境快照 |

**ReasoningContext** 记录单次 LLM 推理的完整上下文：

| 字段 | 说明 |
|------|------|
| `thought_id` | 唯一标识（如 `thought_a1b2c3d4`） |
| `prompt` | 发送给 LLM 的 Prompt |
| `response` | LLM 的响应（Thought + Action） |
| `tool_calls` | 本次推理触发的工具调用列表 |
| `timestamp` | 时间戳 |

### 3.4 全局防御开关

```python
_defense_enabled = True  # 全局开关，关闭后 Analysis Pipeline 全部跳过
```

当 `_defense_enabled = False` 时：
- `process_before_execution` 被跳过，直接返回 `(True, kwargs, {}, set())`
- `process_after_execution` 被跳过，直接返回原始 `result`

该开关可通过前端可视化平台的防御开关 toggle 控制，通过 `/api/config/defense` API 动态修改。

### 3.5 工具语义推断

**`_get_function_description(runtime, function_name)`**：从 `FunctionsRuntime.functions[].description` 获取函数的语义描述（原版 Function 的 docstring 短描述），无需硬编码映射。

**`_infer_app_from_function(function_name)`**：根据函数名推断所属 APP（如 `send_email` → `email`，`get_balance` → `banking`），用于生成友好的可视化标签。

### 3.6 环境状态语义解析

**文件**: `src/agentdojo/method/capture/environment_snapshot.py`

对比执行前后的环境状态，提取语义化的 `DomainData` 实体：

| 实体类型 | 推断关键词 |
|---------|-----------|
| `email` | email, inbox, mail, sent, draft, message |
| `file` | file, document, attachment, download |
| `contact` | contact, recipient, sender, address_book |
| `transaction` | transaction, payment, transfer, balance, account |
| `calendar_event` | calendar, event, meeting, appointment |
| `travel_booking` | flight, hotel, booking, reservation, trip |

**语义噪声过滤**：自动过滤 UI 渲染相关的噪声属性（如 `timestamp`, `uuid`, `scroll_position`, `animation_state` 等），只保留交互属性和数据负载。

**环境增量（EnvironmentDelta）**：

| 集合 | 说明 |
|------|------|
| `created` | 新增的实体 |
| `updated` | 更新的实体 |
| `deleted` | 删除的实体 |
| `accessed` | 访问的实体（无变化） |

---

## 四、Modeling Layer — 知识图谱建模层

**文件**: `src/agentdojo/method/modeling/graph_db.py`

### 4.1 核心机制

使用 **NetworkX** 实现内存中的有向图（`nx.DiGraph`），模拟 **PROV-AGENT**（W3C 溯源标准）和 **FSM**（有限状态机）数据结构的融合。采用单例模式，线程安全。

### 4.2 图谱节点类型

| 节点类型 | 说明 | 对应概念 |
|---------|------|---------|
| `AIAgent` | AI Agent 实体（根节点） | PROV: Agent |
| `AIModelInvocation` | LLM 推理步骤（合并 Thought 概念） | PROV: Activity |
| `AgentTool` | 工具调用活动（FSM Transition） | PROV: Activity |
| `Prompt` | 推理提示内容 | PROV: Entity |
| `DomainData` | 输入/输出/环境数据（FSM State） | PROV: Entity |

### 4.3 图谱边类型（v2 优化）

| 边关系 | 方向 | 语义 |
|-------|------|------|
| `informed` | Prompt → AIModelInvocation | Prompt（用户指令）通知/触发了 LLM 推理 |
| `informed` | AIModelInvocation → AgentTool | LLM 推理通知/触发了工具调用 |
| `used` | AgentTool → DomainData(Input) | 工具调用使用了输入数据 |
| `produces` | AgentTool → DomainData(Output) | 工具调用产生了输出数据 |
| `belongsTo` | AgentTool → AIAgent | 工具调用归属于 Agent |
| `belongsTo` | AIModelInvocation → AIAgent | LLM 推理归属于 Agent |

### 4.4 语义化标签

节点标签使用 emoji + 中文描述，便于可视化展示：

```
📧 发送邮件          (send_email)
💰 查询余额          (get_balance)
📅 获取今日日程      (get_current_day)
📁 创建文件          (create_file)
📄 读取文件          (read_file)
👤 更新用户信息      (update_user_info)
```

优先使用 `Function.description`（来自原版 docstring），不可用时从函数名自动生成。

### 4.5 关键函数

| 函数 | 触发时机 | 说明 |
|------|---------|------|
| `record_llm_interaction(event)` | LLM 推理完成后 | 创建 AIModelInvocation + Prompt 节点，建立 informed 边 |
| `record_activity(event)` | 工具调用执行前 | 创建 AgentTool + DomainData(Input) 节点，链接到 AIModelInvocation |
| `update_activity_outcome(event)` | 工具调用执行后 | 创建 DomainData(Output) + 环境增量节点，建立 produces 边 |
| `get_graph_data()` | 按需调用 | 导出图谱数据（D3.js 兼容格式，source/target 转为对象引用） |
| `get_graph_summary()` | 按需调用 | 返回图谱统计摘要（节点/边数量、类型分布） |

---

## 五、Analysis Layer — 4-Ring 审计管道

**文件**: `src/agentdojo/method/analysis/pipeline.py`

### 5.1 管道编排

```
process_before_execution(event, prompt)   process_after_execution(event, result)
         │                                         │
         ▼                                         ▼
┌──────────────────────┐                 ┌──────────────────────┐
│   Ring 0:            │                 │   Ring 3:            │
│   Prompt Injection   │                 │   DOE Mitigation     │
│   (LLM 推理前检测)    │                 │   (数据过度暴露脱敏)  │
│                      │                 │                      │
│   ⭐ 最先执行！       │                 │   使用 NER + 正则     │
│   使用 DeBERTa + 正则 │                 │   检测并替换敏感数据   │
│   检测用户输入中的注入 │                 └──────────┬───────────┘
│   如检测到则阻断 LLM  │                            ▼
└──────────┬───────────┘                 ┌──────────────────────┐
           ▼                            │   Ring 1:            │
┌──────────────────────┐                 │   Prompt Injection   │
│   Ring 2:            │                 │   Detection          │
│   Intent Consistency │                 │   (工具输出检测)      │
│   (意图一致性检查)    │                 │                      │
│                      │                 │   使用 DeBERTa + 正则 │
│   检查当前操作是否与   │                 │   检测工具输出中的注入 │
│   用户原始意图一致     │                 │   如检测到则阻断结果   │
└──────────────────────┘                 └──────────────────────┘
```

**执行顺序说明**：

- **前置（调用前）**：Ring 0（LLM 前注入检测）→ Ring 2（意图一致性检查）
  - Ring 0 **最先执行**，检测用户输入的 prompt 是否包含注入指令。如果 prompt 本身被注入，后续所有检查都无意义
  - Ring 2 检查当前操作是否与用户原始意图一致，如果不一致则直接阻断
  - 注意：Ring 0 仅在 LLM 推理前触发（`capture_llm_interaction`），工具调用前置检查只执行 Ring 2

- **后置（调用后）**：Ring 3（DOE 脱敏）→ Ring 1（提示注入检测）
  - Ring 3 实现了 **上下文感知脱敏**（D_OE 公式），不仅检测敏感模式，还结合用户意图判断数据是否属于"过度暴露"。用户合法获取凭据时凭据保留，意外泄露时脱敏。
  - Ring 1 检测脱敏后的输出是否包含注入指令，如果检测到则返回阻断消息

### 5.2 模型管理（model_utils.py）

**文件**: `src/agentdojo/method/analysis/model_utils.py`

所有 ML 模型采用**懒加载**机制，首次使用时加载并缓存，后续调用复用。如果模型加载失败或不可用，自动降级为规则/正则回退。

| 模型 | 用途 | 所属 Ring | 降级策略 |
|------|------|-----------|---------|
| `protectai/deberta-v3-base-prompt-injection-v2` | 提示注入检测 | Ring 0 & Ring 1 | 正则模式匹配 |
| `all-MiniLM-L6-v2` (Sentence-BERT) | 语义相似度计算 | Ring 2 | 关键词重叠 |
| `dslim/bert-base-NER` | 敏感实体识别 | Ring 3 | 正则模式匹配 |

**设备自动选择**：优先 CUDA → MPS → CPU。

---

### 5.3 Ring 1: SkillProbe Prompt Injection Detection — 提示注入检测

**文件**: `src/agentdojo/method/analysis/skillprobe_topology.py`

#### 原理

检测工具输出内容中是否包含**间接提示词注入（Indirect Prompt Injection）** 模式。当 Agent 读取外部内容（如邮件、文件、网页）时，这些内容可能包含恶意指令，试图覆盖 Agent 的原始任务。

#### 检测流程

```
工具输出
  │
  ├─ 1. 安全检查模式匹配（SAFE_PATTERNS）
  │    └─ 匹配 → 返回安全（避免误报）
  │
  └─ 2. DeBERTa 模型检测
       ├─ 可用 → 模型推理
       │    └─ safety_score < threshold → 判定为注入
       └─ 不可用 → 正则回退
            └─ 匹配注入模式 → 判定为注入
```

#### 安全模式白名单（SAFE_PATTERNS）

在模型检测前先匹配，避免误报合法内容：

| 模式 | 示例 |
|------|------|
| `ignore (the )?(file\|email\|message\|...)` | "Please ignore the file I sent earlier." |
| `do not (worry\|hesitate\|forget)` | "Do not worry about the deadline." |
| `please ignore` | "Please ignore the previous message." |
| `you can ignore` | "You can ignore the notification." |

#### 正则回退模式

| 类别 | 检测模式 |
|------|---------|
| 指令覆盖 | `ignore (all )?(previous\|prior\|above) (instructions\|directives\|...)` |
| 系统提示篡改 | `(new\|updated\|modified) (system )?prompt` |
| 身份冒充 | `you are (now )?(a )?(new )?(AI\|assistant\|agent\|bot)` |
| 敏感操作诱导 | `send (this )?(email\|message\|...) to` |
| 转账诱导 | `transfer (money\|funds\|payment) to` |
| 元指令 | `this is (an )?(important\|urgent\|critical) (instruction\|message\|update)` |
| 强制指令 | `you must (now )?(do\|perform\|execute\|complete)` |

#### 阻断效果

返回 `False`，触发 `"BLOCKED: Indirect prompt injection detected in tool output."` 错误。

---

### 5.4 Ring 2: FIDES IFC Intent Consistency — 意图一致性检查

**文件**: `src/agentdojo/method/analysis/fides_ifc.py`

#### 原理

检查 Agent 的当前操作是否与用户的原始任务意图一致。当间接提示词注入成功影响 Agent 时，Agent 可能会执行与用户原始请求无关的操作。

#### 实现

1. **意图提取**：从 LLM 推理上下文中提取用户的原始任务描述（`thought_prompt` 中的 `Query:` 部分）
2. **语义相似度计算**：使用 Sentence-BERT（`all-MiniLM-L6-v2`）计算当前操作意图与用户原始任务描述的语义相似度
3. **阈值判定**：相似度阈值 **0.25**（低于此值判定为意图不一致）
4. **读操作豁免**：`search_emails`, `get_balance`, `read_email` 等读操作始终放行
5. **敏感操作严格审查**：`send_email`, `transfer_money` 等敏感操作需要更高相似度（阈值 + 0.1）

#### IntentTracker 单例

管理用户任务状态，支持 `reset()` 方法用于测试隔离：

```python
class IntentTracker:
    _instance = None
    
    def __new__(cls):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance.user_task: Optional[str] = None
            cls._instance.actions_taken: List[str] = []
            cls._instance.injection_detected: bool = False
        return cls._instance
    
    def reset(self):
        """重置状态（用于测试隔离）"""
        self.user_task = None
        self.actions_taken = []
        self.injection_detected = False
```

#### 阻断效果

返回 `False`，触发 `"FIDES IFC: Action inconsistent with user intent (possible injection influence)."` 错误。

---

### 5.5 Ring 3: AgentRaft DOE — 数据过度暴露缓解

**文件**: `src/agentdojo/method/analysis/agentraft_doe.py`

#### 原理

**DOE（Data Over-Exposure，数据过度暴露）** 缓解机制。公式化表示为：

```
D_OE = (D_trans \ (D_nec ∪ D_int)) ∩ D_total
```

其中：
- **D_total**：代理可访问的全部数据
- **D_trans**：在一次交互中实际传输的数据
- **D_nec（必要数据）**：工具功能所必需的数据（如 `get_credentials` 返回凭据是必要的）
- **D_int（意图数据）**：用户本次任务明确意图访问的数据（如用户说"get my credentials"）
- **D_OE（过度暴露数据）**：传输数据中减去必要数据和意图数据后的剩余敏感数据，**只对此部分进行脱敏**

#### 关键区别

| 场景 | 旧行为 | 新行为 |
|------|--------|--------|
| 用户说"get my credentials" | 密码被 `[REDACTED]` ❌ | 密码保留（D_int 含 credential） ✅ |
| 读邮件时意外泄露凭据 | 脱敏 ✅ | 脱敏（凭据是 D_OE） ✅ |
| 无上下文信息 | 脱敏 ✅ | 保守模式，脱敏 ✅ |

#### 实现

1. **D_nec 提取**：从工具意图（`tool_intent`）映射到必要数据类别
   - `get_credentials` → `{"credential", "known_secret"}`
2. **D_int 提取**：从用户原始意图（`thought_prompt`）中解析数据类别
   - "get my credentials" → `{"credential"}`
   - "read my emails" → `{"email"}`
3. **NER 模型检测**：使用 `dslim/bert-base-NER` 检测工具返回结果中的命名实体
4. **正则模式补充**：匹配以下敏感数据类型：

| 类型 | 模式 |
|------|------|
| 凭据 | `(password\|secret\|token\|api[_-]?key)...` |
| 邮箱 | 标准 email 正则 |
| 信用卡 | `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}` |
| SSN | `\d{3}-\d{2}-\d{4}` |
| 已知密钥 | `password123`, `secret_token`, `my_secret` 等 |

5. **选择性脱敏**：只替换类别不在 `D_nec ∪ D_int` 中的敏感项为 `[REDACTED]`
6. **自动降级**：如果 NER 模型不可用，自动降级为纯正则匹配；CUDA 加载失败时自动回退 CPU

#### 执行时机

在工具调用**完成后**（后置处理），对返回结果进行脱敏。Ring 3 在 Ring 1 之前执行，确保即使 Ring 1 检测到注入并阻断，敏感数据也已被脱敏（副作用安全）。

**数据流**：`interceptor.py` 从前置阶段的 Ring 2 获取 `intended_data_categories`（D_int），传递给后置阶段的 Ring 3，实现上下文感知脱敏。

#### 实现

1. **NER 模型检测**：使用 `dslim/bert-base-NER` 检测工具返回结果中的命名实体（人名、组织等）
2. **正则模式补充**：匹配以下敏感数据类型：

| 类型 | 模式 |
|------|------|
| 凭据 | `(password\|secret\|token\|api[_-]?key)...` |
| 邮箱 | 标准 email 正则 |
| 信用卡 | `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}` |
| SSN | `\d{3}-\d{2}-\d{4}` |
| 已知密钥 | `password123`, `secret_token`, `my_secret` 等 |

3. **脱敏替换**：检测到的敏感内容替换为 `[REDACTED]`
4. **自动降级**：如果 NER 模型不可用，自动降级为纯正则匹配

#### 执行时机

在工具调用**完成后**（后置处理），对返回结果进行脱敏。Ring 3 在 Ring 1 之前执行，确保即使 Ring 1 检测到注入并阻断，敏感数据也已被脱敏（副作用安全）。

---

### 5.6 Ring 0: Prompt Injection Detection (LLM 前) — LLM 推理前提示注入检测

**文件**: `src/agentdojo/method/analysis/prompt_injection.py`

#### 原理

在 LLM 推理**执行前**，对用户输入的 Prompt 进行语义检查，检测是否包含直接提示注入（Direct Prompt Injection）内容。如果检测到注入，则阻断 LLM 调用，防止恶意指令影响 Agent 行为。

#### 实现

1. 在 `capture_llm_interaction` 中，LLM 调用前触发 Ring 0 检测
2. 对用户输入的 Prompt 使用 **PI 检测模型**（与 Ring 1 共用 `deberta-v3-base-prompt-injection-v2`）进行语义异常检测
3. 如果 Prompt 被判定为包含注入内容，则阻断 LLM 调用并返回错误
4. 可配置检测阈值（默认 0.5，越低越敏感）
5. 短字符串（< 10 字符）直接放行，不触发检测

#### 阻断效果

返回 `False`，触发 `"BLOCKED: Direct prompt injection detected in user input."` 错误。

---

## 六、Visualization Layer — 可视化层

可视化层由三部分组成：
1. **控制台可视化**（`dashboard.py`）— 命令行输出风险卡片和隐私标签
2. **Flask API 服务器**（`server.py`）— REST API 服务，连接后端与前端
3. **跨 APP 路由 Runtime**（`mock_apps.py`）— 统一路由 workspace + banking 工具

### 6.1 控制台可视化（dashboard.py）

**文件**: `src/agentdojo/method/visualization/dashboard.py`

#### InconPreter 风险卡片

```python
print_risk_card(event_details)
```

生成自然语言格式的安全风险卡片，包含：
- Agent ID
- 目标 APP
- 尝试的操作
- 阻断原因
- 推荐操作（BLOCK / WHITELIST）

#### DataShield 隐私营养标签

```python
check_data_shield(target_app)
```

显示第三方 API 的隐私营养标签，模拟展示：
- 是否收集 PII
- 是否与第三方共享
- 数据保留期限

#### 图谱导出

```python
start_dashboard()
```

从 Modeling Layer 导出完整的 PROV 溯源图谱，以 JSON 格式输出（D3.js 力导向图兼容格式），包含：
- `nodes`：节点列表（含 id, type, label, app 等属性）
- `links`：边列表（含 source, target, relation 属性）

---

### 6.2 Flask API 服务器（server.py）

**文件**: `src/agentdojo/method/visualization/server.py`（1248 行）

#### 架构设计

Flask 服务器作为后端核心，提供 REST API 服务，连接前端可视化平台与后端的 AgentPipeline、知识图谱和防御系统。

```
┌──────────────┐     HTTP/JSON      ┌──────────────────┐
│  前端浏览器   │ ◄──────────────►  │  Flask API 服务器  │
│  (D3.js)     │    REST API       │  (server.py)      │
└──────────────┘                    └────────┬─────────┘
                                             │
                    ┌────────────────────────┼────────────────────┐
                    │                        │                    │
                    ▼                        ▼                    ▼
           ┌──────────────┐       ┌──────────────┐      ┌──────────────┐
           │ AgentPipeline │       │ KnowledgeGraph│      │ Interceptor  │
           │ (真实 LLM)    │       │ (图谱数据)    │      │ (防御开关)   │
           └──────────────┘       └──────────────┘      └──────────────┘
```

#### 完整 API 端点列表

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 健康检查 |
| GET | `/api/graph` | 获取图谱数据（节点 + 边 + 统计） |
| GET | `/api/events` | 获取事件历史 |
| GET | `/api/risk-cards` | 获取风险卡片列表 |
| GET | `/api/node/<node_id>` | 获取节点详情 |
| GET | `/api/apps` | 获取 APP 列表及节点数 |
| GET | `/api/scenarios` | 获取可用预设场景列表 |
| GET | `/api/status` | 获取系统状态（各层健康 + LLM 配置 + 功能清单） |
| POST | `/api/execute` | 执行预设场景或自定义指令 |
| POST | `/api/execute/custom` | 执行自定义指令（带完整参数） |
| POST | `/api/execute/scenario` | 执行预设场景 |
| POST | `/api/config/llm` | 更新 LLM 配置（模型、API Key、参数） |
| GET | `/api/config/llm` | 获取当前 LLM 配置 |
| POST | `/api/config/defense` | 切换防御开关 |
| GET | `/api/config/defense` | 获取防御开关状态 |
| POST | `/api/trace/save` | 保存追踪记录 |
| GET | `/api/trace/list` | 获取追踪记录列表 |
| GET | `/api/trace/<trace_id>` | 获取单条追踪记录详情 |
| DELETE | `/api/trace/<trace_id>` | 删除追踪记录 |
| POST | `/api/reset` | 重置系统状态（清空图谱 + 事件 + 风险卡片） |
| GET | `/api/llm-models` | 获取可用 LLM 模型列表 |

#### API 端点详解

##### 健康检查

```http
GET /api/health
Response: { "status": "ok", "timestamp": 1718000000.0 }
```

##### 图谱数据

```http
GET /api/graph
Response: {
  "nodes": [
    { "id": "agent_1", "type": "AIAgent", "label": "🤖 AI Agent", "app": "system" },
    { "id": "tool_1", "type": "AgentTool", "label": "📧 发送邮件", "app": "email" }
  ],
  "links": [
    { "source": { "id": "agent_1" }, "target": { "id": "tool_1" }, "relation": "belongsTo" }
  ],
  "stats": { "nodes": 10, "edges": 8, "types": { "AIAgent": 1, "AgentTool": 3, ... } }
}
```

##### 事件历史

```http
GET /api/events
Response: [
  {
    "id": "evt_001",
    "type": "tool_call",
    "function": "send_email",
    "args": { "to": "user@example.com", "subject": "Hello", "body": "..." },
    "result": "Email sent",
    "timestamp": 1718000000.0,
    "blocked": false,
    "block_reason": null,
    "app": "email",
    "tool_intent": "send_email"
  }
]
```

##### 风险卡片

```http
GET /api/risk-cards
Response: [
  {
    "agent_id": "AIAgent_Default",
    "target_app": "email",
    "tool_intent": "send_email",
    "block_reason": "SkillProbe: Indirect prompt injection detected in tool output.",
    "timestamp": 1718000000.0
  }
]
```

##### 节点详情

```http
GET /api/node/<node_id>
Response: {
  "id": "tool_1",
  "type": "AgentTool",
  "label": "📧 发送邮件",
  "app": "email",
  "description": "Send an email to a recipient",
  "neighbors": [
    { "id": "agent_1", "relation": "belongsTo", "direction": "incoming" },
    { "id": "data_1", "relation": "produces", "direction": "outgoing" }
  ]
}
```

##### APP 列表

```http
GET /api/apps
Response: {
  "apps": [
    { "name": "email", "node_count": 5 },
    { "name": "banking", "node_count": 3 },
    { "name": "workspace", "node_count": 4 }
  ]
}
```

##### 预设场景

```http
GET /api/scenarios
Response: {
  "scenarios": [
    {
      "id": "injection_email",
      "name": "邮件注入攻击模拟",
      "description": "模拟包含注入指令的邮件内容，测试 Ring 1 提示注入检测",
      "prompt": "Please read my email with id '1'...",
      "tools": ["read_email", "send_email"]
    },
    {
      "id": "intent_mismatch",
      "name": "意图不一致攻击模拟",
      "description": "模拟间接注入场景，测试 Ring 2 意图一致性检查",
      "prompt": "Please check my calendar...",
      "tools": ["read_email", "transfer_money"]
    },
    {
      "id": "data_exposure",
      "name": "数据过度暴露模拟",
      "description": "模拟凭据泄露场景，测试 Ring 3 DOE 脱敏",
      "prompt": "Please get my credentials for the 'bank' service...",
      "tools": ["get_credentials"]
    },
    {
      "id": "config_injection",
      "name": "配置注入攻击模拟",
      "description": "模拟配置参数注入场景，测试 Ring 0 LLM 前注入检测",
      "prompt": "Please update my system configuration...",
      "tools": ["update_config"]
    },
    {
      "id": "full_attack",
      "name": "完整注入攻击模拟",
      "description": "模拟完整注入攻击链路，测试全防御系统",
      "prompt": "Please check the content of this webpage...",
      "tools": ["get_webpage_content", "send_email"]
    }
  ]
}
```

##### 系统状态

```http
GET /api/status
Response: {
  "capture_layer": { "status": "active", "events_count": 15 },
  "modeling_layer": { "status": "active", "nodes": 10, "edges": 8 },
  "analysis_layer": {
    "status": "active",
    "defense_enabled": true,
    "ring1": { "status": "active", "model": "deberta-v3" },
    "ring2": { "status": "active", "model": "all-MiniLM-L6-v2" },
    "ring3": { "status": "active", "model": "bert-base-NER" },
    "ring0": { "status": "active", "model": "deberta-v3" }
  },
  "visualization_layer": { "status": "active" },
  "llm_config": {
    "model": "gemini-2.5-flash",
    "configured": true,
    "available_models": ["gemini-2.5-flash", "gemini-2.0-flash-001", ...]
  },
  "features": {
    "tool_interception": true,
    "llm_capture": true,
    "knowledge_graph": true,
    "prompt_injection_detection": true,
    "intent_consistency": true,
    "doe_mitigation": true,
    "risk_card_generation": true,
    "data_shield": true
  }
}
```

##### 执行预设场景

```http
POST /api/execute/scenario
Body: { "scenario_id": "injection_email" }
Response: {
  "status": "completed",
  "messages": [...],
  "events": [...],
  "risk_cards": [...],
  "trace": [...]
}
```

##### 执行自定义指令

```http
POST /api/execute/custom
Body: {
  "prompt": "Send an email to user@example.com saying hello",
  "tools": [
    { "name": "send_email", "func": "def send_email(to, subject, body): ..." },
    { "name": "read_email", "func": "def read_email(id): ..." }
  ]
}
Response: {
  "status": "completed",
  "messages": [...],
  "events": [...],
  "risk_cards": [...],
  "trace": [...]
}
```

##### LLM 配置

```http
GET /api/config/llm
Response: {
  "model": "gemini-2.5-flash",
  "temperature": 0.7,
  "max_tokens": 4096,
  "api_key_configured": true
}

POST /api/config/llm
Body: {
  "model": "gemini-2.5-flash",
  "temperature": 0.5,
  "max_tokens": 2048,
  "api_key": "your-api-key"
}
Response: { "status": "ok", "message": "LLM configuration updated" }
```

##### 防御开关

```http
GET /api/config/defense
Response: { "defense_enabled": true }

POST /api/config/defense
Body: { "defense_enabled": false }
Response: { "status": "ok", "defense_enabled": false }
```

##### 追踪记录

```http
POST /api/trace/save
Body: { "name": "测试运行 1", "events": [...], "risk_cards": [...] }
Response: { "status": "ok", "trace_id": "trace_abc123" }

GET /api/trace/list
Response: {
  "traces": [
    { "id": "trace_abc123", "name": "测试运行 1", "timestamp": 1718000000.0, "event_count": 10 }
  ]
}

GET /api/trace/<trace_id>
Response: { "id": "trace_abc123", "name": "测试运行 1", "events": [...], "risk_cards": [...] }

DELETE /api/trace/<trace_id>
Response: { "status": "ok", "message": "Trace deleted" }
```

##### 重置系统

```http
POST /api/reset
Response: { "status": "ok", "message": "System state reset" }
```

##### 可用模型列表

```http
GET /api/llm-models
Response: {
  "models": [
    { "id": "gemini-2.5-flash", "name": "Gemini 2.5 Flash", "provider": "google" },
    { "id": "gemini-2.0-flash-001", "name": "Gemini 2.0 Flash", "provider": "google" },
    { "id": "gemini-1.5-flash-002", "name": "Gemini 1.5 Flash", "provider": "google" },
    { "id": "gemini-1.5-pro-002", "name": "Gemini 1.5 Pro", "provider": "google" }
  ]
}
```

#### 服务器启动

```python
from agentdojo.method.visualization.server import start_server

# 启动 Flask 服务器（默认端口 5000）
start_server(host="0.0.0.0", port=5000, debug=True)
```

---

### 6.3 跨 APP 路由 Runtime（mock_apps.py）

**文件**: `src/agentdojo/method/visualization/mock_apps.py`

#### RouterRuntime 设计原理

`RouterRuntime` 继承自 `FunctionsRuntime`，扩展了工具路由能力，支持跨 APP 的工具调用分发：

```python
class RouterRuntime(FunctionsRuntime):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._app_routers: Dict[str, FunctionsRuntime] = {}
        self._current_app: Optional[str] = None
```

**核心功能**：

1. **APP 注册**：`register_app(name, runtime)` — 注册子 APP 的 Runtime
2. **工具路由**：`run_function(name, ...)` — 根据工具名自动路由到对应 APP 的 Runtime
3. **跨 APP 任务标记**：`set_cross_app_task(flag)` — 标记当前是否为跨 APP 任务
4. **APP 感知**：`get_current_app()` — 获取当前执行的 APP 名称

#### UnifiedEnvironment 统一环境

`UnifiedEnvironment` 继承自 `Environment`，统一管理 workspace 和 banking 两个 APP 的环境状态：

```python
class UnifiedEnvironment(Environment):
    def __init__(self):
        super().__init__()
        self._workspace_env = WorkspaceEnvironment()
        self._banking_env = BankingEnvironment()
```

**核心功能**：

1. **统一状态管理**：同时维护 workspace 和 banking 两个子环境
2. **APP 感知查询**：`get_state(app_name)` — 根据 APP 名称返回对应子环境的状态
3. **跨 APP 数据流**：支持一个工具调用同时影响多个 APP 的状态
4. **原版 TaskSuite 加载**：`load_task_suite(suite_name)` — 加载原版 TaskSuite 的初始状态

#### 原版 TaskSuite 加载

```python
def load_task_suite(suite_name: str) -> UnifiedEnvironment:
    """加载原版 TaskSuite 的初始状态到 UnifiedEnvironment"""
    from agentdojo.default_suites.v1 import banking, workspace
    
    env = UnifiedEnvironment()
    env._workspace_env = workspace.create_inbox()
    env._banking_env = banking.create_accounts()
    return env
```

---

## 七、前端可视化平台（frontend/）

**目录**: `frontend/`

### 7.1 架构总览

```
┌─────────────────────────────────────────────────────────────────────┐
│                     前端可视化平台架构                                 │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  index.html (主页面)                                          │   │
│  │  · 布局: 顶部状态栏 + 左侧拓扑图 + 右侧面板                    │   │
│  │  · 引入所有 JS 模块和 CSS 样式                                 │   │
│  └──────────────────────┬──────────────────────────────────────┘   │
│                         │                                          │
│  ┌──────────────────────▼──────────────────────────────────────┐   │
│  │  main.js (主入口 + 全局状态管理)                              │   │
│  │  · Store 对象: 全局状态中心                                   │   │
│  │  · 初始化所有子模块                                           │   │
│  │  · 定时轮询后端 API                                           │   │
│  └──────┬──────────┬──────────┬──────────┬──────────┬─────────┘   │
│         │          │          │          │          │             │
│         ▼          ▼          ▼          ▼          ▼             │
│  ┌────────┐ ┌──────────┐ ┌────────┐ ┌────────┐ ┌────────────┐   │
│  │api.js  │ │graph.js  │ │timeline│ │risk-   │ │console.js  │   │
│  │(API 通信)│ │(拓扑图)  │ │.js     │ │panel.js│ │(操作控制台) │   │
│  └────────┘ │D3.js     │ │(时间线) │ │(风险卡片)│ └────────────┘   │
│             └──────────┘ └────────┘ └────────┘                   │
│  ┌────────┐ ┌────────────┐ ┌────────────┐                       │
│  │status- │ │trace-panel │ │style.css   │                       │
│  │panel.js│ │.js         │ │(样式系统)   │                       │
│  │(状态面板)│ │(追踪面板)  │ └────────────┘                       │
│  └────────┘ └────────────┘                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 数据流

```
后端 API (Flask)                   前端浏览器
┌──────────────┐                  ┌──────────────────────────────┐
│  /api/graph   │ ◄── 轮询 ────  │  api.js → main.js Store      │
│  /api/events  │ ◄── 轮询 ────  │       ↓                      │
│  /api/status  │ ◄── 轮询 ────  │  Store 更新 → 各模块渲染      │
│  /api/risk-   │ ◄── 轮询 ────  │       ↓                      │
│    cards      │                │  ┌────────────────────────┐  │
│  /api/execute │ ◄── 用户操作 ─ │  │  graph.js: 更新拓扑图    │  │
│  /api/config/ │ ◄── 配置修改 ─ │  │  timeline.js: 追加事件   │  │
│    llm        │                │  │  risk-panel.js: 更新卡片 │  │
│  /api/config/ │ ◄── 开关切换 ─ │  │  status-panel.js: 更新   │  │
│    defense    │                │  │  trace-panel.js: 更新    │  │
└──────────────┘                │  └────────────────────────┘  │
                                └──────────────────────────────┘
```

### 7.3 各模块详解

#### api.js — API 通信模块

**文件**: `frontend/js/api.js`

封装所有后端 API 调用，提供统一的错误处理和 Promise 接口：

```javascript
const API = {
    // 图谱数据
    fetchGraph: () => fetch('/api/graph').then(r => r.json()),
    
    // 事件历史
    fetchEvents: () => fetch('/api/events').then(r => r.json()),
    
    // 风险卡片
    fetchRiskCards: () => fetch('/api/risk-cards').then(r => r.json()),
    
    // 系统状态
    fetchStatus: () => fetch('/api/status').then(r => r.json()),
    
    // 执行预设场景
    executeScenario: (scenarioId) => fetch('/api/execute/scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: scenarioId })
    }).then(r => r.json()),
    
    // 执行自定义指令
    executeCustom: (prompt, tools) => fetch('/api/execute/custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt, tools })
    }).then(r => r.json()),
    
    // LLM 配置
    updateLLMConfig: (config) => fetch('/api/config/llm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    }).then(r => r.json()),
    
    // 防御开关
    toggleDefense: (enabled) => fetch('/api/config/defense', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ defense_enabled: enabled })
    }).then(r => r.json()),
    
    // 追踪记录
    saveTrace: (data) => fetch('/api/trace/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    }).then(r => r.json()),
    
    // 重置系统
    resetSystem: () => fetch('/api/reset', { method: 'POST' }).then(r => r.json()),
    
    // 可用模型列表
    fetchModels: () => fetch('/api/llm-models').then(r => r.json()),
    
    // 预设场景列表
    fetchScenarios: () => fetch('/api/scenarios').then(r => r.json()),
    
    // APP 列表
    fetchApps: () => fetch('/api/apps').then(r => r.json()),
    
    // 节点详情
    fetchNodeDetail: (nodeId) => fetch(`/api/node/${nodeId}`).then(r => r.json()),
};
```

#### main.js — 主入口 + 全局状态管理

**文件**: `frontend/js/main.js`

**Store 对象**：全局状态中心，管理所有模块共享的状态：

```javascript
const Store = {
    // 图谱数据
    graphData: { nodes: [], links: [] },
    // 事件列表
    events: [],
    // 风险卡片列表
    riskCards: [],
    // 系统状态
    status: {},
    // 当前选中的节点
    selectedNode: null,
    // 当前选中的事件
    selectedEvent: null,
    // 防御开关状态
    defenseEnabled: true,
    // LLM 配置
    llmConfig: {},
    // 可用模型列表
    availableModels: [],
    // 预设场景列表
    scenarios: [],
    // APP 列表
    apps: [],
    // 追踪记录列表
    traces: [],
};
```

**核心功能**：

1. **初始化**：页面加载时初始化所有子模块，启动定时轮询
2. **定时轮询**：每 2 秒轮询 `/api/graph`、`/api/events`、`/api/status`、`/api/risk-cards`
3. **状态同步**：当 Store 更新时，通知各模块重新渲染
4. **事件处理**：处理节点点击、事件选择等用户交互

#### graph.js — D3.js 拓扑图

**文件**: `frontend/js/graph.js`（1313 行）

使用 D3.js 实现交互式力导向拓扑图，展示知识图谱的完整结构。

**核心功能**：

| 功能 | 说明 |
|------|------|
| **力导向图** | D3.js force simulation，节点自动布局 |
| **泳道图模式** | 按 APP 分泳道（email / banking / workspace / system） |
| **粒子动画** | 数据流粒子沿边运动，展示实时数据流动 |
| **视图切换** | 拓扑视图 ↔ 泳道视图 切换 |
| **节点交互** | 点击节点显示详情，悬停显示标签 |
| **缩放/拖拽** | 鼠标滚轮缩放，拖拽平移 |
| **节点颜色编码** | 按节点类型着色（AIAgent=蓝, AgentTool=绿, DomainData=橙, Prompt=紫, AIModelInvocation=红） |
| **边标签** | 显示边关系（informed / used / produces / belongsTo） |
| **实时更新** | 图谱变化时自动增量更新，支持节点/边的添加和移除动画 |

**关键实现细节**：

```javascript
// 力导向图配置
const simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(150))
    .force("charge", d3.forceManyBody().strength(-300))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collision", d3.forceCollide().radius(30));

// 泳道图配置（按 APP 分组）
const laneForce = d3.forceY(d => {
    const laneIndex = laneOrder.indexOf(d.app);
    return laneIndex >= 0 ? (laneIndex + 1) * height / (laneOrder.length + 1) : height / 2;
}).strength(0.3);

// 粒子动画
function animateParticles(links) {
    // 沿边创建流动粒子
    links.forEach(link => {
        particles.push({ x: link.source.x, y: link.source.y, target: link });
    });
    // 每帧更新粒子位置
    particles.forEach(p => {
        p.x += (p.target.target.x - p.x) * 0.02;
        p.y += (p.target.target.y - p.y) * 0.02;
    });
}
```

#### timeline.js — 事件时间线

**文件**: `frontend/js/timeline.js`

按时间顺序展示所有事件（LLM 推理 + 工具调用），支持筛选和详情查看。

**核心功能**：

1. **时间线渲染**：垂直时间线，每个事件为一个时间点
2. **事件类型标识**：不同颜色标识 LLM 推理（蓝色）和工具调用（绿色/红色）
3. **阻断标记**：被防御系统阻断的事件显示红色标记
4. **详情展开**：点击事件展开详情（参数、结果、阻断原因）
5. **自动滚动**：新事件自动滚动到时间线底部
6. **筛选功能**：按事件类型、APP、阻断状态筛选

#### risk-panel.js — 风险卡片面板

**文件**: `frontend/js/risk-panel.js`

展示 InconPreter 生成的安全风险卡片列表。

**核心功能**：

1. **卡片列表**：按时间倒序排列的风险卡片
2. **严重程度标识**：不同颜色标识风险等级（高=红, 中=橙, 低=黄）
3. **详情展开**：点击卡片展开详细信息
4. **操作按钮**：BLOCK（已自动执行）/ WHITELIST（手动确认）
5. **自动更新**：新风险卡片自动添加到列表顶部
6. **清空功能**：一键清空所有风险卡片

#### console.js — 操作控制台

**文件**: `frontend/js/console.js`

提供 LLM 配置、防御开关、预设场景执行和自定义指令执行功能。

**核心功能**：

| 功能 | 说明 |
|------|------|
| **LLM 模型选择** | 下拉选择可用模型（从 `/api/llm-models` 获取） |
| **API Key 配置** | 输入 Google API Key |
| **模型参数配置** | Temperature、Max Tokens 滑块 |
| **防御开关** | 一键启用/禁用防御系统 |
| **预设场景执行** | 从下拉列表选择预设场景并执行 |
| **自定义指令** | 输入自定义 Prompt 并执行 |
| **工具代码编辑** | 为自定义指令注册工具函数（代码编辑器） |
| **执行结果展示** | 显示执行结果、事件列表和风险卡片 |
| **追踪保存** | 将执行结果保存为追踪记录 |

#### status-panel.js — 系统状态面板

**文件**: `frontend/js/status-panel.js`

实时展示系统各层的健康状态和功能清单。

**核心功能**：

1. **各层状态指示**：Capture / Modeling / Analysis / Visualization 四层的状态（active / inactive / error）
2. **防御开关状态**：显示当前防御开关状态
3. **LLM 配置状态**：显示当前 LLM 模型和配置状态
4. **功能清单**：列出所有功能及其启用状态（绿色/红色指示灯）
5. **图谱统计**：节点数、边数、节点类型分布
6. **事件统计**：总事件数、阻断事件数、风险卡片数

#### trace-panel.js — 指令流转追踪面板

**文件**: `frontend/js/trace-panel.js`

展示 Agent 执行过程中的指令流转追踪，从用户输入到最终输出的完整链路。

**核心功能**：

1. **追踪步骤展示**：按执行顺序展示每个步骤（用户输入 → LLM 推理 → 工具调用 → 工具结果 → LLM 响应）
2. **步骤详情**：点击步骤展开详情（Prompt、Response、参数、结果）
3. **阻断标记**：被防御系统阻断的步骤显示红色标记和阻断原因
4. **追踪记录管理**：保存、加载、删除追踪记录
5. **步骤导航**：上一步/下一步导航，快速定位关键步骤

---

### 7.4 样式系统（style.css）

**文件**: `frontend/css/style.css`（1733 行）

#### 设计主题

- **暗色主题**：深色背景（`#1a1a2e`、`#16213e`），霓虹色点缀
- **赛博朋克风格**：发光边框、渐变背景、霓虹文字
- **响应式布局**：适配不同屏幕尺寸

#### 关键样式组件

| 组件 | 说明 |
|------|------|
| **布局系统** | CSS Grid 布局，顶部状态栏 + 左侧主区域 + 右侧面板 |
| **拓扑图容器** | 全屏 SVG 容器，支持缩放 |
| **时间线样式** | 垂直时间线，圆点标记，连接线 |
| **风险卡片** | 卡片式布局，发光边框，颜色编码 |
| **控制台面板** | 表单样式，按钮样式，代码编辑器 |
| **状态面板** | 指示灯样式，进度条，统计数字 |
| **追踪面板** | 步骤导航，详情展开动画 |
| **动画效果** | 粒子动画，过渡动画，加载动画 |
| **滚动条** | 自定义滚动条样式 |

---

## 八、完整调用流程

```
1. 用户调用 activate_platform()
   │
   ├─ 2. enable_tracking() 执行猴子补丁
   │    ├─ 包装 FunctionsRuntime.run_function
   │    └─ 包装 LLM.query 方法
   │
   ├─ 3. AgentPipeline 开始执行
   │    ├─ 3.1 LLM 推理
   │    │    ├─ 前置: 记录 Prompt
   │    │    ├─ 执行: LLM 调用
   │    │    └─ 后置: 创建 ReasoningContext → 图谱记录
   │    │
   │    └─ 3.2 工具调用 (被 capture_tool_call 拦截)
   │         ├─ 前置:
   │         │    ├─ 环境快照
   │         │    ├─ 图谱记录 (record_activity)
│         │    ├─ Ring 0: LLM 推理前注入检测
│         │    └─ Ring 2: 意图一致性检查
   │         │
   │         ├─ 执行: 原始 run_function
   │         │
   │         └─ 后置:
   │              ├─ 环境增量计算
   │              ├─ 图谱更新 (update_activity_outcome)
   │              ├─ Ring 3: DOE 数据脱敏
   │              └─ Ring 1: 提示注入检测
   │
   ├─ 4. 可视化输出
   │    ├─ 控制台: 风险卡片 + 隐私标签 + 图谱导出
   │    ├─ Flask API: 提供 REST 接口
   │    └─ 前端: D3.js 拓扑图 + 时间线 + 风险面板
   │
   └─ 5. 用户通过前端交互
        ├─ 查看拓扑图
        ├─ 查看事件时间线
        ├─ 查看风险卡片
        ├─ 执行预设场景
        ├─ 配置 LLM
        └─ 切换防御开关
```

---

## 九、使用方式

### 9.1 激活防御平台

```python
from agentdojo.method import activate_platform

# 在 AgentPipeline 执行前调用
activate_platform()

# 之后所有工具调用和 LLM 推理都会被自动拦截和审计
```

### 9.2 启动可视化服务器

```python
from agentdojo.method.visualization.server import start_server

# 启动 Flask API 服务器
start_server(host="0.0.0.0", port=5000, debug=True)
```

### 9.3 前端访问

启动服务器后，在浏览器访问：

```
http://localhost:5000
```

前端页面会自动加载并开始轮询后端 API，实时展示：
- 知识图谱拓扑图
- 事件时间线
- 风险卡片
- 系统状态
- 操作控制台

### 9.4 API 调用示例

```python
import requests

# 健康检查
response = requests.get("http://localhost:5000/api/health")
print(response.json())  # {"status": "ok", "timestamp": 1718000000.0}

# 获取图谱数据
response = requests.get("http://localhost:5000/api/graph")
graph_data = response.json()

# 执行预设场景
response = requests.post("http://localhost:5000/api/execute/scenario", json={
    "scenario_id": "injection_email"
})
result = response.json()

# 切换防御开关
response = requests.post("http://localhost:5000/api/config/defense", json={
    "defense_enabled": False
})
print(response.json())  # {"status": "ok", "defense_enabled": false}

# 更新 LLM 配置
response = requests.post("http://localhost:5000/api/config/llm", json={
    "model": "gemini-2.5-flash",
    "temperature": 0.5,
    "max_tokens": 2048,
    "api_key": "your-api-key"
})
print(response.json())  # {"status": "ok", "message": "LLM configuration updated"}
```

---

## 十、防御机制总结表

| 防御层 | 组件 | 触发时机 | 检测方法 | 阻断效果 |
|--------|------|---------|---------|---------|
| Ring 0 | Prompt Injection (LLM 前) | LLM 推理前 | DeBERTa 模型 + 正则 | 阻断 LLM 调用，返回注入错误 |
| Ring 1 | SkillProbe 提示注入检测 | 工具调用后 | DeBERTa 模型 + 正则 | 阻断工具输出，返回注入错误 |
| Ring 2 | FIDES IFC 意图一致性检查 | 工具调用前 | Sentence-BERT 语义相似度 | 阻断工具调用，返回意图不一致错误 |
| Ring 3 | AgentRaft DOE 数据脱敏 | 工具调用后 | NER 模型 + 正则 + 意图上下文 | 选择性替换 D_OE 为 [REDACTED]，保留 D_nec/D_int |

---

## 十一、文件结构

```
src/agentdojo/method/
├── __init__.py                          # 入口: activate_platform()
├── capture/
│   ├── interceptor.py                   # AOP 拦截器 + LLM 推理捕获
│   └── environment_snapshot.py          # 环境状态语义解析 + 增量计算
├── modeling/
│   └── graph_db.py                      # 知识图谱 (PROV + FSM, NetworkX)
├── analysis/
│   ├── pipeline.py                      # 4-Ring 管道编排
│   ├── model_utils.py                   # 模型管理 (懒加载 + 自动降级)
│   ├── skillprobe_topology.py           # Ring 1: 提示注入检测
│   ├── fides_ifc.py                     # Ring 2: 意图一致性检查
│   ├── agentraft_doe.py                 # Ring 3: DOE 数据脱敏
│   ├── prompt_injection.py              # Ring 0: LLM 前注入检测
│   └── fides_hiding.py                  # Ring 4: 选择性隐藏（已弃用）
└── visualization/
    ├── dashboard.py                     # 控制台可视化 (风险卡片 + 隐私标签)
    ├── server.py                        # Flask API 服务器 (1248 行)
    └── mock_apps.py                     # 跨 APP 路由 Runtime

frontend/
├── index.html                           # 主页面
├── css/
│   └── style.css                        # 样式系统 (1733 行)
└── js/
    ├── api.js                           # API 通信模块
    ├── main.js                          # 主入口 + 全局状态管理
    ├── graph.js                         # D3.js 拓扑图 (1313 行)
    ├── timeline.js                      # 事件时间线
    ├── risk-panel.js                    # 风险卡片面板
    ├── console.js                       # 操作控制台
    ├── status-panel.js                  # 系统状态面板
    └── trace-panel.js                   # 指令流转追踪面板
```

---

## 十二、测试

**文件**: `tests/test_method.py`, `tests/test_method_with_llm.py`

### 12.1 测试概览

| 测试编号 | 测试名称 | 类型 | 说明 |
|---------|---------|------|------|
| 1 | `test_integration` | 集成测试 | 验证拦截器、图谱、风险卡片、仪表盘完整链路 |
| 2 | `test_capture_layer` | 无 LLM | 验证 AOP 拦截是否生效，TrackingContext 单例 |
| 3 | `test_ring1_topology` | 无 LLM | 验证 Ring 1 提示注入检测（安全/注入/系统提示篡改/误报） |
| 4 | `test_ring2_ifc` | 无 LLM | 验证 Ring 2 意图一致性检查（读操作/一致/不一致） |
| 5 | `test_ring3_doe` | 无 LLM | 验证 Ring 3 DOE 公式（保守模式/合法获取/邮件泄露/正常文本） |
| 6 | `test_ring0_injection` | 无 LLM | 验证 Ring 0 LLM 前注入检测（直接注入/正常输入） |
| 7 | `test_modeling_layer` | 无 LLM | 验证知识图谱构建（节点类型/图谱导出） |
| 8 | `test_visualization_layer` | 无 LLM | 验证风险卡片和隐私标签输出 |
| 9 | `test_ring1_with_llm` | 带 LLM | 真实 LLM 调用：Ring 1 提示注入检测 |
| 10 | `test_ring2_with_llm` | 带 LLM | 真实 LLM 调用：Ring 2 意图一致性检查 |
| 11 | `test_ring3_with_llm` | 带 LLM | 真实 LLM 调用：Ring 3 上下文感知脱敏（DeepSeek/Gemini） |
| 12 | `test_ring0_with_llm` | 带 LLM | 真实 LLM 调用：Ring 0 LLM 前注入检测 |
| 13 | `test_full_pipeline_with_llm` | 带 LLM | 完整 Pipeline 注入攻击模拟 |

### 12.2 运行方式

```bash
# 只跑无 LLM 的快速测试
python -m pytest tests/test_method_with_llm.py -v -m "not llm"

# 跑所有测试（含 LLM，需要 GEMINI_API_KEY）
python -m pytest tests/test_method_with_llm.py -v

# 只跑 LLM 测试
python -m pytest tests/test_method_with_llm.py -v -m llm

# 指定模型（默认 gemini-2.5-flash）
python -m pytest tests/test_method_with_llm.py -v --llm-model gemini-2.5-flash -m llm

# 运行基础集成测试
python -m pytest tests/test_method.py -v
```

### 12.3 测试隔离

所有测试使用 `_reset_all_singletons()` 辅助函数重置单例状态，确保测试间隔离：

```python
def _reset_all_singletons():
    """重置所有单例状态，确保测试间隔离"""
    from agentdojo.method.capture.interceptor import TrackingContext
    from agentdojo.method.modeling.graph_db import KnowledgeGraph
    from agentdojo.method.analysis.fides_ifc import IntentTracker

    TrackingContext._instance = None
    KnowledgeGraph._instance = None
    IntentTracker._instance = None

    # 恢复环境变量，防止被 agent_pipeline.py 中的 os.environ.pop 影响
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"
```


