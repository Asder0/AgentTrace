# 面向跨 APP 智能体操控的数据流追踪与可视化平台 - 项目符合性说明

## 一、全链路数据流捕获机制

### 对应文件
- src/agentdojo/method/capture/interceptor.py
- src/agentdojo/method/capture/environment_snapshot.py

### 功能验证
1. AOP 拦截器（Monkey Patching）实时监控 Agent 行为
2. 记录数据来源（Source APP）- 通过函数名推断 APP 归属
3. 记录数据类型（entity_type）- 自动识别 email/contact/transaction 等
4. 记录数据去向（Destination API）- 记录工具调用目标和参数
5. 记录 Agent 推理节点 - ReasoningContext 链

### 跨 APP 支持
基于 agentdojo 原有的 4 个 Task Suite（banking / workspace / slack / travel），mock_apps.py 统一加载各 Suite 的工具模块:
- banking: banking_client + file_reader + user_account（11 个工具）
- workspace: email_client + calendar_client + cloud_drive_client（24 个工具）
- slack: slack + web（11 个工具）
- travel: travel_booking_client + calendar_client + email（28 个工具）



## 二、交互式可视化展示平台

### 前端架构
frontend/index.html - 主页面（由 Flask 在 `/` 同源托管）
frontend/js/graph.js - D3.js 拓扑图
frontend/js/risk-panel.js - 风险卡片面板
frontend/js/status-panel.js - 系统状态面板
frontend/js/audit-summary.js - 任务总结与确定性结果核验
frontend/js/console.js - 操作控制台
frontend/js/storage-view.js - 环境变更（字段差异、敏感等级与完整快照）
frontend/js/api.js - API 通信层
frontend/css/style.css - 暗色主题样式

### 拓扑图功能
- 结构化布局：提示词 → 智能体 → 推理 → 输入数据 → 工具调用 → 输出数据
- 卡片式节点：类型、标题、摘要分层展示，支持图谱定位（`图谱定位`）
- APP 域即 AgentDojo 的四个 task suite：banking（银行）、workspace（办公）、slack（通讯）、travel（旅行）
- file_reader、user_account、email、calendar 等是 suite 内部工具模块，在节点详情中以“工具模块”展示
- 同一 suite 内的跨模块任务（如 banking 中 read_file → update_scheduled_transaction）标记为“跨模块”，跨 APP 仅指真正跨 suite 的执行
- 原版 AgentDojo 的预设定 user_task 均属于单一 suite，TaskCombinator 也只能组合同一 suite 内的任务，不提供跨 suite 任务
- 本项目的 unified 模式通过 RouterRuntime + UnifiedEnvironment 支持跨 APP 执行；在 MOCK_SCENARIOS 中增加 suite="unified" 的任务即可构造跨 APP 场景
- 已提供示例 `cross_app::inbox_and_balance`：先调用 workspace 的 get_unread_emails，再调用 banking 的 get_balance，执行后图谱会出现办公与银行两个 APP 域
- 节点左色条与右上角标签表示 APP 域；顶部 APP 流程条按执行顺序展示 APP 调用与切换次数，点击可聚焦对应 APP
- 列标题与迭代轮次（R1、R2…）引导
- 异常节点红色描边高亮
- 边按关系分色并默认隐藏标签，悬停节点/边时聚焦关联路径、弱化其余元素
- 跨 APP 的因果边带切换点标记，悬停时显示“跨 APP · 关系名”
- 默认展示主信息流，状态、风险证据和聚合分支按需展开
- 拖拽/缩放/平移，重置视图自动适配画布

### 风险审计功能
- 风险卡片按提示注入、敏感数据外发、高风险操作授权和敏感数据对 LLM 暴露分类展示
- 点击风险卡片可聚焦对应工具、数据、授权、风险和出口节点
- 统计概览展示当前可见节点、关系、执行事件和风险卡片数量
- 任务总结展示跨 APP 路径、工具调用、外发行为、字段范围、数据类别和确定性结果核验

### 环境变更
- 默认按“实体 → 字段差异”展示环境变化，并标注人工配置的敏感等级
- 变更详情并排展示变更前后值，支持从图谱节点和工具调用定位到对应变更
- 支持按 APP、实体、字段、值或敏感等级搜索
- 完整初始/当前快照保留为辅助视图，自动刷新默认关闭
- 新 Trace 保存任务基线和执行后快照，可在历史回放中恢复当次环境差异；旧 Trace Schema 已不再兼容
- 当前 Trace Schema 中由旧版本生成的关系语义会在 API 读取和回放时归一化，原始 JSON 不改写
- 只有 `scope=task` 的状态标记为任务终态；活动级 `FAILED`、`QUARANTINED` 等状态不终止整个任务

## 三、多层防御分析系统（4-Ring）

`src/agentdojo/method/analysis/pipeline.py` 编排防御管道：
- Ring 0：本地 prompt-injection-guard-small 对完整用户指令做直接注入门控，命中后按语义块隔离；
- Ring 1：工具输出分块扫描、隔离与不可信控制流提醒；
- Ring 2：基于任务计划和工具元数据执行动作、effect、APP、资源与返回字段授权；所有返回 APP 数据的动作都要声明输出暴露范围，可疑来源影响的 L1 写操作需要人工确认。
- Ring 3：外发前检查最终工具参数以及文件、附件、日历事件等被引用资源的实际内容；来源按 APP、实体、工具和字段路径完整匹配，接收方采用固定授权、受控派生和未授权三态判定。

## 四、知识图谱建模

src/agentdojo/method/modeling/graph_db.py 实现 FSM + PROV 融合知识图谱:
- PROV 实体: AIAgent, AIModelInvocation, AgentTool, Prompt, DomainData、
  HumanAuthorization、PolicyEvent、RiskEvent、EgressSink
- PROV/审计关系: belongsTo, informed, used, produces, wasDerivedFrom、
  authorizes, policy_of, risk_of, risk_evidence, triggered_by,
  egress_to, leak_sink, applies_to_sink
- 只有 Ring 3 敏感外发使用 `leak_sink`；L2 授权等非外泄风险使用
  `applies_to_sink`
- FSM 状态机: State - Transition - State
- 使用 NetworkX 内存实现

## 五、后端 API 服务器

实现位于 `src/agentdojo/method/visualization/server.py`：

- 使用真实 `AgentPipeline` 执行任务
- 提供 29 个 `/api` 路由，覆盖图谱、事件、风险、执行、攻击场景和历史回放
- 前端由 Flask 在 `/` 同源托管
- 默认只监听 `127.0.0.1`，拒绝非本机 Host 和跨源写请求
- API 错误统一返回 `code/message/retryable/request_id`，未知 5xx 不返回内部异常

## 六、测试覆盖

公开仓库当前只纳入 `tests/test_project_invariants.py`，用于校验环境说明、
同源安全边界、错误响应、Accessibility 和图谱语义。

本机完整研究测试集按机制拆分在以下文件中，这些文件由 `.gitignore` 排除，
不会随当前 GitHub 仓库发布：

- `tests/test_flow_policy.py`：Ring 2/3 数据流与来源策略
- `tests/test_ring0_ring1_scanner.py`：直接注入、工具输出注入和 span 处理
- `tests/test_ring3_flow.py`：敏感数据外发检查
- `tests/test_plan_scope_mechanism.py`、`tests/test_plan_contract_matrix.py`：任务计划与执行约束
- `tests/test_cross_app_tasks.py`：跨 APP 任务、攻击构造和真值评测
- `tests/test_cross_app_security_metrics.py`：安全指标与配对运行
- `tests/test_visualization_config.py`、`tests/test_trace_history.py`、`tests/test_risk_visualization.py`：前端配置同步、历史保留和风险展示
- `tests/test_method_with_llm.py`：真实或模拟 LLM 管线集成测试

## 七、总结

| 要求 | 实现 | 状态 |
|------|------|------|
| 数据流捕获 | interceptor.py + environment_snapshot.py | 通过 |
| 拓扑图可视化 | frontend/js/graph.js（D3.js） | 通过 |
| 异常行为高亮 | 红色描边高亮 + 风险卡片 | 通过 |
| 审计与回溯 | 拓扑图 + 任务总结 + 风险卡片 + 历史回放 | 通过 |
| 至少 3 个 APP | 4 个 Task Suite（banking/workspace/slack/travel） | 通过 |
| 敏感数据标记 | Ring 3 APP 原生实体标签与信息流继承 | 通过 |
| 异常告警 | Ring 1 + 风险卡片 | 通过 |
| 知识图谱 | graph_db.py (PROV + FSM) | 通过 |
| 多层防御 | Ring 0-3 管道 | 通过 |
| 可运行原型 | Flask + D3.js + AgentPipeline | 通过 |


生成日期: 2026-11-28
