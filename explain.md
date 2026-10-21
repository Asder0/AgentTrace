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
frontend/index.html - 主页面
frontend/js/graph.js - D3.js 拓扑图
frontend/js/timeline.js - 执行时间线（合并步骤与事件）
frontend/js/risk-panel.js - 风险卡片面板
frontend/js/trace-panel.js - 时间线兼容层（原指令流转追踪）
frontend/js/status-panel.js - 系统状态面板
frontend/js/console.js - 操作控制台
frontend/js/storage-view.js - 存储视图（初始/当前环境快照与差异）
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
- 归属边默认弱化显示，可通过“显示归属边”开关控制
- 拖拽/缩放/平移，重置视图自动适配画布

### 风险审计功能
- 风险卡片按 Ring 分类展示
- 执行时间线：合并生命周期步骤与事件内容，支持全部/阶段/LLM/工具/风险筛选
- 阻断步骤标记与图谱节点定位
- 时间线面板支持拖拽 / 方向键调整高度，双击恢复默认

### 存储视图
- 按 suite 展示环境数据：workspace（邮件/日历/云盘）、banking（银行账户/文件/用户账户）、slack（频道/私信/网页）、travel（酒店/餐厅/租车/航班/预订/邮箱）
- 支持“当前状态 / 初始状态”切换，高亮相对初始状态的 added / removed / changed
- 变更列表可定位到具体路径，详情面板展示变更前后的值
- 支持搜索、仅显示变化、自动刷新；执行任务或重置数据后自动刷新

## 三、多层防御分析系统（3-Ring + DOE）

src/agentdojo/method/analysis/pipeline.py 编排防御管道:
- Ring 0: prompt_injection.py - Prompt 注入检测 (DeBERTa + 正则)
- Ring 1: skillprobe_topology.py - 工具输出注入检测 (DeBERTa + 正则二次验证)
- Ring 2: fides_ifc.py - 意图一致性检查 (Sentence-BERT)
- Ring 3: agentraft_doe.py - DOE 数据脱敏 (NER + 正则)

## 四、知识图谱建模

src/agentdojo/method/modeling/graph_db.py 实现 FSM + PROV 融合知识图谱:
- PROV 实体: AIAgent, AIModelInvocation, AgentTool, Prompt, DomainData
- PROV 关系: belongsTo, informed, used, produces, wasDerivedFrom
- FSM 状态机: State - Transition - State
- 使用 NetworkX 内存实现

## 五、后端 API 服务器

src/agentdojo/method/visualization/server.py (1854 行)
Flask REST API, 使用真实 AgentPipeline 执行
提供 15+ 个 API 端点覆盖图谱/事件/风险/执行/攻击场景等

## 六、测试覆盖

tests/test_method.py - 1 项基础集成测试
tests/test_method_with_llm.py - 完整功能测试

无 LLM 测试:
- test_capture_layer (Capture)
- test_ring1_topology (Ring 1)
- test_ring2_ifc (Ring 2)
- test_ring3_doe (Ring 3)
- test_modeling_layer (Modeling)
- test_visualization_layer (Visualization)

带 LLM 测试:
- test_ring1_with_llm
- test_ring2_with_llm
- test_ring3_with_llm
- test_full_pipeline_with_llm

## 七、总结

| 要求 | 实现 | 状态 |
|------|------|------|
| 数据流捕获 | interceptor.py + environment_snapshot.py | 通过 |
| 拓扑图可视化 | frontend/js/graph.js (D3.js 1411 行) | 通过 |
| 异常行为高亮 | 红色描边高亮 + 风险卡片 | 通过 |
| 审计与回溯 | 时间线 + 追踪面板 | 通过 |
| 至少 3 个 APP | 4 个 Task Suite（banking/workspace/slack/travel） | 通过 |
| 敏感数据标记 | Ring 3 DOE | 通过 |
| 异常告警 | Ring 1 + 风险卡片 | 通过 |
| 知识图谱 | graph_db.py (PROV + FSM) | 通过 |
| 多层防御 | Ring 0-3 管道 | 通过 |
| 可运行原型 | Flask + D3.js + AgentPipeline | 通过 |


生成日期: 2026-07-29
