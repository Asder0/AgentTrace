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
- banking: banking_client + file_reader + user_account
- workspace: email_client + calendar_client + cloud_drive_client + file_reader
- slack: slack + file_reader + user_account
- travel: travel_booking_client + calendar_client + file_reader + user_account



## 二、交互式可视化展示平台

### 前端架构
frontend/index.html - 主页面
frontend/js/graph.js - D3.js 拓扑图
frontend/js/timeline.js - 事件时间线
frontend/js/risk-panel.js - 风险卡片面板
frontend/js/trace-panel.js - 指令流转追踪
frontend/js/status-panel.js - 系统状态面板
frontend/js/console.js - 操作控制台
frontend/js/api.js - API 通信层
frontend/css/style.css - 暗色主题样式

### 拓扑图功能
- 力导向图布局 (D3.js force simulation)
- 5 种节点类型颜色编码
- APP 泳道分区展示
- 异常节点红色脉冲高亮
- 视图切换（技术视图/数据流视图）
- 粒子动画展示数据流动方向
- 悬停高亮关联路径
- 拖拽/缩放/平移

### 风险审计功能
- 风险卡片按 Ring 分类展示
- 事件时间线过滤（全部/LLM/工具/风险）
- 指令完整生命周期流转追踪
- 阻断步骤标记

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
| 异常行为高亮 | 红色脉冲动画 + 风险卡片 | 通过 |
| 审计与回溯 | 时间线 + 追踪面板 | 通过 |
| 至少 3 个 APP | 4 个 Task Suite（banking/workspace/slack/travel） | 通过 |
| 敏感数据标记 | Ring 3 DOE | 通过 |
| 异常告警 | Ring 1 + 风险卡片 | 通过 |
| 知识图谱 | graph_db.py (PROV + FSM) | 通过 |
| 多层防御 | Ring 0-3 管道 | 通过 |
| 可运行原型 | Flask + D3.js + AgentPipeline | 通过 |


生成日期: 2026-07-29
