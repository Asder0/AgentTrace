# AgentTrace

基于 [AgentDojo](https://github.com/ethz-spylab/agentdojo) 的跨 APP 智能体数据流追踪与可视化平台。

AgentTrace 在 AgentDojo 基准测试框架之上，通过 AOP 拦截器（Monkey Patching）实时捕获 Agent 的 LLM 推理与工具调用，构建 PROV 知识图谱，并以可视化仪表盘呈现完整的数据流转、防御监控与历史回放。

运行时方法、四层风险判定、trace 结构和扩展方式详见 [`method.md`](method.md)。

## 功能特性

- **可审计运行时策略（4-Ring，轻量实现）**
  - Ring 0：本地 `Unplug-AI/unplug-tiny-v1` 双头模型检测直接注入并返回精确攻击 span；主模型未命中时使用语义句级后备检测，支持 ADVISORY、QUARANTINE 和 STRICT
  - Ring 1：按 schema 字段类型扫描工具输出；普通字符串一律检测，Unplug 命中时隔离精确 span，后备检测命中时隔离语义块，并将来源实体标记为可疑
  - Ring 2：使用人工定义的 L0/L1/L2 工具等级，对所有工具返回字段和非只读动作的具体资源选择器执行访问授权；L2 及可疑来源影响的 L1 写操作必须通过链路检查并由用户确认
  - Ring 3：在 egress 执行前检查最终参数及被引用资源内容；按 APP 实体字段的敏感等级、多来源最高等级继承、完整来源元组、来源风险和接收方授权状态进行判定
- **信息流标签与风险状态**
  - 每条数据记录 `confidentiality`（public/internal/confidential/secret）和 `integrity`（trusted/untrusted/tainted）
  - 机密性按最高级别传播；注入来源风险只标记被命中的直接实体及其来源，不扩散为整批工具结果或整个上下文
  - PROV 图谱记录来源、派生、用户授权、FSM 状态、风险证据和外部出口
- **可解释风险事件**
  - `PASS / ADVISORY / MITIGATE / QUARANTINE / HOLD / BLOCK` 决策均写入图谱
  - 非阻断风险保持任务运行并在图谱、时间线和风险卡片中高亮
- **全机制开关**
  - Ring 0：小模型分块检测
  - Ring 1：小模型分块扫描 + 不可信控制流提醒
  - Ring 2：任务范围、资源选择器和 Agent 字段暴露授权
  - Ring 3：APP 字段级敏感等级、接收方三态授权与控制器占位符解析
- **四 APP 复合任务**
  - 四个 suite 分别作为 `workspace / banking / slack / travel` 独立 APP 域
  - `unified` 模式持有四个独立环境，并由 `RouterRuntime` 按工具路由到对应域
  - 同名工具使用 `workspace__send_email`、`travel__send_email` 等命名空间，避免静默路由错误
  - 内置只读、文件写入、日历摘要、Slack 外发、酒店预订和敏感转账等跨 APP 验收场景；完整列表见 `method.md`
- **数据流追踪**：拦截 LLM 推理与工具调用，记录数据来源、去向与推理链路
- **知识图谱建模**：基于 PROV-AGENT 模型（AIAgent / AIModelInvocation / AgentTool / Prompt / DomainData）
- **可视化仪表盘**
  - 结构化拓扑图：卡片式节点，按“提示词 → 智能体 → 推理 → 输入数据 → 工具调用 → 输出数据”分列展示；节点带 APP 域标识，顶部 APP 流程条按执行顺序展示跨 APP 调用，支持点击聚焦
  - 图例交互：图例说明可折叠；节点类型、敏感、不可信和风险图例可点击过滤，并自动重排剩余节点
  - 面板折叠：时间线向下拖到底部或侧栏向右拖到最右侧后自动收起，可再次拖动或双击恢复
  - 人工授权：L2 待确认操作生成染色的人工授权节点，节点详情内可直接批准或拒绝；决策状态进入 trace
  - 任务审计摘要：展示任务目标、授权工具、实际调用、跨 APP 路径、敏感数据和策略结论
  - 敏感审计：邮件、金融等数据使用信息流标签高亮，审计视图保留完整证据供用户核查
  - 风险与策略事件：安全风险和任务范围/敏感外发策略分别标注，同时保留在同一审计面板中
  - 执行时间线：合并生命周期步骤与事件内容，展示完整 Prompt、LLM 推理、工具输出与阻断原因，支持拖拽调整高度并定位图谱节点
  - 风险卡片与防御审计
  - 历史回放：新记录保存当时的图谱、执行时间线、任务基线和环境快照；旧记录使用可用字段兼容回放
  - 环境变更：按 APP 查看字段级环境差异、敏感等级和来源链，可定位图谱节点，并回放任务基线与执行后快照
- **多任务套件**：banking / workspace / slack / travel
  - 图谱中的 APP 域即上述四个 task suite；file_reader / user_account / email / calendar 等是 suite 内部工具模块，作为模块信息展示；同一 suite 内的跨模块任务标记为“跨模块”
  - 原版 benchmark 不含跨 APP 预设定任务（TaskCombinator 仅组合同一 suite 内的任务）；本项目提供 unified 模式与跨 APP 示例场景（如“读取未读邮件并查询银行余额”）

## 快速开始

```bash
# 1. 创建环境并安装项目基础依赖（Python 3.10+，推荐 3.12）
conda create -n agent python=3.12 -y
conda activate agent
pip install -e ".[transformers,privacy]"

# 2. 安装可视化平台依赖
pip install flask flask-cors networkx

# 3. 启动可视化 API 服务
python -m agentdojo.method.visualization.server

# 4. 打开前端
# Windows
start frontend/index.html
# macOS
open frontend/index.html
# Linux
xdg-open frontend/index.html
```

> 首次使用时，需在页面右上角“操作控制台”中配置 LLM（选择模型并填写 API Key，支持 OpenAI / Anthropic / DeepSeek / Gemini 等，详见 `src/agentdojo/agent_pipeline/llms/`），之后即可执行指令或攻击场景测试。

> Ring 0/Ring 1 使用项目内 `models/unplug-tiny-v1` 的双头小模型；
> Ring 2/Ring 3 使用任务授权、声明式工具元数据、信息流标签和确定性路径检查。

> 前端通过 `https://d3js.org` 加载 D3 v7。完全离线运行时需要把 D3 资源下载到 `frontend/` 并修改 `frontend/index.html` 的脚本地址。

## 环境变量

| 变量 | 说明 |
| :--- | :--- |
| `AGENTDOJO_PI_MODEL_PATH=<dir>` | 覆盖本地提示注入检测模型目录；未设置时使用项目内 `models/unplug-tiny-v1` |
| `AGENTDOJO_GLINER_MODEL_PATH=<dir>` | 覆盖本地 GLiNER 目录；未设置时使用 `models/gliner_multi-v2.1`，模型不可用时读取 fail-closed |
| `AGENTDOJO_USE_RELOADER=true` | 开启 Flask debug 自动重载（默认关闭，避免重复加载模型） |
| `AGENTDOJO_ATTACK_SCENARIOS_PER_SUITE=<n>` | 每个攻击类型在每个 suite 中生成的预设场景数，默认 3 |
| `LOCAL_LLM_PORT=<port>` | 本地 OpenAI 兼容模型服务端口，默认 `8000` |

提示注入检测模型始终从本地目录加载，并显式启用 `local_files_only=True`；
运行时不访问 Hugging Face，也不会在模型缺失时静默退回在线下载。
GLiNER 使用相同的离线约束，并且是 Ring 2 的强制组件。默认使用
`urchade/gliner_multi-v2.1`；项目不会在运行时自动联网下载，模型不可用时读取结果不会进入 Agent。
首次部署时，可先下载主检测模型：

```bash
hf download Unplug-AI/unplug-tiny-v1 --local-dir models/unplug-tiny-v1
hf download urchade/gliner_multi-v2.1 --local-dir models/gliner_multi-v2.1
```

Unplug 文档头阈值默认设为 `0.9`，BIOES span 阈值默认设为 `0.45`；最终写操作和外发仍由 Ring 2/3 决定。
若项目内仍存在 `models/prompt-injection-guard-small`，它只作为 Unplug 无命中时的
语义句级后备检测器，用于覆盖 Unplug 英文训练分布之外的中文等文本：按段落和句子分块，
超长句才使用带重叠的窗口，命中时隔离整个语义块而不是声称获得精确 span。
Unplug 的训练分布偏英文，中文和混合语言效果应纳入项目自己的攻击集持续评估。
隔离后的可见文本会复扫一次；复扫仍有风险或检测器不可用时阻断，不会进行基于关键词的循环清洗。
未登记的敏感类别按 `secret` 处理，未知来源按 `untrusted` 处理；任务计划或数据访问契约不可用时，所有工具动作均 fail-closed。

策略配置文件：

- `src/agentdojo/method/modeling/tool_security.json`：工具 profile、L0/L1/L2、effect、字段角色和风险阈值
- `src/agentdojo/method/modeling/data_sensitivity.json`：四个 APP 的人工实体/字段敏感等级、类别和工具输出实体映射

## 项目结构

```
src/agentdojo/
├── method/
│   ├── capture/          # AOP 拦截器与环境快照
│   ├── modeling/         # PROV 图谱、信息流标签、工具/数据敏感配置
│   ├── analysis/         # 任务计划、Ring 0–3 与结果审计
│   ├── tasks/            # 跨 APP 复合任务
│   └── visualization/    # Flask API、环境快照与历史回放
├── agent_pipeline/       # Agent 执行管线与各 LLM 适配
├── default_suites/       # 各任务套件（banking/workspace/slack/travel）
└── scripts/              # 基准测试命令行工具
frontend/                 # D3.js 可视化前端
method.md                 # 方法层设计与运行流程
docs/                     # 文档（mkdocs）
```

## 运行边界

- 当前执行入口在单个 Flask 进程内串行化任务，避免并发任务覆盖 APP 环境、任务基线和 trace。
- trace 与历史环境快照可能包含完整邮件、文件内容、账户信息等敏感审计数据，建议只在可信的本地环境运行。
- 旧版 trace 若未保存 `environment_snapshots`，只能回放图谱中的环境变更摘要，无法恢复完整字段级前后值。

## 许可证

MIT License，基于 [AgentDojo](https://github.com/ethz-spylab/agentdojo)（MIT License）。
