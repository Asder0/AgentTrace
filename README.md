# AgentTrace

基于 [AgentDojo](https://github.com/ethz-spylab/agentdojo) 的跨 APP 智能体数据流追踪与可视化平台。

AgentTrace 在 AgentDojo 基准测试框架之上，通过 AOP 拦截器（Monkey Patching）实时捕获 Agent 的 LLM 推理与工具调用，构建 PROV 知识图谱，并以可视化仪表盘呈现完整的数据流转、防御监控与历史回放。

仓库名为 AgentTrace，前端界面展示名为 AgentDojo Trace。

运行时方法、四层风险判定、trace 结构和扩展方式详见 [`method.md`](method.md)。

## 系统怎么工作

系统把“理解任务”和“批准任务”分开。大模型负责理解用户要求、读取系统提供的信息并提
出下一步动作，但模型本身没有直接扩大权限的能力；能不能读取某个字段、调用某个工具、把
数据发送到哪里，由控制器根据用户指令、人工配置的任务规则和数据等级决定。

1. 用户输入先检查是否夹带恶意指令。高风险内容会被隔离、记录或阻止，正常任务继续。
2. 工具返回内容后，系统只检查其中的自然语言部分，避免邮件或文件里的文字冒充系统命令；
   命中内容会在进入模型前被隔离。
3. 模型执行任务前必须给出结构化计划。只读和普通操作只能在计划允许的 APP、数据和动作
   范围内自动执行；敏感发送、删除、交易等高风险操作必须在最初计划中明确出现。
4. 系统尽量少让模型看到真实敏感数据。不需要的字段直接隐藏，只需要搬运的字段用占位符
   代替；模型确实需要比较、计算或理解真实敏感值才能完成任务时，通过 `analysis_fields`
   向模型暴露真实值，并在风险卡片和溯源图中标明暴露内容、等级和原因。
5. 真正发送数据前，系统会再次检查最终发送内容、数据来源、敏感等级和接收方。不仅检查
   模型“打算做什么”，还检查实际参数最终变成了什么。
6. 如果任务要求无法从现有数据中确认，模型不能自行猜测或忽略。系统会先让模型补充读取；
   仍无法确认时，由用户在界面上选择放宽哪些要求或取消任务。
7. 任务结束后，系统检查实际工具结果是否完成了用户要求，并检查最终回答有没有声称未经
   证据支持的事实。最终回答不安全时会被修正；仍无法保证安全时不展示原文。

## 功能特性

- **可审计运行时策略（4-Ring，轻量实现）**
  - Ring 0：本地 prompt-injection-guard-small 直接注入分类器先判断完整用户指令；完整指令命中后，再按句定位风险；默认使用 QUARANTINE，将命中内容替换为 `[[DATA_REMOVED]]`，同时支持 ADVISORY 和 STRICT
  - Ring 1：按 schema 字段类型扫描工具输出；普通字符串一律检测，Unplug 命中时隔离精确 span，后备检测命中时隔离语义块，并将来源实体标记为可疑
  - Ring 2：使用人工定义的 L0/L1/L2 工具等级，控制工具、数据字段和具体资源的访问范围；高风险操作、可疑来源影响的写操作以及任务条件无法确认的情况，均进入相应的检查和用户决策
  - Ring 3：在 egress 执行前检查最终参数及被引用资源内容；按 APP 实体字段的敏感等级、多来源最高等级继承、完整来源元组、来源风险和接收方授权状态进行判定
- **信息流标签与风险状态**
  - 每条数据记录 `confidentiality`（public/internal/confidential/secret）和 `integrity`（trusted/untrusted/tainted）
  - 机密性按最高级别传播；注入来源风险只标记被命中的直接实体及其来源，不扩散为整批工具结果或整个上下文
  - PROV 图谱记录来源、派生、用户授权、FSM 状态、风险证据和外部出口
- **可解释风险事件**
  - `PASS / ADVISORY / MITIGATE / QUARANTINE / HOLD / BLOCK` 决策均写入图谱
  - 非阻断风险保持任务运行，并在图谱节点和风险卡片中高亮
- **全机制开关**
  - Ring 0：prompt-injection-guard-small 完整指令门控、句级定位与占位符隔离
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
- **图谱语义**：`triggered_by` 表示数据或 Prompt 触发风险；只有 Ring 3 敏感外发使用 `leak_sink`，普通授权出口使用 `applies_to_sink`
- **可视化仪表盘**
  - 结构化拓扑图：卡片式节点，按“提示词 → 智能体 → 推理 → 输入数据 → 工具调用 → 输出数据”分列展示；节点带 APP 域标识，顶部 APP 流程条按执行顺序展示跨 APP 调用，支持点击聚焦
  - 图例交互：图例说明可折叠；节点类型、敏感、不可信和风险图例可点击过滤，并自动重排剩余节点
  - 面板折叠：右侧信息栏可拖动调整宽度，拖到最右侧或双击可折叠和恢复
  - 人工授权：L2 待确认操作生成染色的人工授权节点，节点详情内可直接批准或拒绝；决策状态进入 trace
  - 任务总结：展示任务指令、实际调用、跨 APP 路径、资源访问范围、数据类别和结果核验
  - 敏感审计：邮件、金融等数据使用信息流标签高亮，审计视图保留完整证据供用户核查
  - 风险事件：按提示注入、敏感数据外发、高风险操作授权和敏感数据对 LLM 暴露分类；普通策略提醒不进入风险面板，点击卡片可反向聚焦图谱
  - API 错误：统一返回 `code/message/retryable/request_id`；未知 5xx 隐藏内部异常，仅写入服务端日志
  - 历史回放：新记录保存当时的图谱、任务总结、风险事件、任务基线和环境快照；同一任务/攻击配置/防御状态默认只保留最新版本
  - 环境变更：按 APP 查看字段级环境差异、敏感等级和来源链，可定位图谱节点，并回放任务基线与执行后快照
- **前后端执行配置同步**：普通任务和攻击请求都会携带当前防御开关与自动确认状态，后端以请求配置执行，不再用默认值覆盖前端选择
- **两级注入测试面**：`用户提示 · Ring 0` 直接把攻击文本拼入用户任务；邮件、Slack 和云盘注入点保留原任务环境，用于 Ring 1 间接注入测试
- **多任务套件**：banking / workspace / slack / travel
  - 图谱中的 APP 域即上述四个 task suite；file_reader / user_account / email / calendar 等是 suite 内部工具模块，作为模块信息展示；同一 suite 内的跨模块任务标记为“跨模块”
  - 原版 benchmark 不含跨 APP 预设定任务（TaskCombinator 仅组合同一 suite 内的任务）；本项目提供 unified 模式与跨 APP 示例场景（如“读取未读邮件并查询银行余额”）

## 快速开始

> 本项目本地运行、测试和演示统一使用 Conda 环境 `agent`。以下命令都应先执行
> `conda activate agent`；仓库中的 `.venv` 不属于本项目的正式启动环境。

```bash
# 1. 首次使用时创建环境并安装项目基础依赖（Python 3.10+，推荐 3.12）
conda create -n agent python=3.12 -y
conda activate agent
pip install -e ".[transformers,privacy]"

# 确认当前解释器来自 Conda agent 环境
python -c "import sys; print(sys.executable)"

# 2. 安装可视化平台依赖
pip install flask networkx

# 3. 启动同源可视化服务
python -m agentdojo.method.visualization.server

# 4. 在浏览器打开前端
# Windows
start http://127.0.0.1:5000/
# macOS
open http://127.0.0.1:5000/
# Linux
xdg-open http://127.0.0.1:5000/
```

> 首次使用时，需在页面右上角“操作控制台”中配置 LLM（选择模型并填写 API Key，支持 OpenAI / Anthropic / DeepSeek / Gemini 等，详见 `src/agentdojo/agent_pipeline/llms/`），之后即可执行跨 APP 预设任务或攻击测试。

> Ring 0 使用项目内 `models/prompt-injection-guard-small`；
> Ring 1 使用项目内 `models/unplug-tiny-v1` 的双头小模型和
> `models/prompt-injection-guard-small` 多语言后备；
> Ring 2/Ring 3 使用任务授权、声明式工具元数据、信息流标签和确定性路径检查。

> 前端使用项目内置的 D3 v7（`frontend/vendor/d3.v7.min.js`），无需联网加载可视化依赖。

## 环境变量

| 变量 | 说明 |
| :--- | :--- |
| `AGENTDOJO_PI_MODEL_PATH=<dir>` | 覆盖本地提示注入检测模型目录；未设置时使用项目内 `models/unplug-tiny-v1` |
| `AGENTDOJO_DIRECT_PI_MODEL_PATH=<dir>` | 覆盖 Ring 0 直接注入检测模型目录；未设置时使用项目内 `models/prompt-injection-guard-small` |
| `AGENTDOJO_FALLBACK_PI_MODEL_PATH=<dir>` | 覆盖 Ring 1 语义块后备检测器目录；未设置时复用 `models/prompt-injection-guard-small` |
| `AGENTDOJO_GLINER_MODEL_PATH=<dir>` | 覆盖本地 GLiNER 目录；未设置时使用 `models/gliner_multi-v2.1`，模型不可用时读取 fail-closed |
| `AGENTDOJO_DEBUG=true` | 开启 Flask debug（默认关闭，避免暴露调试器） |
| `AGENTDOJO_USE_RELOADER=true` | 开启 Flask 自动重载，不单独开启 debug（默认关闭，避免重复加载模型） |
| `AGENTDOJO_ATTACK_SCENARIOS_PER_SUITE=<n>` | 每个攻击类型在每个 suite 中生成的预设场景数，默认 3 |
| `LOCAL_LLM_PORT=<port>` | 本地 OpenAI 兼容模型服务端口，默认 `8000` |

提示注入检测模型始终从本地目录加载，并显式启用 `local_files_only=True`；
运行时不访问 Hugging Face，也不会在模型缺失时静默退回在线下载。
GLiNER 使用相同的离线约束，并且是 Ring 2 的强制组件。默认使用
`urchade/gliner_multi-v2.1`；项目不会在运行时自动联网下载，模型不可用时读取结果不会进入 Agent。
首次部署时，可先下载主检测模型：

```bash
hf download Unplug-AI/unplug-tiny-v1 --local-dir models/unplug-tiny-v1
hf download Horizon-Labs/prompt-injection-guard-small --local-dir models/prompt-injection-guard-small
hf download urchade/gliner_multi-v2.1 --local-dir models/gliner_multi-v2.1
```

Ring 0 的 prompt-injection-guard-small 阈值默认为 `0.5`。完整用户 prompt 先整体过门控，只有完整输入
被判为可疑时才按句定位，然后以 `[[DATA_REMOVED]]` 替换命中片段；默认模式仍是
`quarantine`，不会把正常任务静默放行为 `advisory`。

Unplug 文档头阈值默认设为 `0.9`，BIOES span 阈值默认设为 `0.45`；最终写操作和外发仍由 Ring 2/3 决定。
`models/prompt-injection-guard-small` 同时作为 Ring 0 的直接注入检测器，以及 Ring 1 中 Unplug 无命中时的
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
frontend/                 # D3.js 可视化前端（含本地 vendor 依赖）
method.md                 # 方法层设计与运行流程
docs/                     # 文档（mkdocs）
```

## 运行边界

- 当前执行入口在单个 Flask 进程内串行化任务，避免并发任务覆盖 APP 环境、任务基线和 trace。
- trace 与历史环境快照可能包含完整邮件、文件内容、账户信息等敏感审计数据。服务默认仅监听
  `127.0.0.1`，并拒绝非本机 Host 与跨源写操作；不要将该服务直接暴露到局域网或公网。
- 当前版本只加载包含完整 `environment_snapshots` 和 `defense_config` 的新版 Trace Schema，旧 Trace Schema 仍不受支持。
- 对当前 Schema 中由旧版本生成的关系语义，API 在读取和回放时自动归一化；原始 Trace JSON 不会被改写。

## 许可证

MIT License，基于 [AgentDojo](https://github.com/ethz-spylab/agentdojo)（MIT License）。
