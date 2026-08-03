# AgentTrace

基于 [AgentDojo](https://github.com/ethz-spylab/agentdojo) 的跨 APP 智能体数据流追踪与可视化平台。

AgentTrace 在 AgentDojo 基准测试框架之上，通过 AOP 拦截器（Monkey Patching）实时捕获 Agent 的 LLM 推理与工具调用，构建 PROV 知识图谱，并以可视化仪表盘呈现完整的数据流转、防御监控与历史回放。

## 功能特性

- **多层防御监控（4-Ring，已接入分析管线）**
  - Ring 0/1：提示注入检测（DeBERTa 模型 + 正则并行）
  - Ring 2：意图一致性检查（Sentence-BERT 语义相似度）
  - Ring 3：数据过度暴露缓解（NER 实体识别 + 类别感知脱敏）
- **数据流追踪**：拦截 LLM 推理与工具调用，记录数据来源、去向与推理链路
- **知识图谱建模**：基于 PROV-AGENT 模型（AIAgent / AIModelInvocation / AgentTool / Prompt / DomainData）
- **可视化仪表盘**
  - 结构化拓扑图：Prompt 在左、智能体居中、右侧按迭代顺序分行（思考 → 工具调用 → 结果）
  - 事件时间线：LLM 思考内容与工具调用结果的完整历史
  - 指令流转追踪：步骤级追踪，五类图谱节点均可点击查看详情
  - 风险卡片与防御审计
  - 历史回放：每条记录保存当时的图谱快照与事件时间线
- **多任务套件**：banking / workspace / slack / travel

## 快速开始

```bash
# 1. 创建环境并安装项目基础依赖（Python 3.10+，推荐 3.12）
conda create -n agent python=3.12 -y
conda activate agent
pip install -e .

# 2. 安装可视化平台与防御模型所需依赖
pip install flask flask-cors networkx scikit-learn requests
pip install torch transformers sentence-transformers

# 3. 启动可视化 API 服务（首次启动会预加载防御模型，约 30-120s）
python -m agentdojo.method.visualization.server

# 4. 打开前端（浏览器直接打开 frontend/index.html）
start frontend/index.html
```

> 首次使用时，需在页面右上角“操作控制台”中配置 LLM（选择模型并填写 API Key，支持 OpenAI / Anthropic / DeepSeek / Gemini 等，详见 `src/agentdojo/agent_pipeline/llms/`），之后即可执行指令或攻击场景测试。

> 若不需要模型检测，可设置 `AGENTDOJO_LIGHTWEIGHT=true` 以纯正则模式启动。

## 环境变量

| 变量 | 说明 |
| :--- | :--- |
| `AGENTDOJO_LIGHTWEIGHT=true` | 跳过模型加载，使用纯正则模式 |
| `AGENTDOJO_LOCAL_MODELS=true` | 离线模式，仅使用已缓存的本地模型 |
| `HF_ENDPOINT=<url>` | 自定义 HuggingFace 端点（默认自动使用 hf-mirror 镜像） |
| `AGENTDOJO_USE_RELOADER=true` | 开启 Flask debug 自动重载（默认关闭，避免重复加载模型） |

## 项目结构

```
src/agentdojo/
├── method/
│   ├── capture/          # AOP 拦截器与环境快照
│   ├── modeling/         # PROV 知识图谱建模
│   ├── analysis/         # 3-Ring 防御分析管线
│   └── visualization/    # Flask API 服务与前端配套
├── agent_pipeline/       # Agent 执行管线与各 LLM 适配
├── default_suites/       # 各任务套件（banking/workspace/slack/travel）
└── scripts/              # 基准测试命令行工具
frontend/                 # D3.js 可视化前端
docs/                     # 文档（mkdocs）
```

## 许可证

MIT License，基于 [AgentDojo](https://github.com/ethz-spylab/agentdojo)（MIT License）。
