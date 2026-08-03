# AgentDojo 命令行测试指南 (TESTING_GUIDE.md)

本指南详细介绍了如何使用 `agentdojo` 命令行工具来运行基准测试、评估攻击效果以及测试防御机制。

## 1. 基础用法

主要的测试入口脚本位于 `src/agentdojo/scripts/benchmark.py`。你可以通过 `python -m` 或直接运行脚本来执行。

```bash
# 运行默认基准测试 (默认使用 GPT-4o)
python src/agentdojo/scripts/benchmark.py --suite workspace
```

## 2. 参数详解

### 核心参数

| 参数 | 短指令 | 描述 | 默认值 |
| :--- | :--- | :--- | :--- |
| `--suite` | `-s` | **(可多次指定)** 要运行的任务套件名。如果未指定，则运行所有可用套件。 | (所有可用套件) |
| `--model` | | 要评估的语言模型名称（如 `gpt-4o-2024-05-13`, `claude-3-5-sonnet-20240620`）。 | `gpt-4o-2024-05-13` |
| `--attack` | | 要使用的攻击方法名称。如果不指定，则运行无注入的正常任务。 | `None` |
| `--defense` | | 要使用的防御机制名称。 | `None` |

### 任务筛选与执行控制

| 参数 | 短指令 | 描述 |
| :--- | :--- | :--- |
| `--user-task` | `-ut` | **(可多次指定)** 指定运行套件中的特定用户任务 ID。仅在指定单个套件时有效。 |
| `--injection-task` | `-it` | **(可多次指定)** 指定运行特定的注入任务 ID。 |
| `--force-rerun` | `-f` | **(Flag)** 强制重新运行任务。默认会跳过已完成并生成结果的任务，使用此参数将覆盖旧结果。 |
| `--max-workers` | | 指定并行执行任务套件的最大工作进程数。默认为 `1`（顺序执行）。 |
| `--enable-data-flow-tracking` | | **(Flag)** 启用“代理数据流追踪与可视化平台”。启用后将激活运行时监控并输出风险分析报告。 |

### 模型与环境配置

| 参数 | 描述 | 默认值 |
| :--- | :--- | :--- |
| `--model-id` | 本地模型 ID。在使用 `local` 或 `vllm_parsed` 模型时用于识别具体模型。 | `None` |
| `--benchmark-version`| 指定基准测试的版本。 | `v1.2.2` |
| `--logdir` | 运行结果和日志的保存目录。 | `./runs` |
| `--tool-delimiter` | 工具分隔符，主要用于本地模型。 | `tool` |

### 进阶配置

| 参数 | 短指令 | 描述 |
| :--- | :--- | :--- |
| `--system-message` | | 直接指定系统提示词字符串。如果提供，将忽略 `--system-message-name`。 |
| `--system-message-name`| | 指定 `data/system_messages.yaml` 中的预定义系统提示词名。 |
| `--module-to-load` | `-ml` | **(可多次指定)** 在启动前加载的 Python 模块。用于注册自定义攻击、套件或防御。 |

---

## 3. 可选值参考

### 任务套件 (`--suite`)
- `workspace`: 办公自动化场景（邮件、日历、文档）。
- `travel`: 旅游预订场景。
- `banking`: 银行转账与账户管理场景。
- `slack`: Slack 消息与频道管理场景。

### 攻击手段 (`--attack`)
- `direct`: 直接注入指令。
- `ignore_previous`: 指令忽略攻击。
- `important_instructions`: 基于特定格式的“重要指令”注入。
- `injecagent`: 参考 InjecAgent 论文的攻击字符串。
- `tool_knowledge`: 包含工具使用知识的攻击。
- (更多详见 `src/agentdojo/attacks/`)

### 防御机制 (`--defense`)
- `tool_filter`: 只有 OpenAI 模型支持，通过另一个 LLM 过滤工具调用。
- `transformers_pi_detector`: 使用 DeBERTa 等模型检测提示词注入。
- `repeat_user_prompt`: 在工具输出后重复用户原始指令。
- `spotlighting_with_delimiting`: 使用特殊分隔符（如 `<< >>`）标记不可信内容。

---

## 4. 常见测试示例

### 4.1 运行基础性能评估
在 `travel` 套件上评估 `GPT-4o mini` 的正常任务完成能力：
```bash
python src/agentdojo/scripts/benchmark.py --model gpt-4o-mini-2024-07-18 --suite travel
```

### 4.2 运行注入攻击评估并启用追踪
使用 `ignore_previous` 攻击方式对 `banking` 套件进行评估，并开启数据流监控：
```bash
python src/agentdojo/scripts/benchmark.py --suite banking --attack ignore_previous --enable-data-flow-tracking
```

### 4.3 强制重新运行实验
如果修改了代码或环境，需要覆盖旧结果：
```bash
python src/agentdojo/scripts/benchmark.py --suite workspace --attack direct -f
```

### 4.4 测试特定防御手段
```bash
python src/agentdojo/scripts/benchmark.py --suite workspace --attack important_instructions --defense repeat_user_prompt
```

### 4.5 并行运行多个套件
同时评估两个套件以节省时间：
```bash
python src/agentdojo/scripts/benchmark.py -s workspace -s banking --max-workers 2
```

---

## 5. 注意事项
- **环境变量**：请确保根目录下有 `.env` 文件，并配置了相应的 API Keys（如 `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` 等）。
- **日志**：运行结果将保存在 `./runs`。启用 `--enable-data-flow-tracking` 时，会额外生成风险评估卡片。
- **多次指定**：带有 **(可多次指定)** 标记的参数可以重复使用，例如 `-s workspace -s travel`。
