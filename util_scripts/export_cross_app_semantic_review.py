"""Export cross-APP tasks and their final semantic truth for manual review."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from agentdojo.method.tasks.cross_app import CROSS_APP_TASKS


def _json_block(value: object) -> str:
    return "```json\n" + json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        default=str,
    ) + "\n```"


def _source_label(task: object) -> str:
    source = task.source
    benchmark = str(source.get("benchmark", "") or "Unspecified")
    quality = str(source.get("migration_quality", "") or "unspecified")
    benchmark_label = {
        "AppWorld": "AppWorld",
        "AgentDojo": "AgentDojo-composed",
        "Handcrafted": "Handcrafted",
    }.get(benchmark, benchmark)
    return f"{benchmark_label}; migration quality: `{quality}`"


def main() -> None:
    output = Path(
        "external_data/validation/"
        "cross_app_tasks_semantic_review_20261116.md"
    )
    output.parent.mkdir(parents=True, exist_ok=True)

    source_counts = Counter(
        str(task.source.get("benchmark", "") or "Unspecified")
        for task in CROSS_APP_TASKS.values()
    )
    auto_tasks = [
        scenario_id
        for scenario_id, task in CROSS_APP_TASKS.items()
        if task.evaluation.get("requirements")
    ]
    lines = [
        "# 跨 APP 任务数据集语义人工核对",
        "",
        "生成日期：2026-11-16",
        "",
        "## 审计结论",
        "",
        f"- 共 `{len(CROSS_APP_TASKS)}` 个任务。",
        f"- 来源分布：`{dict(source_counts)}`。",
        (
            f"- `{len(auto_tasks)}/{len(CROSS_APP_TASKS)}` "
            "个任务具有自动评测真值。"
        ),
        (
            "- 本文件用于人工检查“任务描述、fixture 与自动真值是否"
            "语义一致”，不是由人工判断 Agent 最终结果。"
        ),
        (
            "- 消息评测采用混合策略：固定短回复检查必需措辞；"
            "多实体、多金额和摘要消息检查关键内容覆盖及禁用内容；"
            "交易、预约、文件和日历仍按结构化最终状态检查。"
        ),
        (
            "- 消息允许自然措辞、标点和无关补充说明，但金额、"
            "实体、收件人和顺序等任务约束仍会被检查。"
        ),
        "",
        "## 人工核对重点",
        "",
        "- 顺序敏感任务：",
        "",
        (
            "  - `appworld_4fab96f_pending_request_reminders_*`："
            "金额必须按 ledger 顺序出现。"
        ),
        "",
        "- 收件人身份任务：确认自然语言中的人名、邮件发件人和 "
        "Slack 用户名是否指向同一对象。",
        "",
        "- 排除项任务：确认已付款人员、其他导演电影等禁用内容"
        "不会因正常说明性措辞而误判。",
        "",
        "## 索引",
        "",
        "| # | Scenario | 来源 | 真值类型 |",
        "|---|---|---|---|",
    ]
    for index, (scenario_id, task) in enumerate(
        sorted(CROSS_APP_TASKS.items()),
        start=1,
    ):
        lines.append(
            f"| {index} | `{scenario_id}` | "
            f"{_source_label(task)} | 自动评测 |"
        )

    lines.extend(["", "## 任务详情", ""])
    for index, (scenario_id, task) in enumerate(
        sorted(CROSS_APP_TASKS.items()),
        start=1,
    ):
        lines.extend(
            [
                f"### {index}. `{scenario_id}`",
                "",
                f"**来源：** {_source_label(task)}",
                "",
                "**任务目的：**",
                "",
                task.description,
                "",
                "**用户 prompt：**",
                "",
                f"> {task.prompt}",
                "",
                "**跨 APP 数据路径：**",
                "",
            ]
        )
        for step in task.steps:
            dependency = (
                f"; depends on: {', '.join(step.depends_on)}"
                if step.depends_on
                else ""
            )
            lines.append(
                f"- `{step.step_id}` - `{step.suite}.{step.tool}`: "
                f"{step.purpose}{dependency}"
            )

        lines.extend(
            [
                "",
                "**Fixture 数据：**",
                "",
                _json_block(task.fixtures),
                "",
                "**最终目标真值（评测器 requirements）：**",
                "",
                _json_block(task.evaluation.get("requirements", [])),
                "",
                "**允许的环境变化：**",
                "",
                _json_block(task.evaluation.get("allowed_changes", [])),
                "",
                "---",
                "",
            ]
        )

    output.write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )
    print(output.resolve())


if __name__ == "__main__":
    main()
