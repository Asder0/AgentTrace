"""Export only user prompts and expected final-state changes for review."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from agentdojo.method.tasks.cross_app import CROSS_APP_TASKS


def _join(values: Sequence[Any]) -> str:
    return "、".join(str(value) for value in values)


def _message_expectation(message: Mapping[str, Any]) -> str:
    details: list[str] = []
    if "body" in message:
        details.append(f"正文应为“{message['body']}”")
    if message.get("contains_all"):
        details.append(f"正文必须包含：{_join(message['contains_all'])}")
    if message.get("contains_any"):
        details.append(
            f"正文至少表达以下含义之一：{_join(message['contains_any'])}"
        )
    for candidate_group in message.get("contains_any_groups", []):
        if candidate_group:
            details.append(
                "正文需要再表达以下含义之一："
                f"{_join(candidate_group)}"
            )
    if message.get("ordered_contains_all"):
        details.append(
            "这些内容必须按顺序出现："
            f"{_join(message['ordered_contains_all'])}"
        )
    if message.get("contains_none"):
        details.append(f"正文不得出现：{_join(message['contains_none'])}")
    if "body_number" in message:
        details.append(f"正文中的数值应为 {message['body_number']}")
    if "body_boolean" in message:
        answer = "Yes" if message["body_boolean"] else "No"
        details.append(f"正文应明确表达 {answer}")
    return "；".join(details) or "正文内容满足任务要求"


def _describe_requirement(requirement: Mapping[str, Any]) -> list[str]:
    kind = str(requirement.get("kind") or "")
    lines: list[str] = []

    if kind == "new_transactions":
        for transaction in requirement.get("transactions", []):
            lines.append(
                "新增一笔银行交易："
                f"收款人 {transaction.get('recipient')}，"
                f"金额 {transaction.get('amount')}，"
                f"主题“{transaction.get('subject', '')}”"
                + (
                    f"，日期 {transaction['date']}"
                    if transaction.get("date")
                    else ""
                )
                + "。"
            )
    elif kind == "new_direct_messages":
        for message in requirement.get("messages", []):
            lines.append(
                f"{message.get('recipient')} 新增一条私信；"
                f"{_message_expectation(message)}。"
            )
    elif kind == "new_channel_messages":
        for message in requirement.get("messages", []):
            lines.append(
                f"#{message.get('recipient')} 频道新增一条消息；"
                f"{_message_expectation(message)}。"
            )
    elif kind == "new_emails":
        for email in requirement.get("emails", []):
            details = [f"收件人：{_join(email.get('recipients', []))}"]
            if email.get("subject"):
                details.append(f"主题：{email['subject']}")
            if email.get("contains_all"):
                details.append(
                    f"正文必须包含：{_join(email['contains_all'])}"
                )
            if email.get("body_contains"):
                details.append(
                    f"正文必须包含：{_join(email['body_contains'])}"
                )
            if email.get("contains_any"):
                details.append(
                    "正文至少表达以下含义之一："
                    f"{_join(email['contains_any'])}"
                )
            if email.get("contains_none"):
                details.append(
                    f"正文不得出现：{_join(email['contains_none'])}"
                )
            lines.append("新增一封已发送邮件；" + "；".join(details) + "。")
    elif kind == "new_files":
        for file in requirement.get("files", []):
            details = [f"文件名：{file.get('filename')}"]
            if file.get("content_contains"):
                details.append(
                    f"内容必须包含：{_join(file['content_contains'])}"
                )
            if file.get("content") is not None:
                details.append(f"完整内容应为：{file['content']}")
            lines.append("云盘新增一个文件；" + "；".join(details) + "。")
    elif kind == "new_calendar_events":
        for event in requirement.get("events", []):
            lines.append(
                "新增一个日历事件："
                f"标题“{event.get('title')}”，"
                f"开始 {event.get('start_time')}，"
                f"结束 {event.get('end_time')}。"
            )
    elif kind == "reservation":
        expected = requirement.get("expected", {})
        details = [
            f"预约类型：{expected.get('reservation_type')}",
            f"名称：{expected.get('title')}",
            f"开始：{expected.get('start_time')}",
            f"结束：{expected.get('end_time')}",
        ]
        lines.append("创建以下旅行预约：" + "；".join(details) + "。")
    elif kind == "answer_number":
        lines.append(
            f"最终回答应给出数值 {requirement.get('value')}"
            + (
                "，并允许误差 "
                f"±{requirement.get('tolerance')}"
                if requirement.get("tolerance") is not None
                else ""
            )
            + "。"
        )
    elif kind == "answer_boolean":
        answer = "Yes" if requirement.get("value") else "No"
        lines.append(f"最终回答应明确表达 {answer}。")
    else:
        lines.append(str(requirement.get("name") or kind or "满足任务要求"))
    return lines


def main() -> None:
    output = Path(
        "external_data/validation/"
        "cross_app_prompt_expected_state_review_20261116.md"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 跨 APP 任务：用户指令与预期最终状态",
        "",
        (
            "本文件只列出当前用户输入指令和预期最终状态。"
            "既定变化之外，其他 APP 状态不得发生额外变化。"
        ),
        "",
    ]
    for index, (scenario_id, task) in enumerate(
        sorted(CROSS_APP_TASKS.items()),
        start=1,
    ):
        requirements = task.evaluation.get("requirements", [])
        expected_lines = [
            line
            for requirement in requirements
            if isinstance(requirement, Mapping)
            for line in _describe_requirement(requirement)
        ]
        if not expected_lines:
            expected_lines = ["应用状态不变。"]
        lines.extend(
            [
                f"## {index}. `{scenario_id}`",
                "",
                "**用户输入指令**",
                "",
                f"> {task.prompt}",
                "",
                "**预期最终状态**",
                "",
                *[f"- {line}" for line in expected_lines],
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
