"""AgentDojo APP 域定义：四个 task suite（banking/workspace/slack/travel）。

APP 域划分直接取自原版 AgentDojo 各 suite 的 ``task_suite.py`` 中的 ``TOOLS``：

- banking   : banking_client + file_reader + user_account（11 个工具）
- workspace : email_client + calendar_client + cloud_drive_client（24 个工具）
- slack     : slack + web（11 个工具）
- travel    : travel_booking_client + calendar_client + email_client（28 个工具）

``file_reader``、``user_account``、``email``、``calendar`` 等是 suite 内部的工具模块，
不是独立的 APP 域；图谱中的 ``node.app`` 使用上述四个 suite 名。
同名工具（如 calendar / send_email）在多个 suite 中出现时，以实际执行的 suite 为准。
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

SYSTEM_APP = "system"

# 四个 APP 域 = 原版 AgentDojo 的四个 task suite
APP_DOMAINS: dict[str, dict[str, Any]] = {
    "banking": {
        "label": "银行",
        "color": "#3fb950",
        # 原版 default_suites/v1/banking/task_suite.py::TOOLS
        "tools": [
            "get_iban",
            "send_money",
            "schedule_transaction",
            "update_scheduled_transaction",
            "get_balance",
            "get_most_recent_transactions",
            "get_scheduled_transactions",
            "read_file",
            "get_user_info",
            "update_password",
            "update_user_info",
        ],
    },
    "workspace": {
        "label": "办公",
        "color": "#4f8cff",
        # 原版 default_suites/v1/workspace/task_suite.py::TOOLS
        "tools": [
            "send_email",
            "delete_email",
            "get_unread_emails",
            "get_sent_emails",
            "get_received_emails",
            "get_draft_emails",
            "search_emails",
            "search_contacts_by_name",
            "search_contacts_by_email",
            "get_current_day",
            "search_calendar_events",
            "get_day_calendar_events",
            "create_calendar_event",
            "cancel_calendar_event",
            "reschedule_calendar_event",
            "add_calendar_event_participants",
            "append_to_file",
            "search_files_by_filename",
            "create_file",
            "delete_file",
            "get_file_by_id",
            "list_files",
            "share_file",
            "search_files",
        ],
    },
    "slack": {
        "label": "通讯",
        "color": "#a371f7",
        # 原版 default_suites/v1/slack/task_suite.py::TOOLS
        "tools": [
            "get_channels",
            "add_user_to_channel",
            "read_channel_messages",
            "read_inbox",
            "send_direct_message",
            "send_channel_message",
            "get_users_in_channel",
            "invite_user_to_slack",
            "remove_user_from_slack",
            "get_webpage",
            "post_webpage",
        ],
    },
    "travel": {
        "label": "旅行",
        "color": "#e3b341",
        # 原版 default_suites/v1/travel/task_suite.py::TOOLS
        "tools": [
            "get_user_information",
            "get_all_hotels_in_city",
            "get_hotels_prices",
            "get_rating_reviews_for_hotels",
            "get_hotels_address",
            "get_all_restaurants_in_city",
            "get_cuisine_type_for_restaurants",
            "get_restaurants_address",
            "get_rating_reviews_for_restaurants",
            "get_dietary_restrictions_for_all_restaurants",
            "get_contact_information_for_restaurants",
            "get_price_for_restaurants",
            "check_restaurant_opening_hours",
            "get_all_car_rental_companies_in_city",
            "get_car_types_available",
            "get_rating_reviews_for_car_rental",
            "get_car_fuel_options",
            "get_car_rental_address",
            "get_car_price_per_day",
            "create_calendar_event",
            "search_calendar_events",
            "get_day_calendar_events",
            "cancel_calendar_event",
            "reserve_hotel",
            "reserve_car_rental",
            "reserve_restaurant",
            "get_flight_information",
            "send_email",
        ],
    },
}

# 兼容旧命名
SUITE_DOMAINS = APP_DOMAINS

# 底层工具模块名 → 可能所属的 APP 域
LEGACY_MODULE_DOMAINS: dict[str, list[str]] = {
    "system": ["system"],
    "banking": ["banking"],
    "banking_client": ["banking"],
    "file_reader": ["banking"],
    "user_account": ["banking"],
    "email": ["workspace", "travel"],
    "email_client": ["workspace", "travel"],
    "calendar": ["workspace", "travel"],
    "calendar_client": ["workspace", "travel"],
    "cloud_drive": ["workspace"],
    "cloud_drive_client": ["workspace"],
    "slack": ["slack"],
    "web": ["slack"],
    "travel": ["travel"],
    "travel_booking_client": ["travel"],
}

_TOOL_DOMAINS: dict[str, list[str]] = {}
for _domain, _config in APP_DOMAINS.items():
    for _tool in _config["tools"]:
        _TOOL_DOMAINS.setdefault(_tool, []).append(_domain)


def domain_for_tool(tool_name: str, suite: Optional[str] = None) -> Optional[str]:
    """工具函数名 → APP 域。

    同名工具（calendar / send_email）优先使用实际 suite；否则仅当归属唯一时返回。
    """
    tool = str(tool_name or "")
    if not tool:
        return None
    if suite in APP_DOMAINS and tool in APP_DOMAINS[suite]["tools"]:
        return suite
    owners = _TOOL_DOMAINS.get(tool, [])
    return owners[0] if len(owners) == 1 else None


def domain_for_module(module_name: str, suite: Optional[str] = None) -> Optional[str]:
    """工具模块名 → APP 域（歧义模块优先使用实际 suite）。"""
    module = str(module_name or "")
    if not module:
        return None
    if module in APP_DOMAINS:
        return module
    owners = LEGACY_MODULE_DOMAINS.get(module, [])
    if suite and suite in owners:
        return suite
    return owners[0] if len(owners) == 1 else None


def infer_suite(nodes: Iterable[Mapping[str, Any]]) -> Optional[str]:
    """根据节点中的模块/工具信息推断唯一 task suite。"""
    candidates: Optional[set[str]] = None
    for node in nodes:
        if node.get("type") in ("AIAgent", "Prompt"):
            continue

        owners: set[str] = set()
        module = str(node.get("module") or "")
        if module and module in LEGACY_MODULE_DOMAINS:
            owners.update(LEGACY_MODULE_DOMAINS[module])
        tool_name = str(node.get("label") or "")
        if tool_name and tool_name in _TOOL_DOMAINS:
            owners.update(_TOOL_DOMAINS[tool_name])
        raw_app = str(node.get("app") or "")
        if raw_app in APP_DOMAINS:
            owners.add(raw_app)
        elif raw_app in LEGACY_MODULE_DOMAINS:
            owners.update(LEGACY_MODULE_DOMAINS[raw_app])

        if not owners:
            continue
        candidates = owners if candidates is None else (candidates & owners)
        if not candidates:
            return None

    return next(iter(candidates)) if candidates and len(candidates) == 1 else None


def _id_of(value: Any) -> str:
    if isinstance(value, Mapping):
        return str(value.get("id", ""))
    return str(value or "")


def normalize_graph_nodes(
    nodes: list[dict[str, Any]],
    links: Optional[list[dict[str, Any]]] = None,
    suite: Optional[str] = None,
    tool_app: Optional[Mapping[str, str]] = None,
) -> None:
    """原地规范化图谱节点：

    - ``app``   → APP 域（banking / workspace / slack / travel）
    - ``suite`` → 与 app 相同（保留字段便于前端展示）
    - ``module``→ 原始工具模块名（file_reader / user_account / email / ...）
    """
    if suite not in APP_DOMAINS:
        suite = infer_suite(nodes) or suite

    node_by_id = {str(node.get("id", "")): node for node in nodes}
    tool_for_data: dict[str, str] = {}

    for link in links or []:
        relation = link.get("relation")
        source_id = _id_of(link.get("source"))
        target_id = _id_of(link.get("target"))
        if relation == "used":
            tool_for_data[source_id] = target_id
        elif relation == "produces":
            tool_for_data[target_id] = source_id

    for node in nodes:
        node_type = node.get("type")
        raw_app = str(node.get("app") or "").strip()
        raw_module = str(node.get("module") or "").strip()

        if node_type in ("AIAgent", "Prompt") or raw_app == SYSTEM_APP or raw_module == SYSTEM_APP:
            node["app"] = SYSTEM_APP
            if suite:
                node["suite"] = suite
            continue

        domain: Optional[str] = None
        if node_type == "AgentTool":
            tool_name = str(node.get("label") or "")
            domain = (
                (tool_app or {}).get(tool_name)
                or domain_for_tool(tool_name, suite)
                or domain_for_module(raw_module, suite)
                or (raw_app if raw_app in APP_DOMAINS else None)
            )
        elif node_type == "DomainData":
            tool_id = tool_for_data.get(str(node.get("id", "")))
            tool_node = node_by_id.get(tool_id or "")
            if tool_node:
                tool_name = str(tool_node.get("label") or "")
                domain = (
                    (tool_app or {}).get(tool_name)
                    or domain_for_tool(tool_name, suite)
                    or domain_for_module(str(tool_node.get("module") or ""), suite)
                )
            if not domain:
                domain = domain_for_module(raw_module, suite) or domain_for_module(raw_app, suite)
        else:
            domain = domain_for_module(raw_module, suite) or domain_for_module(raw_app, suite)

        if domain:
            original = raw_module or raw_app
            if original and original != domain:
                node["module"] = original
            elif "module" not in node:
                node["module"] = original
            node["app"] = domain
            node["suite"] = domain
        if suite:
            node["suite"] = suite


def normalize_graph(
    graph: Mapping[str, Any],
    suite: Optional[str] = None,
    tool_app: Optional[Mapping[str, str]] = None,
) -> None:
    """规范化 ``{nodes, links}`` 结构的图谱数据。"""
    nodes = graph.get("nodes") or []
    links = graph.get("links") or []
    normalize_graph_nodes(list(nodes), list(links), suite=suite, tool_app=tool_app)
