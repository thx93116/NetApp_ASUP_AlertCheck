from __future__ import annotations

import re
from typing import Any

from ..customer import customer_from_address
from ..priority import classify_priority, extract_event_title


def build_notification(
    result: dict[str, Any],
    from_address: str | None = None,
    asup_metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    metadata = asup_metadata or {}
    message = result.get("message", {})
    if not isinstance(message, dict):
        message = {}

    subject = str(message.get("subject") or "")
    customer = customer_from_address(from_address or _string_or_none(message.get("from")))
    priority = classify_priority(subject)
    event_title = extract_event_title(subject)
    generated_on = metadata.get("generated_on") or _summary_string(result, "generated_on")
    should_send = priority is not None
    summary = _build_summary(result, metadata, event_title, priority) if should_send else ""

    return {
        "customer": customer,
        "priority": priority,
        "should_send": should_send,
        "generated_on": generated_on,
        "event_title": event_title,
        "summary": summary,
        "telegram_text": _format_telegram_text(customer, priority, generated_on, event_title, summary)
        if should_send
        else "",
    }


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _summary_map(result: dict[str, Any]) -> dict[str, object]:
    evidence = result.get("evidence", {})
    if not isinstance(evidence, dict):
        return {}
    summary = evidence.get("summary", [])
    if not isinstance(summary, list):
        return {}

    mapped: dict[str, object] = {}
    for item in summary:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str):
            mapped[name] = item.get("value")
    return mapped


def _summary_string(result: dict[str, Any], name: str) -> str:
    value = _summary_map(result).get(name)
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return str(value)


def _build_summary(
    result: dict[str, Any],
    metadata: dict[str, str],
    event_title: str,
    priority: str | None,
) -> str:
    classification = result.get("classification", {})
    matched_rule = ""
    if isinstance(classification, dict):
        matched_rule = str(classification.get("matched_rule_id") or "")
    evidence = _summary_map(result)
    message = result.get("message", {})
    subject = message.get("subject", "") if isinstance(message, dict) else ""
    subject_upper = str(subject).upper()

    if matched_rule.startswith("node_panic") or "PANIC" in subject_upper:
        return _panic_summary(evidence, metadata)
    if matched_rule == "arw_activity_seen":
        return _arw_summary(evidence)
    return f"{event_title} 符合 {priority} 通知條件，請確認 AutoSupport 證據與系統狀態。"


def _panic_summary(evidence: dict[str, object], metadata: dict[str, str]) -> str:
    node = metadata.get("hostname") or _as_string(evidence.get("node"))
    partner = metadata.get("partner_hostname") or _as_string(evidence.get("partner_node"))
    version = _short_ontap_version(metadata.get("version") or _as_string(evidence.get("ontap_version")))
    coredump_state = _as_string(evidence.get("coredump_state"))
    panic_string = _as_string(evidence.get("panic_string"))

    if node:
        parts = [f"{node} 發生 controller panic，HA takeover 相關證據已擷取。"]
    else:
        parts = ["發生 controller panic，HA takeover 相關證據已擷取。"]
    if partner:
        parts.append(f"Partner node 為 {partner}。")
    if version:
        parts.append(f"ONTAP 版本 {version}。")
    if coredump_state:
        parts.append(f"coredump 狀態 {coredump_state}。")
    if panic_string:
        parts.append(f"panic string: {panic_string}。")
    return "".join(parts)


def _arw_summary(evidence: dict[str, object]) -> str:
    volume = _as_string(evidence.get("affected_volume"))
    probability = _as_string(evidence.get("attack_probability"))
    detected_by = _as_string(evidence.get("attack_detected_by"))
    parts = ["偵測到 possible ransomware activity。"]
    if volume:
        parts.append(f"影響 Volume: {volume}。")
    if probability:
        parts.append(f"攻擊機率 {probability}。")
    if detected_by:
        parts.append(f"偵測方式 {detected_by}。")
    return "".join(parts)


def _as_string(value: object) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return str(value)


def _short_ontap_version(version: str) -> str:
    match = re.search(r"NetApp\s+Release\s+([^:]+)", version, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return version.strip()


def _format_telegram_text(
    customer: str,
    priority: str | None,
    generated_on: str,
    event_title: str,
    summary: str,
) -> str:
    return (
        f"[NetApp ASUP] {customer} - {priority}\n\n"
        "產生時間:\n"
        f"{generated_on or '未提供'}\n\n"
        "事件:\n"
        f"{event_title}\n\n"
        "判斷:\n"
        f"{summary}"
    )
