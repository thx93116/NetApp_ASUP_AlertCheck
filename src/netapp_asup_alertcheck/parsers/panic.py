from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..models import EvidenceBundle


DOCTYPE_INTERNAL_RE = re.compile(r"<!DOCTYPE\s+[^[]+\[[\s\S]*?\]>\s*", re.IGNORECASE)
DOCTYPE_SIMPLE_RE = re.compile(r"<!DOCTYPE\s+[^>]*>\s*", re.IGNORECASE)
UNSAFE_XML_RE = re.compile(r"<!ENTITY|<!DOCTYPE\s+[^>]*(?:SYSTEM|PUBLIC)", re.IGNORECASE)
RELEVANT_LOG_RE = re.compile(r"\b(panic|takeover|failover|reboot|coredump|core)\b", re.IGNORECASE)
PANIC_STRING_RE = re.compile(r"(?:panic[_ -]?string|panic):\s*(.+)", re.IGNORECASE)


HEADER_SUMMARY_FIELDS = {
    "X-Netapp-asup-subject": "asup_subject",
    "X-Netapp-asup-hostname": "node",
    "X-Netapp-asup-partner-hostname": "partner_node",
    "X-Netapp-asup-cluster-name": "cluster",
    "X-Netapp-asup-os-version": "ontap_version",
    "X-Netapp-asup-generated-on": "generated_on",
    "X-Netapp-asup-model-name": "model",
}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _safe_xml_text(xml_text: str) -> str:
    if UNSAFE_XML_RE.search(xml_text):
        return ""
    without_internal_dtd = DOCTYPE_INTERNAL_RE.sub("", xml_text)
    return DOCTYPE_SIMPLE_RE.sub("", without_internal_dtd).strip()


def _rows(xml_text: str) -> list[ET.Element]:
    safe_text = _safe_xml_text(xml_text)
    if not safe_text:
        return []
    try:
        root = ET.fromstring(safe_text)
    except ET.ParseError:
        return []
    return [element for element in root.iter() if _local_name(element.tag) == "ROW"]


def _child_text(row: ET.Element, name: str) -> str:
    for child in row.iter():
        if _local_name(child.tag) == name:
            return " ".join((child.itertext())).strip()
    return ""


def _parameter_list(row: ET.Element) -> list[str]:
    values = []
    for child in row.iter():
        if _local_name(child.tag) == "li":
            value = " ".join(child.itertext()).strip()
            if value:
                values.append(value)
    return values


def _summary_item(name: str, value: object, **metadata: str) -> dict[str, object]:
    item: dict[str, object] = {"name": name, "value": value}
    item.update(metadata)
    return item


def _parse_headers(text: str) -> dict[str, str]:
    headers = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            headers[key.strip()] = value.strip()
    return headers


def _parse_coredump(xml_text: str) -> dict[str, str]:
    for row in _rows(xml_text):
        state = _child_text(row, "state")
        corename = _child_text(row, "corename")
        if state or corename:
            return {
                "node": _child_text(row, "node"),
                "state": state,
                "corename": corename,
                "type": _child_text(row, "coredump_type"),
                "blocks_saved": _child_text(row, "blocks_saved"),
                "total_blocks": _child_text(row, "total_blocks_core_being_saved"),
            }
    return {}


def _parse_panic_event(xml_text: str) -> dict[str, object]:
    for row in _rows(xml_text):
        parameters = _parameter_list(row)
        event = {
            "time": _child_text(row, "time"),
            "severity": _child_text(row, "severity"),
            "source": _child_text(row, "source"),
            "message_name": _child_text(row, "messagename"),
            "parameters": parameters[:8],
        }
        combined = " ".join(str(value) for value in event.values()).lower()
        if RELEVANT_LOG_RE.search(combined):
            return event
    return {}


def _panic_string_from_event(event: dict[str, object]) -> str:
    parameters = event.get("parameters", [])
    if not isinstance(parameters, list):
        return ""
    for parameter in parameters:
        if not isinstance(parameter, str):
            continue
        match = PANIC_STRING_RE.search(parameter)
        if match:
            return match.group(1).strip()
    return ""


def _panic_string_from_logs(files: dict[str, str]) -> str:
    for file_name, text in files.items():
        if not (file_name.endswith(".gz") or "LOG" in file_name.upper() or "log" in file_name.lower()):
            continue
        for line in text.splitlines():
            match = PANIC_STRING_RE.search(line)
            if match:
                return match.group(1).strip()
    return ""


def _log_refs(files: dict[str, str]) -> list[dict[str, object]]:
    refs: list[dict[str, object]] = []
    for file_name, text in files.items():
        if not (file_name.endswith(".gz") or "LOG" in file_name.upper() or "log" in file_name.lower()):
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if RELEVANT_LOG_RE.search(line):
                refs.append({"file": file_name, "line_number": line_number, "line": line.strip()})
            if len(refs) >= 20:
                return refs
    return refs


def parse_panic_evidence(files: dict[str, str]) -> EvidenceBundle:
    summary: list[dict[str, object]] = []

    headers = _parse_headers(files.get("X-HEADER-DATA.TXT", ""))
    for header_name, summary_name in HEADER_SUMMARY_FIELDS.items():
        value = headers.get(header_name, "")
        if value:
            summary.append(_summary_item(summary_name, value))

    coredump = _parse_coredump(files.get("coredump-status.xml", ""))
    if coredump:
        if coredump["node"] and "node" not in {item["name"] for item in summary}:
            summary.append(_summary_item("node", coredump["node"]))
        summary.extend(
            [
                _summary_item("coredump_state", coredump["state"]),
                _summary_item("coredump_name", coredump["corename"]),
                _summary_item("coredump_type", coredump["type"]),
            ]
        )
        if coredump["blocks_saved"] or coredump["total_blocks"]:
            summary.append(
                _summary_item(
                    "coredump_progress",
                    f"{coredump['blocks_saved']} / {coredump['total_blocks']}".strip(),
                )
            )

    panic_event = _parse_panic_event(files.get("panic-context.xml", ""))
    if panic_event:
        summary.append(_summary_item("panic_event", panic_event))
    panic_string = _panic_string_from_event(panic_event) or _panic_string_from_logs(files)
    if panic_string:
        summary.append(_summary_item("panic_string", panic_string))

    files_used = [{"file": name, "purpose": "panic evidence"} for name in files]
    return EvidenceBundle(summary=summary, files_used=files_used, raw_refs=_log_refs(files))
