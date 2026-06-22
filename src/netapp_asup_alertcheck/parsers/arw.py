from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..models import EvidenceBundle


DOCTYPE_INTERNAL_RE = re.compile(r"<!DOCTYPE\s+[^[]+\[[\s\S]*?\]>\s*", re.IGNORECASE)
DOCTYPE_SIMPLE_RE = re.compile(r"<!DOCTYPE\s+[^>]*>\s*", re.IGNORECASE)
UNSAFE_XML_RE = re.compile(r"<!ENTITY|<!DOCTYPE\s+[^>]*(?:SYSTEM|PUBLIC)", re.IGNORECASE)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(row: ET.Element, name: str) -> str:
    for child in row.iter():
        if _local_name(child.tag) == name:
            return (child.text or "").strip()
    return ""


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


def _parse_status(xml_text: str) -> dict[str, str]:
    for row in _rows(xml_text):
        probability = _child_text(row, "attack_probability")
        if probability:
            return {
                "vserver": _child_text(row, "arw_vserver"),
                "volume": _child_text(row, "arw_volume"),
                "state": _child_text(row, "arw_state"),
                "probability": probability,
                "timeline": _child_text(row, "li"),
                "detected_by": _child_text(row, "attack_detected_by"),
            }
    return {}


def _parse_high_entropy(xml_text: str) -> dict[str, str]:
    rows = _rows(xml_text)
    if not rows:
        return {}
    row = rows[0]
    return {
        "start_time": _child_text(row, "start_time"),
        "total_data_written": _child_text(row, "total_data_written"),
        "encryption_percentage": _child_text(row, "encryption_percentage"),
        "duration": _child_text(row, "duration_of_the_interval"),
    }


def _parse_daily_entropy(xml_text: str) -> list[dict[str, str]]:
    rows = []
    for row in _rows(xml_text):
        rows.append(
            {
                "start_time": _child_text(row, "start_time"),
                "total_data_written": _child_text(row, "total_data_written"),
                "encryption_percentage": _child_text(row, "encryption_percentage"),
                "duration_of_the_interval": _child_text(row, "duration_of_the_interval"),
            }
        )
    return rows


def _ems_refs(file_name: str, text: str) -> list[dict[str, str]]:
    refs = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if "callhome_arw_activity_seen" in line:
            refs.append({"file": file_name, "line_number": line_number, "line": line.strip()})
    if refs:
        return refs

    match = re.search(r"possible ransomware activity detected", text, re.IGNORECASE)
    if not match:
        return []
    start = max(0, match.start() - 80)
    end = min(len(text), match.end() + 80)
    return [{"file": file_name, "line": text[start:end].strip()}]


def _summary_item(name: str, value: object, **metadata: str) -> dict[str, object]:
    item: dict[str, object] = {"name": name, "value": value}
    item.update(metadata)
    return item


def parse_arw_evidence(files: dict[str, str]) -> EvidenceBundle:
    status = _parse_status(files.get("arw-vol-status.xml", ""))
    high_entropy = _parse_high_entropy(files.get("arw-high-entropy-stats.xml", ""))
    daily_entropy = _parse_daily_entropy(files.get("arw-daily-entropy-stats.xml", ""))

    summary: list[dict[str, object]] = []
    if status:
        summary.extend(
            [
                _summary_item("affected_volume", f"{status['vserver']} / {status['volume']}"),
                _summary_item("arw_state", status["state"]),
                _summary_item("attack_probability", status["probability"]),
                _summary_item("attack_timeline", status["timeline"]),
                _summary_item("attack_detected_by", status["detected_by"]),
            ]
        )

    if high_entropy:
        summary.append(
            _summary_item(
                "high_entropy_peak",
                f"{high_entropy['encryption_percentage']} over {high_entropy['duration']}",
                start_time=high_entropy["start_time"],
                total_data_written=high_entropy["total_data_written"],
            )
        )

    if daily_entropy:
        summary.append(_summary_item("daily_entropy_baseline", daily_entropy))

    raw_refs = []
    if "EMS-LOG-FILE.gz" in files:
        raw_refs = _ems_refs("EMS-LOG-FILE.gz", files["EMS-LOG-FILE.gz"])

    files_used = [{"file": name, "purpose": "arw evidence"} for name in files]
    return EvidenceBundle(summary=summary, files_used=files_used, raw_refs=raw_refs)
