from __future__ import annotations

import re

from .classifier import normalize_subject


P1_CONTAINS = [
    "PANIC",
    "(CLUSTER NETWORK DEGRADED)",
    "(HA INTERCONNECT DOWN)",
    "(NODE(S) OUT OF CLUSTER QUORUM)",
    "(SHELF_FAULT)",
    "(HEARTBEAT_LOSS)",
    "(SHELF POWER INTERRUPTED)",
    "POWER SUPPLY DEGRADED",
    "POWER SUPPLY OFF",
    "CHASSIS POWER DEGRADED",
]

P2_CONTAINS = [
    "(SPARES_LOW)",
    "(DISK REDUNDANCY FAILED)",
    "(OUT OF INODES)",
    "SINGLEPATH",
]

REBOOT_POWER_ON = "REBOOT (POWER ON)"
HA_GROUP_MARKER_RE = re.compile(r"HA\s+Group\s+Notification\s+from", re.IGNORECASE)


def _normalized_upper(subject: str) -> str:
    return normalize_subject(subject).upper()


def should_skip_email_analysis(subject: str) -> bool:
    return REBOOT_POWER_ON in _normalized_upper(subject)


def classify_priority(subject: str) -> str | None:
    normalized = _normalized_upper(subject)
    if REBOOT_POWER_ON in normalized:
        return None
    if any(signal in normalized for signal in P1_CONTAINS):
        return "P1"
    if any(signal in normalized for signal in P2_CONTAINS):
        return "P2"
    return None


def extract_event_title(subject: str) -> str:
    normalized = normalize_subject(subject)
    match = HA_GROUP_MARKER_RE.search(normalized)
    if not match:
        return normalized
    return normalized[match.end() :].strip()
