from __future__ import annotations

import re
from typing import Mapping

from netapp_asup_alertcheck.models import Classification
from netapp_asup_alertcheck.registry import RuleRegistry


CONFIDENCE_MULTI_SIGNAL = 0.96
CONFIDENCE_SINGLE_SIGNAL = 0.72
CONFIDENCE_GENERIC = 0.25

EXTERNAL_MARKER_RE = re.compile(
    r"^\s*(?:"
    r"\[(?:External|EXT|External Sender|外部|外部郵件|❗️外部❗️)\]"
    r"|External\s*:"
    r"|CAUTION\s*[:\-]\s*External Email"
    r")",
    re.IGNORECASE,
)
PREFIX_SEPARATOR_RE = re.compile(r"^\s*[:\-]\s*")


def normalize_subject(subject: str) -> str:
    normalized = subject.strip()
    while True:
        without_marker = EXTERNAL_MARKER_RE.sub("", normalized, count=1)
        if without_marker == normalized:
            return normalized
        normalized = PREFIX_SEPARATOR_RE.sub("", without_marker, count=1).strip()


def classify_message(
    subject: str,
    headers: Mapping[str, str],
    registry: RuleRegistry,
) -> Classification:
    normalized_subject = normalize_subject(subject)
    normalized_subject_search = normalized_subject.lower()
    header_blob = "\n".join(str(value) for value in headers.values()).lower()

    for rule in registry.rules:
        if not rule.enabled:
            continue

        matched_signals: list[str] = []
        if rule.subject_contains and rule.subject_contains.lower() in normalized_subject_search:
            matched_signals.append("subject_contains")
        if rule.header_trigger and rule.header_trigger.lower() in header_blob:
            matched_signals.append("header_trigger")

        if matched_signals:
            return Classification(
                matched_rule_id=rule.rule_id,
                alert_type=rule.alert_type,
                parser=rule.parser,
                confidence=CONFIDENCE_MULTI_SIGNAL
                if len(matched_signals) >= 2
                else CONFIDENCE_SINGLE_SIGNAL,
                matched_signals=matched_signals,
            )

    return Classification(
        matched_rule_id="generic_autosupport",
        alert_type="unknown",
        parser="generic",
        confidence=CONFIDENCE_GENERIC,
        matched_signals=[],
    )
