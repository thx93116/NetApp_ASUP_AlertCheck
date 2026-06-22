from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EmailMessageInput:
    received_at: str | None
    from_address: str | None
    subject: str
    headers: dict[str, str] = field(default_factory=dict)
    attachments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "received_at": self.received_at,
            "from": self.from_address,
            "subject": self.subject,
            "headers": dict(self.headers),
            "attachments": list(self.attachments),
        }


@dataclass
class Rule:
    rule_id: str
    enabled: bool
    priority: int
    subject_contains: str
    header_trigger: str
    alert_type: str
    parser: str
    question_direction: str


@dataclass
class EvidenceFileRule:
    rule_id: str
    file_glob: str
    priority: int
    purpose: str
    patterns: list[str] = field(default_factory=list)


@dataclass
class KBQueryRule:
    rule_id: str
    condition: str
    query_template: str


@dataclass
class Classification:
    matched_rule_id: str
    alert_type: str
    parser: str
    confidence: float
    matched_signals: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched_rule_id": self.matched_rule_id,
            "alert_type": self.alert_type,
            "parser": self.parser,
            "confidence": self.confidence,
            "matched_signals": list(self.matched_signals),
        }


@dataclass
class EvidenceBundle:
    summary: list[dict[str, Any]]
    files_used: list[dict[str, Any]]
    raw_refs: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": deepcopy(self.summary),
            "files_used": deepcopy(self.files_used),
            "raw_refs": deepcopy(self.raw_refs),
        }


@dataclass
class AnalysisResult:
    status: str
    severity: str
    confidence: float
    impacted_objects: list[dict[str, Any]]
    recommended_actions: list[str]
    ai_error: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "impacted_objects": deepcopy(self.impacted_objects),
            "recommended_actions": list(self.recommended_actions),
        }
        if self.ai_error is not None:
            data["ai_error"] = deepcopy(self.ai_error)
        return data


@dataclass
class OutputEnvelope:
    message: EmailMessageInput
    classification: Classification
    evidence: EvidenceBundle
    analysis: AnalysisResult
    kb: dict[str, Any]
    warnings: list[str]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message.to_dict(),
            "classification": self.classification.to_dict(),
            "evidence": self.evidence.to_dict(),
            "analysis": self.analysis.to_dict(),
            "kb": deepcopy(self.kb),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }
