from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Any

from .ai import build_messages, call_openai_compatible
from .archive import ArchiveReader
from .classifier import classify_message
from .email_body import parse_asup_body
from .formatters.telegram import build_notification
from .kb import build_kb_queries
from .models import AnalysisResult, EmailMessageInput, EvidenceBundle, KBQueryRule, OutputEnvelope
from .parsers.arw import parse_arw_evidence
from .parsers.panic import parse_panic_evidence
from .registry import RuleRegistry, load_registry_from_dir, load_registry_from_urls


def _select_files(reader: ArchiveReader, names: list[str], wanted: list[str]) -> dict[str, str]:
    selected: dict[str, str] = {}
    for file_glob in wanted:
        for name in names:
            basename = _archive_basename(name)
            if fnmatch.fnmatch(name, file_glob) or fnmatch.fnmatch(basename, file_glob):
                selected.setdefault(basename, reader.read_text(name))
    return selected


def _archive_basename(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def _load_registry_source(
    registry_dir: str | Path | None,
    registry_urls: dict[str, str] | None,
) -> RuleRegistry:
    if registry_urls is not None:
        missing = [key for key in ("rules", "evidence", "kb") if not registry_urls.get(key)]
        if missing:
            raise ValueError(f"Missing registry URL(s): {', '.join(missing)}")
        return load_registry_from_urls(
            registry_urls["rules"],
            registry_urls["evidence"],
            registry_urls["kb"],
        )
    return load_registry_from_dir(registry_dir or "data/rules")


def _analysis_from_ai(ai_data: dict[str, Any]) -> AnalysisResult:
    return AnalysisResult(
        status=str(ai_data.get("status", "unknown")),
        severity=str(ai_data.get("severity", "unknown")),
        confidence=float(ai_data.get("confidence", 0.0)),
        impacted_objects=list(ai_data.get("impacted_objects", [])),
        recommended_actions=list(ai_data.get("recommended_actions", [])),
        ai_error=None,
    )


def _evidence_context(evidence: EvidenceBundle) -> dict[str, object]:
    context: dict[str, object] = {}
    for item in evidence.summary:
        name = item.get("name")
        value = item.get("value")
        if isinstance(name, str) and isinstance(value, (str, int, float, bool)):
            context[name] = value
    return context


def _applicable_kb_rules(rules: list[KBQueryRule], context: dict[str, object]) -> list[KBQueryRule]:
    return [rule for rule in rules if rule.condition != "panic_string" or "panic_string" in context]


def run_manual(
    subject: str,
    attachment_path: str | Path,
    registry_dir: str | Path | None = "data/rules",
    ai_config: dict[str, str] | None = None,
    registry_urls: dict[str, str] | None = None,
    from_address: str | None = None,
    body_text: str | None = None,
    telegram_preview: bool = False,
) -> dict[str, Any]:
    warnings: list[str] = []
    errors: list[str] = []
    ai_config = ai_config or {}
    asup_metadata = parse_asup_body(body_text or "")

    registry = _load_registry_source(registry_dir, registry_urls)
    warnings.extend(registry.warnings)
    headers: dict[str, str] = {}
    classification = classify_message(subject, headers, registry)

    reader = ArchiveReader(attachment_path)
    names = reader.list_names()
    file_rules = registry.evidence_files.get(classification.matched_rule_id, [])
    files = _select_files(reader, names, [rule.file_glob for rule in file_rules])

    if classification.parser == "arw":
        evidence = parse_arw_evidence(files)
    elif classification.parser == "panic":
        evidence = parse_panic_evidence(files)
    else:
        evidence = EvidenceBundle(summary=[], files_used=[], raw_refs=[])

    matched_rule = None
    for rule in registry.rules:
        if rule.rule_id == classification.matched_rule_id:
            matched_rule = rule
            break
    question_direction = matched_rule.question_direction if matched_rule else ""

    analysis = AnalysisResult(
        status="ai_not_run",
        severity="unknown",
        confidence=0.0,
        impacted_objects=[],
        recommended_actions=[],
        ai_error={"reason": "AI provider config not supplied"},
    )

    base_url = ai_config.get("base_url") or os.environ.get("AI_PROVIDER_BASE_URL", "http://127.0.0.1:8000/v1")
    api_key = ai_config.get("api_key") or os.environ.get("AI_PROVIDER_API_KEY", "")
    model = ai_config.get("model") or os.environ.get("AI_PROVIDER_MODEL", "")
    if api_key and model:
        try:
            messages = build_messages(question_direction, evidence.to_dict())
            ai_data = call_openai_compatible(base_url, api_key, model, messages)
            analysis = _analysis_from_ai(ai_data)
        except Exception as exc:
            warnings.append(f"AI finalizer failed: {exc}")
    else:
        warnings.append("AI finalizer skipped because AI_PROVIDER_API_KEY or AI_PROVIDER_MODEL is missing")

    kb_context = _evidence_context(evidence)
    if matched_rule and matched_rule.header_trigger:
        kb_context["header_trigger"] = matched_rule.header_trigger
    kb_rules = _applicable_kb_rules(registry.kb_queries.get(classification.matched_rule_id, []), kb_context)
    kb_queries = build_kb_queries(kb_rules, kb_context)

    envelope = OutputEnvelope(
        message=EmailMessageInput(
            received_at=None,
            from_address=from_address,
            subject=subject,
            headers=headers,
            attachments=[str(attachment_path)],
        ),
        classification=classification,
        evidence=evidence,
        analysis=analysis,
        kb={"search_required": False, "queries": kb_queries, "results": []},
        warnings=warnings,
        errors=errors,
    )
    result = envelope.to_dict()
    if asup_metadata:
        result["asup_metadata"] = asup_metadata
    if telegram_preview or from_address or asup_metadata:
        result["notification"] = build_notification(
            result,
            from_address=from_address,
            asup_metadata=asup_metadata,
        )
    return result
