from __future__ import annotations

import csv
from io import StringIO
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.request import urlopen

from netapp_asup_alertcheck.models import EvidenceFileRule, KBQueryRule, Rule


TRUE_VALUES = {"true", "1", "yes", "y"}
URL_TIMEOUT_SECONDS = 10


@dataclass
class RuleRegistry:
    rules: list[Rule] = field(default_factory=list)
    evidence_files: dict[str, list[EvidenceFileRule]] = field(default_factory=dict)
    kb_queries: dict[str, list[KBQueryRule]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def load_registry_from_dir(root: str | Path) -> RuleRegistry:
    base = Path(root)
    return _load_registry(
        _read_path(base / "Rules.csv"),
        _read_path(base / "EvidenceFiles.csv"),
        _read_path(base / "KBQueries.csv"),
    )


def load_registry_from_urls(rules_url: str, evidence_url: str, kb_url: str) -> RuleRegistry:
    return _load_registry(
        _read_url(rules_url),
        _read_url(evidence_url),
        _read_url(kb_url),
    )


def _read_path(path: Path) -> tuple[str, str]:
    return path.name, path.read_text(encoding="utf-8")


def _read_url(url: str) -> tuple[str, str]:
    with urlopen(url, timeout=URL_TIMEOUT_SECONDS) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return Path(url).name, response.read().decode(charset)


def _load_registry(
    rules_csv: tuple[str, str],
    evidence_csv: tuple[str, str],
    kb_csv: tuple[str, str],
) -> RuleRegistry:
    warnings: list[str] = []
    rules = _load_rules(*rules_csv, warnings)
    evidence_files = _load_evidence_files(*evidence_csv, warnings)
    kb_queries = _load_kb_queries(*kb_csv, warnings)

    return RuleRegistry(
        rules=sorted(rules, key=lambda rule: rule.priority, reverse=True),
        evidence_files=evidence_files,
        kb_queries=kb_queries,
        warnings=warnings,
    )


def _load_rules(filename: str, csv_text: str, warnings: list[str]) -> list[Rule]:
    rules: list[Rule] = []
    for row_number, row in _iter_rows(csv_text):
        rule_id = _value(row, "rule_id")
        priority = _int_value(row, "priority")
        problems = []
        if not rule_id:
            problems.append("missing rule_id")
        if priority is None:
            problems.append("invalid priority")
        if problems:
            _warn(warnings, filename, row_number, problems)
            continue

        rules.append(
            Rule(
                rule_id=rule_id,
                enabled=_value(row, "enabled").lower() in TRUE_VALUES,
                priority=priority,
                subject_contains=_value(row, "subject_contains"),
                header_trigger=_value(row, "header_trigger"),
                alert_type=_value(row, "alert_type") or "unknown",
                parser=_value(row, "parser") or "generic",
                question_direction=_value(row, "question_direction"),
            )
        )
    return rules


def _load_evidence_files(
    filename: str,
    csv_text: str,
    warnings: list[str],
) -> dict[str, list[EvidenceFileRule]]:
    grouped: dict[str, list[EvidenceFileRule]] = {}
    for row_number, row in _iter_rows(csv_text):
        rule_id = _value(row, "rule_id")
        file_glob = _value(row, "file_glob")
        priority = _int_value(row, "priority")
        problems = []
        if not rule_id:
            problems.append("missing rule_id")
        if not file_glob:
            problems.append("missing file_glob")
        if priority is None:
            problems.append("invalid priority")
        if problems:
            _warn(warnings, filename, row_number, problems)
            continue

        grouped.setdefault(rule_id, []).append(
            EvidenceFileRule(
                rule_id=rule_id,
                file_glob=file_glob,
                priority=priority,
                purpose=_value(row, "purpose"),
                patterns=_split_patterns(_value(row, "patterns")),
            )
        )

    for evidence_files in grouped.values():
        evidence_files.sort(key=lambda evidence_file: evidence_file.priority)
    return grouped


def _load_kb_queries(filename: str, csv_text: str, warnings: list[str]) -> dict[str, list[KBQueryRule]]:
    grouped: dict[str, list[KBQueryRule]] = {}
    for row_number, row in _iter_rows(csv_text):
        rule_id = _value(row, "rule_id")
        query_template = _value(row, "query_template")
        problems = []
        if not rule_id:
            problems.append("missing rule_id")
        if not query_template:
            problems.append("missing query_template")
        if problems:
            _warn(warnings, filename, row_number, problems)
            continue

        grouped.setdefault(rule_id, []).append(
            KBQueryRule(
                rule_id=rule_id,
                condition=_value(row, "condition"),
                query_template=query_template,
            )
        )
    return grouped


def _iter_rows(csv_text: str) -> Iterable[tuple[int, dict[str, str]]]:
    reader = csv.DictReader(StringIO(csv_text))
    for index, row in enumerate(reader, start=2):
        yield index, row


def _value(row: dict[str, str], key: str) -> str:
    return (row.get(key) or "").strip()


def _int_value(row: dict[str, str], key: str) -> int | None:
    try:
        return int(_value(row, key))
    except ValueError:
        return None


def _split_patterns(patterns: str) -> list[str]:
    return [pattern.strip() for pattern in re.split(r"[,\n]", patterns) if pattern.strip()]


def _warn(warnings: list[str], filename: str, row_number: int, problems: list[str]) -> None:
    warnings.append(f"{filename} row {row_number}: {'; '.join(problems)}")
