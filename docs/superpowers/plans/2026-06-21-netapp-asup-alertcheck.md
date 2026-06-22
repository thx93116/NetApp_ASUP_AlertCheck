# NetApp ASUP AlertCheck Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI pipeline that classifies NetApp AutoSupport alert emails, extracts targeted evidence from AutoSupport attachments, finalizes diagnosis through an OpenAI-compatible provider, and emits JSON.

**Architecture:** Use deterministic rule matching before AI. Load editable rules from spreadsheet-style CSV tables first, with the same interface ready for Google Sheet CSV/API input. Extract only rule-selected files from AutoSupport archives, parse known structures such as ARW XML, then pass compact evidence to the AI finalizer.

**Tech Stack:** Python standard library, `7z` CLI for `.7z`, `unittest`, `argparse`, `csv`, `json`, `xml.etree.ElementTree`, `zipfile`, `tarfile`, `gzip`, `urllib`.

---

## Scope And Boundaries

This plan delivers a working local CLI and testable library for manual input plus CSV/Google-Sheet-shaped registry input. Gmail credentials, Google Sheet link, and provider key are runtime configuration, so implementations must expose interfaces and clear errors without embedding secrets.

Git guard: current detected git top-level is `/Users/kmoo`, not `/Users/kmoo/Desktop/NetApp_ASUP_AlertCheck`. Before any commit step, run `rtk git rev-parse --show-toplevel`. Commit only if output is `/Users/kmoo/Desktop/NetApp_ASUP_AlertCheck`. If output differs, skip commit and record `rtk git status --short -- .`.

## File Structure

- Create `src/netapp_asup_alertcheck/__init__.py`: package marker and version.
- Create `src/netapp_asup_alertcheck/models.py`: dataclasses shared by registry, classification, evidence, and output.
- Create `src/netapp_asup_alertcheck/registry.py`: load and validate Rules, EvidenceFiles, KBQueries from CSV files or CSV URLs.
- Create `src/netapp_asup_alertcheck/classifier.py`: normalize subjects and select the highest-priority enabled rule.
- Create `src/netapp_asup_alertcheck/archive.py`: list and read selected files from `.7z`, `.zip`, `.tar`, `.tgz`, `.gz`.
- Create `src/netapp_asup_alertcheck/parsers/arw.py`: parse ARW-specific XML and EMS evidence.
- Create `src/netapp_asup_alertcheck/pipeline.py`: orchestrate manual-mode analysis.
- Create `src/netapp_asup_alertcheck/ai.py`: OpenAI-compatible chat completion call and strict JSON handling.
- Create `src/netapp_asup_alertcheck/kb.py`: build KB search queries and optional URL fetch seam.
- Create `src/netapp_asup_alertcheck/cli.py`: command-line entrypoint.
- Create `data/rules/Rules.csv`: editable seed rules.
- Create `data/rules/EvidenceFiles.csv`: editable seed evidence file map.
- Create `data/rules/KBQueries.csv`: editable seed KB query templates.
- Create `tests/fixtures/arw/`: XML and text fixtures copied from the sample evidence in reduced form.
- Create `tests/test_*.py`: focused unit tests for each module.

### Task 1: Project Skeleton

**Files:**
- Create: `src/netapp_asup_alertcheck/__init__.py`
- Create: `src/netapp_asup_alertcheck/parsers/__init__.py`
- Create: `tests/__init__.py`

- [ ] **Step 1: Create package directories**

Run:

```bash
mkdir -p src/netapp_asup_alertcheck/parsers tests
```

Expected: directories exist.

- [ ] **Step 2: Add package markers**

Create `src/netapp_asup_alertcheck/__init__.py`:

```python
"""NetApp AutoSupport alert classification and evidence extraction."""

__version__ = "0.1.0"
```

Create `src/netapp_asup_alertcheck/parsers/__init__.py`:

```python
"""Parser modules for known AutoSupport alert families."""
```

Create `tests/__init__.py`:

```python
"""Test package for NetApp ASUP AlertCheck."""
```

- [ ] **Step 3: Verify imports**

Run:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Expected: `Ran 0 tests` and `OK`.

- [ ] **Step 4: Git checkpoint**

Run:

```bash
rtk git rev-parse --show-toplevel
rtk git status --short -- .
```

Expected: commit only if top-level equals project path.

### Task 2: Shared Models

**Files:**
- Create: `src/netapp_asup_alertcheck/models.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write failing model serialization test**

Create `tests/test_models.py`:

```python
import unittest

from netapp_asup_alertcheck.models import (
    AnalysisResult,
    Classification,
    EmailMessageInput,
    EvidenceBundle,
    OutputEnvelope,
)


class ModelTests(unittest.TestCase):
    def test_output_envelope_serializes_to_expected_shape(self):
        envelope = OutputEnvelope(
            message=EmailMessageInput(
                received_at="2026-06-21T18:05:28+08:00",
                from_address="Kmuh_a20@kmuh.gov.tw",
                subject="[external] POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                headers={"X-Netapp-asup-hostname": "KMUH-Netapp-AFF-A20-01"},
                attachments=["body.7z"],
            ),
            classification=Classification(
                matched_rule_id="arw_activity_seen",
                alert_type="ransomware",
                parser="arw",
                confidence=0.96,
                matched_signals=["subject_contains", "header_trigger"],
            ),
            evidence=EvidenceBundle(summary=[], files_used=[], raw_refs=[]),
            analysis=AnalysisResult(
                status="possible_ransomware_activity_detected",
                severity="high",
                confidence=0.86,
                impacted_objects=[],
                recommended_actions=[],
                ai_error=None,
            ),
            kb={"search_required": False, "queries": [], "results": []},
            warnings=[],
            errors=[],
        )

        data = envelope.to_dict()

        self.assertEqual(data["message"]["from"], "Kmuh_a20@kmuh.gov.tw")
        self.assertEqual(data["classification"]["matched_rule_id"], "arw_activity_seen")
        self.assertEqual(data["analysis"]["severity"], "high")
        self.assertEqual(data["errors"], [])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_models -v
```

Expected: FAIL with `ModuleNotFoundError` or import error for `models`.

- [ ] **Step 3: Add models**

Create `src/netapp_asup_alertcheck/models.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class Rule:
    rule_id: str
    enabled: bool
    priority: int
    subject_contains: str
    header_trigger: str
    alert_type: str
    parser: str
    question_direction: str


@dataclass(frozen=True)
class EvidenceFileRule:
    rule_id: str
    file_glob: str
    priority: int
    purpose: str
    patterns: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class KBQueryRule:
    rule_id: str
    condition: str
    query_template: str


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class EvidenceBundle:
    summary: list[dict[str, Any]]
    files_used: list[dict[str, Any]]
    raw_refs: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": list(self.summary),
            "files_used": list(self.files_used),
            "raw_refs": list(self.raw_refs),
        }


@dataclass(frozen=True)
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
            "impacted_objects": list(self.impacted_objects),
            "recommended_actions": list(self.recommended_actions),
        }
        if self.ai_error is not None:
            data["ai_error"] = dict(self.ai_error)
        return data


@dataclass(frozen=True)
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
            "kb": dict(self.kb),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }
```

- [ ] **Step 4: Run test to verify pass**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_models -v
```

Expected: PASS.

### Task 3: CSV Rule Registry Loader

**Files:**
- Create: `src/netapp_asup_alertcheck/registry.py`
- Create: `data/rules/Rules.csv`
- Create: `data/rules/EvidenceFiles.csv`
- Create: `data/rules/KBQueries.csv`
- Test: `tests/test_registry.py`

- [ ] **Step 1: Write failing registry tests**

Create `tests/test_registry.py`:

```python
import tempfile
import unittest
from pathlib import Path

from netapp_asup_alertcheck.registry import RuleRegistry, load_registry_from_dir


class RegistryTests(unittest.TestCase):
    def test_load_registry_from_csv_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Rules.csv").write_text(
                "rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction\n"
                "arw_activity_seen,TRUE,100,POSSIBLE RANSOMWARE ACTIVITY DETECTED,callhome.arw.activity.seen,ransomware,arw,Confirm ARW evidence\n",
                encoding="utf-8",
            )
            (root / "EvidenceFiles.csv").write_text(
                "rule_id,file_glob,priority,purpose,patterns\n"
                "arw_activity_seen,EMS-LOG-FILE.gz,20,Callhome trigger,callhome_arw_activity_seen\n",
                encoding="utf-8",
            )
            (root / "KBQueries.csv").write_text(
                "rule_id,condition,query_template\n"
                "arw_activity_seen,ai_requests_kb,NetApp {header_trigger} {ontap_version}\n",
                encoding="utf-8",
            )

            registry = load_registry_from_dir(root)

        self.assertIsInstance(registry, RuleRegistry)
        self.assertEqual(registry.rules[0].rule_id, "arw_activity_seen")
        self.assertEqual(registry.evidence_files["arw_activity_seen"][0].file_glob, "EMS-LOG-FILE.gz")
        self.assertEqual(registry.kb_queries["arw_activity_seen"][0].condition, "ai_requests_kb")

    def test_invalid_rule_row_becomes_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Rules.csv").write_text(
                "rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction\n"
                ",TRUE,not_int,subject,trigger,type,parser,direction\n",
                encoding="utf-8",
            )
            (root / "EvidenceFiles.csv").write_text("rule_id,file_glob,priority,purpose,patterns\n", encoding="utf-8")
            (root / "KBQueries.csv").write_text("rule_id,condition,query_template\n", encoding="utf-8")

            registry = load_registry_from_dir(root)

        self.assertEqual(registry.rules, [])
        self.assertTrue(any("Rules.csv row 2" in warning for warning in registry.warnings))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_registry -v
```

Expected: FAIL with import error for `registry`.

- [ ] **Step 3: Add registry loader**

Create `src/netapp_asup_alertcheck/registry.py`:

```python
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.request import urlopen

from .models import EvidenceFileRule, KBQueryRule, Rule


@dataclass(frozen=True)
class RuleRegistry:
    rules: list[Rule]
    evidence_files: dict[str, list[EvidenceFileRule]]
    kb_queries: dict[str, list[KBQueryRule]]
    warnings: list[str] = field(default_factory=list)


def _bool(value: str) -> bool:
    return value.strip().lower() in {"true", "1", "yes", "y"}


def _split_patterns(value: str) -> list[str]:
    if not value:
        return []
    raw = value.replace("\n", ",").split(",")
    return [item.strip() for item in raw if item.strip()]


def _read_csv_path(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _read_csv_url(url: str) -> list[dict[str, str]]:
    with urlopen(url, timeout=30) as response:
        text = response.read().decode("utf-8-sig")
    return list(csv.DictReader(text.splitlines()))


def _group(items: Iterable[EvidenceFileRule | KBQueryRule]) -> dict[str, list]:
    grouped: dict[str, list] = {}
    for item in items:
        grouped.setdefault(item.rule_id, []).append(item)
    for values in grouped.values():
        values.sort(key=lambda item: getattr(item, "priority", 0))
    return grouped


def load_registry_from_dir(root: str | Path) -> RuleRegistry:
    root_path = Path(root)
    return _build_registry(
        rules_rows=_read_csv_path(root_path / "Rules.csv"),
        evidence_rows=_read_csv_path(root_path / "EvidenceFiles.csv"),
        kb_rows=_read_csv_path(root_path / "KBQueries.csv"),
    )


def load_registry_from_urls(rules_url: str, evidence_url: str, kb_url: str) -> RuleRegistry:
    return _build_registry(
        rules_rows=_read_csv_url(rules_url),
        evidence_rows=_read_csv_url(evidence_url),
        kb_rows=_read_csv_url(kb_url),
    )


def _build_registry(
    rules_rows: list[dict[str, str]],
    evidence_rows: list[dict[str, str]],
    kb_rows: list[dict[str, str]],
) -> RuleRegistry:
    warnings: list[str] = []
    rules: list[Rule] = []
    evidence: list[EvidenceFileRule] = []
    kb_queries: list[KBQueryRule] = []

    for index, row in enumerate(rules_rows, start=2):
        try:
            rule_id = row.get("rule_id", "").strip()
            if not rule_id:
                raise ValueError("rule_id is required")
            rules.append(
                Rule(
                    rule_id=rule_id,
                    enabled=_bool(row.get("enabled", "")),
                    priority=int(row.get("priority", "0").strip()),
                    subject_contains=row.get("subject_contains", "").strip(),
                    header_trigger=row.get("header_trigger", "").strip(),
                    alert_type=row.get("alert_type", "").strip() or "unknown",
                    parser=row.get("parser", "").strip() or "generic",
                    question_direction=row.get("question_direction", "").strip(),
                )
            )
        except Exception as exc:
            warnings.append(f"Rules.csv row {index}: {exc}")

    for index, row in enumerate(evidence_rows, start=2):
        try:
            rule_id = row.get("rule_id", "").strip()
            file_glob = row.get("file_glob", "").strip()
            if not rule_id or not file_glob:
                raise ValueError("rule_id and file_glob are required")
            evidence.append(
                EvidenceFileRule(
                    rule_id=rule_id,
                    file_glob=file_glob,
                    priority=int(row.get("priority", "0").strip()),
                    purpose=row.get("purpose", "").strip(),
                    patterns=_split_patterns(row.get("patterns", "")),
                )
            )
        except Exception as exc:
            warnings.append(f"EvidenceFiles.csv row {index}: {exc}")

    for index, row in enumerate(kb_rows, start=2):
        try:
            rule_id = row.get("rule_id", "").strip()
            template = row.get("query_template", "").strip()
            if not rule_id or not template:
                raise ValueError("rule_id and query_template are required")
            kb_queries.append(
                KBQueryRule(
                    rule_id=rule_id,
                    condition=row.get("condition", "").strip(),
                    query_template=template,
                )
            )
        except Exception as exc:
            warnings.append(f"KBQueries.csv row {index}: {exc}")

    rules.sort(key=lambda rule: rule.priority, reverse=True)
    return RuleRegistry(
        rules=rules,
        evidence_files=_group(evidence),
        kb_queries=_group(kb_queries),
        warnings=warnings,
    )
```

- [ ] **Step 4: Add seed CSV files**

Create `data/rules/Rules.csv`:

```csv
rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction
arw_activity_seen,TRUE,100,POSSIBLE RANSOMWARE ACTIVITY DETECTED,callhome.arw.activity.seen,ransomware,arw,"Confirm whether ARW detected possible ransomware activity, affected SVM/volume, probability, time, detection reason, and entropy evidence."
```

Create `data/rules/EvidenceFiles.csv`:

```csv
rule_id,file_glob,priority,purpose,patterns
arw_activity_seen,X-HEADER-DATA.TXT,10,AutoSupport metadata,
arw_activity_seen,EMS-LOG-FILE.gz,20,Callhome trigger and affected object,callhome_arw_activity_seen
arw_activity_seen,arw-vol-status.xml,30,"ARW state, probability, timeline",
arw_activity_seen,arw-high-entropy-stats.xml,40,High entropy spike evidence,
arw_activity_seen,arw-daily-entropy-stats.xml,50,Baseline comparison,
```

Create `data/rules/KBQueries.csv`:

```csv
rule_id,condition,query_template
arw_activity_seen,ai_requests_kb,NetApp {header_trigger} {ontap_version}
arw_activity_seen,low_confidence,NetApp ARW {attack_detected_by}
```

- [ ] **Step 5: Run registry tests**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_registry -v
```

Expected: PASS.

### Task 4: Subject And Header Classifier

**Files:**
- Create: `src/netapp_asup_alertcheck/classifier.py`
- Test: `tests/test_classifier.py`

- [ ] **Step 1: Write failing classifier tests**

Create `tests/test_classifier.py`:

```python
import unittest

from netapp_asup_alertcheck.classifier import classify_message, normalize_subject
from netapp_asup_alertcheck.models import Rule
from netapp_asup_alertcheck.registry import RuleRegistry


class ClassifierTests(unittest.TestCase):
    def test_normalize_subject_removes_external_markers(self):
        subject = "[\u2757\ufe0f\u5916\u90e8\u2757\ufe0f] HA Group Notification (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT"
        self.assertEqual(
            normalize_subject(subject),
            "HA Group Notification (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT",
        )

    def test_classify_uses_subject_and_header_trigger(self):
        registry = RuleRegistry(
            rules=[
                Rule(
                    rule_id="arw_activity_seen",
                    enabled=True,
                    priority=100,
                    subject_contains="POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                    header_trigger="callhome.arw.activity.seen",
                    alert_type="ransomware",
                    parser="arw",
                    question_direction="Confirm ARW evidence",
                )
            ],
            evidence_files={},
            kb_queries={},
        )

        classification = classify_message(
            "[External] HA Group Notification (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT",
            {"trigger": "callhome.arw.activity.seen"},
            registry,
        )

        self.assertEqual(classification.matched_rule_id, "arw_activity_seen")
        self.assertEqual(classification.parser, "arw")
        self.assertIn("subject_contains", classification.matched_signals)
        self.assertIn("header_trigger", classification.matched_signals)

    def test_unknown_subject_uses_generic(self):
        registry = RuleRegistry(rules=[], evidence_files={}, kb_queries={})
        classification = classify_message("UNRECOGNIZED ALERT", {}, registry)
        self.assertEqual(classification.matched_rule_id, "generic_autosupport")
        self.assertEqual(classification.parser, "generic")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_classifier -v
```

Expected: FAIL with import error for `classifier`.

- [ ] **Step 3: Add classifier**

Create `src/netapp_asup_alertcheck/classifier.py`:

```python
from __future__ import annotations

import re

from .models import Classification
from .registry import RuleRegistry

EXTERNAL_MARKERS = (
    r"^\s*\[External\]\s*",
    r"^\s*\[EXT\]\s*",
    r"^\s*\[\u5916\u90e8\]\s*",
    r"^\s*\[\u2757\ufe0f\u5916\u90e8\u2757\ufe0f\]\s*",
)


def normalize_subject(subject: str) -> str:
    normalized = subject.strip()
    changed = True
    while changed:
        changed = False
        for pattern in EXTERNAL_MARKERS:
            next_value = re.sub(pattern, "", normalized, flags=re.IGNORECASE)
            if next_value != normalized:
                normalized = next_value.strip()
                changed = True
    return normalized


def _header_values(headers: dict[str, str]) -> str:
    return "\n".join(str(value) for value in headers.values())


def classify_message(subject: str, headers: dict[str, str], registry: RuleRegistry) -> Classification:
    normalized_subject = normalize_subject(subject)
    header_blob = _header_values(headers)

    for rule in registry.rules:
        if not rule.enabled:
            continue
        signals: list[str] = []
        if rule.subject_contains and rule.subject_contains.lower() in normalized_subject.lower():
            signals.append("subject_contains")
        if rule.header_trigger and rule.header_trigger.lower() in header_blob.lower():
            signals.append("header_trigger")
        if signals:
            confidence = 0.96 if len(signals) >= 2 else 0.72
            return Classification(
                matched_rule_id=rule.rule_id,
                alert_type=rule.alert_type,
                parser=rule.parser,
                confidence=confidence,
                matched_signals=signals,
            )

    return Classification(
        matched_rule_id="generic_autosupport",
        alert_type="unknown",
        parser="generic",
        confidence=0.25,
        matched_signals=[],
    )
```

- [ ] **Step 4: Run classifier tests**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_classifier -v
```

Expected: PASS.

### Task 5: Archive Reader

**Files:**
- Create: `src/netapp_asup_alertcheck/archive.py`
- Test: `tests/test_archive.py`

- [ ] **Step 1: Write failing archive tests**

Create `tests/test_archive.py`:

```python
import gzip
import tempfile
import unittest
import zipfile
from pathlib import Path

from netapp_asup_alertcheck.archive import ArchiveReader


class ArchiveReaderTests(unittest.TestCase):
    def test_zip_manifest_and_read_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "body.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("X-HEADER-DATA.TXT", "X-Netapp-asup-hostname: node1\n")

            reader = ArchiveReader(archive_path)

            self.assertEqual(reader.list_names(), ["X-HEADER-DATA.TXT"])
            self.assertEqual(reader.read_text("X-HEADER-DATA.TXT"), "X-Netapp-asup-hostname: node1\n")

    def test_gzip_member_decodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "EMS-LOG-FILE.gz"
            with gzip.open(archive_path, "wt", encoding="utf-8") as handle:
                handle.write("callhome_arw_activity_seen\n")

            reader = ArchiveReader(archive_path)

            self.assertEqual(reader.list_names(), ["EMS-LOG-FILE"])
            self.assertEqual(reader.read_text("EMS-LOG-FILE"), "callhome_arw_activity_seen\n")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_archive -v
```

Expected: FAIL with import error for `archive`.

- [ ] **Step 3: Add archive reader**

Create `src/netapp_asup_alertcheck/archive.py`:

```python
from __future__ import annotations

import gzip
import subprocess
import tarfile
import zipfile
from pathlib import Path


class ArchiveError(RuntimeError):
    pass


class ArchiveReader:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.exists():
            raise ArchiveError(f"archive not found: {self.path}")

    @property
    def suffix(self) -> str:
        name = self.path.name.lower()
        if name.endswith(".tar.gz") or name.endswith(".tgz"):
            return ".tgz"
        return self.path.suffix.lower()

    def list_names(self) -> list[str]:
        if self.suffix == ".zip":
            with zipfile.ZipFile(self.path) as archive:
                return archive.namelist()
        if self.suffix == ".tgz" or self.suffix == ".tar":
            with tarfile.open(self.path) as archive:
                return [member.name for member in archive.getmembers() if member.isfile()]
        if self.suffix == ".gz":
            return [self.path.name.removesuffix(".gz")]
        if self.suffix == ".7z":
            return self._list_7z()
        raise ArchiveError(f"unsupported archive type: {self.path}")

    def read_text(self, name: str) -> str:
        if self.suffix == ".zip":
            with zipfile.ZipFile(self.path) as archive:
                return archive.read(name).decode("utf-8", errors="replace")
        if self.suffix == ".tgz" or self.suffix == ".tar":
            with tarfile.open(self.path) as archive:
                member = archive.extractfile(name)
                if member is None:
                    raise ArchiveError(f"archive member not readable: {name}")
                return member.read().decode("utf-8", errors="replace")
        if self.suffix == ".gz":
            expected = self.path.name.removesuffix(".gz")
            if name != expected:
                raise ArchiveError(f"gzip archive contains {expected}, not {name}")
            with gzip.open(self.path, "rt", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        if self.suffix == ".7z":
            data = subprocess.check_output(["7z", "x", "-so", str(self.path), name])
            if name.lower().endswith(".gz"):
                return gzip.decompress(data).decode("utf-8", errors="replace")
            return data.decode("utf-8", errors="replace")
        raise ArchiveError(f"unsupported archive type: {self.path}")

    def _list_7z(self) -> list[str]:
        output = subprocess.check_output(["7z", "l", "-slt", str(self.path)], text=True)
        names: list[str] = []
        for line in output.splitlines():
            if line.startswith("Path = ") and not line.endswith(str(self.path)):
                names.append(line.removeprefix("Path = ").strip())
        return [name for name in names if name]
```

- [ ] **Step 4: Run archive tests**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_archive -v
```

Expected: PASS.

### Task 6: ARW Parser

**Files:**
- Create: `src/netapp_asup_alertcheck/parsers/arw.py`
- Create: `tests/fixtures/arw/arw-vol-status.xml`
- Create: `tests/fixtures/arw/arw-high-entropy-stats.xml`
- Create: `tests/fixtures/arw/arw-daily-entropy-stats.xml`
- Create: `tests/fixtures/arw/EMS-LOG-FILE.txt`
- Test: `tests/test_arw_parser.py`

- [ ] **Step 1: Add reduced ARW fixtures**

Create `tests/fixtures/arw/arw-vol-status.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<T_ARW_VOL_STATUS>
  <asup:ROW xmlns:asup="http://asup_search.netapp.com/ns/ASUP/1.1">
    <arw_vserver>ISCSI-SVM</arw_vserver>
    <arw_volume>Netapp_A20_LUN00</arw_volume>
    <arw_state>enabled</arw_state>
    <attack_probability>moderate</attack_probability>
    <attack_timeline><asup:list><asup:li>6/12/2026 17:53:41</asup:li></asup:list></attack_timeline>
    <attack_detected_by>encryption_percentage_analysis</attack_detected_by>
  </asup:ROW>
</T_ARW_VOL_STATUS>
```

Create `tests/fixtures/arw/arw-high-entropy-stats.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<T_ARW_HIGH_ENTROPY_STAT>
  <asup:ROW xmlns:asup="http://asup_search.netapp.com/ns/ASUP/1.1">
    <arw_vserver>ISCSI-SVM</arw_vserver>
    <arw_volume>Netapp_A20_LUN00</arw_volume>
    <start_time>6/12/2026 17:53:41</start_time>
    <total_data_written>46231420928</total_data_written>
    <encryption_percentage>75%</encryption_percentage>
    <duration_of_the_interval>0h10m0s</duration_of_the_interval>
  </asup:ROW>
</T_ARW_HIGH_ENTROPY_STAT>
```

Create `tests/fixtures/arw/arw-daily-entropy-stats.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<T_ARW_DAILY_ENTROPY_STAT>
  <asup:ROW xmlns:asup="http://asup_search.netapp.com/ns/ASUP/1.1">
    <arw_vserver>ISCSI-SVM</arw_vserver>
    <arw_volume>Netapp_A20_LUN00</arw_volume>
    <start_time>6/10/2026 18:23:41</start_time>
    <total_data_written>846912970752</total_data_written>
    <encryption_percentage>1%</encryption_percentage>
    <duration_of_the_interval>23h0m0s</duration_of_the_interval>
  </asup:ROW>
  <asup:ROW xmlns:asup="http://asup_search.netapp.com/ns/ASUP/1.1">
    <arw_vserver>ISCSI-SVM</arw_vserver>
    <arw_volume>Netapp_A20_LUN00</arw_volume>
    <start_time>6/12/2026 16:23:41</start_time>
    <total_data_written>778404864000</total_data_written>
    <encryption_percentage>7%</encryption_percentage>
    <duration_of_the_interval>23h0m0s</duration_of_the_interval>
  </asup:ROW>
</T_ARW_DAILY_ENTROPY_STAT>
```

Create `tests/fixtures/arw/EMS-LOG-FILE.txt`:

```text
<callhome_arw_activity_seen_1 subject="POSSIBLE RANSOMWARE ACTIVITY DETECTED" volName="Netapp_A20_LUN00" volUuid="c0329212-4d5d-11f1-91bb-d039eaef0cf1" vserverName="ISCSI-SVM"/>
```

- [ ] **Step 2: Write failing ARW parser test**

Create `tests/test_arw_parser.py`:

```python
import unittest
from pathlib import Path

from netapp_asup_alertcheck.parsers.arw import parse_arw_evidence


FIXTURE = Path(__file__).parent / "fixtures" / "arw"


class ArwParserTests(unittest.TestCase):
    def test_parse_arw_evidence(self):
        files = {
            "arw-vol-status.xml": (FIXTURE / "arw-vol-status.xml").read_text(encoding="utf-8"),
            "arw-high-entropy-stats.xml": (FIXTURE / "arw-high-entropy-stats.xml").read_text(encoding="utf-8"),
            "arw-daily-entropy-stats.xml": (FIXTURE / "arw-daily-entropy-stats.xml").read_text(encoding="utf-8"),
            "EMS-LOG-FILE.gz": (FIXTURE / "EMS-LOG-FILE.txt").read_text(encoding="utf-8"),
        }

        bundle = parse_arw_evidence(files)
        summary = {item["name"]: item["value"] for item in bundle.summary}

        self.assertEqual(summary["affected_volume"], "ISCSI-SVM / Netapp_A20_LUN00")
        self.assertEqual(summary["attack_probability"], "moderate")
        self.assertEqual(summary["attack_detected_by"], "encryption_percentage_analysis")
        self.assertEqual(summary["high_entropy_peak"], "75% over 0h10m0s")
        self.assertTrue(any(ref["file"] == "EMS-LOG-FILE.gz" for ref in bundle.raw_refs))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_arw_parser -v
```

Expected: FAIL with import error for `parse_arw_evidence`.

- [ ] **Step 4: Add ARW parser**

Create `src/netapp_asup_alertcheck/parsers/arw.py`:

```python
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..models import EvidenceBundle


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(row: ET.Element, name: str) -> str:
    for child in row.iter():
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _rows(xml_text: str) -> list[ET.Element]:
    if not xml_text.strip():
        return []
    root = ET.fromstring(xml_text)
    return [element for element in root.iter() if _local(element.tag) == "ROW"]


def _parse_status(xml_text: str) -> dict[str, str]:
    rows = _rows(xml_text)
    for row in rows:
        probability = _child_text(row, "attack_probability")
        if probability:
            timeline = _child_text(row, "li")
            return {
                "vserver": _child_text(row, "arw_vserver"),
                "volume": _child_text(row, "arw_volume"),
                "state": _child_text(row, "arw_state"),
                "probability": probability,
                "timeline": timeline,
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


def _parse_daily(xml_text: str) -> list[dict[str, str]]:
    daily: list[dict[str, str]] = []
    for row in _rows(xml_text):
        daily.append(
            {
                "start_time": _child_text(row, "start_time"),
                "encryption_percentage": _child_text(row, "encryption_percentage"),
                "total_data_written": _child_text(row, "total_data_written"),
            }
        )
    return daily


def _ems_refs(text: str) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for line in text.splitlines():
        if "callhome_arw_activity_seen" in line:
            refs.append({"file": "EMS-LOG-FILE.gz", "line": line.strip()})
    if refs:
        return refs
    match = re.search(r"POSSIBLE RANSOMWARE ACTIVITY DETECTED", text, re.IGNORECASE)
    if match:
        return [{"file": "EMS-LOG-FILE.gz", "line": text[max(0, match.start() - 80): match.end() + 80]}]
    return []


def parse_arw_evidence(files: dict[str, str]) -> EvidenceBundle:
    status = _parse_status(files.get("arw-vol-status.xml", ""))
    high = _parse_high_entropy(files.get("arw-high-entropy-stats.xml", ""))
    daily = _parse_daily(files.get("arw-daily-entropy-stats.xml", ""))
    ems = files.get("EMS-LOG-FILE.gz", "")

    summary = []
    if status:
        summary.extend(
            [
                {"name": "affected_volume", "value": f"{status['vserver']} / {status['volume']}"},
                {"name": "arw_state", "value": status["state"]},
                {"name": "attack_probability", "value": status["probability"]},
                {"name": "attack_timeline", "value": status["timeline"]},
                {"name": "attack_detected_by", "value": status["detected_by"]},
            ]
        )
    if high:
        summary.append(
            {
                "name": "high_entropy_peak",
                "value": f"{high['encryption_percentage']} over {high['duration']}",
                "start_time": high["start_time"],
                "total_data_written": high["total_data_written"],
            }
        )
    if daily:
        summary.append({"name": "daily_entropy_baseline", "value": daily})

    files_used = [{"file": name, "purpose": "arw evidence"} for name in files]
    return EvidenceBundle(summary=summary, files_used=files_used, raw_refs=_ems_refs(ems))
```

- [ ] **Step 5: Run ARW parser tests**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_arw_parser -v
```

Expected: PASS.

### Task 7: AI Finalizer

**Files:**
- Create: `src/netapp_asup_alertcheck/ai.py`
- Test: `tests/test_ai.py`

- [ ] **Step 1: Write failing AI tests**

Create `tests/test_ai.py`:

```python
import unittest

from netapp_asup_alertcheck.ai import build_messages, parse_ai_json


class AiTests(unittest.TestCase):
    def test_build_messages_contains_evidence_and_json_instruction(self):
        messages = build_messages(
            question_direction="Confirm ARW evidence",
            evidence={"summary": [{"name": "attack_probability", "value": "moderate"}]},
        )

        self.assertEqual(messages[0]["role"], "system")
        self.assertIn("strict JSON", messages[0]["content"])
        self.assertIn("attack_probability", messages[1]["content"])

    def test_parse_ai_json_rejects_non_object(self):
        with self.assertRaises(ValueError):
            parse_ai_json("[1, 2, 3]")

    def test_parse_ai_json_accepts_object(self):
        result = parse_ai_json('{"status":"possible","severity":"high","confidence":0.8}')
        self.assertEqual(result["severity"], "high")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_ai -v
```

Expected: FAIL with import error for `ai`.

- [ ] **Step 3: Add AI module**

Create `src/netapp_asup_alertcheck/ai.py`:

```python
from __future__ import annotations

import json
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


def build_messages(question_direction: str, evidence: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": (
                "You analyze NetApp AutoSupport evidence. Return strict JSON only. "
                "Do not claim facts not present in evidence. Include status, severity, "
                "confidence, impacted_objects, recommended_actions, kb_search_required, "
                "and kb_search_queries."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {"question_direction": question_direction, "evidence": evidence},
                ensure_ascii=False,
                sort_keys=True,
            ),
        },
    ]


def parse_ai_json(text: str) -> dict[str, Any]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("AI response must be a JSON object")
    return data


def call_openai_compatible(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    timeout: int = 60,
) -> dict[str, Any]:
    if not api_key:
        raise ValueError("AI_PROVIDER_API_KEY is required")
    if not model:
        raise ValueError("AI_PROVIDER_MODEL is required")
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        raise RuntimeError(f"AI provider request failed: {exc}") from exc

    content = body["choices"][0]["message"]["content"]
    return parse_ai_json(content)
```

- [ ] **Step 4: Run AI tests**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_ai -v
```

Expected: PASS.

### Task 8: KB Query Builder

**Files:**
- Create: `src/netapp_asup_alertcheck/kb.py`
- Test: `tests/test_kb.py`

- [ ] **Step 1: Write failing KB tests**

Create `tests/test_kb.py`:

```python
import unittest

from netapp_asup_alertcheck.kb import build_kb_queries
from netapp_asup_alertcheck.models import KBQueryRule


class KbTests(unittest.TestCase):
    def test_build_kb_queries_formats_available_context(self):
        rules = [
            KBQueryRule(
                rule_id="arw_activity_seen",
                condition="ai_requests_kb",
                query_template="NetApp {header_trigger} {ontap_version}",
            )
        ]
        context = {
            "header_trigger": "callhome.arw.activity.seen",
            "ontap_version": "9.18.1P2",
        }

        self.assertEqual(
            build_kb_queries(rules, context),
            ["NetApp callhome.arw.activity.seen 9.18.1P2"],
        )

    def test_missing_context_keeps_token_readable(self):
        rules = [KBQueryRule("arw", "low_confidence", "NetApp {missing}")]
        self.assertEqual(build_kb_queries(rules, {}), ["NetApp missing"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_kb -v
```

Expected: FAIL with import error for `kb`.

- [ ] **Step 3: Add KB module**

Create `src/netapp_asup_alertcheck/kb.py`:

```python
from __future__ import annotations

import re

from .models import KBQueryRule


TOKEN_PATTERN = re.compile(r"\{([^{}]+)\}")


def build_kb_queries(rules: list[KBQueryRule], context: dict[str, object]) -> list[str]:
    queries: list[str] = []
    for rule in rules:
        query = rule.query_template
        for token in TOKEN_PATTERN.findall(rule.query_template):
            value = str(context.get(token, token)).strip()
            query = query.replace("{" + token + "}", value)
        normalized = " ".join(query.split())
        if normalized and normalized not in queries:
            queries.append(normalized)
    return queries
```

- [ ] **Step 4: Run KB tests**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_kb -v
```

Expected: PASS.

### Task 9: Manual Pipeline

**Files:**
- Create: `src/netapp_asup_alertcheck/pipeline.py`
- Test: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing pipeline test**

Create `tests/test_pipeline.py`:

```python
import tempfile
import unittest
import zipfile
from pathlib import Path

from netapp_asup_alertcheck.pipeline import run_manual


class PipelineTests(unittest.TestCase):
    def test_run_manual_returns_arw_json_without_ai_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules"
            rules.mkdir()
            (rules / "Rules.csv").write_text(
                "rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction\n"
                "arw_activity_seen,TRUE,100,POSSIBLE RANSOMWARE ACTIVITY DETECTED,callhome.arw.activity.seen,ransomware,arw,Confirm ARW evidence\n",
                encoding="utf-8",
            )
            (rules / "EvidenceFiles.csv").write_text(
                "rule_id,file_glob,priority,purpose,patterns\n"
                "arw_activity_seen,arw-vol-status.xml,30,ARW status,\n",
                encoding="utf-8",
            )
            (rules / "KBQueries.csv").write_text(
                "rule_id,condition,query_template\n"
                "arw_activity_seen,ai_requests_kb,NetApp {header_trigger}\n",
                encoding="utf-8",
            )
            archive_path = root / "body.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "arw-vol-status.xml",
                    "<root><ROW><arw_vserver>svm</arw_vserver><arw_volume>vol</arw_volume>"
                    "<arw_state>enabled</arw_state><attack_probability>moderate</attack_probability>"
                    "<attack_detected_by>encryption_percentage_analysis</attack_detected_by></ROW></root>",
                )

            result = run_manual(
                subject="POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                attachment_path=archive_path,
                registry_dir=rules,
                ai_config={},
            )

        self.assertEqual(result["classification"]["matched_rule_id"], "arw_activity_seen")
        self.assertEqual(result["analysis"]["status"], "ai_not_run")
        self.assertTrue(result["warnings"])
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_pipeline -v
```

Expected: FAIL with import error for `pipeline`.

- [ ] **Step 3: Add pipeline**

Create `src/netapp_asup_alertcheck/pipeline.py`:

```python
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .ai import build_messages, call_openai_compatible
from .archive import ArchiveReader
from .classifier import classify_message
from .kb import build_kb_queries
from .models import AnalysisResult, EmailMessageInput, EvidenceBundle, OutputEnvelope
from .parsers.arw import parse_arw_evidence
from .registry import load_registry_from_dir


def _select_files(reader: ArchiveReader, names: list[str], wanted: list[str]) -> dict[str, str]:
    selected: dict[str, str] = {}
    for file_glob in wanted:
        for name in names:
            if name == file_glob:
                selected[name] = reader.read_text(name)
    return selected


def _analysis_from_ai(ai_data: dict[str, Any]) -> AnalysisResult:
    return AnalysisResult(
        status=str(ai_data.get("status", "unknown")),
        severity=str(ai_data.get("severity", "unknown")),
        confidence=float(ai_data.get("confidence", 0.0)),
        impacted_objects=list(ai_data.get("impacted_objects", [])),
        recommended_actions=list(ai_data.get("recommended_actions", [])),
        ai_error=None,
    )


def run_manual(
    subject: str,
    attachment_path: str | Path,
    registry_dir: str | Path,
    ai_config: dict[str, str] | None = None,
) -> dict[str, Any]:
    warnings: list[str] = []
    errors: list[str] = []
    ai_config = ai_config or {}

    registry = load_registry_from_dir(registry_dir)
    warnings.extend(registry.warnings)
    headers: dict[str, str] = {}
    classification = classify_message(subject, headers, registry)

    reader = ArchiveReader(attachment_path)
    names = reader.list_names()
    file_rules = registry.evidence_files.get(classification.matched_rule_id, [])
    files = _select_files(reader, names, [rule.file_glob for rule in file_rules])

    if classification.parser == "arw":
        evidence = parse_arw_evidence(files)
    else:
        evidence = EvidenceBundle(summary=[], files_used=[], raw_refs=[])

    question_direction = ""
    for rule in registry.rules:
        if rule.rule_id == classification.matched_rule_id:
            question_direction = rule.question_direction
            break

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

    kb_rules = registry.kb_queries.get(classification.matched_rule_id, [])
    kb_queries = build_kb_queries(kb_rules, {"header_trigger": "", "ontap_version": ""})

    envelope = OutputEnvelope(
        message=EmailMessageInput(
            received_at=None,
            from_address=None,
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
    return envelope.to_dict()
```

- [ ] **Step 4: Run pipeline tests**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_pipeline -v
```

Expected: PASS.

### Task 10: CLI

**Files:**
- Create: `src/netapp_asup_alertcheck/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write failing CLI smoke test**

Create `tests/test_cli.py`:

```python
import os
import subprocess
import sys
import unittest


class CliTests(unittest.TestCase):
    def test_cli_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "netapp_asup_alertcheck.cli", "--help"],
            env={**os.environ, "PYTHONPATH": "src"},
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("manual", result.stdout)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_cli -v
```

Expected: FAIL because CLI module does not exist.

- [ ] **Step 3: Add CLI**

Create `src/netapp_asup_alertcheck/cli.py`:

```python
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pipeline import run_manual


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netapp-asup-alertcheck")
    subparsers = parser.add_subparsers(dest="command", required=True)

    manual = subparsers.add_parser("manual", help="Analyze one subject and local AutoSupport attachment")
    manual.add_argument("--subject", required=True)
    manual.add_argument("--attachment", required=True)
    manual.add_argument("--registry-dir", default="data/rules")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "manual":
        result = run_manual(
            subject=args.subject,
            attachment_path=Path(args.attachment),
            registry_dir=Path(args.registry_dir),
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 1 if result.get("errors") else 0
    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run CLI tests**

Run:

```bash
PYTHONPATH=src python -m unittest tests.test_cli -v
```

Expected: PASS.

- [ ] **Step 5: Run CLI with sample archive**

Run:

```bash
PYTHONPATH=src python -m netapp_asup_alertcheck.cli manual \
  --subject "[❗️外部❗️] HA Group Notification from KMUH-Netapp-AFF-A20-01 (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT" \
  --attachment /Users/kmoo/Desktop/body.7z \
  --registry-dir data/rules
```

Expected: JSON output with `classification.matched_rule_id` equal to `arw_activity_seen`, warnings about missing AI provider config if env vars are absent, and no fatal errors.

### Task 11: Full Test Run And Documentation

**Files:**
- Create: `README.md`

- [ ] **Step 1: Add README**

Create `README.md`:

````markdown
# NetApp ASUP AlertCheck

Analyze NetApp AutoSupport alert emails by matching subject/header rules, extracting selected attachment evidence, and returning JSON for automation.

## Manual Run

```bash
PYTHONPATH=src python -m netapp_asup_alertcheck.cli manual \
  --subject "[❗️外部❗️] HA Group Notification from KMUH-Netapp-AFF-A20-01 (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT" \
  --attachment /Users/kmoo/Desktop/body.7z \
  --registry-dir data/rules
```

## AI Provider

Set these environment variables before AI finalization:

```bash
export AI_PROVIDER_BASE_URL="http://127.0.0.1:8000/v1"
export AI_PROVIDER_API_KEY="..."
export AI_PROVIDER_MODEL="..."
```

## Rule Registry

The editable registry uses three spreadsheet-shaped tables:

- `Rules.csv`
- `EvidenceFiles.csv`
- `KBQueries.csv`

These can be exported from Google Sheets or loaded from CSV URLs by the registry module.
````

- [ ] **Step 2: Run complete unit test suite**

Run:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Expected: all tests PASS.

- [ ] **Step 3: Run sample CLI**

Run:

```bash
PYTHONPATH=src python -m netapp_asup_alertcheck.cli manual \
  --subject "[❗️外部❗️] HA Group Notification from KMUH-Netapp-AFF-A20-01 (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT" \
  --attachment /Users/kmoo/Desktop/body.7z \
  --registry-dir data/rules
```

Expected: valid JSON on stdout. Confirm these fields:

- `classification.matched_rule_id`: `arw_activity_seen`
- `classification.parser`: `arw`
- `analysis.status`: `ai_not_run` when AI env vars are absent
- `errors`: empty list

- [ ] **Step 4: Git checkpoint**

Run:

```bash
rtk git rev-parse --show-toplevel
rtk git status --short -- .
```

Expected: if top-level equals `/Users/kmoo/Desktop/NetApp_ASUP_AlertCheck`, commit with:

```bash
rtk git add README.md data src tests docs/superpowers/plans/2026-06-21-netapp-asup-alertcheck.md
rtk git commit -m "feat: add NetApp ASUP alertcheck MVP"
```

If top-level is `/Users/kmoo`, do not commit from this workspace.

## Completion Checks

- [ ] `PYTHONPATH=src python -m unittest discover -s tests -v` passes.
- [ ] Manual CLI run with `/Users/kmoo/Desktop/body.7z` returns JSON.
- [ ] Missing AI provider config returns warning, not fatal error.
- [ ] Rule registry can be edited through CSV files shaped like Google Sheet tabs.
- [ ] No provider key or Gmail credential is committed.
