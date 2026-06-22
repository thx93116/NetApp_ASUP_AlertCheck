# Telegram Notification Preview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a safe Telegram preview notification layer for NetApp ASUP AlertCheck without sending real Telegram messages.

**Architecture:** Keep notification code separate from analysis. The pipeline still builds the analysis JSON first, then optional metadata and notification formatters add top-level `asup_metadata` and `notification` blocks for manual preview and future email ingestion.

**Tech Stack:** Python standard library, `unittest`, existing CSV registry, existing CLI module.

---

## File Structure

- Create `src/netapp_asup_alertcheck/email_body.py`: parse ASUP email body key-value metadata.
- Create `src/netapp_asup_alertcheck/customer.py`: map sender domain to customer name.
- Create `src/netapp_asup_alertcheck/priority.py`: classify subject into P1/P2/no-send and expose email skip rules.
- Create `src/netapp_asup_alertcheck/formatters/__init__.py`: package marker.
- Create `src/netapp_asup_alertcheck/formatters/telegram.py`: build notification JSON and preview text.
- Modify `src/netapp_asup_alertcheck/pipeline.py`: accept optional sender/body text/telegram preview and attach notification output.
- Modify `src/netapp_asup_alertcheck/cli.py`: add `--from-address`, `--body-file`, `--telegram-preview`.
- Create tests for each new module and CLI/pipeline integration.

### Task 1: ASUP Body Parser

**Files:**
- Create: `src/netapp_asup_alertcheck/email_body.py`
- Test: `tests/test_email_body.py`

- [ ] **Step 1: Write failing test**

```python
from netapp_asup_alertcheck.email_body import parse_asup_body


def test_parse_asup_body_maps_known_fields():
    text = "GENERATED_ON=Mon Jun 22 13:25:32 +0800 2026\nBOOT_CLUSTERED='true'\n"
    result = parse_asup_body(text)
    assert result["generated_on"] == "Mon Jun 22 13:25:32 +0800 2026"
    assert result["boot_clustered"] == "true"
```

- [ ] **Step 2: Run red test**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_email_body -v`
Expected: import failure because `email_body.py` does not exist.

- [ ] **Step 3: Implement parser**

```python
KEY_MAP = {"GENERATED_ON": "generated_on", "VERSION": "version", "SYSTEM_ID": "system_id", "SERIAL_NUM": "serial_num", "HOSTNAME": "hostname", "SEQUENCE": "sequence", "PARTNER_SYSTEM_ID": "partner_system_id", "PARTNER_HOSTNAME": "partner_hostname", "BOOT_CLUSTERED": "boot_clustered"}

def parse_asup_body(text: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        mapped = KEY_MAP.get(key.strip().upper())
        if mapped:
            metadata[mapped] = _strip_quotes(value.strip())
    return metadata
```

- [ ] **Step 4: Run green test**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_email_body -v`
Expected: pass.

### Task 2: Customer Mapping

**Files:**
- Create: `src/netapp_asup_alertcheck/customer.py`
- Test: `tests/test_customer.py`

- [ ] **Step 1: Write failing tests**

```python
from netapp_asup_alertcheck.customer import customer_from_address


def test_customer_from_known_sender_domain():
    assert customer_from_address("autosupport@mail.realtek.com") == "RTK"


def test_customer_from_unknown_sender_domain():
    assert customer_from_address("autosupport@example.com") == "UNKNOWN"
```

- [ ] **Step 2: Run red test**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_customer -v`
Expected: import failure because `customer.py` does not exist.

- [ ] **Step 3: Implement domain mapping**

```python
DOMAIN_CUSTOMERS = {"realtek.com": "RTK", "mediatek.com": "MTK", "nuvoton.com": "NVTK", "innolux.com": "INX"}

def customer_from_address(address: str | None) -> str:
    domain = _extract_domain(address)
    for suffix, customer in DOMAIN_CUSTOMERS.items():
        if domain == suffix or domain.endswith("." + suffix):
            return customer
    return "UNKNOWN"
```

- [ ] **Step 4: Run green test**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_customer -v`
Expected: pass.

### Task 3: Priority and Event Title

**Files:**
- Create: `src/netapp_asup_alertcheck/priority.py`
- Test: `tests/test_priority.py`

- [ ] **Step 1: Write failing tests**

```python
from netapp_asup_alertcheck.priority import classify_priority, extract_event_title, should_skip_email_analysis


def test_panic_subject_is_p1():
    assert classify_priority("[外部] HA Group Notification from nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY") == "P1"


def test_reboot_power_on_is_skipped_for_email_mode():
    subject = "[外部] HA Group Notification from nbt1-12 (REBOOT (power on)) NOTICE"
    assert should_skip_email_analysis(subject) is True
    assert classify_priority(subject) is None
    assert extract_event_title(subject) == "nbt1-12 (REBOOT (power on)) NOTICE"
```

- [ ] **Step 2: Run red test**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_priority -v`
Expected: import failure because `priority.py` does not exist.

- [ ] **Step 3: Implement rules**

```python
P1_CONTAINS = ["PANIC", "(CLUSTER NETWORK DEGRADED)", "(HA INTERCONNECT DOWN)", "(NODE(S) OUT OF CLUSTER QUORUM)", "(SHELF_FAULT)", "(HEARTBEAT_LOSS)", "(SHELF POWER INTERRUPTED)", "POWER SUPPLY DEGRADED", "POWER SUPPLY OFF", "CHASSIS POWER DEGRADED"]
P2_CONTAINS = ["(SPARES_LOW)", "(DISK REDUNDANCY FAILED)", "(OUT OF INODES)", "SINGLEPATH"]

def classify_priority(subject: str) -> str | None:
    normalized = normalize_subject(subject).upper()
    if should_skip_email_analysis(subject):
        return None
    if any(token in normalized for token in P1_CONTAINS):
        return "P1"
    if any(token in normalized for token in P2_CONTAINS):
        return "P2"
    return None
```

- [ ] **Step 4: Run green test**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_priority -v`
Expected: pass.

### Task 4: Telegram Formatter

**Files:**
- Create: `src/netapp_asup_alertcheck/formatters/__init__.py`
- Create: `src/netapp_asup_alertcheck/formatters/telegram.py`
- Test: `tests/test_telegram_formatter.py`

- [ ] **Step 1: Write failing tests**

```python
from netapp_asup_alertcheck.formatters.telegram import build_notification


def test_build_notification_for_p1_panic():
    result = {"message": {"subject": "[外部] HA Group Notification from nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY", "from": "asup@mail.realtek.com"}, "classification": {"matched_rule_id": "node_panic_takeover_complete"}, "evidence": {"summary": [{"name": "node", "value": "nbt1-11"}, {"name": "partner_node", "value": "nbt1-12"}, {"name": "ontap_version", "value": "NetApp Release 9.16.1P11"}]}}
    notification = build_notification(result, asup_metadata={"generated_on": "Mon Jun 22 10:23:43 +0800 2026"})
    assert notification["customer"] == "RTK"
    assert notification["priority"] == "P1"
    assert notification["should_send"] is True
    assert "nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY" in notification["telegram_text"]
```

- [ ] **Step 2: Run red test**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_telegram_formatter -v`
Expected: import failure because formatter package does not exist.

- [ ] **Step 3: Implement formatter**

```python
def build_notification(result: dict[str, object], from_address: str | None = None, asup_metadata: dict[str, str] | None = None) -> dict[str, object]:
    subject = result["message"]["subject"]
    customer = customer_from_address(from_address or result["message"].get("from"))
    priority = classify_priority(subject)
    event_title = extract_event_title(subject)
    generated_on = (asup_metadata or {}).get("generated_on", "")
    should_send = priority is not None
    summary = _build_summary(result) if should_send else ""
    return {"customer": customer, "priority": priority, "should_send": should_send, "generated_on": generated_on, "event_title": event_title, "summary": summary, "telegram_text": _format_text(customer, priority, generated_on, event_title, summary) if should_send else ""}
```

- [ ] **Step 4: Run green test**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_telegram_formatter -v`
Expected: pass.

### Task 5: Pipeline and CLI Preview

**Files:**
- Modify: `src/netapp_asup_alertcheck/pipeline.py`
- Modify: `src/netapp_asup_alertcheck/cli.py`
- Test: `tests/test_pipeline.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

```python
def test_run_manual_can_add_notification_preview(...):
    result = run_manual(..., from_address="asup@mail.realtek.com", body_text="GENERATED_ON=Mon Jun 22 10:23:43 +0800 2026\n", telegram_preview=True)
    assert result["asup_metadata"]["generated_on"] == "Mon Jun 22 10:23:43 +0800 2026"
    assert result["notification"]["customer"] == "RTK"
    assert result["notification"]["priority"] == "P1"

def test_cli_passes_body_file_and_sender_to_pipeline(...):
    exit_code = main(["manual", "--subject", "...", "--attachment", "body.7z", "--from-address", "asup@mail.realtek.com", "--body-file", "body.txt", "--telegram-preview"])
    assert exit_code == 0
```

- [ ] **Step 2: Run red tests**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_pipeline tests.test_cli -v`
Expected: `run_manual` and CLI do not accept the new arguments yet.

- [ ] **Step 3: Implement pipeline and CLI args**

```python
def run_manual(..., from_address: str | None = None, body_text: str | None = None, telegram_preview: bool = False) -> dict[str, Any]:
    asup_metadata = parse_asup_body(body_text or "")
    envelope = OutputEnvelope(...)
    result = envelope.to_dict()
    if asup_metadata:
        result["asup_metadata"] = asup_metadata
    if telegram_preview or from_address or asup_metadata:
        result["notification"] = build_notification(result, from_address=from_address, asup_metadata=asup_metadata)
    return result
```

- [ ] **Step 4: Run green tests**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_pipeline tests.test_cli -v`
Expected: pass.

### Task 6: Final Verification and GitHub

**Files:**
- All modified files.

- [ ] **Step 1: Run full test suite**

Run: `rtk env PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v`
Expected: all tests pass.

- [ ] **Step 2: Inspect diff**

Run: `rtk git diff --stat`
Expected: only notification feature files and spec/plan changes.

- [ ] **Step 3: Commit and push**

Run: `rtk git add ...`
Run: `rtk git commit -m "Add Telegram notification preview"`
Run: `rtk git push`
Expected: remote `main` receives the commit.

## Self-Review

- Spec coverage: body metadata, customer mapping, subject extraction, priority, skip/no-send, notification JSON, Telegram preview format, manual CLI input are covered.
- Placeholder scan: no `TBD` or deferred implementation steps are used inside the executable scope. Telegram sending is intentionally outside this plan because the user has not provided bot token/chat ID yet.
- Type consistency: `asup_metadata`, `notification`, `generated_on`, `event_title`, `telegram_text`, `from_address`, and `body_text` are consistently named across tests and implementation.
