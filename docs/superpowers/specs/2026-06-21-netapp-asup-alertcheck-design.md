# NetApp ASUP AlertCheck Design

## Goal

Build an automation pipeline that reads NetApp AutoSupport alert emails, classifies the alert from subject and headers, extracts only the relevant AutoSupport attachment evidence, asks an OpenAI-compatible AI provider for final diagnosis, and returns machine-readable JSON for downstream automation.

The first runnable version supports manual test input with a subject and attachment path. The production version reads Gmail messages by received time, then processes each message subject, headers, body, and attachments.

## Provider Configuration

The AI provider uses an OpenAI-compatible API endpoint:

- Base URL: `http://127.0.0.1:8000/v1`
- API key source: `AI_PROVIDER_API_KEY`
- Model source: `AI_PROVIDER_MODEL`

Provider secrets are not committed. Missing API key causes an explicit configuration error before AI calls.

## Inputs

### Manual Test Input

Manual mode accepts:

- `subject`: email subject string
- `attachment_path`: local AutoSupport archive path, such as `.7z`, `.zip`, `.tgz`, or `.gz`

This mode validates parsers and output schema before mailbox integration.

### Gmail Input

Gmail mode accepts:

- `received_after`: inclusive lower bound
- `received_before`: exclusive upper bound
- optional sender or label filters

For each matching email, the pipeline reads:

- `received_at`
- `from`
- `subject`
- `headers`
- `body`
- attachment metadata
- attachment content for selected AutoSupport files

## Rule Registry

Rules are user-maintained outside code. Google Sheets is the preferred source. Direct Google Sheets API, published CSV export, or local CSV/XLSX export can all feed the same internal registry.

The registry has three logical tables.

### Rules

Columns:

- `rule_id`: stable identifier
- `enabled`: true or false
- `priority`: higher value wins when multiple rules match
- `subject_contains`: subject text match
- `header_trigger`: AutoSupport trigger match when available
- `alert_type`: normalized alert type
- `parser`: parser family to run
- `question_direction`: human-editable guidance for what the analysis should determine

Example row:

| rule_id | enabled | priority | subject_contains | header_trigger | alert_type | parser | question_direction |
| --- | --- | ---: | --- | --- | --- | --- | --- |
| arw_activity_seen | TRUE | 100 | POSSIBLE RANSOMWARE ACTIVITY DETECTED | callhome.arw.activity.seen | ransomware | arw | Confirm whether ARW detected possible ransomware activity, affected SVM/volume, probability, time, detection reason, and entropy evidence. |

### EvidenceFiles

Columns:

- `rule_id`: links to `Rules.rule_id`
- `file_glob`: archive file name or glob
- `priority`: extraction order
- `purpose`: why this file matters
- `patterns`: optional newline- or comma-separated search terms

Example rows:

| rule_id | file_glob | priority | purpose | patterns |
| --- | --- | ---: | --- | --- |
| arw_activity_seen | X-HEADER-DATA.TXT | 10 | AutoSupport metadata | |
| arw_activity_seen | EMS-LOG-FILE.gz | 20 | Callhome trigger and affected object | callhome_arw_activity_seen |
| arw_activity_seen | arw-vol-status.xml | 30 | ARW state, probability, timeline | |
| arw_activity_seen | arw-high-entropy-stats.xml | 40 | High entropy spike evidence | |
| arw_activity_seen | arw-daily-entropy-stats.xml | 50 | Baseline comparison | |

### KBQueries

Columns:

- `rule_id`: links to `Rules.rule_id`
- `condition`: when to run or emit the query
- `query_template`: query string with evidence placeholders

Example rows:

| rule_id | condition | query_template |
| --- | --- | --- |
| arw_activity_seen | ai_requests_kb | NetApp {header_trigger} {ontap_version} |
| arw_activity_seen | low_confidence | NetApp ARW {attack_detected_by} |

## Classification

The classifier combines deterministic rule matching and AI fallback.

1. Normalize subject by removing external-mail markers such as `[External]`, `[外部]`, or `[❗️外部❗️]`.
2. Read AutoSupport headers when present, especially trigger, hostname, generated time, serial, model, ONTAP version, and cluster name.
3. Match enabled rules by `subject_contains` and `header_trigger`.
4. Select the highest-priority matched rule.
5. If no rule matches, use `generic_autosupport` and ask AI to classify based on subject, headers, body summary, manifest, AutoSupport history, and EMS excerpts.

Known sample classification:

- Subject: `[❗️外部❗️] HA Group Notification from KMUH-Netapp-AFF-A20-01 (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT`
- Header trigger or EMS event: `callhome.arw.activity.seen`
- Matched rule: `arw_activity_seen`
- Parser: `arw`

## Evidence Extraction

The archive reader lists the AutoSupport attachment contents before extraction. It extracts only files selected by the matched rule. Gzip files are decompressed for pattern search. XML files are parsed structurally rather than by fragile string slicing.

The ARW parser extracts:

- cluster and node metadata from headers
- AutoSupport generated time
- ONTAP version
- callhome trigger and event subject
- affected SVM and volume
- ARW state
- attack probability
- attack timeline
- detection method
- recent high entropy rows
- daily entropy baseline rows
- relevant EMS lines

For the provided sample archive, the ARW parser should extract:

- Node: `KMUH-Netapp-AFF-A20-01`
- Model: `AFF-A20`
- ONTAP version: `9.18.1P2`
- Generated time: `2026-06-21 18:05:28 +0800`
- Volume: `ISCSI-SVM / Netapp_A20_LUN00`
- ARW state: `enabled`
- Attack probability: `moderate`
- Detection method: `encryption_percentage_analysis`
- Attack timeline: `2026-06-12 17:53:41`
- High entropy evidence: `75%` over `0h10m0s`, data written `46231420928`
- Daily baseline: mostly `1-3%`, one `11%`, then event spike

## AI Finalization

The AI receives compact evidence, not the full archive. Prompt instructions require strict JSON output and prohibit unstated claims.

The AI finalizer determines:

- current system situation
- severity
- confidence
- impacted objects
- evidence references
- likely cause or interpretation
- recommended next actions
- whether KB lookup is needed
- KB search queries when needed

The AI provider call fails closed: if provider config is missing or the API returns invalid JSON, the pipeline returns deterministic evidence plus an `ai_error` object instead of hiding the failure.

## KB Lookup

KB lookup targets `kb.netapp.com`. It runs only when:

- matched rule says KB lookup is allowed, and
- AI requests KB lookup or confidence is below threshold, and
- network/search configuration is available

If KB lookup fails, output still includes diagnosis and generated `kb_search_queries`.

## Output JSON

Every run returns one JSON object per processed email.

Required top-level fields:

- `message`
- `classification`
- `evidence`
- `analysis`
- `kb`
- `warnings`
- `errors`

Example shape:

```json
{
  "message": {
    "received_at": "2026-06-21T18:05:28+08:00",
    "from": "Kmuh_a20@kmuh.gov.tw",
    "subject": "[❗️外部❗️] HA Group Notification from KMUH-Netapp-AFF-A20-01 (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT",
    "attachments": ["body.7z"]
  },
  "classification": {
    "matched_rule_id": "arw_activity_seen",
    "alert_type": "ransomware",
    "parser": "arw",
    "confidence": 0.96,
    "matched_signals": ["subject_contains", "header_trigger"]
  },
  "evidence": {
    "summary": [],
    "files_used": [],
    "raw_refs": []
  },
  "analysis": {
    "status": "possible_ransomware_activity_detected",
    "severity": "high",
    "confidence": 0.86,
    "impacted_objects": [],
    "recommended_actions": []
  },
  "kb": {
    "search_required": false,
    "queries": [],
    "results": []
  },
  "warnings": [],
  "errors": []
}
```

## Error Handling

The pipeline returns structured errors for:

- no matching emails
- no attachment found
- unsupported archive type
- missing expected evidence file
- malformed registry rows
- parser failure
- missing AI provider key
- invalid AI JSON response
- KB lookup failure

Non-fatal issues go into `warnings`. Fatal issues go into `errors` and stop that email only, not the entire batch.

## Testing

First tests use the provided sample:

- subject with `POSSIBLE RANSOMWARE ACTIVITY DETECTED`
- attachment `/Users/kmoo/Desktop/body.7z`

Test coverage should include:

- subject normalization
- rule priority matching
- Google Sheet or CSV registry loading
- archive manifest listing
- selective extraction
- ARW XML parsing
- gzip EMS pattern extraction
- JSON output schema validation
- unknown alert fallback
- AI provider error handling

## Implementation Phases

1. Manual CLI mode with local registry export and sample `body.7z`.
2. Google Sheet registry loader through CSV export or API.
3. Gmail reader by received time, including attachment fetch.
4. AI finalizer through OpenAI-compatible provider.
5. KB lookup and result attachment.
