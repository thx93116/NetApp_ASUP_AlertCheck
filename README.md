# NetApp ASUP AlertCheck

Analyze NetApp AutoSupport alert emails by matching subject/header rules, extracting selected attachment evidence, and returning JSON for automation.

## 中文說明

NetApp ASUP AlertCheck 用來分析 NetApp AutoSupport 警報信件。流程先用信件主旨與 header 規則判斷問題方向，再從 AutoSupport 附件中抽取指定檔案與證據，最後輸出 JSON，供後續自動化流程使用。

Workflow 流程圖：[`docs/workflow.md`](docs/workflow.md)

目前支援：

- 以主旨與本機 AutoSupport 附件手動分析
- 從本機 CSV 或 Google Sheet CSV URL 載入規則表
- 讀取 `.7z`、`.zip`、`.tar`、`.tgz`、`.gz` 附件
- 解析 ARW / ransomware 相關 AutoSupport 證據
- 使用 OpenAI-compatible 第三方 AI provider 做最終判斷
- AI key 尚未提供時，仍回傳 deterministic evidence 與 `ai_not_run`

### 手動執行

```bash
PYTHONPATH=src python -m netapp_asup_alertcheck.cli manual \
  --subject "[❗️外部❗️] HA Group Notification from KMUH-Netapp-AFF-A20-01 (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT" \
  --attachment /Users/kmoo/Desktop/body.7z \
  --registry-dir data/rules
```

`.7z` 需要系統 PATH 裡有 `7z` CLI。

### 使用 Google Sheet / CSV URL

之後可將 Google Sheet 各分頁發佈或匯出成 CSV URL，再用三個 URL 載入規則：

```bash
PYTHONPATH=src python -m netapp_asup_alertcheck.cli manual \
  --subject "[❗️外部❗️] HA Group Notification from KMUH-Netapp-AFF-A20-01 (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT" \
  --attachment /Users/kmoo/Desktop/body.7z \
  --rules-url "https://example.test/Rules.csv" \
  --evidence-url "https://example.test/EvidenceFiles.csv" \
  --kb-url "https://example.test/KBQueries.csv"
```

三個 URL 必須一起提供。

### AI Provider 設定

第三方 provider 使用 OpenAI-compatible `/chat/completions` API。預設 base URL 已是：

```bash
http://127.0.0.1:8000/v1
```

執行 AI finalizer 前設定：

```bash
export AI_PROVIDER_BASE_URL="http://127.0.0.1:8000/v1"
export AI_PROVIDER_API_KEY="..."
export AI_PROVIDER_MODEL="..."
```

API key 只放 runtime env，不寫入程式碼或規則表。

### 規則表格式

建議 Google Sheet 使用三個分頁：

| 分頁 | 必要欄位 |
| --- | --- |
| `Rules` | `rule_id`, `enabled`, `priority`, `subject_contains`, `header_trigger`, `alert_type`, `parser`, `question_direction` |
| `EvidenceFiles` | `rule_id`, `file_glob`, `priority`, `purpose`, `patterns` |
| `KBQueries` | `rule_id`, `condition`, `query_template` |

目前內建規則：

- `arw_activity_seen`
- 主旨包含：`POSSIBLE RANSOMWARE ACTIVITY DETECTED`
- parser：`arw`
- 優先讀取：`X-HEADER-DATA.TXT`、`EMS-LOG-FILE.gz`、`arw-vol-status.xml`、`arw-high-entropy-stats.xml`、`arw-daily-entropy-stats.xml`
- KB query：`NetApp {header_trigger}`、`NetApp ARW {attack_detected_by}`

### 測試

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
```

## Manual Run

```bash
PYTHONPATH=src python -m netapp_asup_alertcheck.cli manual \
  --subject "[❗️外部❗️] HA Group Notification from KMUH-Netapp-AFF-A20-01 (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT" \
  --attachment /Users/kmoo/Desktop/body.7z \
  --registry-dir data/rules
```

The `.7z` archive reader requires the `7z` CLI to be available on `PATH`.

You can also load the rule registry from three CSV URLs, including Google Sheet published/export CSV links:

```bash
PYTHONPATH=src python -m netapp_asup_alertcheck.cli manual \
  --subject "[❗️外部❗️] HA Group Notification from KMUH-Netapp-AFF-A20-01 (POSSIBLE RANSOMWARE ACTIVITY DETECTED) ALERT" \
  --attachment /Users/kmoo/Desktop/body.7z \
  --rules-url "https://example.test/Rules.csv" \
  --evidence-url "https://example.test/EvidenceFiles.csv" \
  --kb-url "https://example.test/KBQueries.csv"
```

## AI Provider

Set these environment variables before AI finalization:

```bash
export AI_PROVIDER_BASE_URL="http://127.0.0.1:8000/v1"
export AI_PROVIDER_API_KEY="..."
export AI_PROVIDER_MODEL="..."
```

Provider secrets are runtime configuration only. Do not commit real API keys.
The default base URL in code is already `http://127.0.0.1:8000/v1`; you only need to override it if the provider endpoint changes.

## Rule Registry

The editable registry uses three spreadsheet-shaped tables:

- `Rules.csv`
- `EvidenceFiles.csv`
- `KBQueries.csv`

These can be exported from Google Sheets or loaded from CSV URLs by the registry module.

Suggested Google Sheet tabs:

| Tab | Required columns |
| --- | --- |
| `Rules` | `rule_id`, `enabled`, `priority`, `subject_contains`, `header_trigger`, `alert_type`, `parser`, `question_direction` |
| `EvidenceFiles` | `rule_id`, `file_glob`, `priority`, `purpose`, `patterns` |
| `KBQueries` | `rule_id`, `condition`, `query_template` |

Current seed rule:

- `arw_activity_seen`: subject contains `POSSIBLE RANSOMWARE ACTIVITY DETECTED`
- parser: `arw`
- evidence priority: `X-HEADER-DATA.TXT`, `EMS-LOG-FILE.gz`, `arw-vol-status.xml`, `arw-high-entropy-stats.xml`, `arw-daily-entropy-stats.xml`
- KB query templates: `NetApp {header_trigger}`, `NetApp ARW {attack_detected_by}`

## Tests

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
```
