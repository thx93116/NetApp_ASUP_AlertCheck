# Telegram Notification Design

## Goal

Add a notification layer for NetApp ASUP AlertCheck. The analysis pipeline continues to produce structured JSON, while a separate formatter builds short Telegram messages for events that should notify operators.

## Input Sources

Manual mode may later accept:

- `from_address`
- `body_file`
- `subject`
- `attachment_path`

Future email mode will read:

- sender address
- subject
- body
- received time
- ASUP attachment

## Email Body Metadata

ASUP email body can include key-value lines:

```text
CONFIDENTIALITY=NetApp Confidential
GENERATED_ON=Mon Jun 22 13:25:32 +0800 2026
VERSION=NetApp Release 9.16.1P11: Thu Jan 15 06:21:38 EST 2026
SYSTEM_ID=0537420918
SERIAL_NUM=792206000367
HOSTNAME=nbt1-12
SEQUENCE=6035
PARTNER_SYSTEM_ID=0537420884
PARTNER_HOSTNAME=nbt1-11
BOOT_CLUSTERED='true'
```

The parser maps these fields to `asup_metadata`:

```json
{
  "generated_on": "Mon Jun 22 13:25:32 +0800 2026",
  "version": "NetApp Release 9.16.1P11: Thu Jan 15 06:21:38 EST 2026",
  "hostname": "nbt1-12",
  "partner_hostname": "nbt1-11",
  "system_id": "0537420918",
  "serial_num": "792206000367",
  "sequence": "6035",
  "boot_clustered": "true"
}
```

## Customer Mapping

Customer name is derived from sender domain.

Initial customer set:

- `MTK`
- `RTK`
- `NVTK`
- `INX`

Domain-to-customer mapping should be externalized later in CSV. Unknown domains map to `UNKNOWN`.

## Subject Event Title

Notification event title is the text after `HA Group Notification from`.

Example:

```text
[❗️外部❗️] HA Group Notification from nbt1-12 (REBOOT (power on)) NOTICE
```

becomes:

```text
nbt1-12 (REBOOT (power on)) NOTICE
```

External-mail markers are removed before matching.

## Priority Rules

Priority matching is case-insensitive.

P1 if normalized subject contains any:

- `PANIC`
- `(CLUSTER NETWORK DEGRADED)`
- `(HA INTERCONNECT DOWN)`
- `(NODE(S) OUT OF CLUSTER QUORUM)`
- `(SHELF_FAULT)`
- `(HEARTBEAT_LOSS)`
- `(SHELF POWER INTERRUPTED)`
- `POWER SUPPLY DEGRADED`
- `POWER SUPPLY OFF`
- `CHASSIS POWER DEGRADED`

P2 if normalized subject contains any:

- `(SPARES_LOW)`
- `(DISK REDUNDANCY FAILED)`
- `(OUT OF INODES)`
- `SinglePath`

Priority order:

```text
P1 > P2 > no_send
```

If both P1 and P2 match, use P1.

## Skip Rules

Future email mode must skip `REBOOT (power on)` before attachment analysis:

- do not run parser
- do not call AI
- do not search KB
- do not send Telegram

Manual mode may still analyze `REBOOT (power on)` for testing.

## Notification JSON

Add `notification` block:

```json
{
  "customer": "RTK",
  "priority": "P1",
  "should_send": true,
  "generated_on": "Mon Jun 22 10:23:43 +0800 2026",
  "event_title": "nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY",
  "summary": "nbt1-11 發生 controller panic，HA takeover 已完成。",
  "telegram_text": "[NetApp ASUP] RTK - P1\n\n..."
}
```

No-notify example:

```json
{
  "customer": "RTK",
  "priority": null,
  "should_send": false,
  "generated_on": "Mon Jun 22 13:25:32 +0800 2026",
  "event_title": "nbt1-12 (REBOOT (power on)) NOTICE",
  "summary": "",
  "telegram_text": ""
}
```

## Telegram Message Format

```text
[NetApp ASUP] RTK - P1

產生時間:
Mon Jun 22 10:23:43 +0800 2026

事件:
nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY

判斷:
nbt1-11 發生 controller panic，HA takeover 已完成。Partner node 為 nbt1-12。ONTAP 版本 9.16.1P11。EMS 有 takeover / kernel::panic 相關證據。
```

## Implementation Notes

Keep notification logic separate from analysis logic:

- `email_body.py`: parse body key-value metadata
- `customer.py`: sender domain to customer
- `priority.py`: P1/P2/no_send rules and email skip rules
- `formatters/telegram.py`: build `notification` object and Telegram text
- future `notifiers/telegram.py`: send Telegram via Bot API

Do not commit Telegram bot tokens. Use runtime env:

```bash
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
```
