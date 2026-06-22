from __future__ import annotations


KEY_MAP = {
    "GENERATED_ON": "generated_on",
    "VERSION": "version",
    "SYSTEM_ID": "system_id",
    "SERIAL_NUM": "serial_num",
    "HOSTNAME": "hostname",
    "SEQUENCE": "sequence",
    "PARTNER_SYSTEM_ID": "partner_system_id",
    "PARTNER_HOSTNAME": "partner_hostname",
    "BOOT_CLUSTERED": "boot_clustered",
}


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_asup_body(text: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        mapped_key = KEY_MAP.get(key.strip().upper())
        if mapped_key:
            metadata[mapped_key] = _strip_quotes(value.strip())
    return metadata
