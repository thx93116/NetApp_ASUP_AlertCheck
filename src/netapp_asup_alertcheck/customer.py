from __future__ import annotations

from email.utils import parseaddr


DOMAIN_CUSTOMERS = {
    "realtek.com": "RTK",
    "mediatek.com": "MTK",
    "nuvoton.com": "NVTK",
    "innolux.com": "INX",
}


def _extract_domain(address: str | None) -> str:
    if not address:
        return ""
    _display_name, parsed = parseaddr(address)
    candidate = parsed or address
    if "@" not in candidate:
        return ""
    return candidate.rsplit("@", 1)[-1].strip().strip(">").lower()


def customer_from_address(address: str | None) -> str:
    domain = _extract_domain(address)
    for suffix, customer in DOMAIN_CUSTOMERS.items():
        if domain == suffix or domain.endswith("." + suffix):
            return customer
    return "UNKNOWN"
