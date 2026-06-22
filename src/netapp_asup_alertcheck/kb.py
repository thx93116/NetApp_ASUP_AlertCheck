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
