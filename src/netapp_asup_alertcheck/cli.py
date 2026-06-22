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
    manual.add_argument("--rules-url")
    manual.add_argument("--evidence-url")
    manual.add_argument("--kb-url")
    manual.add_argument("--from-address")
    manual.add_argument("--body-file")
    manual.add_argument(
        "--telegram-preview",
        action="store_true",
        help="Include notification preview JSON without sending Telegram messages",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "manual":
        registry_urls = None
        supplied_urls = [args.rules_url, args.evidence_url, args.kb_url]
        if any(supplied_urls):
            if not all(supplied_urls):
                parser.error("--rules-url, --evidence-url, and --kb-url must be supplied together")
            registry_urls = {
                "rules": args.rules_url,
                "evidence": args.evidence_url,
                "kb": args.kb_url,
            }
        body_text = None
        if args.body_file:
            body_text = Path(args.body_file).read_text(encoding="utf-8")
        result = run_manual(
            subject=args.subject,
            attachment_path=Path(args.attachment),
            registry_dir=None if registry_urls else Path(args.registry_dir),
            registry_urls=registry_urls,
            from_address=args.from_address,
            body_text=body_text,
            telegram_preview=args.telegram_preview,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 1 if result.get("errors") else 0
    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
