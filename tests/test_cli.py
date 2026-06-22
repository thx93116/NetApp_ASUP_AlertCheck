import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from netapp_asup_alertcheck.cli import main


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

    def test_manual_passes_registry_urls_to_pipeline(self):
        with patch(
            "netapp_asup_alertcheck.cli.run_manual",
            return_value={"errors": []},
        ) as run_manual:
            with redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        "manual",
                        "--subject",
                        "POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                        "--attachment",
                        "body.7z",
                        "--rules-url",
                        "https://example.test/Rules.csv",
                        "--evidence-url",
                        "https://example.test/EvidenceFiles.csv",
                        "--kb-url",
                        "https://example.test/KBQueries.csv",
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertIsNone(run_manual.call_args.kwargs["registry_dir"])
        self.assertEqual(
            run_manual.call_args.kwargs["registry_urls"],
            {
                "rules": "https://example.test/Rules.csv",
                "evidence": "https://example.test/EvidenceFiles.csv",
                "kb": "https://example.test/KBQueries.csv",
            },
        )

    def test_manual_passes_sender_body_and_telegram_preview_to_pipeline(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as body_file:
            body_file.write("GENERATED_ON=Mon Jun 22 10:23:43 +0800 2026\n")
            body_file.flush()

            with patch(
                "netapp_asup_alertcheck.cli.run_manual",
                return_value={"errors": []},
            ) as run_manual:
                with redirect_stdout(io.StringIO()):
                    exit_code = main(
                        [
                            "manual",
                            "--subject",
                            "[外部] HA Group Notification from nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY",
                            "--attachment",
                            "body.7z",
                            "--registry-dir",
                            "data/rules",
                            "--from-address",
                            "autosupport@mail.realtek.com",
                            "--body-file",
                            body_file.name,
                            "--telegram-preview",
                        ]
                    )

        self.assertEqual(exit_code, 0)
        self.assertEqual(run_manual.call_args.kwargs["from_address"], "autosupport@mail.realtek.com")
        self.assertEqual(
            run_manual.call_args.kwargs["body_text"],
            "GENERATED_ON=Mon Jun 22 10:23:43 +0800 2026\n",
        )
        self.assertTrue(run_manual.call_args.kwargs["telegram_preview"])


if __name__ == "__main__":
    unittest.main()
