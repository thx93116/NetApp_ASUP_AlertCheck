import io
import os
import subprocess
import sys
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


if __name__ == "__main__":
    unittest.main()
