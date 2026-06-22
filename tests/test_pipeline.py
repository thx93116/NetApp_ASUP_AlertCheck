import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from netapp_asup_alertcheck.models import EvidenceFileRule, Rule
from netapp_asup_alertcheck.pipeline import run_manual
from netapp_asup_alertcheck.registry import RuleRegistry


class PipelineTests(unittest.TestCase):
    def test_run_manual_returns_arw_json_without_ai_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules"
            rules.mkdir()
            (rules / "Rules.csv").write_text(
                "rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction\n"
                "arw_activity_seen,TRUE,100,POSSIBLE RANSOMWARE ACTIVITY DETECTED,callhome.arw.activity.seen,ransomware,arw,Confirm ARW evidence\n",
                encoding="utf-8",
            )
            (rules / "EvidenceFiles.csv").write_text(
                "rule_id,file_glob,priority,purpose,patterns\n"
                "arw_activity_seen,arw-vol-status.xml,30,ARW status,\n",
                encoding="utf-8",
            )
            (rules / "KBQueries.csv").write_text(
                "rule_id,condition,query_template\n"
                "arw_activity_seen,ai_requests_kb,NetApp {header_trigger}\n"
                "arw_activity_seen,low_confidence,NetApp ARW {attack_detected_by}\n",
                encoding="utf-8",
            )
            archive_path = root / "body.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "arw-vol-status.xml",
                    "<root><ROW><arw_vserver>svm</arw_vserver><arw_volume>vol</arw_volume>"
                    "<arw_state>enabled</arw_state><attack_probability>moderate</attack_probability>"
                    "<attack_detected_by>encryption_percentage_analysis</attack_detected_by></ROW></root>",
                )

            result = run_manual(
                subject="POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                attachment_path=archive_path,
                registry_dir=rules,
                ai_config={},
            )

        self.assertEqual(result["classification"]["matched_rule_id"], "arw_activity_seen")
        self.assertEqual(result["analysis"]["status"], "ai_not_run")
        self.assertEqual(
            result["kb"]["queries"],
            ["NetApp callhome.arw.activity.seen", "NetApp ARW encryption_percentage_analysis"],
        )
        self.assertTrue(result["warnings"])
        self.assertEqual(result["errors"], [])

    def test_run_manual_matches_evidence_file_globs_inside_archive_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules"
            rules.mkdir()
            (rules / "Rules.csv").write_text(
                "rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction\n"
                "arw_activity_seen,TRUE,100,POSSIBLE RANSOMWARE ACTIVITY DETECTED,callhome.arw.activity.seen,ransomware,arw,Confirm ARW evidence\n",
                encoding="utf-8",
            )
            (rules / "EvidenceFiles.csv").write_text(
                "rule_id,file_glob,priority,purpose,patterns\n"
                "arw_activity_seen,*/arw-vol-status.xml,30,ARW status,\n",
                encoding="utf-8",
            )
            (rules / "KBQueries.csv").write_text(
                "rule_id,condition,query_template\n",
                encoding="utf-8",
            )
            archive_path = root / "body.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "autosupport/arw-vol-status.xml",
                    "<root><ROW><arw_vserver>svm</arw_vserver><arw_volume>vol</arw_volume>"
                    "<arw_state>enabled</arw_state><attack_probability>moderate</attack_probability>"
                    "<attack_detected_by>encryption_percentage_analysis</attack_detected_by></ROW></root>",
                )

            result = run_manual(
                subject="POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                attachment_path=archive_path,
                registry_dir=rules,
                ai_config={},
            )

        self.assertIn(
            {"name": "affected_volume", "value": "svm / vol"},
            result["evidence"]["summary"],
        )

    def test_run_manual_can_load_registry_from_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "body.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "arw-vol-status.xml",
                    "<root><ROW><arw_vserver>svm</arw_vserver><arw_volume>vol</arw_volume>"
                    "<arw_state>enabled</arw_state><attack_probability>moderate</attack_probability>"
                    "<attack_detected_by>encryption_percentage_analysis</attack_detected_by></ROW></root>",
                )

            registry = RuleRegistry(
                rules=[
                    Rule(
                        rule_id="arw_activity_seen",
                        enabled=True,
                        priority=100,
                        subject_contains="POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                        header_trigger="callhome.arw.activity.seen",
                        alert_type="ransomware",
                        parser="arw",
                        question_direction="Confirm ARW evidence",
                    )
                ],
                evidence_files={
                    "arw_activity_seen": [
                        EvidenceFileRule(
                            rule_id="arw_activity_seen",
                            file_glob="arw-vol-status.xml",
                            priority=30,
                            purpose="ARW status",
                        )
                    ]
                },
            )

            with patch(
                "netapp_asup_alertcheck.pipeline.load_registry_from_urls",
                return_value=registry,
            ) as load_registry_from_urls:
                result = run_manual(
                    subject="POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                    attachment_path=archive_path,
                    registry_dir=None,
                    registry_urls={
                        "rules": "https://example.test/Rules.csv",
                        "evidence": "https://example.test/EvidenceFiles.csv",
                        "kb": "https://example.test/KBQueries.csv",
                    },
                    ai_config={},
                )

        load_registry_from_urls.assert_called_once_with(
            "https://example.test/Rules.csv",
            "https://example.test/EvidenceFiles.csv",
            "https://example.test/KBQueries.csv",
        )
        self.assertEqual(result["classification"]["matched_rule_id"], "arw_activity_seen")


if __name__ == "__main__":
    unittest.main()
