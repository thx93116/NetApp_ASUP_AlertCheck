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

    def test_run_manual_returns_node_panic_evidence_without_ai_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules"
            rules.mkdir()
            (rules / "Rules.csv").write_text(
                "rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction\n"
                "node_panic_takeover_complete,TRUE,110,CONTROLLER TAKEOVER COMPLETE PANIC,,node_panic,panic,Confirm node panic and takeover evidence\n",
                encoding="utf-8",
            )
            (rules / "EvidenceFiles.csv").write_text(
                "rule_id,file_glob,priority,purpose,patterns\n"
                "node_panic_takeover_complete,X-HEADER-DATA.TXT,10,ASUP headers,\n"
                "node_panic_takeover_complete,coredump-status.xml,20,Coredump status,\n"
                "node_panic_takeover_complete,panic-context.xml,30,Panic context,\n"
                "node_panic_takeover_complete,EMS-LOG-FILE.gz,40,EMS panic and takeover events,\n",
                encoding="utf-8",
            )
            (rules / "KBQueries.csv").write_text(
                "rule_id,condition,query_template\n"
                "node_panic_takeover_complete,ai_requests_kb,NetApp {header_trigger} {ontap_version}\n",
                encoding="utf-8",
            )
            archive_path = root / "panic.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "X-HEADER-DATA.TXT",
                    "X-Netapp-asup-hostname: nbt1-11\n"
                    "X-Netapp-asup-partner-hostname: nbt1-12\n"
                    "X-Netapp-asup-cluster-name: nbt1\n"
                    "X-Netapp-asup-os-version: NetApp Release 9.16.1P11\n",
                )
                archive.writestr(
                    "coredump-status.xml",
                    "<root><ROW><node>nbt1-11</node><state>saving</state>"
                    "<corename>core.123</corename><coredump_type>kernel</coredump_type></ROW></root>",
                )
                archive.writestr(
                    "panic-context.xml",
                    "<root><ROW><time>6/22/2026 10:21:52</time><severity>EMERGENCY</severity>"
                    "<source>panic</source><messagename>callhome.panic</messagename>"
                    "<parameters><list><li>panic_string: page fault</li></list></parameters></ROW></root>",
                )
                archive.writestr("EMS-LOG-FILE.gz", "PANIC: page fault\nFAILOVER: TakeOver complete\n")

            result = run_manual(
                subject="[外部] HA Group Notification from nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY",
                attachment_path=archive_path,
                registry_dir=rules,
                ai_config={},
            )

        summary = {item["name"]: item["value"] for item in result["evidence"]["summary"]}
        self.assertEqual(result["classification"]["matched_rule_id"], "node_panic_takeover_complete")
        self.assertEqual(result["classification"]["parser"], "panic")
        self.assertEqual(summary["node"], "nbt1-11")
        self.assertEqual(summary["coredump_state"], "saving")
        self.assertEqual(summary["panic_event"]["message_name"], "callhome.panic")

    def test_run_manual_returns_power_on_reboot_evidence_without_ai_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules"
            rules.mkdir()
            (rules / "Rules.csv").write_text(
                "rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction\n"
                "node_reboot_power_on,TRUE,90,REBOOT (power on),,node_reboot,panic,Confirm node reboot power-on evidence\n",
                encoding="utf-8",
            )
            (rules / "EvidenceFiles.csv").write_text(
                "rule_id,file_glob,priority,purpose,patterns\n"
                "node_reboot_power_on,X-HEADER-DATA.TXT,10,ASUP headers,\n"
                "node_reboot_power_on,coredump-status.xml,20,Coredump status,\n"
                "node_reboot_power_on,EMS-LOG-FILE.gz,30,EMS reboot and core events,\n",
                encoding="utf-8",
            )
            (rules / "KBQueries.csv").write_text(
                "rule_id,condition,query_template\n"
                "node_reboot_power_on,ai_requests_kb,NetApp REBOOT power on {ontap_version}\n",
                encoding="utf-8",
            )
            archive_path = root / "reboot.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "X-HEADER-DATA.TXT",
                    "X-Netapp-asup-hostname: nbt1-12\n"
                    "X-Netapp-asup-partner-hostname: nbt1-11\n"
                    "X-Netapp-asup-cluster-name: nbt1\n"
                    "X-Netapp-asup-os-version: NetApp Release 9.16.1P11\n"
                    "X-Netapp-asup-model-name: FAS9000\n",
                )
                archive.writestr(
                    "coredump-status.xml",
                    "<root><ROW><node>nbt1-12</node><state>saved</state>"
                    "<corename>core.537420918</corename><coredump_type>spare</coredump_type></ROW></root>",
                )
                archive.writestr(
                    "EMS-LOG-FILE.gz",
                    "<coredump_save_completed_1 file=\"core.537420918\"/>\n"
                    "<callhome_coredump_save_done_1 subject=\"COREDUMP SAVE COMPLETED\"/>\n",
                )

            result = run_manual(
                subject="[外部] HA Group Notification from nbt1-12 (REBOOT (power on)) NOTICE",
                attachment_path=archive_path,
                registry_dir=rules,
                ai_config={},
            )

        summary = {item["name"]: item["value"] for item in result["evidence"]["summary"]}
        self.assertEqual(result["classification"]["matched_rule_id"], "node_reboot_power_on")
        self.assertEqual(result["classification"]["alert_type"], "node_reboot")
        self.assertEqual(result["classification"]["parser"], "panic")
        self.assertEqual(summary["node"], "nbt1-12")
        self.assertEqual(summary["partner_node"], "nbt1-11")
        self.assertEqual(summary["coredump_state"], "saved")


if __name__ == "__main__":
    unittest.main()
