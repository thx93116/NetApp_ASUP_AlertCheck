import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from netapp_asup_alertcheck.registry import RuleRegistry, load_registry_from_dir, load_registry_from_urls


def write_registry_csvs(root: Path, rules: str, evidence: str, kb: str) -> None:
    (root / "Rules.csv").write_text(textwrap.dedent(rules).lstrip(), encoding="utf-8")
    (root / "EvidenceFiles.csv").write_text(textwrap.dedent(evidence).lstrip(), encoding="utf-8")
    (root / "KBQueries.csv").write_text(textwrap.dedent(kb).lstrip(), encoding="utf-8")


class RuleRegistryTests(unittest.TestCase):
    def test_load_registry_from_csv_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_registry_csvs(
                root,
                """
                rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction
                arw_activity_seen,TRUE,100,POSSIBLE RANSOMWARE ACTIVITY DETECTED,callhome.arw.activity.seen,ransomware,arw,Confirm details.
                lower_priority,true,10,OTHER,other.trigger,,,Ask follow-up.
                """,
                """
                rule_id,file_glob,priority,purpose,patterns
                arw_activity_seen,EMS-LOG-FILE.gz,20,Callhome trigger,callhome_arw_activity_seen
                """,
                """
                rule_id,condition,query_template
                arw_activity_seen,ai_requests_kb,NetApp {header_trigger} {ontap_version}
                """,
            )

            registry = load_registry_from_dir(root)

        self.assertIsInstance(registry, RuleRegistry)
        self.assertEqual(registry.rules[0].rule_id, "arw_activity_seen")
        self.assertEqual(registry.evidence_files["arw_activity_seen"][0].file_glob, "EMS-LOG-FILE.gz")
        self.assertEqual(registry.kb_queries["arw_activity_seen"][0].condition, "ai_requests_kb")

    def test_invalid_rule_row_becomes_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_registry_csvs(
                root,
                """
                rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction
                ,TRUE,not-an-int,POSSIBLE RANSOMWARE ACTIVITY DETECTED,callhome.arw.activity.seen,ransomware,arw,Confirm details.
                """,
                """
                rule_id,file_glob,priority,purpose,patterns
                """,
                """
                rule_id,condition,query_template
                """,
            )

            registry = load_registry_from_dir(root)

        self.assertEqual(registry.rules, [])
        self.assertIn("Rules.csv row 2: missing rule_id; invalid priority", registry.warnings)

    def test_invalid_evidence_row_warning_names_specific_problems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_registry_csvs(
                root,
                """
                rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction
                arw_activity_seen,TRUE,100,POSSIBLE RANSOMWARE ACTIVITY DETECTED,callhome.arw.activity.seen,ransomware,arw,Confirm details.
                """,
                """
                rule_id,file_glob,priority,purpose,patterns
                arw_activity_seen,,not-an-int,Missing file glob,
                """,
                """
                rule_id,condition,query_template
                """,
            )

            registry = load_registry_from_dir(root)

        self.assertEqual(registry.evidence_files, {})
        self.assertIn("EvidenceFiles.csv row 2: missing file_glob; invalid priority", registry.warnings)

    def test_invalid_kb_row_warning_names_missing_query_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_registry_csvs(
                root,
                """
                rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction
                arw_activity_seen,TRUE,100,POSSIBLE RANSOMWARE ACTIVITY DETECTED,callhome.arw.activity.seen,ransomware,arw,Confirm details.
                """,
                """
                rule_id,file_glob,priority,purpose,patterns
                """,
                """
                rule_id,condition,query_template
                arw_activity_seen,ai_requests_kb,
                """,
            )

            registry = load_registry_from_dir(root)

        self.assertEqual(registry.kb_queries, {})
        self.assertIn("KBQueries.csv row 2: missing query_template", registry.warnings)

    def test_evidence_patterns_split_and_sorted_by_priority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_registry_csvs(
                root,
                """
                rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction
                arw_activity_seen,TRUE,100,POSSIBLE RANSOMWARE ACTIVITY DETECTED,callhome.arw.activity.seen,ransomware,arw,Confirm details.
                """,
                """
                rule_id,file_glob,priority,purpose,patterns
                arw_activity_seen,second.xml,20,Second,"beta
                gamma"
                arw_activity_seen,first.xml,10,First,"alpha, beta,
                gamma"
                """,
                """
                rule_id,condition,query_template
                """,
            )

            registry = load_registry_from_dir(root)

        evidence = registry.evidence_files["arw_activity_seen"]
        self.assertEqual([item.file_glob for item in evidence], ["first.xml", "second.xml"])
        self.assertEqual(evidence[0].patterns, ["alpha", "beta", "gamma"])
        self.assertEqual(evidence[1].patterns, ["beta", "gamma"])

    def test_load_registry_from_urls_uses_timeout(self):
        rules_response = Mock()
        rules_response.headers.get_content_charset.return_value = "utf-8"
        rules_response.read.return_value = (
            b"rule_id,enabled,priority,subject_contains,header_trigger,alert_type,parser,question_direction\n"
        )
        evidence_response = Mock()
        evidence_response.headers.get_content_charset.return_value = "utf-8"
        evidence_response.read.return_value = b"rule_id,file_glob,priority,purpose,patterns\n"
        kb_response = Mock()
        kb_response.headers.get_content_charset.return_value = "utf-8"
        kb_response.read.return_value = b"rule_id,condition,query_template\n"

        for response in (rules_response, evidence_response, kb_response):
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=None)

        with patch(
            "netapp_asup_alertcheck.registry.urlopen",
            side_effect=[rules_response, evidence_response, kb_response],
        ) as urlopen:
            registry = load_registry_from_urls(
                "https://example.test/Rules.csv",
                "https://example.test/EvidenceFiles.csv",
                "https://example.test/KBQueries.csv",
            )

        self.assertIsInstance(registry, RuleRegistry)
        self.assertEqual(
            [call.kwargs["timeout"] for call in urlopen.call_args_list],
            [10, 10, 10],
        )


if __name__ == "__main__":
    unittest.main()
