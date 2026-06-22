import unittest
from pathlib import Path

from netapp_asup_alertcheck.models import EvidenceBundle
from netapp_asup_alertcheck.parsers.arw import parse_arw_evidence


FIXTURE = Path(__file__).parent / "fixtures" / "arw"


class ArwParserTests(unittest.TestCase):
    def test_parse_arw_evidence(self):
        files = {
            "arw-vol-status.xml": (FIXTURE / "arw-vol-status.xml").read_text(encoding="utf-8"),
            "arw-high-entropy-stats.xml": (FIXTURE / "arw-high-entropy-stats.xml").read_text(encoding="utf-8"),
            "arw-daily-entropy-stats.xml": (FIXTURE / "arw-daily-entropy-stats.xml").read_text(encoding="utf-8"),
            "EMS-LOG-FILE.gz": (FIXTURE / "EMS-LOG-FILE.txt").read_text(encoding="utf-8"),
        }

        bundle = parse_arw_evidence(files)
        summary = {item["name"]: item["value"] for item in bundle.summary}

        self.assertEqual(summary["affected_volume"], "ISCSI-SVM / Netapp_A20_LUN00")
        self.assertEqual(summary["attack_probability"], "moderate")
        self.assertEqual(summary["attack_detected_by"], "encryption_percentage_analysis")
        self.assertEqual(summary["high_entropy_peak"], "75% over 0h10m0s")
        self.assertEqual([row["encryption_percentage"] for row in summary["daily_entropy_baseline"]], ["1%", "7%"])
        self.assertTrue(any(ref["file"] == "EMS-LOG-FILE.gz" for ref in bundle.raw_refs))

    def test_parse_arw_evidence_handles_missing_files(self):
        empty_bundle = parse_arw_evidence({})
        ems_bundle = parse_arw_evidence(
            {
                "EMS-LOG-FILE.gz": (
                    "There was POSSIBLE RANSOMWARE ACTIVITY DETECTED for Netapp_A20_LUN00, "
                    "but no callhome event tag was present."
                )
            }
        )

        self.assertIsInstance(empty_bundle, EvidenceBundle)
        self.assertEqual(empty_bundle.summary, [])
        self.assertEqual(empty_bundle.files_used, [])
        self.assertEqual(ems_bundle.summary, [])
        self.assertEqual(ems_bundle.files_used, [{"file": "EMS-LOG-FILE.gz", "purpose": "arw evidence"}])
        self.assertIn("POSSIBLE RANSOMWARE ACTIVITY DETECTED", ems_bundle.raw_refs[0]["line"])

    def test_parse_arw_evidence_reads_namespace_local_names(self):
        files = {
            "arw-vol-status.xml": """
                <ns:T_ARW_VOL_STATUS xmlns:ns="urn:test">
                  <ns:ROW>
                    <ns:arw_vserver>ISCSI-SVM</ns:arw_vserver>
                    <ns:arw_volume>Netapp_A20_LUN00</ns:arw_volume>
                    <ns:arw_state>enabled</ns:arw_state>
                    <ns:attack_probability>moderate</ns:attack_probability>
                    <ns:attack_timeline><ns:list><ns:li>6/12/2026 17:53:41</ns:li></ns:list></ns:attack_timeline>
                    <ns:attack_detected_by>encryption_percentage_analysis</ns:attack_detected_by>
                  </ns:ROW>
                </ns:T_ARW_VOL_STATUS>
            """
        }

        bundle = parse_arw_evidence(files)
        summary = {item["name"]: item["value"] for item in bundle.summary}

        self.assertEqual(summary["affected_volume"], "ISCSI-SVM / Netapp_A20_LUN00")
        self.assertEqual(summary["attack_timeline"], "6/12/2026 17:53:41")

    def test_parse_arw_evidence_strips_netapp_internal_dtd(self):
        files = {
            "arw-vol-status.xml": """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE T_ARW_VOL_STATUS [
                  <!ELEMENT T_ARW_VOL_STATUS (asup:ROW*)>
                  <!ELEMENT asup:ROW (arw_vserver,arw_volume,arw_state,attack_probability,attack_timeline,attack_detected_by)>
                  <!ELEMENT arw_vserver (#PCDATA)>
                  <!ELEMENT arw_volume (#PCDATA)>
                  <!ELEMENT arw_state (#PCDATA)>
                  <!ELEMENT attack_probability (#PCDATA)>
                  <!ELEMENT attack_timeline (asup:list?)>
                  <!ELEMENT attack_detected_by (#PCDATA)>
                ]>
                <T_ARW_VOL_STATUS xmlns:asup="http://asup_search.netapp.com/ns/ASUP/1.1">
                  <asup:ROW>
                    <arw_vserver>ISCSI-SVM</arw_vserver>
                    <arw_volume>Netapp_A20_LUN00</arw_volume>
                    <arw_state>enabled</arw_state>
                    <attack_probability>moderate</attack_probability>
                    <attack_timeline><asup:list><asup:li>6/12/2026 17:53:41</asup:li></asup:list></attack_timeline>
                    <attack_detected_by>encryption_percentage_analysis</attack_detected_by>
                  </asup:ROW>
                </T_ARW_VOL_STATUS>
            """
        }

        bundle = parse_arw_evidence(files)
        summary = {item["name"]: item["value"] for item in bundle.summary}

        self.assertEqual(summary["affected_volume"], "ISCSI-SVM / Netapp_A20_LUN00")
        self.assertEqual(summary["attack_probability"], "moderate")

    def test_parse_arw_evidence_rejects_unsafe_xml_declarations(self):
        files = {
            "arw-vol-status.xml": """
                <!DOCTYPE T_ARW_VOL_STATUS [
                  <!ENTITY probability "moderate">
                ]>
                <T_ARW_VOL_STATUS>
                  <ROW>
                    <arw_vserver>ISCSI-SVM</arw_vserver>
                    <arw_volume>Netapp_A20_LUN00</arw_volume>
                    <arw_state>enabled</arw_state>
                    <attack_probability>&probability;</attack_probability>
                    <attack_detected_by>encryption_percentage_analysis</attack_detected_by>
                  </ROW>
                </T_ARW_VOL_STATUS>
            """
        }

        bundle = parse_arw_evidence(files)

        self.assertEqual(bundle.summary, [])
        self.assertEqual(bundle.files_used, [{"file": "arw-vol-status.xml", "purpose": "arw evidence"}])

    def test_parse_arw_evidence_handles_malformed_xml(self):
        bundle = parse_arw_evidence({"arw-vol-status.xml": "<T_ARW_VOL_STATUS><ROW>"})

        self.assertEqual(bundle.summary, [])
        self.assertEqual(bundle.files_used, [{"file": "arw-vol-status.xml", "purpose": "arw evidence"}])


if __name__ == "__main__":
    unittest.main()
