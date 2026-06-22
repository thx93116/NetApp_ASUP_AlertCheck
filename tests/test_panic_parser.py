import unittest

from netapp_asup_alertcheck.parsers.panic import parse_panic_evidence


class PanicParserTests(unittest.TestCase):
    def test_parse_panic_evidence_extracts_headers_core_and_events(self):
        files = {
            "X-HEADER-DATA.TXT": "\n".join(
                [
                    "X-Netapp-asup-subject: HA Group Notification from nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY",
                    "X-Netapp-asup-hostname: nbt1-11",
                    "X-Netapp-asup-partner-hostname: nbt1-12",
                    "X-Netapp-asup-cluster-name: nbt1",
                    "X-Netapp-asup-os-version: NetApp Release 9.16.1P11: Thu Jan 15 06:21:38 EST 2026",
                    "X-Netapp-asup-generated-on: Mon Jun 22 10:23:43 +0800 2026",
                    "X-Netapp-asup-model-name: FAS9000",
                ]
            ),
            "coredump-status.xml": """
                <T_COREDUMP_STATUS>
                  <ROW>
                    <node>nbt1-11</node>
                    <state>saving</state>
                    <corename>core.123</corename>
                    <coredump_type>kernel</coredump_type>
                    <blocks_saved>10</blocks_saved>
                    <total_blocks_core_being_saved>100</total_blocks_core_being_saved>
                  </ROW>
                </T_COREDUMP_STATUS>
            """,
            "panic-context.xml": """
                <T_EMS_LOCAL_LOG xmlns:asup="http://asup_search.netapp.com/ns/ASUP/1.1">
                  <asup:ROW>
                    <time>6/22/2026 10:21:52</time>
                    <severity>EMERGENCY</severity>
                    <source>panic</source>
                    <messagename>callhome.panic</messagename>
                    <parameters><asup:list><asup:li>panic_string: page fault</asup:li></asup:list></parameters>
                  </asup:ROW>
                </T_EMS_LOCAL_LOG>
            """,
            "EMS-LOG-FILE.gz": 'PANIC: page fault on nbt1-11\nFAILOVER: TakeOver for raid done\n',
        }

        bundle = parse_panic_evidence(files)
        summary = {item["name"]: item["value"] for item in bundle.summary}

        self.assertEqual(summary["node"], "nbt1-11")
        self.assertEqual(summary["partner_node"], "nbt1-12")
        self.assertEqual(summary["cluster"], "nbt1")
        self.assertEqual(summary["ontap_version"], "NetApp Release 9.16.1P11: Thu Jan 15 06:21:38 EST 2026")
        self.assertEqual(summary["coredump_state"], "saving")
        self.assertEqual(summary["coredump_name"], "core.123")
        self.assertEqual(summary["panic_event"]["message_name"], "callhome.panic")
        self.assertEqual(summary["panic_string"], "page fault")
        self.assertTrue(any(ref["file"] == "EMS-LOG-FILE.gz" for ref in bundle.raw_refs))

    def test_parse_panic_evidence_handles_missing_files(self):
        bundle = parse_panic_evidence({})

        self.assertEqual(bundle.summary, [])
        self.assertEqual(bundle.files_used, [])
        self.assertEqual(bundle.raw_refs, [])


if __name__ == "__main__":
    unittest.main()
