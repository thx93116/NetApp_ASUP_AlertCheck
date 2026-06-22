import unittest

from netapp_asup_alertcheck.kb import build_kb_queries
from netapp_asup_alertcheck.models import KBQueryRule


class KbTests(unittest.TestCase):
    def test_build_kb_queries_formats_available_context(self):
        rules = [
            KBQueryRule(
                rule_id="arw_activity_seen",
                condition="ai_requests_kb",
                query_template="NetApp {header_trigger} {ontap_version}",
            )
        ]
        context = {
            "header_trigger": "callhome.arw.activity.seen",
            "ontap_version": "9.18.1P2",
        }

        self.assertEqual(
            build_kb_queries(rules, context),
            ["NetApp callhome.arw.activity.seen 9.18.1P2"],
        )

    def test_missing_context_keeps_token_readable(self):
        rules = [KBQueryRule("arw", "low_confidence", "NetApp {missing}")]
        self.assertEqual(build_kb_queries(rules, {}), ["NetApp missing"])


if __name__ == "__main__":
    unittest.main()
