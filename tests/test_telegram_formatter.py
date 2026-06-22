import unittest

from netapp_asup_alertcheck.formatters.telegram import build_notification


class TelegramFormatterTests(unittest.TestCase):
    def test_build_notification_for_p1_panic(self):
        result = {
            "message": {
                "subject": "[外部] HA Group Notification from nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY",
                "from": "autosupport@mail.realtek.com",
            },
            "classification": {"matched_rule_id": "node_panic_takeover_complete"},
            "evidence": {
                "summary": [
                    {"name": "node", "value": "nbt1-11"},
                    {"name": "partner_node", "value": "nbt1-12"},
                    {"name": "ontap_version", "value": "NetApp Release 9.16.1P11"},
                    {"name": "coredump_state", "value": "saving"},
                    {"name": "panic_string", "value": "page fault"},
                ]
            },
        }

        notification = build_notification(
            result,
            asup_metadata={"generated_on": "Mon Jun 22 10:23:43 +0800 2026"},
        )

        self.assertEqual(notification["customer"], "RTK")
        self.assertEqual(notification["priority"], "P1")
        self.assertTrue(notification["should_send"])
        self.assertEqual(notification["generated_on"], "Mon Jun 22 10:23:43 +0800 2026")
        self.assertEqual(
            notification["event_title"],
            "nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY",
        )
        self.assertIn("[NetApp ASUP] RTK - P1", notification["telegram_text"])
        self.assertIn("nbt1-11 發生 controller panic", notification["telegram_text"])
        self.assertIn("panic string: page fault", notification["telegram_text"])

    def test_build_notification_for_reboot_power_on_is_no_send(self):
        result = {
            "message": {
                "subject": "[外部] HA Group Notification from nbt1-12 (REBOOT (power on)) NOTICE",
                "from": "autosupport@mail.realtek.com",
            },
            "classification": {"matched_rule_id": "node_reboot_power_on"},
            "evidence": {"summary": []},
        }

        notification = build_notification(
            result,
            asup_metadata={"generated_on": "Mon Jun 22 13:25:32 +0800 2026"},
        )

        self.assertEqual(notification["customer"], "RTK")
        self.assertIsNone(notification["priority"])
        self.assertFalse(notification["should_send"])
        self.assertEqual(notification["telegram_text"], "")
        self.assertEqual(notification["summary"], "")


if __name__ == "__main__":
    unittest.main()
