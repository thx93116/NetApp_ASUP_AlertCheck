import unittest

from netapp_asup_alertcheck.priority import classify_priority, extract_event_title, should_skip_email_analysis


class PriorityTests(unittest.TestCase):
    def test_p1_subject_signals(self):
        cases = [
            "[外部] HA Group Notification from nbt1-11 (CONTROLLER TAKEOVER COMPLETE PANIC) EMERGENCY",
            "[❗️外部❗️] HA Group Notification from nbt1-01 (CLUSTER NETWORK DEGRADED) ALERT",
            "HA Group Notification from nbt1-02 POWER SUPPLY DEGRADED ALERT",
            "HA Group Notification from nbt1-03 CHASSIS POWER DEGRADED ALERT",
        ]

        for subject in cases:
            with self.subTest(subject=subject):
                self.assertEqual(classify_priority(subject), "P1")

    def test_p2_subject_signals(self):
        cases = [
            "HA Group Notification from nbt1-01 (SPARES_LOW) ALERT",
            "HA Group Notification from nbt1-02 (DISK REDUNDANCY FAILED) ALERT",
            "HA Group Notification from nbt1-03 SinglePath WARNING",
        ]

        for subject in cases:
            with self.subTest(subject=subject):
                self.assertEqual(classify_priority(subject), "P2")

    def test_p1_wins_when_subject_has_p1_and_p2(self):
        subject = "HA Group Notification from nbt1-01 PANIC SinglePath ALERT"

        self.assertEqual(classify_priority(subject), "P1")

    def test_reboot_power_on_is_no_send_and_skipped_for_email_mode(self):
        subject = "[❗️外部❗️] HA Group Notification from nbt1-12 (REBOOT (power on)) NOTICE"

        self.assertIsNone(classify_priority(subject))
        self.assertTrue(should_skip_email_analysis(subject))
        self.assertEqual(extract_event_title(subject), "nbt1-12 (REBOOT (power on)) NOTICE")


if __name__ == "__main__":
    unittest.main()
