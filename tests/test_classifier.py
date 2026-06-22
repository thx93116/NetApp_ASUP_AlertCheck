import unittest

from netapp_asup_alertcheck.classifier import (
    CONFIDENCE_GENERIC,
    CONFIDENCE_MULTI_SIGNAL,
    classify_message,
    normalize_subject,
)
from netapp_asup_alertcheck.models import Rule
from netapp_asup_alertcheck.registry import RuleRegistry


def build_rule(
    rule_id: str = "arw_activity_seen",
    enabled: bool = True,
    subject_contains: str = "POSSIBLE RANSOMWARE ACTIVITY DETECTED",
    header_trigger: str = "callhome.arw.activity.seen",
    alert_type: str = "ransomware",
    parser: str = "arw",
) -> Rule:
    return Rule(
        rule_id=rule_id,
        enabled=enabled,
        priority=100,
        subject_contains=subject_contains,
        header_trigger=header_trigger,
        alert_type=alert_type,
        parser=parser,
        question_direction="Confirm details.",
    )


class ClassifierTests(unittest.TestCase):
    def test_normalize_subject_removes_external_markers(self):
        cases = [
            ("[External] POSSIBLE RANSOMWARE ACTIVITY DETECTED", "POSSIBLE RANSOMWARE ACTIVITY DETECTED"),
            ("[External]: POSSIBLE RANSOMWARE ACTIVITY DETECTED", "POSSIBLE RANSOMWARE ACTIVITY DETECTED"),
            ("[EXT] POSSIBLE RANSOMWARE ACTIVITY DETECTED", "POSSIBLE RANSOMWARE ACTIVITY DETECTED"),
            ("[External Sender] POSSIBLE RANSOMWARE ACTIVITY DETECTED", "POSSIBLE RANSOMWARE ACTIVITY DETECTED"),
            ("[外部] POSSIBLE RANSOMWARE ACTIVITY DETECTED", "POSSIBLE RANSOMWARE ACTIVITY DETECTED"),
            ("[外部郵件] POSSIBLE RANSOMWARE ACTIVITY DETECTED", "POSSIBLE RANSOMWARE ACTIVITY DETECTED"),
            ("[❗️外部❗️] POSSIBLE RANSOMWARE ACTIVITY DETECTED", "POSSIBLE RANSOMWARE ACTIVITY DETECTED"),
            ("External: POSSIBLE RANSOMWARE ACTIVITY DETECTED", "POSSIBLE RANSOMWARE ACTIVITY DETECTED"),
            ("CAUTION: External Email POSSIBLE RANSOMWARE ACTIVITY DETECTED", "POSSIBLE RANSOMWARE ACTIVITY DETECTED"),
            ("CAUTION - External Email POSSIBLE RANSOMWARE ACTIVITY DETECTED", "POSSIBLE RANSOMWARE ACTIVITY DETECTED"),
            (
                "[External]: [外部郵件] - CAUTION: External Email POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                "POSSIBLE RANSOMWARE ACTIVITY DETECTED",
            ),
            (" [External Sender]   -   Actual: Subject - Keep ", "Actual: Subject - Keep"),
        ]

        for subject, expected in cases:
            with self.subTest(subject=subject):
                self.assertEqual(normalize_subject(subject), expected)

    def test_classify_uses_subject_and_header_trigger(self):
        registry = RuleRegistry(rules=[build_rule()])

        classification = classify_message(
            "[EXT] possible ransomware activity detected",
            {"X-NetApp-Trigger": "CALLHOME.ARW.ACTIVITY.SEEN"},
            registry,
        )

        self.assertEqual(classification.matched_rule_id, "arw_activity_seen")
        self.assertEqual(classification.parser, "arw")
        self.assertEqual(
            classification.matched_signals,
            ["subject_contains", "header_trigger"],
        )
        self.assertEqual(classification.confidence, CONFIDENCE_MULTI_SIGNAL)

    def test_disabled_rules_are_ignored(self):
        registry = RuleRegistry(rules=[build_rule(enabled=False)])

        classification = classify_message(
            "POSSIBLE RANSOMWARE ACTIVITY DETECTED",
            {"X-NetApp-Trigger": "callhome.arw.activity.seen"},
            registry,
        )

        self.assertEqual(classification.matched_rule_id, "generic_autosupport")
        self.assertEqual(classification.matched_signals, [])

    def test_unknown_subject_uses_generic_classification(self):
        registry = RuleRegistry(rules=[build_rule()])

        classification = classify_message(
            "Daily autosupport",
            {"X-NetApp-Trigger": "callhome.normal"},
            registry,
        )

        self.assertEqual(classification.matched_rule_id, "generic_autosupport")
        self.assertEqual(classification.alert_type, "unknown")
        self.assertEqual(classification.parser, "generic")
        self.assertEqual(classification.confidence, CONFIDENCE_GENERIC)
        self.assertEqual(classification.matched_signals, [])


if __name__ == "__main__":
    unittest.main()
