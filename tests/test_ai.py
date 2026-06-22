import unittest

from netapp_asup_alertcheck.ai import build_messages, parse_ai_json


class AiTests(unittest.TestCase):
    def test_build_messages_contains_evidence_and_json_instruction(self):
        messages = build_messages(
            question_direction="Confirm ARW evidence",
            evidence={"summary": [{"name": "attack_probability", "value": "moderate"}]},
        )

        self.assertEqual(messages[0]["role"], "system")
        self.assertIn("strict JSON", messages[0]["content"])
        self.assertIn("attack_probability", messages[1]["content"])

    def test_parse_ai_json_rejects_non_object(self):
        with self.assertRaises(ValueError):
            parse_ai_json("[1, 2, 3]")

    def test_parse_ai_json_accepts_object(self):
        result = parse_ai_json('{"status":"possible","severity":"high","confidence":0.8}')
        self.assertEqual(result["severity"], "high")


if __name__ == "__main__":
    unittest.main()
