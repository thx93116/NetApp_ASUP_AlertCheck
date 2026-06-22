import unittest
from pathlib import Path

from netapp_asup_alertcheck.registry import load_registry_from_dir


ROOT = Path(__file__).resolve().parents[1]


class SeedRuleTests(unittest.TestCase):
    def test_seed_rules_include_power_on_reboot(self):
        registry = load_registry_from_dir(ROOT / "data" / "rules")
        rules = {rule.rule_id: rule for rule in registry.rules}

        self.assertIn("node_reboot_power_on", rules)
        self.assertEqual(rules["node_reboot_power_on"].subject_contains, "REBOOT (power on)")
        self.assertEqual(rules["node_reboot_power_on"].alert_type, "node_reboot")
        self.assertEqual(rules["node_reboot_power_on"].parser, "panic")
        self.assertIn("node_reboot_power_on", registry.evidence_files)
        self.assertIn("node_reboot_power_on", registry.kb_queries)


if __name__ == "__main__":
    unittest.main()
