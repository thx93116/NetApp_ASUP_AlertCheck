import unittest

from netapp_asup_alertcheck.email_body import parse_asup_body


class EmailBodyTests(unittest.TestCase):
    def test_parse_asup_body_maps_known_fields_and_strips_quotes(self):
        text = (
            "CONFIDENTIALITY=NetApp Confidential\n"
            "GENERATED_ON=Mon Jun 22 13:25:32 +0800 2026\n"
            "VERSION=NetApp Release 9.16.1P11: Thu Jan 15 06:21:38 EST 2026\n"
            "SYSTEM_ID=0537420918\n"
            "SERIAL_NUM=792206000367\n"
            "HOSTNAME=nbt1-12\n"
            "SEQUENCE=6035\n"
            "PARTNER_SYSTEM_ID=0537420884\n"
            "PARTNER_HOSTNAME=nbt1-11\n"
            "BOOT_CLUSTERED='true'\n"
        )

        result = parse_asup_body(text)

        self.assertEqual(result["generated_on"], "Mon Jun 22 13:25:32 +0800 2026")
        self.assertEqual(result["version"], "NetApp Release 9.16.1P11: Thu Jan 15 06:21:38 EST 2026")
        self.assertEqual(result["system_id"], "0537420918")
        self.assertEqual(result["serial_num"], "792206000367")
        self.assertEqual(result["hostname"], "nbt1-12")
        self.assertEqual(result["sequence"], "6035")
        self.assertEqual(result["partner_system_id"], "0537420884")
        self.assertEqual(result["partner_hostname"], "nbt1-11")
        self.assertEqual(result["boot_clustered"], "true")
        self.assertNotIn("confidentiality", result)


if __name__ == "__main__":
    unittest.main()
