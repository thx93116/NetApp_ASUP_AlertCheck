import unittest

from netapp_asup_alertcheck.customer import customer_from_address


class CustomerTests(unittest.TestCase):
    def test_customer_from_known_sender_domain(self):
        self.assertEqual(customer_from_address("autosupport@mail.realtek.com"), "RTK")
        self.assertEqual(customer_from_address("autosupport@mediatek.com"), "MTK")
        self.assertEqual(customer_from_address("autosupport@nuvoton.com"), "NVTK")
        self.assertEqual(customer_from_address("autosupport@innolux.com"), "INX")

    def test_customer_from_unknown_or_missing_sender_domain(self):
        self.assertEqual(customer_from_address("autosupport@example.com"), "UNKNOWN")
        self.assertEqual(customer_from_address(None), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
