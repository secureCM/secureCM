"""ATT&CK coverage catalog tests."""
import unittest
import copy
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_coverage.catalog import load_catalog, validate_catalog


class TestCatalog(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()
        cls.techniques = {t["id"]: t for t in cls.catalog["techniques"]}

    def test_catalog_loads_with_version(self):
        self.assertEqual(self.catalog["attack_version"], "15.1")

    def test_inscope_techniques_present_with_detectors(self):
        t1562 = self.techniques["T1562.007"]
        self.assertEqual(t1562["status"], "covered")
        self.assertEqual(t1562["detector"], "detect_firewall_exposure")

        t1098 = self.techniques["T1098.003"]
        self.assertEqual(t1098["status"], "covered")
        self.assertIsNotNone(t1098["detector"])

        t1199 = self.techniques["T1199"]
        self.assertEqual(t1199["status"], "partial")

    def test_every_out_of_scope_has_reason(self):
        for t in self.catalog["techniques"]:
            if t["status"] == "out-of-scope":
                self.assertTrue(
                    t.get("reason") and len(t["reason"]) > 0,
                    f"{t['id']} missing reason"
                )

    def test_covered_partial_name_detector_and_fixture(self):
        for t in self.catalog["techniques"]:
            if t["status"] in ("covered", "partial"):
                self.assertIsNotNone(t.get("detector"), f"{t['id']} missing detector")
                self.assertIsInstance(t["detector"], str, f"{t['id']} detector not str")
                self.assertIsNotNone(t.get("fixture"), f"{t['id']} missing fixture")
                self.assertIsInstance(t["fixture"], str, f"{t['id']} fixture not str")

    def test_validate_flags_missing_reason(self):
        bad = copy.deepcopy(self.catalog)
        # find first out-of-scope and null its reason
        for t in bad["techniques"]:
            if t["status"] == "out-of-scope":
                t["reason"] = None
                break
        problems = validate_catalog(bad)
        self.assertTrue(len(problems) > 0)


if __name__ == "__main__":
    unittest.main()
