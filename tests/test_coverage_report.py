"""Tests for attack_coverage.report — TDD per task-7-brief."""
import copy
import unittest


class TestCoverageReport(unittest.TestCase):
    def _build(self, catalog=None):
        from attack_coverage.report import build_report
        return build_report(catalog)

    # ── metric ──────────────────────────────────────────────────────────────

    def test_report_metric_excludes_out_of_scope(self):
        catalog = {
            "attack_version": "test",
            "techniques": [
                {"id": "T1001", "name": "A", "tactic": "t", "status": "covered",
                 "detector": "detect_privilege_grant",
                 "fixture": "fixtures/incidents/account_manipulation.json", "reason": None},
                {"id": "T1002", "name": "B", "tactic": "t", "status": "not-covered",
                 "detector": None, "fixture": None, "reason": None},
                {"id": "T1003", "name": "C", "tactic": "t", "status": "out-of-scope",
                 "detector": None, "fixture": None,
                 "reason": "excluded"},
            ],
        }
        r = self._build(catalog)
        # covered=1, total=3, out_of_scope=1 → coverage = 1/(3-1) = 0.5
        self.assertAlmostEqual(r["coverage"], 0.5)

    # ── shipped catalog ──────────────────────────────────────────────────────

    def test_shipped_catalog_has_no_regressions(self):
        r = self._build()
        self.assertEqual(r["regressions"], [])

    def test_shipped_catalog_has_no_dangling(self):
        r = self._build()
        self.assertEqual(r["dangling"], [])

    def test_no_inscope_left_not_covered(self):
        r = self._build()
        self.assertEqual(r["not_covered"], [])

    # ── dangling detection ───────────────────────────────────────────────────

    def test_dangling_detector_is_caught(self):
        from attack_coverage.catalog import load_catalog
        catalog = copy.deepcopy(load_catalog())
        # inject a bad fixture into the first covered/partial entry
        for t in catalog["techniques"]:
            if t.get("status") in ("covered", "partial"):
                t["fixture"] = "fixtures/incidents/nope.json"
                break
        r = self._build(catalog)
        self.assertTrue(len(r["dangling"]) > 0)


if __name__ == "__main__":
    unittest.main()
