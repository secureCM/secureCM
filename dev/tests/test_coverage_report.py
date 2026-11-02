"""Tests for attack_coverage.report — TDD per task-7-brief."""
import copy
import json
import pathlib
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
INCIDENTS = REPO / "dev" / "fixtures" / "incidents"


class TestNativeFixtureMigration(unittest.TestCase):
    """Task-7-brief required tests: native fixtures, logs-only derivation, campaigns."""

    def test_coverage_report_no_regressions_on_native(self):
        """build_report() regressions == [] and not_covered == [] on native fixtures."""
        import importlib.util as _ilu; _spec = _ilu.spec_from_file_location('dev_report', str(pathlib.Path(__file__).resolve().parent.parent / 'report.py')); _mod = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_mod); build_report = _mod.build_report
        r = build_report()
        self.assertEqual(r["regressions"], [],
                         f"Regressions on native fixtures: {r['regressions']}")
        self.assertEqual(r["not_covered"], [],
                         f"Not-covered items: {r['not_covered']}")

    def test_every_change_derived_from_logs(self):
        """Loaded haystack has NO top-level audit_changes key; changes come only from log_entries."""
        with open(INCIDENTS / "inscope_haystack.json") as f:
            haystack = json.load(f)
        self.assertNotIn(
            "audit_changes", haystack,
            "Native haystack must not have a top-level audit_changes key",
        )
        self.assertIn(
            "log_entries", haystack,
            "Native haystack must have a log_entries key",
        )
        # Changes must derive successfully from log_entries
        from gcp_policy_analyzer.loaders import load_audit_changes
        changes = load_audit_changes(haystack)
        self.assertGreater(len(changes), 0,
                           "Expected changes derived from log_entries")

    def test_six_campaigns_still_detected(self):
        """run_detectors on native haystack still yields the six campaigns' technique ids."""
        with open(INCIDENTS / "inscope_haystack.json") as f:
            haystack = json.load(f)
        from attack_coverage.signatures import run_detectors
        findings = run_detectors(haystack)
        technique_ids = {f.technique_id for f in findings}
        # Ground-truth campaign techniques
        expected = {
            "T1098.003",  # campaign-a
            "T1199",      # campaign-a + campaign-d
            "T1562.007",  # campaign-b + campaign-c + campaign-f
            "T1098",      # campaign-e
        }
        for tid in expected:
            self.assertIn(
                tid, technique_ids,
                f"Expected technique {tid} from campaigns not found in findings {technique_ids}",
            )


class TestCoverageReport(unittest.TestCase):
    def _build(self, catalog=None):
        import importlib.util as _ilu; _spec = _ilu.spec_from_file_location('dev_report', str(pathlib.Path(__file__).resolve().parent.parent / 'report.py')); _mod = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_mod); build_report = _mod.build_report
        return build_report(catalog)

    # ── metric ──────────────────────────────────────────────────────────────

    def test_report_metric_excludes_out_of_scope(self):
        catalog = {
            "attack_version": "test",
            "techniques": [
                {"id": "T1001", "name": "A", "tactic": "t", "status": "covered",
                 "detector": "detect_privilege_grant",
                 "fixture": "dev/fixtures/incidents/account_manipulation.json", "reason": None},
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
                t["fixture"] = "dev/fixtures/incidents/nope.json"
                break
        r = self._build(catalog)
        self.assertTrue(len(r["dangling"]) > 0)

    # ── partial gate ─────────────────────────────────────────────────────────

    def test_partial_real_detector_flagged_as_regression(self):
        """A partial entry whose real finding-emitter detector fires nothing → regression."""
        # detect_privilege_grant is a real Finding-emitter; use account_manipulation.json
        # but point the technique at a fixture that produces no T1999.001 finding.
        catalog = {
            "attack_version": "test",
            "techniques": [
                {
                    "id": "T1999.001",
                    "name": "Fake Partial",
                    "tactic": "persistence",
                    "status": "partial",
                    "detector": "detect_privilege_grant",
                    # account_manipulation.json fires T1098 findings, not T1999.001
                    "fixture": "dev/fixtures/incidents/account_manipulation.json",
                    "verified": False,
                    "reason": None,
                }
            ],
        }
        r = self._build(catalog)
        self.assertIn("T1999.001", r["regressions"],
                      "partial with real detector that emits no matching finding must be a regression")

    def test_partial_enrich_with_enablers_not_flagged(self):
        """enrich_with_enablers partial entry is never flagged as a regression."""
        catalog = {
            "attack_version": "test",
            "techniques": [
                {
                    "id": "T1098.001",
                    "name": "Additional Cloud Credentials",
                    "tactic": "persistence",
                    "status": "partial",
                    "detector": "enrich_with_enablers",
                    "fixture": "dev/fixtures/incidents/sa_key_enabler.json",
                    "verified": None,
                    "reason": None,
                }
            ],
        }
        r = self._build(catalog)
        self.assertNotIn("T1098.001", r["regressions"],
                         "enrich_with_enablers partial must never appear in regressions")


if __name__ == "__main__":
    unittest.main()
