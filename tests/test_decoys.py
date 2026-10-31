"""Tests that pin the honest current behavior of decoys vs run_detectors.

should_not_alert decoys produce no finding at their resource.
fires_but_benign decoys DO fire their expected technique.
"""
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from attack_coverage.signatures import run_detectors  # noqa: E402


def _load(path):
    with open(path) as f:
        return json.load(f)


class TestDecoys(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        incidents = REPO / "fixtures" / "incidents"
        cls.haystack = _load(incidents / "inscope_haystack.json")
        gt = _load(incidents / "inscope_ground_truth.json")
        cls.decoys = {d["id"]: d for d in gt["decoys"]}
        cls.findings = run_detectors(cls.haystack)

    def _findings_at(self, resource):
        return [f for f in self.findings if f.resource == resource]

    def test_benign_internal_range_widen_produces_no_finding(self):
        """benign-internal-range-widen stays fully internal — no finding expected."""
        decoy = self.decoys["benign-internal-range-widen"]
        self.assertTrue(
            decoy.get("should_not_alert"),
            "benign-internal-range-widen must still be should_not_alert",
        )
        # This decoy has no resource field; verify no allow-internal-range finding fires
        # by checking that no T1562.007 fires on a purely-internal range widening.
        # The haystack has /24-to-/8 changes in allow-internal-* rules; none should fire.
        internal_fw_findings = [
            f for f in self.findings
            if "allow-internal" in f.resource and f.technique_id == "T1562.007"
        ]
        self.assertEqual(
            internal_fw_findings, [],
            f"Expected no T1562.007 for internal-range-only firewall changes, got: {internal_fw_findings}",
        )

    def test_reverted_dev_firewall_fires_t1562_007(self):
        """reverted-dev-firewall: the open fires T1562.007 (stateless detector, can't see the revert)."""
        decoy = self.decoys["reverted-dev-firewall"]
        self.assertTrue(decoy.get("fires_but_benign"), "decoy must be fires_but_benign")
        resource = decoy["resource"]
        technique = decoy["expected_technique"]
        hits = [f for f in self._findings_at(resource) if f.technique_id == technique]
        self.assertTrue(
            hits,
            f"Expected {technique} at {resource!r} but no such finding (drift detected).",
        )

    def test_approved_external_viewer_fires_t1199(self):
        """approved-external-viewer: fires T1199 because non-corp external identity."""
        decoy = self.decoys["approved-external-viewer"]
        self.assertTrue(decoy.get("fires_but_benign"), "decoy must be fires_but_benign")
        resource = decoy["resource"]
        technique = decoy["expected_technique"]
        hits = [f for f in self._findings_at(resource) if f.technique_id == technique]
        self.assertTrue(
            hits,
            f"Expected {technique} at {resource!r} but no such finding (drift detected).",
        )

    def test_expected_staging_owner_sa_fires_t1098_003(self):
        """expected-staging-owner-sa: fires T1098.003 because roles/owner is high-privilege."""
        decoy = self.decoys["expected-staging-owner-sa"]
        self.assertTrue(decoy.get("fires_but_benign"), "decoy must be fires_but_benign")
        resource = decoy["resource"]
        technique = decoy["expected_technique"]
        hits = [f for f in self._findings_at(resource) if f.technique_id == technique]
        self.assertTrue(
            hits,
            f"Expected {technique} at {resource!r} but no such finding (drift detected).",
        )


if __name__ == "__main__":
    unittest.main()
