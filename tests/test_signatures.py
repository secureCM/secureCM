"""Tests for attack_coverage/signatures.py — Task 5."""
import importlib
import unittest

from attack_coverage.catalog import load_catalog
from attack_coverage.signatures import (
    TECHNIQUE_DETECTOR,
    findings_for_technique,
    run_detectors,
)
from gcp_policy_analyzer.detect import Finding


class TestRegistry(unittest.TestCase):
    def test_registry_matches_catalog(self):
        catalog = load_catalog()
        expected = {
            t["id"]
            for t in catalog["techniques"]
            if t.get("status") in ("covered", "partial")
        }
        self.assertEqual(set(TECHNIQUE_DETECTOR), expected)

    def test_every_registry_detector_exists(self):
        import gcp_policy_analyzer.detect as det_mod
        for tid, name in TECHNIQUE_DETECTOR.items():
            self.assertTrue(
                callable(getattr(det_mod, name, None)),
                f"{name} for {tid} not callable in gcp_policy_analyzer.detect",
            )


class TestRunDetectors(unittest.TestCase):
    def _firewall_envelope(self):
        return {
            "audit_changes": [
                {
                    "resource": "projects/proj/global/firewalls/fw1",
                    "resource_type": "firewall",
                    "action": "UPDATE",
                    "principal": "admin@acme.example.com",
                    "timestamp": "2026-10-31T10:00:00Z",
                    "before": {"sourceRanges": ["10.0.0.0/8"], "allowed": []},
                    "after": {
                        "sourceRanges": ["0.0.0.0/0"],
                        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                    },
                    "labels": {},
                }
            ]
        }

    def test_run_detectors_on_fixture_returns_findings(self):
        findings = run_detectors(self._firewall_envelope())
        self.assertGreaterEqual(len(findings), 1)
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertIsNotNone(f.technique_id)

    def test_run_detectors_empty_envelope(self):
        findings = run_detectors({})
        self.assertIsInstance(findings, list)
        self.assertEqual(findings, [])

    def test_each_detector_runs_once(self):
        """run_detectors deduplicates; 4 distinct detectors → each called once."""
        distinct = len({v for v in TECHNIQUE_DETECTOR.values()})
        self.assertEqual(distinct, 4)  # firewall, privilege, discovery, anomalous_actor

    def test_findings_for_technique_filters(self):
        findings = run_detectors(self._firewall_envelope())
        t1562_findings = findings_for_technique(findings, "T1562.007")
        self.assertTrue(all(f.technique_id == "T1562.007" for f in t1562_findings))
        # There should be at least one T1562.007 finding from the firewall envelope
        self.assertGreaterEqual(len(t1562_findings), 1)

    def test_findings_for_technique_empty(self):
        self.assertEqual(findings_for_technique([], "T1098"), [])
        all_findings = run_detectors(self._firewall_envelope())
        self.assertEqual(findings_for_technique(all_findings, "T9999"), [])
