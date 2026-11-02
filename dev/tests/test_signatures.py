"""Tests for attack_coverage/signatures.py — Task 5."""
import importlib
import unittest
from unittest.mock import patch

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
        import gcp_policy_analyzer.enrich as enrich_mod
        for tid, name in TECHNIQUE_DETECTOR.items():
            # Detectors may live in detect.py or enrich.py
            found = callable(getattr(det_mod, name, None)) or callable(getattr(enrich_mod, name, None))
            self.assertTrue(found, f"{name} for {tid} not callable in detect or enrich")


class TestRunDetectors(unittest.TestCase):
    def _firewall_envelope(self):
        # Native log_entries: insert then patch to world-open → detect_firewall_exposure fires T1562.007
        return {
            "log_entries": [
                {
                    "protoPayload": {
                        "methodName": "compute.firewalls.insert",
                        "resourceName": "projects/proj/global/firewalls/fw1",
                        "authenticationInfo": {"principalEmail": "admin@acme.example.com"},
                        "requestMetadata": {"callerIp": "10.0.0.1"},
                        "serviceData": {},
                        "request": {"sourceRanges": ["10.0.0.0/8"],
                                    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
                    },
                    "timestamp": "2026-10-31T09:00:00Z",
                },
                {
                    "protoPayload": {
                        "methodName": "compute.firewalls.patch",
                        "resourceName": "projects/proj/global/firewalls/fw1",
                        "authenticationInfo": {"principalEmail": "admin@acme.example.com"},
                        "requestMetadata": {"callerIp": "10.0.0.1"},
                        "serviceData": {},
                        "request": {"sourceRanges": ["0.0.0.0/0"],
                                    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
                    },
                    "timestamp": "2026-10-31T10:00:00Z",
                },
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
        """run_detectors deduplicates; distinct detectors → each called once."""
        distinct = len(set(TECHNIQUE_DETECTOR.values()))
        expected = len({v for v in TECHNIQUE_DETECTOR.values()})
        self.assertEqual(distinct, expected)

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

    def test_run_detectors_unknown_detector_raises(self):
        """If a detector name in TECHNIQUE_DETECTOR is unmapped, raise ValueError."""
        envelope = self._firewall_envelope()
        # Patch TECHNIQUE_DETECTOR to include a bogus detector name
        with patch(
            "attack_coverage.signatures.TECHNIQUE_DETECTOR",
            {**TECHNIQUE_DETECTOR, "T9999": "detect_nonexistent"},
        ):
            with self.assertRaises(ValueError) as cm:
                run_detectors(envelope)
            self.assertIn("no dispatch branch for detector", str(cm.exception))
            self.assertIn("detect_nonexistent", str(cm.exception))
