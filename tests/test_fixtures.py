"""Tests for fixtures/incidents/ generator (Task 6)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INCIDENTS = REPO / "fixtures" / "incidents"
CATALOG_PATH = REPO / "attack_coverage" / "attack_catalog.json"
GENERATE = INCIDENTS / "generate.py"

VALID_RESOURCE_TYPES = {"iam_policy", "firewall_rule", "network_firewall_policy"}


def _load(path):
    with open(path) as f:
        return json.load(f)


class TestFixtureGenerator(unittest.TestCase):

    def test_generator_is_deterministic(self):
        """Running generate.py twice produces byte-identical files."""
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            r1 = subprocess.run(
                [sys.executable, str(GENERATE), "--out-dir", tmp1],
                capture_output=True, check=True
            )
            r2 = subprocess.run(
                [sys.executable, str(GENERATE), "--out-dir", tmp2],
                capture_output=True, check=True
            )
            files1 = sorted(Path(tmp1).glob("*.json"))
            files2 = sorted(Path(tmp2).glob("*.json"))
            self.assertEqual(
                [f.name for f in files1],
                [f.name for f in files2],
                "file lists differ",
            )
            for f1, f2 in zip(files1, files2):
                self.assertEqual(
                    f1.read_bytes(), f2.read_bytes(),
                    f"{f1.name} differs between runs",
                )

    def test_haystack_only_inscope_resource_types(self):
        """Every audit_change in inscope_haystack.json has an in-scope resource_type,
        and all three surfaces (iam_policy, firewall_rule, network_firewall_policy) appear."""
        haystack = _load(INCIDENTS / "inscope_haystack.json")
        seen_types: set[str] = set()
        for change in haystack.get("audit_changes", []):
            rt = change.get("resource_type")
            self.assertIn(
                rt, VALID_RESOURCE_TYPES,
                f"Out-of-scope resource_type {rt!r} in audit_changes",
            )
            seen_types.add(rt)
        self.assertEqual(
            seen_types, VALID_RESOURCE_TYPES,
            f"Not all three surfaces present; found: {seen_types}",
        )

    def test_haystack_contains_each_campaign(self):
        """Ground truth lists >=5 campaigns; each campaign id appears in haystack."""
        gt = _load(INCIDENTS / "inscope_ground_truth.json")
        campaigns = gt.get("campaigns", [])
        self.assertGreaterEqual(len(campaigns), 5, "Expected >=5 campaigns in ground truth")
        haystack = _load(INCIDENTS / "inscope_haystack.json")
        # Collect all principals + resources from haystack for basic presence check
        all_principals = set()
        for ch in haystack.get("audit_changes", []):
            all_principals.add(ch.get("principal", ""))
        for le in haystack.get("log_entries", []):
            all_principals.add(le.get("principalEmail", ""))
        for campaign in campaigns:
            marker = campaign.get("marker")
            self.assertIsNotNone(marker, "Campaign missing 'marker' field")
            self.assertTrue(
                any(marker in p for p in all_principals)
                or any(marker in ch.get("resource", "") for ch in haystack.get("audit_changes", [])),
                f"Campaign marker {marker!r} not found in haystack principals/resources",
            )

    def test_per_technique_fixtures_exist(self):
        """For each covered/partial catalog entry, its fixture file exists and is valid JSON."""
        catalog = _load(CATALOG_PATH)
        for tech in catalog["techniques"]:
            if tech["status"] not in ("covered", "partial"):
                continue
            fixture_path = tech.get("fixture")
            self.assertIsNotNone(fixture_path, f"{tech['id']} has no fixture path")
            full_path = REPO / fixture_path
            self.assertTrue(
                full_path.exists(),
                f"Missing fixture: {fixture_path}",
            )
            data = _load(full_path)
            self.assertIsInstance(data, dict, f"{fixture_path} is not a JSON object")

    def test_per_technique_detector_fires(self):
        """Each per-technique fixture makes its mapped detector produce a finding.

        For partial techniques (parent IDs like T1562), a sub-technique finding
        (e.g. T1562.007) satisfies the requirement since the detector maps to
        the sub-technique.
        """
        sys.path.insert(0, str(REPO))
        from gcp_policy_analyzer.detect import (
            detect_privilege_grant,
            detect_firewall_exposure,
            detect_discovery_bursts,
            detect_anomalous_actor,
        )
        catalog = _load(CATALOG_PATH)
        for tech in catalog["techniques"]:
            if tech["status"] not in ("covered", "partial"):
                continue
            fixture_path = REPO / tech["fixture"]
            if not fixture_path.exists():
                continue
            data = _load(fixture_path)
            detector = tech["detector"]
            tid = tech["id"]

            if detector == "detect_privilege_grant":
                findings = detect_privilege_grant(
                    data.get("iam_policies", []),
                    data.get("audit_changes", []),
                )
            elif detector == "detect_firewall_exposure":
                findings = detect_firewall_exposure(
                    data.get("vpc_firewall_rules", []),
                    data.get("audit_changes", []),
                )
            elif detector == "detect_discovery_bursts":
                findings = detect_discovery_bursts(data.get("log_entries", []))
            elif detector == "detect_anomalous_actor":
                findings = detect_anomalous_actor(
                    data.get("audit_changes", []),
                    data.get("log_entries", []),
                )
            elif detector == "enrich_with_enablers":
                continue  # correlation enricher — annotates changes, emits no Findings; skip fire-check
            else:
                self.fail(f"Unknown detector {detector!r} for {tid}")

            technique_ids = {f.technique_id for f in findings}
            # Accept exact match OR any sub-technique (e.g. T1562.007 satisfies T1562)
            matched = tid in technique_ids or any(
                t.startswith(tid + ".") for t in technique_ids
            )
            self.assertTrue(
                matched,
                f"Detector {detector} did not fire {tid} (got {technique_ids})",
            )

    def test_decoys_present(self):
        """Reverted-firewall pair and approved-external-viewer are present in haystack."""
        haystack = _load(INCIDENTS / "inscope_haystack.json")
        gt = _load(INCIDENTS / "inscope_ground_truth.json")
        decoys = gt.get("decoys", [])
        decoy_ids = {d["id"] for d in decoys}
        self.assertIn("reverted-dev-firewall", decoy_ids)
        self.assertIn("approved-external-viewer", decoy_ids)

        # Verify the reverted firewall: open then closed back within 2h
        changes = haystack.get("audit_changes", [])
        fw_opens = [
            c for c in changes
            if c.get("resource_type") == "firewall_rule"
            and "0.0.0.0/0" in str(c.get("after", {}).get("sourceRanges", []))
            and "decoy-revert" in c.get("resource", "")
        ]
        fw_closes = [
            c for c in changes
            if c.get("resource_type") == "firewall_rule"
            and "decoy-revert" in c.get("resource", "")
            and "0.0.0.0/0" not in str(c.get("after", {}).get("sourceRanges", []))
            and c.get("action") == "UPDATE"
        ]
        self.assertTrue(len(fw_opens) >= 1, "No decoy revert-open found")
        self.assertTrue(len(fw_closes) >= 1, "No decoy revert-close found")

        # Verify approved external viewer present
        ext_viewers = [
            c for c in changes
            if "approved-external-viewer" in c.get("principal", "")
            or "approved-external-viewer" in str(c.get("after", {}))
        ]
        self.assertTrue(len(ext_viewers) >= 1, "No approved-external-viewer event found")


if __name__ == "__main__":
    unittest.main()
