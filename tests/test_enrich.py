"""Tests for gcp_policy_analyzer.enrich — enabler-event correlation."""
import unittest
from datetime import datetime, timezone

from gcp_policy_analyzer.diff import Change
from attack_coverage.catalog import load_catalog, validate_catalog


def _ts(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _change(principal: str, ts: str) -> Change:
    return Change(
        resource="projects/p/global/firewalls/fw1",
        resource_type="firewall_rule",
        action="UPDATE",
        before={},
        after={"allowed": [{"IPProtocol": "all"}]},
        timestamp=_ts(ts),
        principal=principal,
    )


class TestEnrichWithEnablers(unittest.TestCase):
    def setUp(self):
        from gcp_policy_analyzer.enrich import enrich_with_enablers
        self.enrich = enrich_with_enablers

    def test_keymint_before_inscope_change_annotates(self):
        """CreateServiceAccountKey for SA at t, then SA makes an in-scope Change at t+1h → annotated."""
        sa = "svc@proj.iam.gserviceaccount.com"
        enabler = {
            "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            "principalEmail": sa,
            "timestamp": "2026-10-31T10:00:00Z",
            "resourceName": "projects/proj/serviceAccounts/svc@proj.iam.gserviceaccount.com",
            "callerIp": "1.2.3.4",
        }
        change = _change(sa, "2026-10-31T11:00:00Z")
        result = self.enrich([change], [enabler])
        self.assertIn("enabler", result[0].labels)
        self.assertIn("CreateServiceAccountKey", result[0].labels["enabler"]["method"])
        self.assertEqual(result[0].labels["enabler"]["enabler_ts"], "2026-10-31T10:00:00Z")

    def test_group_add_before_change_annotates(self):
        """google.admin.directory.member.insert then a change by that member → annotated."""
        member = "attacker@example.com"
        enabler = {
            "methodName": "google.admin.directory.member.insert",
            "principalEmail": member,
            "timestamp": "2026-10-30T08:00:00Z",
            "resourceName": "groups/eng-team",
            "callerIp": "5.6.7.8",
        }
        change = _change(member, "2026-10-31T08:00:00Z")
        result = self.enrich([change], [enabler])
        self.assertIn("enabler", result[0].labels)
        self.assertEqual(result[0].labels["enabler"]["method"], "google.admin.directory.member.insert")

    def test_enabler_without_followon_change_no_output(self):
        """Enabler event but no later in-scope change by that principal → no change annotated."""
        enabler = {
            "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            "principalEmail": "other@proj.iam.gserviceaccount.com",
            "timestamp": "2026-10-31T10:00:00Z",
            "resourceName": "projects/proj/serviceAccounts/other",
            "callerIp": "1.2.3.4",
        }
        change = _change("someone_else@example.com", "2026-10-31T11:00:00Z")
        result = self.enrich([change], [enabler])
        self.assertNotIn("enabler", result[0].labels)
        self.assertEqual(len(result), 1)  # no spurious Change created

    def test_enabler_outside_window_not_annotated(self):
        """Enabler more than window_seconds before the change → not annotated."""
        sa = "svc@proj.iam.gserviceaccount.com"
        enabler = {
            "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            "principalEmail": sa,
            "timestamp": "2026-10-29T10:00:00Z",  # 48 h before
            "resourceName": "projects/proj/serviceAccounts/svc",
            "callerIp": "1.2.3.4",
        }
        change = _change(sa, "2026-10-31T10:00:00Z")
        # default window is 86400 s (24 h) — 48 h gap should miss
        result = self.enrich([change], [enabler], window_seconds=86400)
        self.assertNotIn("enabler", result[0].labels)

    def test_catalog_reclassified_partial(self):
        """T1098.001 must have status partial with detector enrich_with_enablers and a fixture."""
        catalog = load_catalog()
        problems = validate_catalog(catalog)
        self.assertEqual(problems, [], f"validate_catalog: {problems}")
        t1 = next(t for t in catalog["techniques"] if t["id"] == "T1098.001")
        self.assertEqual(t1["status"], "partial")
        self.assertEqual(t1["detector"], "enrich_with_enablers")
        self.assertIsNotNone(t1["fixture"])


if __name__ == "__main__":
    unittest.main()
