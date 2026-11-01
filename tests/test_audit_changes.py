"""Tests for load_audit_changes — legacy path and IAM-from-logs path."""
import unittest
from datetime import timezone, datetime

from gcp_policy_analyzer.loaders import load_audit_changes, _config_changes_from_logs
from gcp_policy_analyzer.detect import detect_privilege_grant, detect_firewall_exposure


# ---------------------------------------------------------------------------
# Helpers for firewall audit entries
# ---------------------------------------------------------------------------

def _fw_entry(method: str, resource: str, request: dict,
              principal: str = "admin@example.com",
              timestamp: str = "2026-10-31T12:00:00Z") -> dict:
    """Build a flat firewall log entry."""
    return {
        "methodName": method,
        "principalEmail": principal,
        "callerIp": "1.2.3.4",
        "resourceName": resource,
        "timestamp": timestamp,
        "serviceData": {},
        "request": request,
    }


def _make_setiampolicy_entry(deltas: list[dict], resource: str = "projects/my-proj",
                              principal: str = "admin@example.com") -> dict:
    """Build a native flat SetIamPolicy log entry with the given bindingDeltas."""
    return {
        "methodName": "SetIamPolicy",
        "principalEmail": principal,
        "callerIp": "1.2.3.4",
        "resourceName": resource,
        "timestamp": "2026-10-31T12:00:00Z",
        "serviceData": {
            "policyDelta": {
                "bindingDeltas": deltas,
            }
        },
        "request": {},
    }


class TestSetIamPolicyAddBecomesGrantChange(unittest.TestCase):
    def test_setiampolicy_add_becomes_grant_change(self):
        """ADD roles/owner for user:x → Change.after bindings has (roles/owner, user:x), before lacks it; detect_privilege_grant fires T1098.003."""
        entry = _make_setiampolicy_entry([
            {"action": "ADD", "role": "roles/owner", "member": "user:x@example.com"},
        ])
        data = {"log_entries": [{"protoPayload": {
            "methodName": entry["methodName"],
            "resourceName": entry["resourceName"],
            "authenticationInfo": {"principalEmail": entry["principalEmail"]},
            "requestMetadata": {"callerIp": entry["callerIp"]},
            "serviceData": entry["serviceData"],
            "request": entry["request"],
        }, "timestamp": entry["timestamp"]}]}

        changes = load_audit_changes(data)
        self.assertEqual(len(changes), 1)
        c = changes[0]
        self.assertEqual(c.resource_type, "iam_policy")
        self.assertEqual(c.action, "UPDATE")
        self.assertEqual(c.resource, "projects/my-proj")
        self.assertEqual(c.principal, "admin@example.com")
        # after has the ADD binding
        after_roles = {b["role"]: b["members"] for b in c.after["bindings"]}
        self.assertIn("roles/owner", after_roles)
        self.assertIn("user:x@example.com", after_roles["roles/owner"])
        # before does NOT have the member
        before_roles = {b["role"]: b["members"] for b in c.before["bindings"]}
        self.assertNotIn("user:x@example.com", before_roles.get("roles/owner", []))

        # detect_privilege_grant fires T1098.003
        findings = detect_privilege_grant([], changes)
        technique_ids = {f.technique_id for f in findings}
        self.assertIn("T1098.003", technique_ids)


class TestSetIamPolicyRemoveIsNotAGrant(unittest.TestCase):
    def test_setiampolicy_remove_is_not_a_grant(self):
        """REMOVE → member in before not after; detect_privilege_grant yields no grant."""
        data = {"log_entries": [{"protoPayload": {
            "methodName": "SetIamPolicy",
            "resourceName": "projects/my-proj",
            "authenticationInfo": {"principalEmail": "admin@example.com"},
            "requestMetadata": {"callerIp": "1.2.3.4"},
            "serviceData": {"policyDelta": {"bindingDeltas": [
                {"action": "REMOVE", "role": "roles/owner", "member": "user:x@example.com"},
            ]}},
            "request": {},
        }, "timestamp": "2026-10-31T12:00:00Z"}]}

        changes = load_audit_changes(data)
        self.assertEqual(len(changes), 1)
        c = changes[0]
        # member in before, not in after
        before_roles = {b["role"]: b["members"] for b in c.before["bindings"]}
        after_roles = {b["role"]: b["members"] for b in c.after["bindings"]}
        self.assertIn("user:x@example.com", before_roles.get("roles/owner", []))
        self.assertNotIn("user:x@example.com", after_roles.get("roles/owner", []))

        # detect_privilege_grant yields no grant finding
        findings = detect_privilege_grant([], changes)
        grant_findings = [f for f in findings if f.technique_id == "T1098.003"]
        self.assertEqual(len(grant_findings), 0)


class TestEnablerMethodsEmitNoIamChange(unittest.TestCase):
    def test_enabler_methods_emit_no_iam_change(self):
        """A CreateServiceAccountKey entry → 0 Changes from load_audit_changes."""
        data = {"log_entries": [{"protoPayload": {
            "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            "resourceName": "projects/my-proj/serviceAccounts/sa@proj.iam.gserviceaccount.com",
            "authenticationInfo": {"principalEmail": "admin@example.com"},
            "requestMetadata": {"callerIp": "1.2.3.4"},
            "serviceData": {},
            "request": {},
        }, "timestamp": "2026-10-31T12:00:00Z"}]}

        changes = load_audit_changes(data)
        self.assertEqual(len(changes), 0)


class TestLegacyAuditChangesPath(unittest.TestCase):
    def test_legacy_audit_changes_key_still_works(self):
        """data with audit_changes key → legacy path, no log_entries needed."""
        data = {"audit_changes": [{
            "resource": "projects/p",
            "resource_type": "iam_policy",
            "action": "UPDATE",
            "principal": "u@example.com",
            "timestamp": "2026-10-31T12:00:00Z",
            "before": {"bindings": []},
            "after": {"bindings": [{"role": "roles/viewer", "members": ["user:u@example.com"]}]},
        }]}
        changes = load_audit_changes(data)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].resource, "projects/p")


# ---------------------------------------------------------------------------
# Task 3: firewall/NFP replay tests
# ---------------------------------------------------------------------------

_FW_RESOURCE = "projects/p/global/firewalls/allow-ssh"
_NFP_RESOURCE = "projects/p/global/firewallPolicies/corp-policy"


class TestInsertThenPatchWorldOpenFires(unittest.TestCase):
    def test_insert_then_patch_world_open_fires(self):
        """insert (10.0.0.0/8) then patch (0.0.0.0/0) -> Change before has /8, after world; detect_firewall_exposure T1562.007"""
        entries = [
            _fw_entry("compute.firewalls.insert", _FW_RESOURCE,
                      {"sourceRanges": ["10.0.0.0/8"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                       "priority": 1000, "direction": "INGRESS"},
                      timestamp="2026-10-31T10:00:00Z"),
            _fw_entry("compute.firewalls.patch", _FW_RESOURCE,
                      {"sourceRanges": ["0.0.0.0/0"]},
                      timestamp="2026-10-31T11:00:00Z"),
        ]
        changes = _config_changes_from_logs(entries)
        self.assertEqual(len(changes), 2)
        insert_c, patch_c = changes[0], changes[1]
        self.assertEqual(insert_c.action, "CREATE")
        self.assertEqual(patch_c.action, "UPDATE")
        # before has /8; after has world-open
        self.assertIn("10.0.0.0/8", patch_c.before["sourceRanges"])
        self.assertIn("0.0.0.0/0", patch_c.after["sourceRanges"])
        # detector fires T1562.007
        findings = detect_firewall_exposure([], [patch_c])
        self.assertTrue(any(f.technique_id == "T1562.007" for f in findings))


class TestPartialPatchMergesNotReplaces(unittest.TestCase):
    def test_partial_patch_merges_not_replaces(self):
        """insert full rule, patch only {priority} -> after still has original sourceRanges/allowed (merge)"""
        entries = [
            _fw_entry("compute.firewalls.insert", _FW_RESOURCE,
                      {"sourceRanges": ["192.168.0.0/16"],
                       "allowed": [{"IPProtocol": "tcp", "ports": ["80"]}],
                       "priority": 1000},
                      timestamp="2026-10-31T10:00:00Z"),
            _fw_entry("compute.firewalls.patch", _FW_RESOURCE,
                      {"priority": 500},
                      timestamp="2026-10-31T11:00:00Z"),
        ]
        changes = _config_changes_from_logs(entries)
        patch_c = changes[1]
        # priority updated
        self.assertEqual(patch_c.after["priority"], 500)
        # original keys preserved
        self.assertEqual(patch_c.after["sourceRanges"], ["192.168.0.0/16"])
        self.assertEqual(patch_c.after["allowed"], [{"IPProtocol": "tcp", "ports": ["80"]}])


class TestBaselineGapSetsBeforeNone(unittest.TestCase):
    def test_baseline_gap_sets_before_none(self):
        """first event is a patch, no prior insert -> before is None, labels.baseline == 'predates_window', no crash"""
        entries = [
            _fw_entry("compute.firewalls.patch", _FW_RESOURCE,
                      {"sourceRanges": ["0.0.0.0/0"]},
                      timestamp="2026-10-31T10:00:00Z"),
        ]
        changes = _config_changes_from_logs(entries)
        self.assertEqual(len(changes), 1)
        c = changes[0]
        self.assertIsNone(c.before)
        self.assertEqual(c.labels.get("baseline"), "predates_window")


class TestPriorityShadowDetectedViaReplay(unittest.TestCase):
    def test_priority_shadow_detected_via_replay(self):
        """insert deny pri=100 then patch pri=9000 -> detect_firewall_exposure fires (priority shadow)"""
        entries = [
            _fw_entry("compute.firewalls.insert", _FW_RESOURCE,
                      {"denied": [{"IPProtocol": "all"}], "sourceRanges": ["10.0.0.0/8"], "priority": 100},
                      timestamp="2026-10-31T10:00:00Z"),
            _fw_entry("compute.firewalls.patch", _FW_RESOURCE,
                      {"priority": 9000},
                      timestamp="2026-10-31T11:00:00Z"),
        ]
        changes = _config_changes_from_logs(entries)
        patch_c = changes[1]
        self.assertEqual(patch_c.before["priority"], 100)
        self.assertEqual(patch_c.after["priority"], 9000)
        findings = detect_firewall_exposure([], [patch_c])
        self.assertTrue(any(f.technique_id == "T1562.007" for f in findings))


class TestNfpWorldOpenViaReplay(unittest.TestCase):
    def test_nfp_world_open_via_replay(self):
        """networkFirewallPolicies addRule allow 0.0.0.0/0 -> Change resource_type network_firewall_policy, detector fires"""
        entries = [
            _fw_entry("compute.networkFirewallPolicies.addRule", _NFP_RESOURCE,
                      {"rules": [{"action": "allow", "match": {"srcIpRanges": ["0.0.0.0/0"]},
                                  "priority": 100, "direction": "INGRESS"}]},
                      timestamp="2026-10-31T10:00:00Z"),
        ]
        changes = _config_changes_from_logs(entries)
        self.assertEqual(len(changes), 1)
        c = changes[0]
        self.assertEqual(c.resource_type, "network_firewall_policy")
        self.assertEqual(c.action, "UPDATE")
        # baseline gap: no prior insert
        self.assertIsNone(c.before)
        # after has the world-open rule
        self.assertTrue(any("0.0.0.0/0" in r.get("match", {}).get("srcIpRanges", [])
                            for r in c.after.get("rules", [])))
        findings = detect_firewall_exposure([], [c])
        self.assertTrue(any(f.technique_id == "T1562.007" for f in findings))


if __name__ == "__main__":
    unittest.main()
