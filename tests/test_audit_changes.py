"""Tests for load_audit_changes — legacy path and IAM-from-logs path."""
import unittest
from datetime import timezone, datetime

from gcp_policy_analyzer.loaders import load_audit_changes
from gcp_policy_analyzer.detect import detect_privilege_grant


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


if __name__ == "__main__":
    unittest.main()
