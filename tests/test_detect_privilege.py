"""Tests for detect_privilege_grant — T1098, T1098.003, T1199."""
import unittest
from datetime import datetime, timezone

from gcp_policy_analyzer.diff import Change
from gcp_policy_analyzer.detect import detect_privilege_grant

_TS = datetime(2026, 10, 31, tzinfo=timezone.utc)


def _change(resource, before_bindings, after_bindings, action="UPDATE", principal="admin@acme.example.com"):
    return Change(
        resource=resource,
        resource_type="iam_policy",
        action=action,
        before={"bindings": before_bindings},
        after={"bindings": after_bindings},
        timestamp=_TS,
        principal=principal,
    )


class TestDetectPrivilegeGrant(unittest.TestCase):

    def test_owner_grant_flags_T1098_003(self):
        change = _change(
            "projects/my-proj",
            before_bindings=[],
            after_bindings=[{"role": "roles/owner", "members": ["user:bob@acme.example.com"]}],
        )
        findings = detect_privilege_grant([], [change])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique_id, "T1098.003")
        self.assertEqual(findings[0].severity, "critical")

    def test_external_member_flags_T1199(self):
        # user:x@partner.example is non-corp and non-SA
        change = _change(
            "projects/my-proj",
            before_bindings=[],
            after_bindings=[{"role": "roles/editor", "members": ["user:x@partner.example"]}],
        )
        findings = detect_privilege_grant([], [change])
        tech_ids = {f.technique_id for f in findings}
        self.assertIn("T1199", tech_ids)

    def test_folder_scope_bumps_severity(self):
        # roles/editor is normally "high" — at folder scope it should bump to "critical"
        change = _change(
            "folders/123456",
            before_bindings=[],
            after_bindings=[{"role": "roles/editor", "members": ["user:bob@acme.example.com"]}],
        )
        findings = detect_privilege_grant([], [change])
        self.assertTrue(len(findings) >= 1)
        t1098_003 = [f for f in findings if f.technique_id == "T1098.003"]
        self.assertTrue(len(t1098_003) >= 1)
        self.assertEqual(t1098_003[0].severity, "critical")

    def test_toxic_combo_flagged(self):
        # roles/iam.serviceAccountTokenCreator + SA member = toxic
        change = _change(
            "projects/my-proj",
            before_bindings=[],
            after_bindings=[{
                "role": "roles/iam.serviceAccountTokenCreator",
                "members": ["serviceAccount:svc@my-proj.iam.gserviceaccount.com"],
            }],
        )
        findings = detect_privilege_grant([], [change])
        tech_ids = {f.technique_id for f in findings}
        self.assertIn("T1098", tech_ids)

    def test_lookalike_domain_flags_T1199(self):
        # attacker@evilacme.example.com ends with "acme.example.com" but is NOT internal — must fire T1199
        change = _change(
            "projects/my-proj",
            before_bindings=[],
            after_bindings=[{"role": "roles/viewer", "members": ["user:attacker@evilacme.example.com"]}],
        )
        findings = detect_privilege_grant([], [change], corp_domains=("acme.example.com",))
        tech_ids = {f.technique_id for f in findings}
        self.assertIn("T1199", tech_ids)

    def test_real_corp_member_not_flagged_T1199(self):
        # user:real@acme.example.com IS internal — must NOT fire T1199
        change = _change(
            "projects/my-proj",
            before_bindings=[],
            after_bindings=[{"role": "roles/viewer", "members": ["user:real@acme.example.com"]}],
        )
        findings = detect_privilege_grant([], [change])
        tech_ids = {f.technique_id for f in findings}
        self.assertNotIn("T1199", tech_ids)

    def test_noop_regrant_not_flagged(self):
        # after == before — no new (role, member) pairs added
        bindings = [{"role": "roles/owner", "members": ["user:alice@acme.example.com"]}]
        change = _change("projects/my-proj", bindings, bindings)
        findings = detect_privilege_grant([], [change])
        self.assertEqual(findings, [])

    def test_partial_envelope_empty(self):
        self.assertEqual(detect_privilege_grant([], []), [])
        # change with before=None and after=None must not raise
        from gcp_policy_analyzer.diff import Change
        null_change = Change(
            resource="projects/x", resource_type="iam_policy", action="UPDATE",
            before=None, after=None, timestamp=None, principal="",
        )
        self.assertEqual(detect_privilege_grant([], [null_change]), [])
        # non-UPDATE action yields no finding
        create_change = Change(
            resource="projects/x", resource_type="iam_policy", action="CREATE",
            before=None,
            after={"bindings": [{"role": "roles/owner", "members": ["user:bob@acme.example.com"]}]},
            timestamp=_TS, principal="admin@acme.example.com",
        )
        self.assertEqual(detect_privilege_grant([], [create_change]), [])


if __name__ == "__main__":
    unittest.main()
