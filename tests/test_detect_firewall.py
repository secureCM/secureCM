"""Tests for detect_firewall_exposure — TDD (written before implementation)."""
import unittest
from datetime import datetime, timezone

from gcp_policy_analyzer.diff import Change


def _change(action, before, after, labels=None, resource="fw-1", resource_type="firewall_rule"):
    return Change(
        resource=resource,
        resource_type=resource_type,
        action=action,
        before=before,
        after=after,
        timestamp=datetime(2026, 10, 31, tzinfo=timezone.utc),
        principal="user@example.com",
        labels=labels or {},
    )


class TestDetectFirewallExposure(unittest.TestCase):

    def test_world_open_widen_flags_T1562_007(self):
        """10.0.0.0/8 → 0.0.0.0/0 widens toward world; must produce T1562.007."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "UPDATE",
            {"sourceRanges": ["10.0.0.0/8"]},
            {"sourceRanges": ["0.0.0.0/0"]},
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique_id, "T1562.007")

    def test_prod_label_makes_critical(self):
        """World-open widen on a prod-labeled resource must be severity critical."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "UPDATE",
            {"sourceRanges": ["10.0.0.0/8"]},
            {"sourceRanges": ["0.0.0.0/0"]},
            labels={"env": "prod"},
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_deny_delete_flags(self):
        """DELETE of a deny rule → Finding T1562.007 (defense evasion)."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "DELETE",
            {"denied": [{"IPProtocol": "all"}], "sourceRanges": ["0.0.0.0/0"]},
            None,
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique_id, "T1562.007")

    def test_priority_shadow_flags(self):
        """Deny rule priority raised (100 → 9000) so an allow can shadow it → T1562.007."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "UPDATE",
            {"denied": [{"IPProtocol": "tcp", "ports": ["22"]}], "priority": 100},
            {"denied": [{"IPProtocol": "tcp", "ports": ["22"]}], "priority": 9000},
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique_id, "T1562.007")

    def test_narrowing_not_flagged(self):
        """0.0.0.0/0 → 10.0.0.0/8 narrows access; must produce no findings."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "UPDATE",
            {"sourceRanges": ["0.0.0.0/0"]},
            {"sourceRanges": ["10.0.0.0/8"]},
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(findings, [])

    def test_fw_delete_flags_T1485(self):
        """DELETE of a firewall resource (no deny in before) → Finding T1485."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "DELETE",
            {"allowed": [{"IPProtocol": "tcp", "ports": ["80"]}], "sourceRanges": ["10.0.0.0/8"]},
            None,
            resource_type="firewall_rule",
        )
        findings = detect_firewall_exposure([], [change])
        t1485 = [f for f in findings if f.technique_id == "T1485"]
        self.assertEqual(len(t1485), 1)

    def test_empty_envelope_returns_empty(self):
        """detect_firewall_exposure([], []) must return []."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        self.assertEqual(detect_firewall_exposure([], []), [])


if __name__ == "__main__":
    unittest.main()
