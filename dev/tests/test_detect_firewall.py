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
        """DELETE of a deny rule → exactly one Finding T1562.007 (defense evasion); NOT also T1485."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "DELETE",
            {"denied": [{"IPProtocol": "all"}], "sourceRanges": ["0.0.0.0/0"]},
            None,
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique_id, "T1562.007")
        # Precedence: deny-delete is defense evasion only; T1485 must NOT be emitted
        t1485 = [f for f in findings if f.technique_id == "T1485"]
        self.assertEqual(t1485, [], "deny-rule delete must not emit T1485")

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

    def test_port_added_to_denied_not_flagged(self):
        """Adding an admin port to a denied[] entry on a world-open rule is NOT exposure (blocks more)."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "UPDATE",
            {"denied": [{"IPProtocol": "tcp", "ports": ["80"]}], "sourceRanges": ["0.0.0.0/0"]},
            {"denied": [{"IPProtocol": "tcp", "ports": ["80", "22"]}], "sourceRanges": ["0.0.0.0/0"]},
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(findings, [], "adding ports to denied[] must not produce a finding")

    def test_empty_envelope_returns_empty(self):
        """detect_firewall_exposure([], []) must return []."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        self.assertEqual(detect_firewall_exposure([], []), [])

    def test_nfp_world_open_allow_flags_T1562_007(self):
        """network_firewall_policy change adding 0.0.0.0/0 allow rule → T1562.007."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "UPDATE",
            {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                        "match": {"srcIpRanges": ["10.0.0.0/8"]}}]},
            {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                        "match": {"srcIpRanges": ["0.0.0.0/0"]}}]},
            resource_type="network_firewall_policy",
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique_id, "T1562.007")

    def test_nfp_world_open_already_present_not_flagged(self):
        """network_firewall_policy already world-open before → no new finding."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "UPDATE",
            {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                        "match": {"srcIpRanges": ["0.0.0.0/0"]}}]},
            {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                        "match": {"srcIpRanges": ["0.0.0.0/0"]}}]},
            resource_type="network_firewall_policy",
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(findings, [])

    def test_nfp_prod_label_makes_critical(self):
        """NFP world-open allow on prod → severity critical."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "UPDATE",
            {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                        "match": {"srcIpRanges": ["10.0.0.0/8"]}}]},
            {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                        "match": {"srcIpRanges": ["0.0.0.0/0"]}}]},
            labels={"env": "prod"},
            resource_type="network_firewall_policy",
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_nfp_deny_action_not_flagged(self):
        """network_firewall_policy deny rule with 0.0.0.0/0 → not exposure (blocks, doesn't open)."""
        from gcp_policy_analyzer.detect import detect_firewall_exposure
        change = _change(
            "UPDATE",
            {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "deny",
                        "match": {"srcIpRanges": ["10.0.0.0/8"]}}]},
            {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "deny",
                        "match": {"srcIpRanges": ["0.0.0.0/0"]}}]},
            resource_type="network_firewall_policy",
        )
        findings = detect_firewall_exposure([], [change])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
