"""Tests for Task 8: coverage block in describe_capabilities and __all__ exports."""
import unittest


class TestMcpCoverage(unittest.TestCase):
    def test_preamble_has_coverage_and_run_detectors(self):
        from codemode.mcp_server import _PREAMBLE
        self.assertIn("run_detectors(", _PREAMBLE)
        self.assertIn("T1562.007", _PREAMBLE)

    def test_new_helpers_exported(self):
        import gcp_policy_analyzer
        required = {
            "Finding",
            "detect_firewall_exposure",
            "detect_privilege_grant",
            "detect_discovery_bursts",
            "detect_anomalous_actor",
            "cross_project_timeline",
        }
        self.assertTrue(required.issubset(set(gcp_policy_analyzer.__all__)))


if __name__ == "__main__":
    unittest.main()
