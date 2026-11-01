"""Tests for flatten_log_entry and load_log_entries (native GCP Cloud Audit LogEntry)."""
import unittest

from gcp_policy_analyzer.loaders import (
    flatten_log_entry,
    load_log_entries,
    FW_CHANGE_METHODS,
    NFP_CHANGE_METHODS,
)


class TestFlattenLogEntry(unittest.TestCase):

    def test_flatten_carries_callerip_and_core_fields(self):
        entry = {
            "timestamp": "2026-10-31T12:00:00Z",
            "protoPayload": {
                "methodName": "SetIamPolicy",
                "resourceName": "projects/my-project",
                "authenticationInfo": {"principalEmail": "admin@example.com"},
                "requestMetadata": {"callerIp": "203.0.113.5"},
                "serviceData": {"policyDelta": {}},
                "request": {"policy": {}},
            },
        }
        flat = flatten_log_entry(entry)
        self.assertEqual(flat["methodName"], "SetIamPolicy")
        self.assertEqual(flat["principalEmail"], "admin@example.com")
        self.assertEqual(flat["callerIp"], "203.0.113.5")
        self.assertEqual(flat["resourceName"], "projects/my-project")
        self.assertEqual(flat["timestamp"], "2026-10-31T12:00:00Z")
        self.assertEqual(flat["serviceData"], {"policyDelta": {}})
        self.assertEqual(flat["request"], {"policy": {}})

    def test_flatten_missing_fields_no_raise(self):
        flat = flatten_log_entry({})
        self.assertEqual(flat["methodName"], "")
        self.assertEqual(flat["principalEmail"], "")
        self.assertEqual(flat["callerIp"], "")
        self.assertEqual(flat["resourceName"], "")
        self.assertEqual(flat["timestamp"], "")
        self.assertEqual(flat["serviceData"], {})
        self.assertEqual(flat["request"], {})


class TestLoadLogEntries(unittest.TestCase):

    def _make_native(self, method: str) -> dict:
        return {
            "timestamp": "2026-10-31T12:00:00Z",
            "protoPayload": {
                "methodName": method,
                "resourceName": "projects/my-project",
                "authenticationInfo": {"principalEmail": "u@example.com"},
                "requestMetadata": {"callerIp": "1.2.3.4"},
            },
        }

    def test_load_log_entries_filters_to_known_methods(self):
        data = {
            "log_entries": [
                self._make_native("storage.objects.list"),        # dropped
                self._make_native("SetIamPolicy"),                # kept (IAM)
                self._make_native("google.iam.admin.v1.CreateServiceAccountKey"),  # kept (enabler)
            ]
        }
        result = load_log_entries(data)
        self.assertEqual(len(result), 2)
        methods = {e["methodName"] for e in result}
        self.assertIn("SetIamPolicy", methods)
        self.assertIn("google.iam.admin.v1.CreateServiceAccountKey", methods)
        self.assertNotIn("storage.objects.list", methods)

    def test_load_log_entries_idempotent_on_flat(self):
        flat_entry = {
            "methodName": "SetIamPolicy",
            "principalEmail": "u@example.com",
            "callerIp": "1.2.3.4",
            "resourceName": "projects/p",
            "timestamp": "2026-10-31T12:00:00Z",
            "serviceData": {},
            "request": {},
        }
        data = {"log_entries": [flat_entry]}
        result = load_log_entries(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["methodName"], "SetIamPolicy")
        self.assertEqual(result[0]["callerIp"], "1.2.3.4")

    def test_nfp_and_fw_methods_are_distinct(self):
        """NFP_CHANGE_METHODS contains only networkFirewallPolicies; FW_CHANGE_METHODS contains only firewalls."""
        # networkFirewallPolicies methods in NFP but not in FW
        nfp_only = {"compute.networkFirewallPolicies.addRule", "compute.networkFirewallPolicies.patchRule"}
        for method in nfp_only:
            self.assertIn(method, NFP_CHANGE_METHODS)
            self.assertNotIn(method, FW_CHANGE_METHODS)
        # VPC firewall methods in FW but not in NFP
        fw_only = {"compute.firewalls.insert", "compute.firewalls.patch"}
        for method in fw_only:
            self.assertIn(method, FW_CHANGE_METHODS)
            self.assertNotIn(method, NFP_CHANGE_METHODS)

    def test_networkfirewall_policies_addrule_kept_by_load_log_entries(self):
        """A networkFirewallPolicies.addRule entry is kept and in NFP_CHANGE_METHODS, not in FW_CHANGE_METHODS."""
        data = {
            "log_entries": [
                self._make_native("compute.networkFirewallPolicies.addRule"),
            ]
        }
        result = load_log_entries(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["methodName"], "compute.networkFirewallPolicies.addRule")
        self.assertIn("compute.networkFirewallPolicies.addRule", NFP_CHANGE_METHODS)
        self.assertNotIn("compute.networkFirewallPolicies.addRule", FW_CHANGE_METHODS)

    def test_firewalls_patch_in_fw_not_nfp(self):
        """A compute.firewalls.patch entry is kept and in FW_CHANGE_METHODS, but not in NFP_CHANGE_METHODS."""
        data = {
            "log_entries": [
                self._make_native("compute.firewalls.patch"),
            ]
        }
        result = load_log_entries(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["methodName"], "compute.firewalls.patch")
        self.assertIn("compute.firewalls.patch", FW_CHANGE_METHODS)
        self.assertNotIn("compute.firewalls.patch", NFP_CHANGE_METHODS)


if __name__ == "__main__":
    unittest.main()
