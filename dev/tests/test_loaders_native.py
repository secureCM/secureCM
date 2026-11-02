"""Tests for flatten_log_entry and load_log_entries (native GCP Cloud Audit LogEntry)."""
import unittest

from gcp_policy_analyzer.loaders import (
    flatten_log_entry,
    load_log_entries,
    load_iam_policies,
    load_vpc_firewall_rules,
    load_network_firewall_policies,
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


class TestNativeStateLoaders(unittest.TestCase):

    def test_iam_asset_wrapped_resource_from_name(self):
        """Asset-Inventory-wrapped IAM: resource derived from name by stripping //service/ prefix."""
        data = {
            "iam_policies": [
                {
                    "name": "//cloudresourcemanager.googleapis.com/folders/77",
                    "asset_type": "cloudresourcemanager.googleapis.com/Folder",
                    "iam_policy": {
                        "bindings": [
                            {"role": "roles/viewer", "members": ["user:a@example.com"]}
                        ]
                    },
                }
            ]
        }
        result = load_iam_policies(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].resource, "folders/77")
        self.assertEqual(result[0].bindings[0].role, "roles/viewer")

    def test_iam_asset_wrapped_organizations_prefix(self):
        """organizations/ prefix: //cloudresourcemanager.googleapis.com/organizations/555 → 'organizations/555'."""
        data = {
            "iam_policies": [
                {
                    "name": "//cloudresourcemanager.googleapis.com/organizations/555",
                    "asset_type": "cloudresourcemanager.googleapis.com/Organization",
                    "iam_policy": {
                        "bindings": [
                            {"role": "roles/owner", "members": ["user:admin@example.com"]}
                        ]
                    },
                }
            ]
        }
        result = load_iam_policies(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].resource, "organizations/555")

    def test_firewall_native_compute_kind_parses(self):
        """Native compute#firewall with logConfig.enable=True → log_enabled True, raw present."""
        data = {
            "vpc_firewall_rules": [
                {
                    "kind": "compute#firewall",
                    "name": "allow-http",
                    "network": "global/networks/default",
                    "direction": "INGRESS",
                    "priority": 1000,
                    "sourceRanges": ["0.0.0.0/0"],
                    "allowed": [{"IPProtocol": "tcp", "ports": ["80"]}],
                    "logConfig": {"enable": True},
                }
            ]
        }
        result = load_vpc_firewall_rules(data)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].log_enabled)
        self.assertIsNotNone(result[0].raw)

    def test_nfp_regional_vs_global(self):
        """NFP with region set → region preserved; without region → None (global)."""
        data = {
            "network_firewall_policies": [
                {"kind": "compute#firewallPolicy", "name": "regional-pol", "region": "us-central1", "rules": []},
                {"kind": "compute#firewallPolicy", "name": "global-pol", "rules": []},
            ]
        }
        result = load_network_firewall_policies(data)
        self.assertEqual(len(result), 2)
        regional = next(r for r in result if r.name == "regional-pol")
        global_ = next(r for r in result if r.name == "global-pol")
        self.assertEqual(regional.region, "us-central1")
        self.assertIsNone(global_.region)

    def test_member_prefixes_preserved(self):
        """serviceAccount:, user:, group: prefixes are kept verbatim in IamBinding.members."""
        data = {
            "iam_policies": [
                {
                    "resource": "projects/my-proj",
                    "bindings": [
                        {
                            "role": "roles/editor",
                            "members": [
                                "serviceAccount:sa@proj.iam.gserviceaccount.com",
                                "user:bob@example.com",
                                "group:eng@example.com",
                            ],
                        }
                    ],
                }
            ]
        }
        result = load_iam_policies(data)
        members = result[0].bindings[0].members
        self.assertIn("serviceAccount:sa@proj.iam.gserviceaccount.com", members)
        self.assertIn("user:bob@example.com", members)
        self.assertIn("group:eng@example.com", members)


if __name__ == "__main__":
    unittest.main()
