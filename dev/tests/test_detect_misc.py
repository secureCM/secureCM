"""Tests for Task 4: discover-burst, anomalous-actor, timeline, subnet correlation."""
import unittest
from datetime import datetime, timezone


def _ts(offset_secs: int = 0) -> datetime:
    from datetime import timedelta
    base = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    return base + timedelta(seconds=offset_secs)


def _ts_abs(secs: int) -> datetime:
    """Absolute epoch-based timestamp for easy arithmetic."""
    from datetime import timedelta
    base = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    return base + timedelta(seconds=secs)


def _log(principal, method, resource, ts_offset=0, caller_ip="1.2.3.4"):
    return {
        "principalEmail": principal,
        "methodName": method,
        "resourceName": resource,
        "callerIp": caller_ip,
        "timestamp": _ts_abs(ts_offset).isoformat().replace("+00:00", "Z"),
    }


def _change(resource, principal, ts_offset=0):
    from gcp_policy_analyzer.diff import Change
    return Change(
        resource=resource,
        resource_type="iam_policy",
        action="UPDATE",
        before={},
        after={},
        timestamp=_ts_abs(ts_offset),
        principal=principal,
        risk_delta=0,
        labels={},
    )


class TestDiscoveryBurst(unittest.TestCase):
    def test_discovery_burst_flags_T1580(self):
        """10 .list calls in 5 min by one principal => Finding T1580."""
        from gcp_policy_analyzer.detect import detect_discovery_bursts

        logs = [
            _log("alice@example.com", "iam.googleapis.com.projects.serviceAccounts.list",
                 "projects/p1/iam", ts_offset=i * 20)
            for i in range(10)  # 10 calls over 180 seconds — within 5 min window
        ]
        findings = detect_discovery_bursts(logs, window_seconds=300, min_calls=10)
        self.assertTrue(len(findings) >= 1)
        t_ids = {f.technique_id for f in findings}
        self.assertIn("T1580", t_ids)
        for f in findings:
            self.assertEqual(f.principal, "alice@example.com")

    def test_discovery_burst_groups_permissions_T1069(self):
        """Calls targeting groups/permissions resource => T1069.003."""
        from gcp_policy_analyzer.detect import detect_discovery_bursts

        logs = [
            _log("bob@example.com", "cloudresourcemanager.googleapis.com.projects.getIamPolicy",
                 "projects/p1/groups/all-users/permissions", ts_offset=i * 10)
            for i in range(10)
        ]
        findings = detect_discovery_bursts(logs, window_seconds=300, min_calls=10)
        self.assertTrue(len(findings) >= 1)
        t_ids = {f.technique_id for f in findings}
        self.assertIn("T1069.003", t_ids)

    def test_discovery_burst_no_flag_below_threshold(self):
        """9 calls => no finding."""
        from gcp_policy_analyzer.detect import detect_discovery_bursts

        logs = [
            _log("alice@example.com", "iam.googleapis.com.projects.serviceAccounts.list",
                 "projects/p1/iam", ts_offset=i * 20)
            for i in range(9)
        ]
        findings = detect_discovery_bursts(logs, window_seconds=300, min_calls=10)
        self.assertEqual(len(findings), 0)

    def test_discovery_burst_outside_window_no_flag(self):
        """10 calls spread over 10 minutes => no flag for 5 min window."""
        from gcp_policy_analyzer.detect import detect_discovery_bursts

        logs = [
            _log("alice@example.com", "iam.googleapis.com.projects.serviceAccounts.list",
                 "projects/p1/iam", ts_offset=i * 70)  # 70s apart = 630s for 10 calls
            for i in range(10)
        ]
        findings = detect_discovery_bursts(logs, window_seconds=300, min_calls=10)
        self.assertEqual(len(findings), 0)

    def test_discovery_burst_two_separated_bursts_yields_two_findings(self):
        """One actor with two separated 10-call bursts (t=0..9s and t=1000..1009s) => 2 Findings."""
        from gcp_policy_analyzer.detect import detect_discovery_bursts

        burst1 = [
            _log("alice@example.com", "iam.googleapis.com.projects.serviceAccounts.list",
                 "projects/p1/iam", ts_offset=i)
            for i in range(10)  # t=0..9s
        ]
        burst2 = [
            _log("alice@example.com", "iam.googleapis.com.projects.serviceAccounts.list",
                 "projects/p1/iam", ts_offset=1000 + i)
            for i in range(10)  # t=1000..1009s — 991s gap, well outside 300s window
        ]
        findings = detect_discovery_bursts(burst1 + burst2, window_seconds=300, min_calls=10)
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertEqual(f.principal, "alice@example.com")
            self.assertEqual(f.technique_id, "T1580")


class TestAnomalousActor(unittest.TestCase):
    def test_anomalous_actor_rotating_subnet(self):
        """Principal on 2 IPs in one /24 not seen elsewhere => Finding T1078.004."""
        from gcp_policy_analyzer.detect import detect_anomalous_actor

        # alice has 10 events from 1.2.3.4 and 2 events from 1.2.3.5 (same /24)
        # 1.2.3.5 is anomalous_ip (low fraction); also same subnet as main IP => rotating subnet
        logs = (
            [_log("alice@example.com", "iam.googleapis.com.projects.serviceAccounts.list",
                  "projects/p1/iam", ts_offset=i * 10, caller_ip="1.2.3.4") for i in range(10)]
            + [_log("alice@example.com", "iam.googleapis.com.projects.serviceAccounts.list",
                    "projects/p1/iam", ts_offset=100 + i * 10, caller_ip="1.2.3.5") for i in range(2)]
        )
        changes = [_change("projects/p1/iam", "alice@example.com")]

        findings = detect_anomalous_actor(changes, logs)
        self.assertTrue(len(findings) >= 1)
        t_ids = {f.technique_id for f in findings}
        self.assertIn("T1078.004", t_ids)
        actors = {f.principal for f in findings}
        self.assertIn("alice@example.com", actors)
        # resource must be populated from the first in-scope change/log
        alice_findings = [f for f in findings if f.principal == "alice@example.com"]
        for f in alice_findings:
            self.assertNotEqual(f.resource, "", "resource should be non-empty")

    def test_anomalous_actor_no_flag_single_stable_ip(self):
        """Principal with only one IP, all events => no finding."""
        from gcp_policy_analyzer.detect import detect_anomalous_actor

        logs = [
            _log("stable@example.com", "iam.googleapis.com.projects.serviceAccounts.list",
                 "projects/p1/iam", ts_offset=i * 10, caller_ip="10.0.0.1")
            for i in range(5)
        ]
        changes = [_change("projects/p1/iam", "stable@example.com")]
        findings = detect_anomalous_actor(changes, logs)
        self.assertEqual(len(findings), 0)


class TestCrossProjectTimeline(unittest.TestCase):
    def test_cross_project_timeline_orders_multi_project(self):
        """Events across 2 projects sorted ascending with project tags."""
        from gcp_policy_analyzer.detect import cross_project_timeline

        logs = [
            _log("alice@example.com", "iam.googleapis.com.list",
                 "projects/proj-A/iam/policies/main", ts_offset=10),
            _log("alice@example.com", "compute.googleapis.com.list",
                 "projects/proj-B/compute/firewalls/fw1", ts_offset=5),
        ]
        changes = [
            _change("projects/proj-A/iam/policies/old", "alice@example.com", ts_offset=20),
        ]
        timeline = cross_project_timeline(changes, logs)
        self.assertEqual(len(timeline), 3)

        # Verify ascending order
        ts_list = [item["ts"] for item in timeline]
        self.assertEqual(ts_list, sorted(ts_list))

        # Verify project tags
        projects = {item["project"] for item in timeline}
        self.assertIn("proj-A", projects)
        self.assertIn("proj-B", projects)

        # Verify kind field
        kinds = {item["kind"] for item in timeline}
        self.assertIsSubset(kinds, {"change", "log"})

    def assertIsSubset(self, a, b):
        self.assertTrue(a <= b, f"{a!r} is not a subset of {b!r}")

    def test_cross_project_timeline_filtered_by_principal(self):
        """principal= filter reduces to one actor's events."""
        from gcp_policy_analyzer.detect import cross_project_timeline

        logs = [
            _log("alice@example.com", "iam.list", "projects/A/iam", ts_offset=1),
            _log("bob@example.com", "iam.list", "projects/B/iam", ts_offset=2),
        ]
        changes = []
        timeline = cross_project_timeline(changes, logs, principal="alice@example.com")
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["project"], "A")

    def test_cross_project_timeline_folder_org_scopes(self):
        """folders/N and organizations/N parsed as project field."""
        from gcp_policy_analyzer.detect import cross_project_timeline

        logs = [
            _log("admin@example.com", "iam.list", "folders/123/iam/policies/p", ts_offset=1),
            _log("admin@example.com", "iam.list", "organizations/456/iam/policies/p", ts_offset=2),
        ]
        timeline = cross_project_timeline([], logs)
        projects = [item["project"] for item in timeline]
        self.assertEqual(projects[0], "folders/123")
        self.assertEqual(projects[1], "organizations/456")


class TestCorrelateSubnet(unittest.TestCase):
    def test_correlate_subnet_additive(self):
        """subnet_bits=24 adds shared_subnets; shared_ips unchanged; default call has no subnet keys."""
        from gcp_policy_analyzer.logs import correlate_by_actor

        entries = [
            {"principalEmail": "a@x.com", "callerIp": "185.220.101.1", "methodName": "m", "timestamp": "2026-10-31T12:00:00Z"},
            {"principalEmail": "b@x.com", "callerIp": "185.220.101.2", "methodName": "m", "timestamp": "2026-10-31T12:00:01Z"},
        ]

        # Default call: no subnet keys
        result_default = correlate_by_actor([], entries)
        self.assertNotIn("shared_subnets", result_default)
        for actor in result_default["actors"]:
            self.assertNotIn("anomalous_subnets", actor)

        # subnet_bits=24 call: new keys present
        result_subnet = correlate_by_actor([], entries, subnet_bits=24)
        self.assertIn("shared_subnets", result_subnet)
        # Both actors share 185.220.101.0/24
        self.assertIn("185.220.101.0/24", result_subnet["shared_subnets"])
        shared = result_subnet["shared_subnets"]["185.220.101.0/24"]
        self.assertIn("a@x.com", shared)
        self.assertIn("b@x.com", shared)

        # shared_ips still present and accurate (these are different IPs so NOT shared)
        self.assertIn("shared_ips", result_subnet)
        self.assertNotIn("185.220.101.1", result_subnet["shared_ips"])

    def test_correlate_subnet_deterministic(self):
        """Tie order stable across different PYTHONHASHSEED values (subprocess-verified)."""
        import json
        import os
        import subprocess
        import sys

        script = """
import json, sys
from gcp_policy_analyzer.logs import correlate_by_actor
entries = [
    {"principalEmail": "a@x.com", "callerIp": "10.0.0.1", "methodName": "m", "timestamp": "2026-10-31T12:00:00Z"},
    {"principalEmail": "b@x.com", "callerIp": "10.0.0.2", "methodName": "m", "timestamp": "2026-10-31T12:00:01Z"},
    {"principalEmail": "c@x.com", "callerIp": "10.0.0.3", "methodName": "m", "timestamp": "2026-10-31T12:00:02Z"},
]
result = correlate_by_actor([], entries, subnet_bits=24)
out = {
    "actors": [a["actor"] for a in result["actors"]],
    "shared_subnets": result["shared_subnets"],
}
print(json.dumps(out))
"""

        def _run(seed: int) -> dict:
            env = {**os.environ, "PYTHONHASHSEED": str(seed)}
            proc = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True, text=True, env=env, check=True,
            )
            return json.loads(proc.stdout)

        r1 = _run(0)
        r2 = _run(99999)
        self.assertEqual(r1["actors"], r2["actors"])
        self.assertEqual(r1["shared_subnets"], r2["shared_subnets"])

    def test_correlate_subnet_ignores_non_ipv4(self):
        """IPv6 and unparseable IPs are ignored for subnet grouping."""
        from gcp_policy_analyzer.logs import correlate_by_actor

        entries = [
            {"principalEmail": "a@x.com", "callerIp": "2001:db8::1", "methodName": "m", "timestamp": "2026-10-31T12:00:00Z"},
            {"principalEmail": "b@x.com", "callerIp": "not-an-ip", "methodName": "m", "timestamp": "2026-10-31T12:00:01Z"},
        ]
        result = correlate_by_actor([], entries, subnet_bits=24)
        self.assertEqual(result.get("shared_subnets", {}), {})


class TestAnomalousActorPublicOnly(unittest.TestCase):
    def _logs(self, principal, ips):
        return [{"principalEmail": principal, "callerIp": ip, "methodName": "v1.compute.firewalls.patch",
                 "timestamp": "2026-11-01T0%d:00:00Z" % (i % 10), "resourceName": "projects/p/global/firewalls/r"}
                for i, ip in enumerate(ips)]

    def test_internal_range_spread_not_flagged(self):
        """A principal spread across many internal 10.1.0.x IPs is NOT an anomalous actor."""
        from gcp_policy_analyzer.detect import detect_anomalous_actor
        ips = ["10.1.0.%d" % n for n in range(10, 50)]  # 40 internal IPs, normal corp spread
        findings = detect_anomalous_actor([], self._logs("alice@acme.example.com", ips))
        self.assertEqual([f for f in findings if f.technique_id == "T1078.004"], [])

    def test_public_minority_ip_flagged(self):
        """A principal mostly internal but with a minority PUBLIC IP IS flagged T1078.004."""
        from gcp_policy_analyzer.detect import detect_anomalous_actor
        ips = ["10.1.0.%d" % n for n in range(10, 30)] + ["203.0.113.9"]  # 1 public minority
        findings = detect_anomalous_actor([], self._logs("svc@p.iam.gserviceaccount.com", ips))
        t = [f for f in findings if f.technique_id == "T1078.004"]
        self.assertEqual(len(t), 1)
        self.assertIn("203.0.113.9", t[0].evidence.get("anomalous_ips", []))
