"""Deterministic seeded fixture generator for gcp_policy_analyzer attack-coverage tests.

Usage:
    python generate.py                     # writes to fixtures/incidents/ (alongside this file)
    python generate.py --out-dir /tmp/foo  # writes to custom dir

All changes are expressed as native Cloud Audit LogEntry objects under log_entries.
No legacy audit_changes key is emitted.
No wall-clock — ANCHOR is a fixed constant.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Fixed anchor — no wall-clock usage anywhere
ANCHOR = datetime(2026, 9, 15, 0, 0, 0, tzinfo=timezone.utc)
SEED = 20261031

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _delta(**kw) -> timedelta:
    return timedelta(**kw)


def _iam_log_entry(
    resource: str,
    principal: str,
    timestamp: str,
    add_bindings: list[dict] | None = None,
    remove_bindings: list[dict] | None = None,
    caller_ip: str = "10.1.0.1",
) -> dict:
    """Build a native SetIamPolicy LogEntry.

    add_bindings/remove_bindings: list of {role, members:[...]} dicts.
    Expanded into bindingDeltas with action ADD/REMOVE.
    """
    deltas: list[dict] = []
    for b in (add_bindings or []):
        for m in b.get("members", []):
            deltas.append({"action": "ADD", "role": b["role"], "member": m})
    for b in (remove_bindings or []):
        for m in b.get("members", []):
            deltas.append({"action": "REMOVE", "role": b["role"], "member": m})
    return {
        "protoPayload": {
            "methodName": "SetIamPolicy",
            "resourceName": resource,
            "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {"callerIp": caller_ip},
            "serviceData": {"policyDelta": {"bindingDeltas": deltas}},
            "request": {},
        },
        "timestamp": timestamp,
    }


def _fw_log_entry(
    method: str,
    resource: str,
    principal: str,
    timestamp: str,
    request: dict | None = None,
    caller_ip: str = "10.1.0.1",
) -> dict:
    """Build a native compute.firewalls.* or compute.networkFirewallPolicies.* LogEntry."""
    return {
        "protoPayload": {
            "methodName": method,
            "resourceName": resource,
            "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {"callerIp": caller_ip},
            "serviceData": {},
            "request": request or {},
        },
        "timestamp": timestamp,
    }


# ---------------------------------------------------------------------------
# Per-technique small fixtures (native log_entries only)
# ---------------------------------------------------------------------------

def _make_account_manipulation() -> dict:
    """T1098 — toxic combination (token-creator on folder → bumped to critical)."""
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "log_entries": [
            _iam_log_entry(
                resource="folders/111111111111",
                principal="admin@acme.example.com",
                timestamp=_ts(ANCHOR),
                add_bindings=[{
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "members": ["serviceAccount:attacker-sa@fake-proj.iam.gserviceaccount.com"],
                }],
            )
        ],
        "resources": [],
    }


def _make_additional_cloud_roles() -> dict:
    """T1098.003 — high-privilege owner grant on folder (cascading)."""
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "log_entries": [
            _iam_log_entry(
                resource="folders/222222222222",
                principal="admin@acme.example.com",
                timestamp=_ts(ANCHOR),
                add_bindings=[{
                    "role": "roles/owner",
                    "members": ["user:ext-attacker@external.example.com"],
                }],
            )
        ],
        "resources": [],
    }


def _make_trusted_relationship() -> dict:
    """T1199 — external identity (non-corp, non-SA) granted editor on a project."""
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "log_entries": [
            _iam_log_entry(
                resource="projects/fake-prod-001",
                principal="admin@acme.example.com",
                timestamp=_ts(ANCHOR),
                add_bindings=[{
                    "role": "roles/editor",
                    "members": ["user:partner@external-partner.example.com"],
                }],
            )
        ],
        "resources": [],
    }


def _make_impair_defenses() -> dict:
    """T1562 — DELETE of a deny rule (RemovedProtection).

    We insert the deny rule first so the replay has before-state, then delete it.
    """
    resource = "projects/fake-prod-001/global/firewalls/deny-all-egress"
    principal = "infra-sa@fake-prod-001.iam.gserviceaccount.com"
    t0 = _ts(ANCHOR - timedelta(hours=1))
    t1 = _ts(ANCHOR)
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "log_entries": [
            _fw_log_entry("compute.firewalls.insert", resource, principal, t0,
                          request={"denied": [{"IPProtocol": "all"}], "direction": "EGRESS",
                                   "labels": {"env": "prod"}}),
            _fw_log_entry("compute.firewalls.delete", resource, principal, t1),
        ],
        "resources": [],
    }


def _make_disable_cloud_firewall() -> dict:
    """T1562.007 — source-range widened to 0.0.0.0/0.

    Insert with internal range, then patch to world-open.
    """
    resource = "projects/fake-prod-002/global/firewalls/allow-ssh"
    principal = "infra-sa@fake-prod-002.iam.gserviceaccount.com"
    t0 = _ts(ANCHOR - timedelta(hours=1))
    t1 = _ts(ANCHOR)
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "log_entries": [
            _fw_log_entry("compute.firewalls.insert", resource, principal, t0,
                          request={"sourceRanges": ["10.0.0.0/8"],
                                   "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                                   "labels": {"env": "prod"}}),
            _fw_log_entry("compute.firewalls.patch", resource, principal, t1,
                          request={"sourceRanges": ["0.0.0.0/0"],
                                   "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                                   "labels": {"env": "prod"}}),
        ],
        "resources": [],
    }


def _make_data_destruction() -> dict:
    """T1485 — DELETE of an allow firewall rule (non-deny DELETE).

    Insert then delete.
    """
    resource = "projects/fake-prod-003/global/firewalls/allow-internal"
    principal = "bad-actor@acme.example.com"
    t0 = _ts(ANCHOR - timedelta(hours=1))
    t1 = _ts(ANCHOR)
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "log_entries": [
            _fw_log_entry("compute.firewalls.insert", resource, principal, t0,
                          request={"allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
                                   "labels": {"env": "prod"}}),
            _fw_log_entry("compute.firewalls.delete", resource, principal, t1),
        ],
        "resources": [],
    }


def _make_cloud_infra_discovery() -> dict:
    """T1580 — 12 IAM/firewall list calls in a 5-min window."""
    t = ANCHOR
    entries = []
    for i in range(12):
        entries.append({
            "methodName": "v1.compute.firewalls.list",
            "principalEmail": "recon-actor@external.example.com",
            "callerIp": "198.51.100.55",
            "timestamp": _ts(t + timedelta(seconds=i * 20)),
            "resourceName": "projects/fake-prod-001/global/firewalls",
        })
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "log_entries": entries,
        "resources": [],
    }


def _make_cloud_groups_discovery() -> dict:
    """T1069.003 — 12 groups/permissions list calls in a 5-min window."""
    t = ANCHOR
    entries = []
    for i in range(12):
        entries.append({
            "methodName": "cloudidentity.groups.list",
            "principalEmail": "recon-groups@external.example.com",
            "callerIp": "198.51.100.56",
            "timestamp": _ts(t + timedelta(seconds=i * 20)),
            "resourceName": "projects/fake-prod-001/groups/all",
        })
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "log_entries": entries,
        "resources": [],
    }


def _make_cloud_accounts() -> dict:
    """T1078.004 — actors sharing a /24 subnet trigger anomalous_subnets detection.

    Log entries alone are sufficient: actor-a and actor-b share 10.99.1.0/24,
    which surfaces as anomalous_subnets for both.
    """
    t = ANCHOR
    entries = []
    # actor-a: 3 majority IPs + 1 minority (10.99.1.5, ratio 1/4 <= 0.25 → anomalous_ips)
    for i in range(3):
        entries.append({
            "methodName": "v1.compute.firewalls.get",
            "principalEmail": "cloud-actor-a@acme.example.com",
            "callerIp": f"192.0.2.{10 + i}",
            "timestamp": _ts(t + timedelta(minutes=i)),
            "resourceName": "projects/fake-prod-001/global/firewalls/rule-a",
        })
    entries.append({
        "methodName": "v1.compute.firewalls.get",
        "principalEmail": "cloud-actor-a@acme.example.com",
        "callerIp": "10.99.1.5",
        "timestamp": _ts(t + timedelta(minutes=10)),
        "resourceName": "projects/fake-prod-001/global/firewalls/rule-a",
    })
    # actor-b uses same /24 subnet → shared subnet → anomalous_subnets for both
    for i in range(3):
        entries.append({
            "methodName": "v1.compute.firewalls.get",
            "principalEmail": "cloud-actor-b@external.example.com",
            "callerIp": f"10.99.1.{7 + i}",
            "timestamp": _ts(t + timedelta(minutes=11 + i)),
            "resourceName": "projects/fake-prod-001/global/firewalls/rule-a",
        })
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "log_entries": entries,
        "resources": [],
    }


# ---------------------------------------------------------------------------
# Haystack generator
# ---------------------------------------------------------------------------

PROJECTS = [
    "fake-prod-001", "fake-prod-002", "fake-prod-003",
    "fake-prod-004", "fake-prod-005",
    "fake-staging-001", "fake-staging-002",
    "fake-dev-001", "fake-dev-002", "fake-dev-003",
]
PROD_PROJECTS = [p for p in PROJECTS if "prod" in p]
STAGING_PROJECTS = [p for p in PROJECTS if "staging" in p]
DEV_PROJECTS = [p for p in PROJECTS if "dev" in p]
FOLDER_ID = "folders/999000000001"
ORG_ID = "organizations/999000000000"

CORP_PRINCIPALS = [
    "deploy-sa@fake-prod-001.iam.gserviceaccount.com",
    "deploy-sa@fake-prod-002.iam.gserviceaccount.com",
    "terraform-sa@fake-prod-003.iam.gserviceaccount.com",
    "cicd-sa@fake-staging-001.iam.gserviceaccount.com",
    "alice@acme.example.com",
    "bob@acme.example.com",
    "carol@acme.example.com",
]

CORP_IPS = [f"10.1.0.{i}" for i in range(10, 50)]
INTERNAL_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def _rand_project(rng: random.Random, projects=None) -> str:
    return rng.choice(projects or PROJECTS)


def _rand_ts(rng: random.Random, base: datetime, window_days: int = 45) -> datetime:
    offset = timedelta(seconds=rng.randint(0, window_days * 86400))
    return base + offset


def _noise_iam_log(rng: random.Random, t: datetime, project: str) -> dict:
    """Noise IAM change as native SetIamPolicy LogEntry."""
    role = rng.choice(["roles/viewer", "roles/logging.viewer", "roles/monitoring.viewer"])
    principal = rng.choice(CORP_PRINCIPALS)
    member = rng.choice([f"serviceAccount:worker-sa@{project}.iam.gserviceaccount.com",
                         "user:bob@acme.example.com"])
    return _iam_log_entry(
        resource=f"projects/{project}",
        principal=principal,
        timestamp=_ts(t),
        caller_ip=rng.choice(CORP_IPS),
        add_bindings=[{"role": role, "members": [member]}],
    )


def _noise_fw_log(rng: random.Random, t: datetime, project: str) -> dict:
    """Noise firewall patch as native compute.firewalls.patch LogEntry (baseline gap = OK)."""
    rule_name = f"allow-internal-{rng.randint(100, 999)}"
    return _fw_log_entry(
        method="compute.firewalls.patch",
        resource=f"projects/{project}/global/firewalls/{rule_name}",
        principal=rng.choice(CORP_PRINCIPALS),
        timestamp=_ts(t),
        request={
            "sourceRanges": [rng.choice(INTERNAL_RANGES)],
            "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
        },
        caller_ip=rng.choice(CORP_IPS),
    )


def _noise_nfp_log(rng: random.Random, t: datetime, project: str) -> dict:
    """Noise NFP patch as native compute.networkFirewallPolicies.patchRule LogEntry."""
    rule_name = f"corp-policy-{rng.randint(100, 999)}"
    src = rng.choice(INTERNAL_RANGES)
    return _fw_log_entry(
        method="compute.networkFirewallPolicies.patchRule",
        resource=f"projects/{project}/global/firewallPolicies/{rule_name}",
        principal=rng.choice(CORP_PRINCIPALS),
        timestamp=_ts(t),
        request={"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                             "match": {"srcIpRanges": [src]}}]},
        caller_ip=rng.choice(CORP_IPS),
    )


def _noise_log(rng: random.Random, t: datetime, project: str) -> dict:
    """Flat (pre-flattened) discovery/read log entry for actor correlation noise."""
    method = rng.choice(["v1.compute.firewalls.patch", "SetIamPolicy", "v1.compute.firewalls.get"])
    return {
        "methodName": method,
        "principalEmail": rng.choice(CORP_PRINCIPALS),
        "callerIp": rng.choice(CORP_IPS),
        "timestamp": _ts(t),
        "resourceName": f"projects/{project}/global/firewalls/allow-internal-{rng.randint(100,999)}",
    }


def _make_haystack(rng: random.Random) -> tuple[dict, dict]:
    """Generate inscope_haystack + ground_truth. Returns (haystack, ground_truth)."""
    log_entries: list[dict] = []

    # --- Noise: ~3400+ routine log entries across 45 days ---
    base = ANCHOR
    for _ in range(2200):
        t = _rand_ts(rng, base, 45)
        p = _rand_project(rng)
        log_entries.append(_noise_iam_log(rng, t, p))
    for _ in range(900):
        t = _rand_ts(rng, base, 45)
        p = _rand_project(rng)
        log_entries.append(_noise_fw_log(rng, t, p))
    for _ in range(300):
        t = _rand_ts(rng, base, 45)
        p = _rand_project(rng)
        log_entries.append(_noise_nfp_log(rng, t, p))
    for _ in range(500):
        t = _rand_ts(rng, base, 45)
        p = _rand_project(rng)
        log_entries.append(_noise_log(rng, t, p))

    # -------------------------------------------------------------------------
    # Campaign (a): folder/org-level owner grant to external identity (T1098.003 + T1199)
    # marker: "campaign-a-ext-attacker"
    # -------------------------------------------------------------------------
    t_a = base + timedelta(days=5, hours=2)
    log_entries.append(_iam_log_entry(
        resource=FOLDER_ID,
        principal="campaign-a-ext-attacker@external-domain.example.com",
        timestamp=_ts(t_a),
        add_bindings=[{"role": "roles/owner",
                       "members": ["user:campaign-a-ext-attacker@external-domain.example.com"]}],
    ))
    # Cascade: same actor grants owner on two prod projects
    for i, proj in enumerate(PROD_PROJECTS[:2]):
        log_entries.append(_iam_log_entry(
            resource=f"projects/{proj}",
            principal="campaign-a-ext-attacker@external-domain.example.com",
            timestamp=_ts(t_a + timedelta(hours=i + 1)),
            add_bindings=[{"role": "roles/owner",
                           "members": ["user:campaign-a-ext-attacker@external-domain.example.com"]}],
        ))

    # -------------------------------------------------------------------------
    # Campaign (b): firewall world-open on admin ports across prod from rotating IPs
    # marker: "campaign-b-fw-attacker" (in resource path)
    # -------------------------------------------------------------------------
    attacker_ips_b = [f"203.0.113.{i}" for i in range(10, 14)]  # rotating within one /24
    t_b = base + timedelta(days=12, hours=3)
    for i, proj in enumerate(PROD_PROJECTS):
        attacker_ip = attacker_ips_b[i % len(attacker_ips_b)]
        rule_name = f"campaign-b-fw-attacker-ssh-{proj}"
        resource = f"projects/{proj}/global/firewalls/{rule_name}"
        principal = f"infra-sa@{proj}.iam.gserviceaccount.com"
        t_insert = _ts(t_b + timedelta(hours=i * 2) - timedelta(minutes=5))
        t_patch  = _ts(t_b + timedelta(hours=i * 2))
        log_entries.append(_fw_log_entry(
            "compute.firewalls.insert", resource, principal, t_insert,
            request={"sourceRanges": ["10.0.0.0/8"],
                     "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                     "labels": {"env": "prod"}},
            caller_ip=attacker_ip,
        ))
        log_entries.append(_fw_log_entry(
            "compute.firewalls.patch", resource, principal, t_patch,
            request={"sourceRanges": ["0.0.0.0/0"],
                     "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                     "labels": {"env": "prod"}},
            caller_ip=attacker_ip,
        ))

    # -------------------------------------------------------------------------
    # Campaign (c): priority-shadow of a deny-egress rule (T1562.007)
    # marker: in resource name "campaign-c-shadow"
    # -------------------------------------------------------------------------
    t_c = base + timedelta(days=20, hours=6)
    resource_c = "projects/fake-prod-003/global/firewalls/campaign-c-shadow-deny-egress"
    principal_c = "bad-actor@acme.example.com"
    log_entries.append(_fw_log_entry(
        "compute.firewalls.insert", resource_c, principal_c,
        _ts(t_c - timedelta(minutes=10)),
        request={"denied": [{"IPProtocol": "all"}], "priority": 500, "labels": {"env": "prod"}},
    ))
    log_entries.append(_fw_log_entry(
        "compute.firewalls.patch", resource_c, principal_c, _ts(t_c),
        request={"denied": [{"IPProtocol": "all"}], "priority": 900, "labels": {"env": "prod"}},
    ))

    # -------------------------------------------------------------------------
    # Campaign (d): external-partner editor/owner grant across projects (T1199)
    # marker: "campaign-d-partner" — appears in principal to be found by test
    # -------------------------------------------------------------------------
    t_d = base + timedelta(days=28, hours=1)
    for i, proj in enumerate(PROD_PROJECTS[:3]):
        log_entries.append(_iam_log_entry(
            resource=f"projects/{proj}",
            principal="campaign-d-partner@external-partner.example.com",
            timestamp=_ts(t_d + timedelta(hours=i)),
            add_bindings=[{"role": "roles/editor",
                           "members": ["user:campaign-d-partner@external-partner.example.com"]}],
        ))

    # -------------------------------------------------------------------------
    # Campaign (e): direct folder-scope owner/token-creator binding to SA (T1098)
    # marker: "campaign-e-sa-owner" in principal field
    # -------------------------------------------------------------------------
    t_e = base + timedelta(days=35, hours=4)
    log_entries.append(_iam_log_entry(
        resource=FOLDER_ID,
        principal="campaign-e-sa-owner@acme.example.com",
        timestamp=_ts(t_e),
        add_bindings=[{
            "role": "roles/iam.serviceAccountTokenCreator",
            "members": ["serviceAccount:priv-sa@fake-prod-001.iam.gserviceaccount.com"],
        }],
    ))

    # -------------------------------------------------------------------------
    # Campaign (f): network_firewall_policy world-open allow across prod (T1562.007)
    # marker: "campaign-f-nfp-attacker" in resource path
    # -------------------------------------------------------------------------
    t_f = base + timedelta(days=38, hours=5)
    for i, proj in enumerate(PROD_PROJECTS[:3]):
        policy_name = f"campaign-f-nfp-attacker-policy-{proj}"
        resource_f = f"projects/{proj}/global/firewallPolicies/{policy_name}"
        principal_f = f"infra-sa@{proj}.iam.gserviceaccount.com"
        # addRule = UPDATE-like with no prior insert, gives baseline gap → before=None
        log_entries.append(_fw_log_entry(
            "compute.networkFirewallPolicies.addRule", resource_f, principal_f,
            _ts(t_f + timedelta(hours=i)),
            request={"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                                 "match": {"srcIpRanges": ["0.0.0.0/0"]}}]},
        ))

    # -------------------------------------------------------------------------
    # Decoy 1: reverted dev firewall — open to 0.0.0.0/0 then back to internal 2h later
    # -------------------------------------------------------------------------
    t_decoy1 = base + timedelta(days=8, hours=9)
    resource_d1 = "projects/fake-dev-001/global/firewalls/decoy-revert-dev-fw"
    principal_d1 = "carol@acme.example.com"
    log_entries.append(_fw_log_entry(
        "compute.firewalls.insert", resource_d1, principal_d1,
        _ts(t_decoy1 - timedelta(minutes=5)),
        request={"sourceRanges": ["10.0.0.0/8"],
                 "allowed": [{"IPProtocol": "tcp", "ports": ["8080"]}],
                 "labels": {"env": "dev"}},
    ))
    log_entries.append(_fw_log_entry(
        "compute.firewalls.patch", resource_d1, principal_d1, _ts(t_decoy1),
        request={"sourceRanges": ["0.0.0.0/0"],
                 "allowed": [{"IPProtocol": "tcp", "ports": ["8080"]}],
                 "labels": {"env": "dev"}},
    ))
    # Revert 2h later
    log_entries.append(_fw_log_entry(
        "compute.firewalls.patch", resource_d1, principal_d1,
        _ts(t_decoy1 + timedelta(hours=2)),
        request={"sourceRanges": ["10.0.0.0/8"],
                 "allowed": [{"IPProtocol": "tcp", "ports": ["8080"]}],
                 "labels": {"env": "dev"}},
    ))

    # -------------------------------------------------------------------------
    # Decoy 2: approved external viewer (read-only in staging)
    # -------------------------------------------------------------------------
    t_decoy2 = base + timedelta(days=15, hours=11)
    log_entries.append(_iam_log_entry(
        resource="projects/fake-staging-001",
        principal="approved-external-viewer@trusted-vendor.example.com",
        timestamp=_ts(t_decoy2),
        add_bindings=[{
            "role": "roles/viewer",
            "members": ["user:approved-external-viewer@trusted-vendor.example.com"],
        }],
    ))

    # -------------------------------------------------------------------------
    # Decoy 3: expected staging owner-SA
    # -------------------------------------------------------------------------
    t_decoy3 = base + timedelta(days=22, hours=7)
    log_entries.append(_iam_log_entry(
        resource="projects/fake-staging-002",
        principal="carol@acme.example.com",
        timestamp=_ts(t_decoy3),
        add_bindings=[{
            "role": "roles/owner",
            "members": ["serviceAccount:staging-owner-sa@fake-staging-002.iam.gserviceaccount.com"],
        }],
    ))

    # -------------------------------------------------------------------------
    # Decoy 4: benign internal-range firewall widen
    # -------------------------------------------------------------------------
    t_decoy4 = base + timedelta(days=30, hours=14)
    resource_d4 = "projects/fake-prod-004/global/firewalls/allow-corp-expanded"
    principal_d4 = "deploy-sa@fake-prod-001.iam.gserviceaccount.com"
    log_entries.append(_fw_log_entry(
        "compute.firewalls.insert", resource_d4, principal_d4,
        _ts(t_decoy4 - timedelta(minutes=5)),
        request={"sourceRanges": ["10.1.0.0/24"],
                 "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
                 "labels": {"env": "prod"}},
    ))
    log_entries.append(_fw_log_entry(
        "compute.firewalls.patch", resource_d4, principal_d4, _ts(t_decoy4),
        request={"sourceRanges": ["10.0.0.0/8"],
                 "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
                 "labels": {"env": "prod"}},
    ))

    # Build IAM policies snapshot (static) — native asset-wrapped shape
    iam_policies = [
        {
            "name": f"//cloudresourcemanager.googleapis.com/projects/{p}",
            "asset_type": "cloudresourcemanager.googleapis.com/Project",
            "iam_policy": {
                "bindings": [
                    {"role": "roles/viewer",
                     "members": [f"serviceAccount:deploy-sa@{p}.iam.gserviceaccount.com"]}
                ]
            },
        }
        for p in PROJECTS
    ]
    iam_policies.append({
        "name": f"//cloudresourcemanager.googleapis.com/{FOLDER_ID}",
        "asset_type": "cloudresourcemanager.googleapis.com/Folder",
        "iam_policy": {
            "bindings": [{"role": "roles/viewer", "members": ["user:alice@acme.example.com"]}]
        },
    })

    haystack = {
        "iam_policies": iam_policies,
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "log_entries": log_entries,
        "resources": [{"name": f"subnet-{p}", "network": "default", "project": p} for p in PROJECTS],
    }

    ground_truth = {
        "campaigns": [
            {
                "id": "campaign-a",
                "techniques": ["T1098.003", "T1199"],
                "description": "Folder/org-level owner grant cascading to external identity",
                "marker": "campaign-a-ext-attacker",
            },
            {
                "id": "campaign-b",
                "techniques": ["T1562.007"],
                "description": "Firewall world-open on admin ports across prod from rotating IPs",
                "marker": "campaign-b-fw-attacker",
            },
            {
                "id": "campaign-c",
                "techniques": ["T1562.007"],
                "description": "Priority-shadow of deny-egress rule",
                "marker": "campaign-c-shadow",
            },
            {
                "id": "campaign-d",
                "techniques": ["T1199"],
                "description": "External-partner editor/owner grant across projects",
                "marker": "campaign-d-partner",
            },
            {
                "id": "campaign-e",
                "techniques": ["T1098"],
                "description": "Direct folder-scope token-creator binding to SA",
                "marker": "campaign-e-sa-owner",
            },
            {
                "id": "campaign-f",
                "techniques": ["T1562.007"],
                "description": "Network firewall policy world-open allow across prod projects",
                "marker": "campaign-f-nfp-attacker",
            },
        ],
        "decoys": [
            {
                "id": "reverted-dev-firewall",
                "description": "0.0.0.0/0 opened then reverted to internal within 2h in dev",
                "fires_but_benign": True,
                "resource": "projects/fake-dev-001/global/firewalls/decoy-revert-dev-fw",
                "expected_technique": "T1562.007",
            },
            {
                "id": "approved-external-viewer",
                "description": "Approved read-only external viewer in staging",
                "fires_but_benign": True,
                "resource": "projects/fake-staging-001",
                "expected_technique": "T1199",
            },
            {
                "id": "expected-staging-owner-sa",
                "description": "Expected staging service-account owner",
                "fires_but_benign": True,
                "resource": "projects/fake-staging-002",
                "expected_technique": "T1098.003",
            },
            {
                "id": "benign-internal-range-widen",
                "description": "Firewall widened from /24 to /8 but stays internal",
                "should_not_alert": True,
            },
        ],
    }

    return haystack, ground_truth


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

TECHNIQUE_GENERATORS = {
    "fixtures/incidents/account_manipulation.json": _make_account_manipulation,
    "fixtures/incidents/additional_cloud_roles.json": _make_additional_cloud_roles,
    "fixtures/incidents/trusted_relationship.json": _make_trusted_relationship,
    "fixtures/incidents/impair_defenses.json": _make_impair_defenses,
    "fixtures/incidents/disable_cloud_firewall.json": _make_disable_cloud_firewall,
    "fixtures/incidents/data_destruction.json": _make_data_destruction,
    "fixtures/incidents/cloud_infra_discovery.json": _make_cloud_infra_discovery,
    "fixtures/incidents/cloud_groups_discovery.json": _make_cloud_groups_discovery,
    "fixtures/incidents/cloud_accounts.json": _make_cloud_accounts,
}


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def main(out_dir: Path | None = None) -> None:
    rng = random.Random(SEED)

    # Determine repo root (generate.py lives at fixtures/incidents/generate.py)
    repo_root = Path(__file__).resolve().parent.parent.parent

    if out_dir is None:
        out_dir = Path(__file__).resolve().parent

    # Per-technique fixtures
    for rel_path, gen_fn in TECHNIQUE_GENERATORS.items():
        dest = out_dir / Path(rel_path).name
        _write(dest, gen_fn())

    # Haystack + ground truth
    haystack, ground_truth = _make_haystack(rng)
    _write(out_dir / "inscope_haystack.json", haystack)
    _write(out_dir / "inscope_ground_truth.json", ground_truth)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate attack-coverage fixtures")
    parser.add_argument("--out-dir", type=Path, default=None,
                        help="Output directory (default: same dir as this script)")
    args = parser.parse_args()
    main(out_dir=args.out_dir)
    print(f"Generated fixtures in {args.out_dir or Path(__file__).parent}", file=sys.stderr)
