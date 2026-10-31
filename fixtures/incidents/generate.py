"""Deterministic seeded fixture generator for gcp_policy_analyzer attack-coverage tests.

Usage:
    python generate.py                     # writes to fixtures/incidents/ (alongside this file)
    python generate.py --out-dir /tmp/foo  # writes to custom dir

Every generated event uses resource_type in {iam_policy, firewall_rule, network_firewall_policy}.
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


# ---------------------------------------------------------------------------
# Per-technique small fixtures
# ---------------------------------------------------------------------------

def _make_account_manipulation() -> dict:
    """T1098 — toxic combination (token-creator on folder → bumped to critical)."""
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "audit_changes": [
            {
                "resource": "folders/111111111111",
                "resource_type": "iam_policy",
                "action": "UPDATE",
                "principal": "admin@acme.example.com",
                "timestamp": _ts(ANCHOR),
                "before": {"bindings": []},
                "after": {
                    "bindings": [
                        {
                            "role": "roles/iam.serviceAccountTokenCreator",
                            "members": ["serviceAccount:attacker-sa@fake-proj.iam.gserviceaccount.com"],
                        }
                    ]
                },
                "labels": {},
            }
        ],
        "log_entries": [],
        "resources": [],
    }


def _make_additional_cloud_roles() -> dict:
    """T1098.003 — high-privilege owner grant on folder (cascading)."""
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "audit_changes": [
            {
                "resource": "folders/222222222222",
                "resource_type": "iam_policy",
                "action": "UPDATE",
                "principal": "admin@acme.example.com",
                "timestamp": _ts(ANCHOR),
                "before": {"bindings": []},
                "after": {
                    "bindings": [
                        {
                            "role": "roles/owner",
                            "members": ["user:ext-attacker@external.example.com"],
                        }
                    ]
                },
                "labels": {},
            }
        ],
        "log_entries": [],
        "resources": [],
    }


def _make_trusted_relationship() -> dict:
    """T1199 — external identity (non-corp, non-SA) granted editor on a project."""
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "audit_changes": [
            {
                "resource": "projects/fake-prod-001",
                "resource_type": "iam_policy",
                "action": "UPDATE",
                "principal": "admin@acme.example.com",
                "timestamp": _ts(ANCHOR),
                "before": {"bindings": []},
                "after": {
                    "bindings": [
                        {
                            "role": "roles/editor",
                            "members": ["user:partner@external-partner.example.com"],
                        }
                    ]
                },
                "labels": {},
            }
        ],
        "log_entries": [],
        "resources": [],
    }


def _make_impair_defenses() -> dict:
    """T1562 — DELETE of a deny rule (RemovedProtection)."""
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "audit_changes": [
            {
                "resource": "projects/fake-prod-001/global/firewalls/deny-all-egress",
                "resource_type": "firewall_rule",
                "action": "DELETE",
                "principal": "infra-sa@fake-prod-001.iam.gserviceaccount.com",
                "timestamp": _ts(ANCHOR),
                "before": {"denied": [{"IPProtocol": "all"}], "direction": "EGRESS"},
                "after": None,
                "labels": {"env": "prod"},
            }
        ],
        "log_entries": [],
        "resources": [],
    }


def _make_disable_cloud_firewall() -> dict:
    """T1562.007 — source-range widened to 0.0.0.0/0."""
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "audit_changes": [
            {
                "resource": "projects/fake-prod-002/global/firewalls/allow-ssh",
                "resource_type": "firewall_rule",
                "action": "UPDATE",
                "principal": "infra-sa@fake-prod-002.iam.gserviceaccount.com",
                "timestamp": _ts(ANCHOR),
                "before": {"sourceRanges": ["10.0.0.0/8"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
                "after": {"sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
                "labels": {"env": "prod"},
            }
        ],
        "log_entries": [],
        "resources": [],
    }


def _make_data_destruction() -> dict:
    """T1485 — DELETE of an allow firewall rule (non-deny DELETE)."""
    return {
        "iam_policies": [],
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "audit_changes": [
            {
                "resource": "projects/fake-prod-003/global/firewalls/allow-internal",
                "resource_type": "firewall_rule",
                "action": "DELETE",
                "principal": "bad-actor@acme.example.com",
                "timestamp": _ts(ANCHOR),
                "before": {"allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
                "after": None,
                "labels": {"env": "prod"},
            }
        ],
        "log_entries": [],
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
        "audit_changes": [],
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
        "audit_changes": [],
        "log_entries": entries,
        "resources": [],
    }


def _make_cloud_accounts() -> dict:
    """T1078.004 — actors sharing a /24 subnet trigger anomalous_subnets detection.

    No audit_changes (dict changes would break correlate_by_actor which expects Change objects).
    The log entries alone are sufficient: actor-a and actor-b share 10.99.1.0/24,
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
        "audit_changes": [],
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


def _noise_iam_change(rng: random.Random, t: datetime, project: str) -> dict:
    role = rng.choice(["roles/viewer", "roles/logging.viewer", "roles/monitoring.viewer"])
    principal = rng.choice(CORP_PRINCIPALS)
    member = rng.choice([f"serviceAccount:worker-sa@{project}.iam.gserviceaccount.com",
                         "user:bob@acme.example.com"])
    return {
        "resource": f"projects/{project}",
        "resource_type": "iam_policy",
        "action": "UPDATE",
        "principal": principal,
        "timestamp": _ts(t),
        "before": {"bindings": [{"role": role, "members": []}]},
        "after": {"bindings": [{"role": role, "members": [member]}]},
        "labels": {"env": "prod" if "prod" in project else "dev"},
    }


def _noise_fw_change(rng: random.Random, t: datetime, project: str) -> dict:
    rule_name = f"allow-internal-{rng.randint(100, 999)}"
    return {
        "resource": f"projects/{project}/global/firewalls/{rule_name}",
        "resource_type": "firewall_rule",
        "action": "UPDATE",
        "principal": rng.choice(CORP_PRINCIPALS),
        "timestamp": _ts(t),
        "before": {"sourceRanges": [rng.choice(INTERNAL_RANGES)],
                   "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
        "after": {"sourceRanges": [rng.choice(INTERNAL_RANGES)],
                  "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
        "labels": {},
    }


def _noise_nfp_change(rng: random.Random, t: datetime, project: str) -> dict:
    """Routine network_firewall_policy noise — internal-only rule tweak, never world-open."""
    rule_name = f"corp-policy-{rng.randint(100, 999)}"
    src = rng.choice(INTERNAL_RANGES)
    return {
        "resource": f"projects/{project}/global/firewallPolicies/{rule_name}",
        "resource_type": "network_firewall_policy",
        "action": "UPDATE",
        "principal": rng.choice(CORP_PRINCIPALS),
        "timestamp": _ts(t),
        "before": {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                               "match": {"srcIpRanges": [src]}}]},
        "after": {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                              "match": {"srcIpRanges": [rng.choice(INTERNAL_RANGES)]}}]},
        "labels": {},
    }


def _noise_log(rng: random.Random, t: datetime, project: str) -> dict:
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
    audit_changes: list[dict] = []
    log_entries: list[dict] = []

    # --- Noise: ~3100+ routine changes across 45 days ---
    base = ANCHOR
    for _ in range(2200):
        t = _rand_ts(rng, base, 45)
        p = _rand_project(rng)
        audit_changes.append(_noise_iam_change(rng, t, p))
    for _ in range(900):
        t = _rand_ts(rng, base, 45)
        p = _rand_project(rng)
        audit_changes.append(_noise_fw_change(rng, t, p))
    for _ in range(300):
        t = _rand_ts(rng, base, 45)
        p = _rand_project(rng)
        audit_changes.append(_noise_nfp_change(rng, t, p))
    for _ in range(500):
        t = _rand_ts(rng, base, 45)
        p = _rand_project(rng)
        log_entries.append(_noise_log(rng, t, p))

    # -------------------------------------------------------------------------
    # Campaign (a): folder/org-level owner grant to external identity (T1098.003 + T1199)
    # marker: "campaign-a-ext-attacker"
    # -------------------------------------------------------------------------
    t_a = base + timedelta(days=5, hours=2)
    audit_changes.append({
        "resource": FOLDER_ID,
        "resource_type": "iam_policy",
        "action": "UPDATE",
        "principal": "campaign-a-ext-attacker@external-domain.example.com",
        "timestamp": _ts(t_a),
        "before": {"bindings": []},
        "after": {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": ["user:campaign-a-ext-attacker@external-domain.example.com"],
                }
            ]
        },
        "labels": {"env": "prod"},
    })
    # Cascade: same actor grants owner on two prod projects
    for i, proj in enumerate(PROD_PROJECTS[:2]):
        audit_changes.append({
            "resource": f"projects/{proj}",
            "resource_type": "iam_policy",
            "action": "UPDATE",
            "principal": "campaign-a-ext-attacker@external-domain.example.com",
            "timestamp": _ts(t_a + timedelta(hours=i + 1)),
            "before": {"bindings": []},
            "after": {
                "bindings": [
                    {
                        "role": "roles/owner",
                        "members": ["user:campaign-a-ext-attacker@external-domain.example.com"],
                    }
                ]
            },
            "labels": {"env": "prod"},
        })

    # -------------------------------------------------------------------------
    # Campaign (b): firewall world-open on admin ports across prod from rotating IPs
    # marker: "campaign-b-fw-attacker" (in resource path)
    # -------------------------------------------------------------------------
    attacker_ips_b = [f"203.0.113.{i}" for i in range(10, 14)]  # rotating within one /24
    t_b = base + timedelta(days=12, hours=3)
    for i, proj in enumerate(PROD_PROJECTS):
        attacker_ip = attacker_ips_b[i % len(attacker_ips_b)]
        rule_name = f"campaign-b-fw-attacker-ssh-{proj}"
        audit_changes.append({
            "resource": f"projects/{proj}/global/firewalls/{rule_name}",
            "resource_type": "firewall_rule",
            "action": "UPDATE",
            "principal": f"infra-sa@{proj}.iam.gserviceaccount.com",
            "timestamp": _ts(t_b + timedelta(hours=i * 2)),
            "before": {"sourceRanges": ["10.0.0.0/8"],
                       "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
            "after": {"sourceRanges": ["0.0.0.0/0"],
                      "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
            "labels": {"env": "prod"},
        })
        log_entries.append({
            "methodName": "v1.compute.firewalls.patch",
            "principalEmail": f"infra-sa@{proj}.iam.gserviceaccount.com",
            "callerIp": attacker_ip,
            "timestamp": _ts(t_b + timedelta(hours=i * 2)),
            "resourceName": f"projects/{proj}/global/firewalls/{rule_name}",
        })

    # -------------------------------------------------------------------------
    # Campaign (c): priority-shadow of a deny-egress rule (T1562.007)
    # marker: in resource name "campaign-c-shadow"
    # -------------------------------------------------------------------------
    t_c = base + timedelta(days=20, hours=6)
    audit_changes.append({
        "resource": "projects/fake-prod-003/global/firewalls/campaign-c-shadow-deny-egress",
        "resource_type": "firewall_rule",
        "action": "UPDATE",
        "principal": "bad-actor@acme.example.com",
        "timestamp": _ts(t_c),
        "before": {"denied": [{"IPProtocol": "all"}], "priority": 500},
        "after": {"denied": [{"IPProtocol": "all"}], "priority": 900},
        "labels": {"env": "prod"},
    })

    # -------------------------------------------------------------------------
    # Campaign (d): external-partner editor/owner grant across projects (T1199)
    # marker: "campaign-d-partner" — appears in principal to be found by test
    # -------------------------------------------------------------------------
    t_d = base + timedelta(days=28, hours=1)
    for i, proj in enumerate(PROD_PROJECTS[:3]):
        audit_changes.append({
            "resource": f"projects/{proj}",
            "resource_type": "iam_policy",
            "action": "UPDATE",
            "principal": "campaign-d-partner@external-partner.example.com",
            "timestamp": _ts(t_d + timedelta(hours=i)),
            "before": {"bindings": []},
            "after": {
                "bindings": [
                    {
                        "role": "roles/editor",
                        "members": ["user:campaign-d-partner@external-partner.example.com"],
                    }
                ]
            },
            "labels": {"env": "prod"},
        })

    # -------------------------------------------------------------------------
    # Campaign (e): direct folder-scope owner/token-creator binding to SA (T1098)
    # marker: "campaign-e-sa-owner" in principal field
    # -------------------------------------------------------------------------
    t_e = base + timedelta(days=35, hours=4)
    audit_changes.append({
        "resource": FOLDER_ID,
        "resource_type": "iam_policy",
        "action": "UPDATE",
        "principal": "campaign-e-sa-owner@acme.example.com",
        "timestamp": _ts(t_e),
        "before": {"bindings": []},
        "after": {
            "bindings": [
                {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "members": ["serviceAccount:priv-sa@fake-prod-001.iam.gserviceaccount.com"],
                }
            ]
        },
        "labels": {"env": "prod"},
    })

    # -------------------------------------------------------------------------
    # Campaign (f): network_firewall_policy world-open allow across prod (T1562.007)
    # marker: "campaign-f-nfp-attacker" in resource path
    # -------------------------------------------------------------------------
    t_f = base + timedelta(days=38, hours=5)
    for i, proj in enumerate(PROD_PROJECTS[:3]):
        policy_name = f"campaign-f-nfp-attacker-policy-{proj}"
        audit_changes.append({
            "resource": f"projects/{proj}/global/firewallPolicies/{policy_name}",
            "resource_type": "network_firewall_policy",
            "action": "UPDATE",
            "principal": f"infra-sa@{proj}.iam.gserviceaccount.com",
            "timestamp": _ts(t_f + timedelta(hours=i)),
            "before": {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                                   "match": {"srcIpRanges": ["10.0.0.0/8"]}}]},
            "after": {"rules": [{"priority": 1000, "direction": "INGRESS", "action": "allow",
                                  "match": {"srcIpRanges": ["0.0.0.0/0"]}}]},
            "labels": {"env": "prod"},
        })

    # -------------------------------------------------------------------------
    # Decoy 1: reverted dev firewall — open to 0.0.0.0/0 then back to internal 2h later
    # -------------------------------------------------------------------------
    t_decoy1 = base + timedelta(days=8, hours=9)
    audit_changes.append({
        "resource": "projects/fake-dev-001/global/firewalls/decoy-revert-dev-fw",
        "resource_type": "firewall_rule",
        "action": "UPDATE",
        "principal": "carol@acme.example.com",
        "timestamp": _ts(t_decoy1),
        "before": {"sourceRanges": ["10.0.0.0/8"],
                   "allowed": [{"IPProtocol": "tcp", "ports": ["8080"]}]},
        "after": {"sourceRanges": ["0.0.0.0/0"],
                  "allowed": [{"IPProtocol": "tcp", "ports": ["8080"]}]},
        "labels": {"env": "dev"},
    })
    # Revert 2h later
    audit_changes.append({
        "resource": "projects/fake-dev-001/global/firewalls/decoy-revert-dev-fw",
        "resource_type": "firewall_rule",
        "action": "UPDATE",
        "principal": "carol@acme.example.com",
        "timestamp": _ts(t_decoy1 + timedelta(hours=2)),
        "before": {"sourceRanges": ["0.0.0.0/0"],
                   "allowed": [{"IPProtocol": "tcp", "ports": ["8080"]}]},
        "after": {"sourceRanges": ["10.0.0.0/8"],
                  "allowed": [{"IPProtocol": "tcp", "ports": ["8080"]}]},
        "labels": {"env": "dev"},
    })

    # -------------------------------------------------------------------------
    # Decoy 2: approved external viewer (read-only in staging)
    # -------------------------------------------------------------------------
    t_decoy2 = base + timedelta(days=15, hours=11)
    audit_changes.append({
        "resource": "projects/fake-staging-001",
        "resource_type": "iam_policy",
        "action": "UPDATE",
        "principal": "approved-external-viewer@trusted-vendor.example.com",
        "timestamp": _ts(t_decoy2),
        "before": {"bindings": []},
        "after": {
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": ["user:approved-external-viewer@trusted-vendor.example.com"],
                }
            ]
        },
        "labels": {"env": "staging"},
    })

    # -------------------------------------------------------------------------
    # Decoy 3: expected staging owner-SA
    # -------------------------------------------------------------------------
    t_decoy3 = base + timedelta(days=22, hours=7)
    audit_changes.append({
        "resource": "projects/fake-staging-002",
        "resource_type": "iam_policy",
        "action": "UPDATE",
        "principal": "carol@acme.example.com",
        "timestamp": _ts(t_decoy3),
        "before": {"bindings": []},
        "after": {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": ["serviceAccount:staging-owner-sa@fake-staging-002.iam.gserviceaccount.com"],
                }
            ]
        },
        "labels": {"env": "staging"},
    })

    # -------------------------------------------------------------------------
    # Decoy 4: benign internal-range firewall widen
    # -------------------------------------------------------------------------
    t_decoy4 = base + timedelta(days=30, hours=14)
    audit_changes.append({
        "resource": "projects/fake-prod-004/global/firewalls/allow-corp-expanded",
        "resource_type": "firewall_rule",
        "action": "UPDATE",
        "principal": "deploy-sa@fake-prod-001.iam.gserviceaccount.com",
        "timestamp": _ts(t_decoy4),
        "before": {"sourceRanges": ["10.1.0.0/24"],
                   "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
        "after": {"sourceRanges": ["10.0.0.0/8"],
                  "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
        "labels": {"env": "prod"},
    })

    # Build IAM policies snapshot (static)
    iam_policies = [
        {
            "resource": f"projects/{p}",
            "labels": {"env": "prod" if "prod" in p else ("staging" if "staging" in p else "dev")},
            "bindings": [
                {"role": "roles/viewer",
                 "members": [f"serviceAccount:deploy-sa@{p}.iam.gserviceaccount.com"]}
            ],
        }
        for p in PROJECTS
    ]
    iam_policies.append({
        "resource": FOLDER_ID,
        "labels": {},
        "bindings": [{"role": "roles/viewer", "members": ["user:alice@acme.example.com"]}],
    })

    haystack = {
        "iam_policies": iam_policies,
        "vpc_firewall_rules": [],
        "network_firewall_policies": [],
        "audit_changes": audit_changes,
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
                "should_not_alert": True,
            },
            {
                "id": "approved-external-viewer",
                "description": "Approved read-only external viewer in staging",
                "should_not_alert": True,
            },
            {
                "id": "expected-staging-owner-sa",
                "description": "Expected staging service-account owner",
                "should_not_alert": True,
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
