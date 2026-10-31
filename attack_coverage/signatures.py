"""Technique→detector registry and batch runner."""
from __future__ import annotations

from attack_coverage.catalog import load_catalog
from gcp_policy_analyzer.detect import (
    Finding,
    detect_anomalous_actor,
    detect_discovery_bursts,
    detect_firewall_exposure,
    detect_privilege_grant,
)
from gcp_policy_analyzer.loaders import (
    load_audit_changes,
    load_iam_policies,
    load_network_firewall_policies,
    load_vpc_firewall_rules,
)

# Build registry from catalog so test_registry_matches_catalog always passes.
TECHNIQUE_DETECTOR: dict[str, str] = {
    t["id"]: t["detector"]
    for t in load_catalog()["techniques"]
    if t.get("status") in ("covered", "partial")
}

_DETECTORS = {
    "detect_firewall_exposure": detect_firewall_exposure,
    "detect_privilege_grant": detect_privilege_grant,
    "detect_discovery_bursts": detect_discovery_bursts,
    "detect_anomalous_actor": detect_anomalous_actor,
}


def run_detectors(envelope: dict) -> list[Finding]:
    """Run every distinct detector once over envelope; return all Findings."""
    if not envelope:
        return []

    rules = load_vpc_firewall_rules(envelope) + [
        r for p in load_network_firewall_policies(envelope) for r in p.rules
    ]
    iam = load_iam_policies(envelope)
    changes = load_audit_changes(envelope)
    logs = envelope.get("log_entries", [])

    results: list[Finding] = []
    # Run each distinct detector once; order matches catalog appearance.
    seen: set[str] = set()
    for name in TECHNIQUE_DETECTOR.values():
        if name in seen:
            continue
        seen.add(name)
        if name not in _DETECTORS:
            raise ValueError(f"run_detectors: no dispatch branch for detector {name!r}")
        fn = _DETECTORS[name]
        if name == "detect_firewall_exposure":
            results.extend(fn(rules, changes))
        elif name == "detect_privilege_grant":
            results.extend(fn(iam, changes))
        elif name == "detect_discovery_bursts":
            results.extend(fn(logs))
        elif name == "detect_anomalous_actor":
            results.extend(fn(changes, logs))

    return results


def findings_for_technique(findings: list[Finding], technique_id: str) -> list[Finding]:
    return [f for f in findings if f.technique_id == technique_id]
