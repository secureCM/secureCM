"""ATT&CK-mapped findings and firewall exposure detector."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from gcp_policy_analyzer.helpers import is_production
from gcp_policy_analyzer.scoring import classify_change, ChangeClass

_WORLD_RANGES: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})
_ADMIN_PORTS: frozenset[str] = frozenset({"22", "3389", "3333", "4444", "14444"})


@dataclass
class Finding:
    technique_id: str
    technique_name: str
    tactic: str
    severity: str           # "critical" | "high" | "medium" | "low"
    resource: str
    principal: str
    timestamp: datetime | None
    evidence: dict = field(default_factory=dict)


def _has_world(ranges: list[str]) -> bool:
    return bool(_WORLD_RANGES & set(ranges))


def _broad_ports(entries: list[dict]) -> bool:
    """True if entries include all-protocol, all-ports, or admin/mining ports."""
    for e in entries:
        proto = e.get("IPProtocol", "")
        if proto == "all":
            return True
        ports = e.get("ports", [])
        if not ports:   # proto specified but no port restriction = all ports
            return True
        if "0-65535" in ports:
            return True
        if _ADMIN_PORTS & set(ports):
            return True
    return False


def detect_firewall_exposure(rules: list, changes: list) -> list[Finding]:  # noqa: ARG001
    """Detect ATT&CK T1562.007 and T1485 from firewall rules and audit changes."""
    # ponytail: rules list reserved for future static-rule scanning; unused now
    findings: list[Finding] = []

    for change in changes:
        if isinstance(change, dict):
            action: str = change.get("action", "")
            resource: str = change.get("resource", "")
            principal: str = change.get("principal", "")
            timestamp = change.get("timestamp")
            labels: dict = change.get("labels", {})
            before: dict = change.get("before") or {}
            after: dict = change.get("after") or {}
        else:
            action = getattr(change, "action", "")
            resource = getattr(change, "resource", "")
            principal = getattr(change, "principal", "")
            timestamp = getattr(change, "timestamp", None)
            labels = getattr(change, "labels", {})
            before = getattr(change, "before", None) or {}
            after = getattr(change, "after", None) or {}

        prod = is_production(change)
        base_sev = "critical" if prod else "high"

        cc = classify_change(change)

        # --- T1562.007: BroadenedAccess via source range widening ---
        if cc == ChangeClass.BroadenedAccess:
            after_ranges = after.get("sourceRanges", [])
            before_ranges = before.get("sourceRanges", [])
            widened = _has_world(after_ranges) and not _has_world(before_ranges)
            if widened:
                findings.append(Finding(
                    technique_id="T1562.007",
                    technique_name="Disable or Modify Cloud Firewall",
                    tactic="defense-evasion",
                    severity=base_sev,
                    resource=resource,
                    principal=principal,
                    timestamp=timestamp,
                    evidence={"before_ranges": before_ranges, "after_ranges": after_ranges},
                ))
                continue

        # --- T1562.007: broad ports added to world-open rule ---
        after_ranges = after.get("sourceRanges", [])
        after_allowed = after.get("allowed", []) + after.get("denied", [])
        if _has_world(after_ranges) and _broad_ports(after_allowed):
            before_ranges = before.get("sourceRanges", [])
            before_allowed = before.get("allowed", []) + before.get("denied", [])
            # Only flag if this is new (wasn't already world+broad before)
            if not (_has_world(before_ranges) and _broad_ports(before_allowed)):
                findings.append(Finding(
                    technique_id="T1562.007",
                    technique_name="Disable or Modify Cloud Firewall",
                    tactic="defense-evasion",
                    severity=base_sev,
                    resource=resource,
                    principal=principal,
                    timestamp=timestamp,
                    evidence={"after_ranges": after_ranges, "allowed": after_allowed},
                ))
                continue

        # --- T1562.007: RemovedProtection (DELETE or disable of deny rule, or priority raised) ---
        if cc == ChangeClass.RemovedProtection:
            findings.append(Finding(
                technique_id="T1562.007",
                technique_name="Disable or Modify Cloud Firewall",
                tactic="defense-evasion",
                severity=base_sev,
                resource=resource,
                principal=principal,
                timestamp=timestamp,
                evidence={"action": action, "before": before},
            ))
            continue

        # --- T1562.007: priority raised on a deny rule (shadow) ---
        before_denied = before.get("denied", [])
        after_denied = after.get("denied", [])
        if before_denied and after_denied and action == "UPDATE":
            before_pri = before.get("priority", 1000)
            after_pri = after.get("priority", 1000)
            if after_pri > before_pri:  # higher number = lower priority = shadowed
                findings.append(Finding(
                    technique_id="T1562.007",
                    technique_name="Disable or Modify Cloud Firewall",
                    tactic="defense-evasion",
                    severity=base_sev,
                    resource=resource,
                    principal=principal,
                    timestamp=timestamp,
                    evidence={"before_priority": before_pri, "after_priority": after_pri},
                ))
                continue

        # --- T1485: DELETE of any firewall/policy resource ---
        if action == "DELETE":
            findings.append(Finding(
                technique_id="T1485",
                technique_name="Data Destruction",
                tactic="impact",
                severity=base_sev,
                resource=resource,
                principal=principal,
                timestamp=timestamp,
                evidence={"before": before},
            ))

    return findings
