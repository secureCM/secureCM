"""ATT&CK-mapped findings and firewall exposure detector."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from gcp_policy_analyzer.helpers import is_production, is_service_account
from gcp_policy_analyzer.scoring import classify_change, ChangeClass, score_iam_binding, HIGH_PRIVILEGE_ROLES

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

        # --- T1562.007: broad ports added to world-open ALLOW rule ---
        # ponytail: scan allowed[] only — adding ports to denied[] blocks more, not less; not exposure
        after_ranges = after.get("sourceRanges", [])
        after_allowed = after.get("allowed", [])
        if _has_world(after_ranges) and _broad_ports(after_allowed):
            before_ranges = before.get("sourceRanges", [])
            before_allowed = before.get("allowed", [])
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
        # Precedence: deny-delete → T1562.007 ONLY (defense evasion); `continue` prevents T1485 fallthrough.
        # A DELETE of a non-deny resource falls through to T1485 below (RemovedProtection not returned for those).
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


# Severity ladder used for bumping
_SEV_ORDER = ("low", "medium", "high", "critical")


def _bump_severity(sev: str) -> str:
    idx = _SEV_ORDER.index(sev) if sev in _SEV_ORDER else 0
    return _SEV_ORDER[min(idx + 1, len(_SEV_ORDER) - 1)]


# Roles that are always critical (no bump needed — already at top)
_CRITICAL_ROLES = frozenset({"roles/owner", "roles/iam.securityAdmin"})


def detect_privilege_grant(
    iam_policies: list,
    changes: list,
    *,
    corp_domains: tuple[str, ...] = ("acme.example.com",),
) -> list[Finding]:
    """Detect IAM privilege escalation and external-identity grants.

    ATT&CK:
      T1098.003 — high-privilege role granted (critical for owner/securityAdmin)
      T1199     — external (non-corp, non-SA) identity granted any role
      T1098     — newly-added binding produces toxic combination
    """
    # ponytail: iam_policies param reserved for future static-snapshot scanning
    findings: list[Finding] = []

    for change in changes:
        if isinstance(change, dict):
            action: str = change.get("action", "")
            resource: str = change.get("resource", "")
            principal: str = change.get("principal", "")
            timestamp = change.get("timestamp")
            before: dict = change.get("before") or {}
            after: dict = change.get("after") or {}
        else:
            action = getattr(change, "action", "")
            resource = getattr(change, "resource", "")
            principal = getattr(change, "principal", "")
            timestamp = getattr(change, "timestamp", None)
            before = getattr(change, "before", None) or {}
            after = getattr(change, "after", None) or {}

        if action != "UPDATE":
            continue

        # Build set of (role, member) pairs present before the change
        before_pairs: set[tuple[str, str]] = set()
        for b in before.get("bindings", []):
            role = b.get("role", "")
            for m in b.get("members", []):
                before_pairs.add((role, m))

        cascade = resource.startswith("folders/") or resource.startswith("organizations/")

        for binding in after.get("bindings", []):
            role = binding.get("role", "")
            members = binding.get("members", [])

            # Only look at newly-added members for this role
            new_members = [m for m in members if (role, m) not in before_pairs]
            if not new_members:
                continue

            # Score the full binding (all members) for toxic combination check
            rs = score_iam_binding(binding)

            for member in new_members:
                # --- T1098.003: high-privilege role grant ---
                if role in HIGH_PRIVILEGE_ROLES:
                    sev = "critical" if role in _CRITICAL_ROLES else "high"
                    if cascade:
                        sev = _bump_severity(sev)
                    findings.append(Finding(
                        technique_id="T1098.003",
                        technique_name="Additional Cloud Roles",
                        tactic="persistence",
                        severity=sev,
                        resource=resource,
                        principal=principal,
                        timestamp=timestamp,
                        evidence={"role": role, "member": member},
                    ))

                # --- T1199: external identity grant ---
                if not is_service_account(member) and not any(
                    member.endswith(d) or member.endswith("@" + d)
                    or (":" in member and member.split(":", 1)[1].endswith("@" + d))
                    for d in corp_domains
                ):
                    sev = "high"
                    if cascade:
                        sev = _bump_severity(sev)
                    findings.append(Finding(
                        technique_id="T1199",
                        technique_name="Trusted Relationship",
                        tactic="initial-access",
                        severity=sev,
                        resource=resource,
                        principal=principal,
                        timestamp=timestamp,
                        evidence={"role": role, "member": member},
                    ))

            # --- T1098: toxic combination (per binding, not per member) ---
            if rs.toxic_combination and new_members:
                sev = "high"
                if cascade:
                    sev = _bump_severity(sev)
                findings.append(Finding(
                    technique_id="T1098",
                    technique_name="Account Manipulation",
                    tactic="persistence",
                    severity=sev,
                    resource=resource,
                    principal=principal,
                    timestamp=timestamp,
                    evidence={"role": role, "toxic_flags": rs.flags},
                ))

    return findings
