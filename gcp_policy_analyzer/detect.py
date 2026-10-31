"""ATT&CK-mapped findings and firewall exposure detector."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from gcp_policy_analyzer.helpers import is_production, is_service_account
from gcp_policy_analyzer.loaders import _parse_ts
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
                # ponytail: strip prefix (e.g. "user:") then require exact "@domain" suffix
                # — bare endswith(d) would match lookalikes like attacker@evilacme.example.com
                _email = member.split(":", 1)[1] if ":" in member else member
                if not is_service_account(member) and not any(
                    _email.endswith("@" + d) for d in corp_domains
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


# ---------------------------------------------------------------------------
# IAM/firewall resource patterns for discovery burst detection
# ---------------------------------------------------------------------------
_DISCOVERY_RESOURCES = ("iam", "firewall", "firewalls", "policies", "serviceaccounts",
                        "iampolicies", "roles", "groups", "permissions")
_GROUP_PERM_RESOURCES = ("groups", "permissions")


def _is_discovery_method(method: str) -> bool:
    m = method.lower()
    return ".list" in m or ".get" in m


def _is_iam_or_firewall(resource: str) -> bool:
    r = resource.lower()
    return any(kw in r for kw in _DISCOVERY_RESOURCES)


def _is_group_perm(resource: str) -> bool:
    r = resource.lower()
    return any(kw in r for kw in _GROUP_PERM_RESOURCES)


def _parse_log_ts(entry: dict) -> datetime | None:
    ts = entry.get("timestamp")
    if not ts:
        return None
    try:
        return _parse_ts(ts)
    except Exception:
        return None


def detect_discovery_bursts(
    logs: list,
    *,
    window_seconds: int = 300,
    min_calls: int = 10,
) -> list[Finding]:
    """Detect T1580 / T1069.003 from discovery bursts on IAM/firewall resources.

    A principal making ≥min_calls list/get calls on IAM/firewall resources within
    any window_seconds sliding window triggers T1580; if the targeted resource
    contains groups/permissions → T1069.003.
    """
    # Group qualifying events per principal
    from collections import defaultdict
    by_principal: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)

    for entry in logs:
        method = entry.get("methodName", "")
        resource = entry.get("resourceName", "") or entry.get("resource", "")
        if not (_is_discovery_method(method) and _is_iam_or_firewall(resource)):
            continue
        ts = _parse_log_ts(entry)
        if ts is None:
            continue
        actor = entry.get("principalEmail", "")
        if actor:
            by_principal[actor].append((ts, entry))

    findings: list[Finding] = []
    for actor, events in by_principal.items():
        events.sort(key=lambda e: e[0])  # deterministic ascending
        timestamps = [e[0] for e in events]
        n = len(timestamps)
        # Sliding window: two-pointer
        left = 0
        for right in range(n):
            while (timestamps[right] - timestamps[left]).total_seconds() > window_seconds:
                left += 1
            window_size = right - left + 1
            if window_size >= min_calls:
                # Determine technique based on resource name
                window_events = events[left:right + 1]
                any_group_perm = any(_is_group_perm(e.get("resourceName", "")) for _, e in window_events)
                technique_id = "T1069.003" if any_group_perm else "T1580"
                technique_name = (
                    "Cloud Groups" if technique_id == "T1069.003"
                    else "Cloud Infrastructure Discovery"
                )
                tactic = "discovery"
                findings.append(Finding(
                    technique_id=technique_id,
                    technique_name=technique_name,
                    tactic=tactic,
                    severity="medium",
                    resource=window_events[0][1].get("resourceName", ""),
                    principal=actor,
                    timestamp=timestamps[left],
                    evidence={
                        "window_start": timestamps[left].isoformat(),
                        "window_end": timestamps[right].isoformat(),
                        "call_count": window_size,
                    },
                ))
                # Skip past this burst; continue scanning the same actor for further bursts
                left = right + 1

    return findings


def detect_anomalous_actor(changes: list, logs: list) -> list[Finding]:
    """Detect T1078.004 from principals acting from external or rotating-subnet IPs.

    Calls correlate_by_actor(subnet_bits=24) to find anomalous or shared-subnet IPs,
    then emits a Finding per principal that has such an IP tied to an in-scope change/log.
    """
    from gcp_policy_analyzer.logs import correlate_by_actor

    result = correlate_by_actor(changes, logs, subnet_bits=24)

    # Build set of principals that appear in changes or logs
    principals_in_scope: set[str] = set()
    for change in changes:
        p = change.principal if hasattr(change, "principal") else change.get("principal", "")
        if p:
            principals_in_scope.add(p)
    for entry in logs:
        p = entry.get("principalEmail", "")
        if p:
            principals_in_scope.add(p)

    # Index changes and logs by principal for resource lookup
    changes_by_principal: dict[str, list] = {}
    for change in changes:
        p = change.principal if hasattr(change, "principal") else change.get("principal", "")
        if p:
            changes_by_principal.setdefault(p, []).append(change)
    logs_by_principal: dict[str, list] = {}
    for entry in logs:
        p = entry.get("principalEmail", "")
        if p:
            logs_by_principal.setdefault(p, []).append(entry)

    def _first_resource(actor: str) -> str:
        for ch in changes_by_principal.get(actor, []):
            r = ch.resource if hasattr(ch, "resource") else ch.get("resource", "")
            if r:
                return r
        for entry in logs_by_principal.get(actor, []):
            r = entry.get("resourceName", "") or entry.get("resource", "")
            if r:
                return r
        return ""

    findings: list[Finding] = []
    for actor_info in result["actors"]:
        actor = actor_info["actor"]
        if actor not in principals_in_scope:
            continue
        anomalous_ips = actor_info.get("anomalous_ips", [])
        anomalous_subnets = actor_info.get("anomalous_subnets", [])
        if not anomalous_ips and not anomalous_subnets:
            continue
        findings.append(Finding(
            technique_id="T1078.004",
            technique_name="Valid Accounts: Cloud Accounts",
            tactic="defense-evasion",
            severity="high",
            resource=_first_resource(actor),
            principal=actor,
            timestamp=None,
            evidence={
                "anomalous_ips": anomalous_ips,
                "anomalous_subnets": anomalous_subnets,
            },
        ))

    return findings


def _parse_project(resource: str) -> str:
    """Extract project/scope from a resource path.

    "projects/X/..." → "X"
    "folders/N/..." → "folders/N"
    "organizations/N/..." → "organizations/N"
    """
    parts = resource.split("/")
    if not parts:
        return ""
    if parts[0] == "projects" and len(parts) >= 2:
        return parts[1]
    if parts[0] in ("folders", "organizations") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def cross_project_timeline(
    changes: list,
    logs: list,
    *,
    principal: str | None = None,
) -> list[dict]:
    """Merge changes + logs, optionally filtered to one principal, sorted by timestamp.

    Each item: {"ts": datetime, "project": str, "kind": "change"|"log", "resource": str, "detail": dict}
    """
    items: list[dict] = []

    for change in changes:
        if hasattr(change, "principal"):
            p = change.principal
            resource = change.resource
            ts = change.timestamp
            action = change.action
        else:
            p = change.get("principal", "")
            resource = change.get("resource", "")
            ts = change.get("timestamp")
            action = change.get("action", "")
        if principal is not None and p != principal:
            continue
        if ts is None:
            continue
        ts_dt = _parse_ts(ts) if not isinstance(ts, datetime) else ts
        items.append({
            "ts": ts_dt,
            "project": _parse_project(resource),
            "kind": "change",
            "resource": resource,
            "detail": {"action": action, "principal": p},
        })

    for entry in logs:
        p = entry.get("principalEmail", "")
        if principal is not None and p != principal:
            continue
        resource = entry.get("resourceName", "") or entry.get("resource", "")
        ts_raw = entry.get("timestamp")
        if not ts_raw:
            continue
        ts_dt = _parse_ts(ts_raw)
        items.append({
            "ts": ts_dt,
            "project": _parse_project(resource),
            "kind": "log",
            "resource": resource,
            "detail": {"method": entry.get("methodName", ""), "principal": p},
        })

    # Sort ascending by ts; tiebreak by (kind, resource) for determinism
    items.sort(key=lambda x: (x["ts"], x["kind"], x["resource"]))
    return items
