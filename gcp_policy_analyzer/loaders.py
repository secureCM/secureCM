from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from gcp_policy_analyzer.diff import Change


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class IamBinding:
    role: str
    members: list[str] = field(default_factory=list)


@dataclass
class IamPolicy:
    resource: str
    bindings: list[IamBinding]
    labels: dict = field(default_factory=dict)


@dataclass
class VpcFirewallRule:
    name: str
    network: str
    direction: str              # "INGRESS" | "EGRESS"
    priority: int
    source_ranges: list[str]
    allowed: list[dict]         # e.g. [{"IPProtocol": "tcp", "ports": ["8080"]}]
    denied: list[dict]          # e.g. [{"IPProtocol": "all"}]
    disabled: bool
    log_enabled: bool
    labels: dict
    raw: dict


@dataclass
class NetworkFirewallPolicy:
    name: str
    region: str | None          # None for global
    rules: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_ts(value: str | datetime) -> datetime:
    """Return an aware UTC datetime from an ISO-8601 Z string or datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    # "2026-10-31T00:00:00Z" → replace Z with +00:00 for fromisoformat
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _strip_asset_name(name: str) -> str:
    """Strip '//service/' prefix from an Asset Inventory name → 'projects/X' etc."""
    # "//cloudresourcemanager.googleapis.com/projects/X" → "projects/X"
    if name.startswith("//"):
        slash = name.find("/", 2)          # find the '/' after the service host
        if slash != -1:
            return name[slash + 1:]        # everything after "//host"
    return name


def load_iam_policies(data: dict) -> list[IamPolicy]:
    """Parse IAM policy records from the export envelope into IamPolicy objects.

    Accepts three shapes:
    (a) normalized  {resource, bindings, labels}
    (b) bare getIamPolicy  {bindings:[{role,members,condition?}]}  (condition dropped)
    (c) Asset-Inventory-wrapped  {name:"//…/projects/X", asset_type, iam_policy:{bindings}}
    """
    out: list[IamPolicy] = []
    for record in data.get("iam_policies", []):
        # (c) asset-wrapped: has iam_policy sub-key
        if "iam_policy" in record:
            raw_bindings = record["iam_policy"].get("bindings", [])
            resource = _strip_asset_name(record.get("name", ""))
        else:
            # (a) normalized or (b) bare getIamPolicy
            raw_bindings = record.get("bindings", [])
            resource = record.get("resource", "")
        bindings = [
            IamBinding(role=b["role"], members=b.get("members", []))
            for b in raw_bindings
            # ponytail: condition dropped — no dataclass field for it
        ]
        out.append(IamPolicy(
            resource=resource,
            bindings=bindings,
            labels=record.get("labels", {}),
        ))
    return out


def load_vpc_firewall_rules(data: dict) -> list[VpcFirewallRule]:
    """Parse VPC firewall rule records from the export envelope into VpcFirewallRule objects.

    Accepts three shapes:
    (a) normalized  {name, network, direction, priority, …, log_enabled, labels, raw}
    (b) bare native  {kind:"compute#firewall", name, network, …, logConfig:{enable}}
    (c) Asset-Inventory-wrapped  {name, asset_type, resource:{data:{…compute#firewall…}}}
    """
    out: list[VpcFirewallRule] = []
    for record in data.get("vpc_firewall_rules", []):
        # (c) asset-wrapped: firewall data lives under resource.data
        fw = record.get("resource", {}).get("data", record) if "asset_type" in record else record
        log_cfg = fw.get("logConfig", {})
        log_enabled = log_cfg.get("enable", fw.get("log_enabled", False))
        out.append(VpcFirewallRule(
            name=fw.get("name", ""),
            network=fw.get("network", ""),
            direction=fw.get("direction", "INGRESS"),
            priority=fw.get("priority", 1000),
            source_ranges=fw.get("sourceRanges", []),
            allowed=fw.get("allowed", []),
            denied=fw.get("denied", []),
            disabled=fw.get("disabled", False),
            log_enabled=bool(log_enabled),
            labels=fw.get("labels", {}),
            raw=fw,
        ))
    return out


def load_network_firewall_policies(data: dict) -> list[NetworkFirewallPolicy]:
    """Parse network firewall policy records from the export envelope into NetworkFirewallPolicy objects.

    Accepts three shapes:
    (a) normalized  {name, region?, rules, raw}
    (b) bare native  {kind:"compute#firewallPolicy", name, region?, rules:[…]}
    (c) Asset-Inventory-wrapped  {name, asset_type, resource:{data:{…compute#firewallPolicy…}}}
    region present → regional; absent → None (global).
    """
    out: list[NetworkFirewallPolicy] = []
    for record in data.get("network_firewall_policies", []):
        # (c) asset-wrapped: policy data lives under resource.data
        pol = record.get("resource", {}).get("data", record) if "asset_type" in record else record
        out.append(NetworkFirewallPolicy(
            name=pol.get("name", ""),
            region=pol.get("region") or None,   # absent or falsy → None (global)
            rules=pol.get("rules", []),
            raw=pol,
        ))
    return out


# ---------------------------------------------------------------------------
# Native Cloud Audit Log constants and loaders
# ---------------------------------------------------------------------------

IAM_CHANGE_METHODS: frozenset[str] = frozenset({
    "SetIamPolicy",
    "google.iam.v1.IAMPolicy.SetIamPolicy",
})

FW_CHANGE_METHODS: frozenset[str] = frozenset({
    # VPC firewall  (compute.firewalls.<verb>)
    "compute.firewalls.insert",
    "compute.firewalls.patch",
    "compute.firewalls.delete",
})

NFP_CHANGE_METHODS: frozenset[str] = frozenset({
    # Network Firewall Policy  (compute.networkFirewallPolicies.<verb>)
    "compute.networkFirewallPolicies.insert",
    "compute.networkFirewallPolicies.patch",
    "compute.networkFirewallPolicies.delete",
    "compute.networkFirewallPolicies.addRule",
    "compute.networkFirewallPolicies.patchRule",
    "compute.networkFirewallPolicies.removeRule",
})

ENABLER_METHODS: frozenset[str] = frozenset({
    "google.iam.admin.v1.CreateServiceAccountKey",
    "google.iam.admin.v1.DeleteServiceAccountKey",
    "google.iam.admin.v1.UploadServiceAccountKey",
    "google.admin.directory.member.insert",
    "google.admin.directory.member.delete",
})

_ALL_KNOWN_METHODS: frozenset[str] = (
    IAM_CHANGE_METHODS | FW_CHANGE_METHODS | NFP_CHANGE_METHODS | ENABLER_METHODS
)


def flatten_log_entry(entry: dict) -> dict:
    """Map a native Cloud Audit LogEntry dict to a flat dict for downstream use."""
    proto = entry.get("protoPayload", {})
    auth = proto.get("authenticationInfo", {})
    meta = proto.get("requestMetadata", {})
    return {
        "methodName":     proto.get("methodName", ""),
        "principalEmail": auth.get("principalEmail", ""),
        "callerIp":       meta.get("callerIp", ""),
        "resourceName":   proto.get("resourceName", ""),
        "timestamp":      entry.get("timestamp", ""),
        "serviceData":    proto.get("serviceData", {}),
        "request":        proto.get("request", {}),
    }


def load_log_entries(data: dict) -> list[dict]:
    """Flatten log_entries and keep only entries for known change/enabler methods."""
    out: list[dict] = []
    for entry in data.get("log_entries", []):
        # Idempotent: already-flat entries have top-level methodName, no protoPayload
        if "protoPayload" in entry:
            flat = flatten_log_entry(entry)
        else:
            flat = entry
        if flat.get("methodName", "") in _ALL_KNOWN_METHODS:
            out.append(flat)
    return out


def _iam_changes_from_logs(flat_entries: list[dict]) -> list[Change]:
    """Derive IAM Change records from flat SetIamPolicy log entries via policyDelta."""
    out: list[Change] = []
    for entry in flat_entries:
        if entry.get("methodName") not in IAM_CHANGE_METHODS:
            continue
        # serviceData path primary; fallback to protoPayload.metadata (not flattened, skip)
        service_data = entry.get("serviceData") or {}
        deltas = service_data.get("policyDelta", {}).get("bindingDeltas", [])
        if not deltas:
            continue
        # Group ADD deltas by role → after bindings; REMOVE deltas → before bindings
        add_by_role: dict[str, list[str]] = {}
        rem_by_role: dict[str, list[str]] = {}
        for d in deltas:
            action = d.get("action", "")
            role = d.get("role", "")
            member = d.get("member", "")
            if action == "ADD":
                add_by_role.setdefault(role, []).append(member)
            elif action == "REMOVE":
                rem_by_role.setdefault(role, []).append(member)
        after = {"bindings": [{"role": r, "members": m} for r, m in add_by_role.items()]}
        before = {"bindings": [{"role": r, "members": m} for r, m in rem_by_role.items()]}
        ts_raw = entry.get("timestamp", "")
        ts = _parse_ts(ts_raw) if ts_raw else datetime.now(timezone.utc)
        out.append(Change(
            resource=entry.get("resourceName", ""),
            resource_type="iam_policy",
            action="UPDATE",
            principal=entry.get("principalEmail", ""),
            timestamp=ts,
            before=before,
            after=after,
        ))
    return out


def _config_changes_from_logs(flat_entries: list[dict]) -> list[Change]:
    """Derive firewall and NFP Change records by replaying the audit-log stream per resource."""
    # Bucket by resourceName, filter to FW/NFP methods only
    by_resource: dict[str, list[dict]] = {}
    for entry in flat_entries:
        method = entry.get("methodName", "")
        if method not in FW_CHANGE_METHODS and method not in NFP_CHANGE_METHODS:
            continue
        resource = entry.get("resourceName", "")
        by_resource.setdefault(resource, []).append(entry)

    out: list[Change] = []
    for resource, events in by_resource.items():
        # Sort ascending by timestamp
        events.sort(key=lambda e: e.get("timestamp", ""))

        # resource_type from resourceName path
        if "/firewalls/" in resource:
            resource_type = "firewall_rule"
        elif "/firewallPolicies/" in resource:
            resource_type = "network_firewall_policy"
        else:
            resource_type = "firewall_rule"  # ponytail: fallback; unknown paths treated as VPC

        running: dict | None = None  # reconstructed state; None until first insert

        for entry in events:
            method = entry.get("methodName", "")
            request = dict(entry.get("request") or {})
            ts_raw = entry.get("timestamp", "")
            ts = _parse_ts(ts_raw) if ts_raw else datetime.now(timezone.utc)
            principal = entry.get("principalEmail", "")

            verb = method.rsplit(".", 1)[-1]  # insert / patch / delete / addRule / patchRule / removeRule

            if verb == "insert":
                before_state = running  # normally None for first insert
                running = dict(request)
                out.append(Change(
                    resource=resource,
                    resource_type=resource_type,
                    action="CREATE",
                    before=before_state if before_state is not None else {},
                    after=dict(running),
                    timestamp=ts,
                    principal=principal,
                ))

            elif verb == "delete":
                labels: dict = {}
                before_state = running
                if running is None:
                    labels = {"baseline": "predates_window"}
                out.append(Change(
                    resource=resource,
                    resource_type=resource_type,
                    action="DELETE",
                    before=before_state,
                    after=None,
                    timestamp=ts,
                    principal=principal,
                    labels=labels,
                ))
                running = None

            else:
                # patch / addRule / patchRule / removeRule → UPDATE with merge
                labels = {}
                before_state = dict(running) if running is not None else None
                if running is None:
                    labels = {"baseline": "predates_window"}
                    running = {}
                running = {**running, **request}  # partial merge
                out.append(Change(
                    resource=resource,
                    resource_type=resource_type,
                    action="UPDATE",
                    before=before_state,
                    after=dict(running),
                    timestamp=ts,
                    principal=principal,
                    labels=labels,
                ))

    return out


def load_audit_changes(
    data: dict,
    resource_types: list[str] | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[Change]:
    """Parse audit change records from the export envelope, filtering by type and time window.

    Dual-mode: uses legacy data["audit_changes"] list if present; otherwise derives
    IAM changes from data["log_entries"] via _iam_changes_from_logs. (Task 7 removes legacy path.)
    """
    # Convert naive start/end to UTC
    utc_start = _parse_ts(start) if start is not None else None
    utc_end   = _parse_ts(end)   if end   is not None else None

    if "audit_changes" in data:
        # Legacy path
        raw_changes: list[Change] = []
        for record in data["audit_changes"]:
            if resource_types and record.get("resource_type") not in resource_types:
                continue
            if "timestamp" not in record:
                continue
            ts = _parse_ts(record["timestamp"])
            if utc_start is not None and ts < utc_start:
                continue
            if utc_end is not None and ts > utc_end:
                continue
            raw_changes.append(Change(
                resource=record.get("resource", ""),
                resource_type=record.get("resource_type", ""),
                action=record.get("action", ""),
                principal=record.get("principal", ""),
                timestamp=ts,
                before=record.get("before"),
                after=record.get("after"),
                labels=record.get("labels", {}),
            ))
        return raw_changes

    # Native log_entries path
    flat = load_log_entries(data)
    derived = _iam_changes_from_logs(flat) + _config_changes_from_logs(flat)
    # Apply resource_type and time filters
    out: list[Change] = []
    for c in derived:
        if resource_types and c.resource_type not in resource_types:
            continue
        if utc_start is not None and c.timestamp < utc_start:
            continue
        if utc_end is not None and c.timestamp > utc_end:
            continue
        out.append(c)
    return out
