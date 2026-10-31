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

def load_iam_policies(data: dict) -> list[IamPolicy]:
    out: list[IamPolicy] = []
    for record in data.get("iam_policies", []):
        bindings = [
            IamBinding(role=b["role"], members=b.get("members", []))
            for b in record.get("bindings", [])
        ]
        out.append(IamPolicy(
            resource=record.get("resource", ""),
            bindings=bindings,
            labels=record.get("labels", {}),
        ))
    return out


def load_vpc_firewall_rules(data: dict) -> list[VpcFirewallRule]:
    out: list[VpcFirewallRule] = []
    for record in data.get("vpc_firewall_rules", []):
        log_cfg = record.get("logConfig", {})
        log_enabled = log_cfg.get("enable", record.get("log_enabled", False))
        out.append(VpcFirewallRule(
            name=record.get("name", ""),
            network=record.get("network", ""),
            direction=record.get("direction", "INGRESS"),
            priority=record.get("priority", 1000),
            source_ranges=record.get("sourceRanges", []),
            allowed=record.get("allowed", []),
            denied=record.get("denied", []),
            disabled=record.get("disabled", False),
            log_enabled=bool(log_enabled),
            labels=record.get("labels", {}),
            raw=record,
        ))
    return out


def load_network_firewall_policies(data: dict) -> list[NetworkFirewallPolicy]:
    out: list[NetworkFirewallPolicy] = []
    for record in data.get("network_firewall_policies", []):
        out.append(NetworkFirewallPolicy(
            name=record.get("name", ""),
            region=record.get("region", None),
            rules=record.get("rules", []),
            raw=record,
        ))
    return out


def load_audit_changes(
    data: dict,
    resource_types: list[str] | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[Change]:
    # Convert naive start/end to UTC
    utc_start = _parse_ts(start) if start is not None else None
    utc_end   = _parse_ts(end)   if end   is not None else None

    out: list[Change] = []
    for record in data.get("audit_changes", []):
        if resource_types and record.get("resource_type") not in resource_types:
            continue
        # I1: skip records missing timestamp rather than raise KeyError
        if "timestamp" not in record:
            continue
        ts = _parse_ts(record["timestamp"])
        if utc_start is not None and ts < utc_start:
            continue
        if utc_end is not None and ts > utc_end:
            continue
        out.append(Change(
            resource=record.get("resource", ""),
            resource_type=record.get("resource_type", ""),
            action=record.get("action", ""),
            principal=record.get("principal", ""),
            timestamp=ts,
            before=record.get("before"),
            after=record.get("after"),
            labels=record.get("labels", {}),
        ))
    return out
