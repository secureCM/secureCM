from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from gcp_policy_analyzer.diff import Change


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Binding:
    role: str
    members: list[str] = field(default_factory=list)


@dataclass
class IamPolicy:
    resource: str
    bindings: list[Binding] = field(default_factory=list)


@dataclass
class VpcFirewallRule:
    name: str
    network: str
    direction: str              # "INGRESS" | "EGRESS"
    priority: int
    action: str                 # "ALLOW" | "DENY"
    source_ranges: list[str] = field(default_factory=list)
    destination_ranges: list[str] = field(default_factory=list)
    labels: dict = field(default_factory=dict)
    project: str = ""


@dataclass
class NetworkFirewallPolicy:
    name: str
    project: str
    rules: list[dict] = field(default_factory=list)


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
            Binding(role=b["role"], members=b.get("members", []))
            for b in record.get("bindings", [])
        ]
        out.append(IamPolicy(resource=record.get("resource", ""), bindings=bindings))
    return out


def load_vpc_firewall_rules(data: dict) -> list[VpcFirewallRule]:
    out: list[VpcFirewallRule] = []
    for record in data.get("firewall_rules", []):
        out.append(VpcFirewallRule(
            name=record.get("name", ""),
            network=record.get("network", ""),
            direction=record.get("direction", "INGRESS"),
            priority=record.get("priority", 1000),
            action=record.get("action", "ALLOW"),
            source_ranges=record.get("sourceRanges", []),
            destination_ranges=record.get("destinationRanges", []),
            labels=record.get("labels", {}),
            project=record.get("project", ""),
        ))
    return out


def load_network_firewall_policies(data: dict) -> list[NetworkFirewallPolicy]:
    out: list[NetworkFirewallPolicy] = []
    for record in data.get("network_firewall_policies", []):
        out.append(NetworkFirewallPolicy(
            name=record.get("name", ""),
            project=record.get("project", ""),
            rules=record.get("rules", []),
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
        ts = _parse_ts(record["timestamp"])
        if utc_start is not None and ts < utc_start:
            continue
        if utc_end is not None and ts > utc_end:
            continue
        out.append(Change(
            change_id=record.get("change_id", ""),
            resource_name=record.get("resource_name", ""),
            resource_type=record.get("resource_type", ""),
            operation=record.get("operation", ""),
            principal=record.get("principal", ""),
            timestamp=ts,
            caller_ip=record.get("caller_ip", ""),
            before=record.get("before", {}),
            after=record.get("after", {}),
            labels=record.get("labels", {}),
        ))
    return out
