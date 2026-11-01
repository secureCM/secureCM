"""Blast radius computation, change prioritization."""
from __future__ import annotations

from dataclasses import dataclass

from gcp_policy_analyzer.diff import Change
from gcp_policy_analyzer.helpers import is_production
from gcp_policy_analyzer.scoring import ChangeClass, classify_change

_WORLD_RANGES = {"0.0.0.0/0", "::/0"}
_EXCLUDED = {ChangeClass.Neutral, ChangeClass.Other}


@dataclass
class BlastRadius:
    affected_resources: int
    external_exposure: bool
    production: bool
    score: int


@dataclass
class PrioritizedChange:
    rank: int
    change: Change
    change_class: ChangeClass
    blast_radius: BlastRadius


def _last_path_segment(resource: str) -> str | None:
    """Extract the final path segment from a resource path."""
    parts = resource.rsplit("/", 1)
    return parts[-1] if parts else None


def _project_from_resource_path(resource: str) -> str | None:
    """Extract project id from resource path like 'projects/<proj>/...' or 'projects/<proj>'."""
    parts = resource.split("/")
    if len(parts) >= 2 and parts[0] == "projects":
        return parts[1]
    return None


def _count_affected(change: Change, context: dict) -> int:
    resources = context.get("resources")
    if not resources:
        return 1

    if change.resource_type in ("firewall_rule", "network_firewall_policy"):
        # Find network by looking up the firewall rule name in vpc_firewall_rules
        rule_name = _last_path_segment(change.resource)
        network = None
        for rule in context.get("vpc_firewall_rules", []):
            # rule["network"] is like "projects/.../networks/prod-network"
            rule_network = rule.get("network", "")
            rule_name_in_context = rule.get("name", "")
            if rule_name_in_context == rule_name:
                network = rule_network.rsplit("/", 1)[-1]
                break
        if network is None:
            return 1
        return max(1, sum(1 for r in resources if r.get("network") == network))

    # IAM or other: match by project
    project = _project_from_resource_path(change.resource)
    if project is None:
        return 1
    return max(1, sum(1 for r in resources if r.get("project") == project))


def _is_world_open(after: dict | None) -> bool:
    if not after:
        return False
    ranges = after.get("sourceRanges", [])
    return bool(_WORLD_RANGES & set(ranges))


def compute_blast_radius(change: Change, context: dict | None = None) -> BlastRadius:
    """Compute blast radius score for a change based on affected resources, external exposure, and production status."""
    affected = 1 if context is None else _count_affected(change, context)
    change_class = classify_change(change)
    external = change_class is ChangeClass.BroadenedAccess and _is_world_open(change.after)
    prod = is_production(change)
    score = affected * (2 if external else 1) * (2 if prod else 1)
    return BlastRadius(
        affected_resources=affected,
        external_exposure=external,
        production=prod,
        score=score,
    )


def prioritize_changes(changes: list[Change], context: dict | None = None) -> list[PrioritizedChange]:
    """Filter, rank, and sort changes by blast radius score, excluding Neutral and Other classes."""
    results = []
    for change in changes:
        cc = classify_change(change)
        if cc in _EXCLUDED:
            continue
        br = compute_blast_radius(change, context)
        results.append(PrioritizedChange(rank=0, change=change, change_class=cc, blast_radius=br))

    results.sort(key=lambda pc: (pc.blast_radius.score, pc.change.risk_delta, pc.change.timestamp), reverse=True)
    for i, pc in enumerate(results, 1):
        pc.rank = i
    return results
