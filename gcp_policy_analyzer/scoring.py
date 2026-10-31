"""Exposure scoring, IAM risk scoring, and change classification."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from gcp_policy_analyzer.helpers import is_service_account

# ---------------------------------------------------------------------------
# Constants — override by passing kwargs to scoring functions
# ---------------------------------------------------------------------------

HIGH_PRIVILEGE_ROLES: frozenset[str] = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountKeyAdmin",
})

TOXIC_COMBINATIONS: frozenset[str] = frozenset({
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.securityAdmin",
})

_WORLD_RANGES = {"0.0.0.0/0", "::/0"}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ExposureScore:
    score: int
    flags: list[str] = field(default_factory=list)


@dataclass
class RiskScore:
    is_high_privilege: bool = False
    service_account_member: bool = False
    toxic_combination: bool = False


class ChangeClass(Enum):
    BroadenedAccess = "BroadenedAccess"
    RemovedProtection = "RemovedProtection"
    ShadowCreated = "ShadowCreated"
    LeastPrivilegeImproved = "LeastPrivilegeImproved"
    Neutral = "Neutral"
    Other = "Other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _attr(obj, key, default=None):
    """Get attribute from dataclass or dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _all_protocols(entries: list[dict]) -> bool:
    return any(e.get("IPProtocol", "") == "all" for e in entries)


def _all_ports(entries: list[dict]) -> bool:
    """True if any entry has no ports or ports includes 0-65535."""
    for e in entries:
        ports = e.get("ports", [])
        if not ports or "0-65535" in ports:
            return True
    return False


# ---------------------------------------------------------------------------
# score_rule_exposure
# ---------------------------------------------------------------------------

def score_rule_exposure(rule) -> ExposureScore:
    """Score a firewall rule's network exposure based on source ranges, ports, logging, and priority."""
    source_ranges: list[str] = _attr(rule, "source_ranges", [])
    allowed: list[dict] = _attr(rule, "allowed", [])
    denied: list[dict] = _attr(rule, "denied", [])
    log_enabled: bool = _attr(rule, "log_enabled", False)
    priority: int = _attr(rule, "priority", 1000)

    all_entries = allowed + denied
    flags: list[str] = []
    score = 0

    if _WORLD_RANGES & set(source_ranges):
        flags.append("open_to_world")
        score += 40

    if all_entries and _all_ports(all_entries):
        flags.append("all_ports")
        score += 20
    elif not all_entries:
        # no protocol entries — treat as all ports implied
        pass

    if not log_enabled:
        flags.append("logging_disabled")
        score += 10

    if priority < 1000:
        flags.append("high_priority")
        score += 10

    if _all_protocols(all_entries):
        flags.append("broad_protocol")
        score += 20

    return ExposureScore(score=score, flags=flags)


# ---------------------------------------------------------------------------
# score_iam_binding
# ---------------------------------------------------------------------------

def score_iam_binding(binding, *, high_privilege_roles: frozenset[str] | None = None, toxic_combinations: frozenset[str] | None = None) -> RiskScore:
    """Score an IAM binding for high-privilege roles, service account members, and toxic combinations."""
    roles = high_privilege_roles if high_privilege_roles is not None else HIGH_PRIVILEGE_ROLES
    toxic_roles = toxic_combinations if toxic_combinations is not None else TOXIC_COMBINATIONS
    role: str = _attr(binding, "role", "")
    members: list[str] = _attr(binding, "members", [])

    high_priv = role in roles
    sa_member = any(is_service_account(m) for m in members)
    toxic = role in toxic_roles and sa_member

    return RiskScore(
        is_high_privilege=high_priv,
        service_account_member=sa_member,
        toxic_combination=toxic,
    )


# ---------------------------------------------------------------------------
# classify_change
# ---------------------------------------------------------------------------

def _has_world_range(ranges: list[str]) -> bool:
    return bool(_WORLD_RANGES & set(ranges))


def classify_change(change) -> ChangeClass:
    """Classify a policy change as BroadenedAccess, RemovedProtection, ShadowCreated, LeastPrivilegeImproved, Neutral, or Other."""
    action: str = _attr(change, "action", "")
    before: dict | None = _attr(change, "before")
    after: dict | None = _attr(change, "after")

    b = before or {}
    a = after or {}

    # DELETE of a deny rule → RemovedProtection
    if action == "DELETE" and b.get("denied"):
        return ChangeClass.RemovedProtection

    # DELETE of rule with logging enabled removed (the protection was the logging)
    if action == "DELETE" and b.get("logConfig", {}).get("enable") is True:
        return ChangeClass.RemovedProtection

    # BroadenedAccess: source ranges widened to world
    after_ranges = a.get("sourceRanges", [])
    before_ranges = b.get("sourceRanges", [])
    if after_ranges and _has_world_range(after_ranges) and not _has_world_range(before_ranges):
        return ChangeClass.BroadenedAccess

    # BroadenedAccess: new allow rule to world (CREATE with 0.0.0.0/0)
    if action == "CREATE" and _has_world_range(a.get("sourceRanges", [])):
        return ChangeClass.BroadenedAccess

    # BroadenedAccess: high-priv role granted
    after_bindings = a.get("bindings", [])
    before_roles = {bb.get("role") for bb in b.get("bindings", [])}
    for ab in after_bindings:
        if ab.get("role") in HIGH_PRIVILEGE_ROLES and ab.get("role") not in before_roles:
            return ChangeClass.BroadenedAccess

    # RemovedProtection: deny rule or logging removed in UPDATE
    if action == "UPDATE":
        if b.get("denied") and not a.get("denied"):
            return ChangeClass.RemovedProtection
        if b.get("logConfig", {}).get("enable") is True and a.get("logConfig", {}).get("enable") is False:
            return ChangeClass.RemovedProtection

    # ShadowCreated: CREATE of a disabled or duplicate-priority rule
    if action == "CREATE":
        if a.get("disabled") or a.get("priority") == b.get("priority"):
            return ChangeClass.ShadowCreated

    # LeastPrivilegeImproved: high-priv role removed
    before_bindings = b.get("bindings", [])
    after_roles = {ab.get("role") for ab in a.get("bindings", [])}
    for bb in before_bindings:
        if bb.get("role") in HIGH_PRIVILEGE_ROLES and bb.get("role") not in after_roles:
            return ChangeClass.LeastPrivilegeImproved

    # LeastPrivilegeImproved: ranges narrowed (had world, now doesn't)
    if before_ranges and _has_world_range(before_ranges) and after_ranges and not _has_world_range(after_ranges):
        return ChangeClass.LeastPrivilegeImproved

    # Empty-diff (both empty): classify as Other
    if not b and not a:
        return ChangeClass.Other

    # Neutral: before/after differ only in description
    b_keys = set(b.keys())
    a_keys = set(a.keys())
    all_keys = b_keys | a_keys
    if all_keys == {"description"} or all_keys <= {"description"}:
        return ChangeClass.Neutral

    return ChangeClass.Other
