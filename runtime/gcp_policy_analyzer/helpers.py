"""Production and service-account predicates, and report formatting."""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gcp_policy_analyzer.diff import Change
    from gcp_policy_analyzer.prioritize import PrioritizedChange

PROD_LABEL_KEYS: tuple[str, ...] = ("env", "environment")
PROD_LABEL_VALUES: tuple[str, ...] = ("prod", "production")


def _get_labels(obj) -> dict:
    if isinstance(obj, dict):
        return obj.get("labels", {})
    return getattr(obj, "labels", {})


def is_production(
    obj,
    *,
    label_keys: tuple[str, ...] | None = None,
    label_values: tuple[str, ...] | None = None,
) -> bool:
    """True iff obj has a label whose key is in label_keys and value in label_values."""
    keys = label_keys if label_keys is not None else PROD_LABEL_KEYS
    values = label_values if label_values is not None else PROD_LABEL_VALUES
    # Normalize values to lowercase for case-insensitive comparison
    lower_values = {str(v).lower() for v in values}
    labels = _get_labels(obj)
    return any(str(labels.get(k, "")).lower() in lower_values for k in keys)


def is_service_account(member: str | dict) -> bool:
    """True iff member (string or dict with 'member' key) is a GCP service account."""
    if isinstance(member, dict):
        member = member.get("member", "")
    # strip prefix
    email = member.removeprefix("serviceAccount:").removeprefix("user:").removeprefix("group:")
    return email.endswith(".gserviceaccount.com")


def format_report(prioritized: "list[PrioritizedChange]", all_changes: "list[Change] | None" = None) -> dict:
    """Build a summary report dict from prioritized changes; all SA emails redacted internally.

    Args:
        prioritized: list of PrioritizedChange (already filtered)
        all_changes: optional list of all changes (before filtering). If provided:
            - stats.total_changes = len(all_changes)
            - stats.neutral = count of changes classified as Neutral or Other
            - stats.principals = all unique principals from all_changes
            If None, uses legacy behavior (total_changes = risky = len(prioritized), neutral = 0)
    """
    from dataclasses import asdict
    from gcp_policy_analyzer.redact import redact_sensitive
    from gcp_policy_analyzer.scoring import classify_change, ChangeClass

    risky = len(prioritized)
    principals = {pc.change.principal for pc in prioritized}

    if all_changes is not None:
        total = len(all_changes)
        neutral = sum(1 for c in all_changes if classify_change(c) in {ChangeClass.Neutral, ChangeClass.Other})
        all_principals = {c.principal for c in all_changes}
    else:
        total = risky
        neutral = 0
        all_principals = principals

    raw = {
        "summary": f"{risky} risky change(s) prioritized.",
        "prioritized": [
            {
                "rank": pc.rank,
                "resource": pc.change.resource,
                "action": pc.change.action,
                "principal": pc.change.principal,
                "change_class": pc.change_class.value,
                "blast_radius": asdict(pc.blast_radius),
                "risk_delta": pc.change.risk_delta,
                "timestamp": pc.change.timestamp.isoformat(),
            }
            for pc in prioritized
        ],
        "stats": {
            "total_changes": total,
            "risky": risky,
            "neutral": neutral,
            "principals": list(all_principals),
        },
    }
    return redact_sensitive(raw)
