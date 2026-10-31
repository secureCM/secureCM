"""Production and service-account predicates, and report formatting."""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
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
    labels = _get_labels(obj)
    return any(labels.get(k, "").lower() in values for k in keys)


def is_service_account(member: str | dict) -> bool:
    """True iff member (string or dict with 'member' key) is a GCP service account."""
    if isinstance(member, dict):
        member = member.get("member", "")
    # strip prefix
    email = member.removeprefix("serviceAccount:").removeprefix("user:").removeprefix("group:")
    return email.endswith(".gserviceaccount.com")


def format_report(prioritized: "list[PrioritizedChange]") -> dict:
    """Build a summary report dict from prioritized changes; all SA emails redacted internally."""
    from dataclasses import asdict
    from gcp_policy_analyzer.redact import redact_sensitive

    risky = len(prioritized)
    principals = {pc.change.principal for pc in prioritized}
    # ponytail: neutral/other already excluded by prioritize_changes; no re-count needed
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
            "total_changes": risky,
            "risky": risky,
            "neutral": 0,  # neutral/other were excluded upstream
            "principals": list(principals),
        },
    }
    return redact_sensitive(raw)
