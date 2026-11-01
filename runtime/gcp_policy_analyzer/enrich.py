"""Enabler-event correlation: annotate in-scope Changes with SA-key / group-add context."""
from __future__ import annotations

from datetime import datetime, timezone

from gcp_policy_analyzer.diff import Change
from gcp_policy_analyzer.loaders import ENABLER_METHODS


def _parse_ts(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def enrich_with_enablers(
    changes: list[Change],
    flat_logs: list[dict],
    *,
    window_seconds: int = 86400,
) -> list[Change]:
    """For each Change, annotate labels["enabler"] if the principal had an enabler event
    within window_seconds before the change timestamp. Pure, order-stable.
    Note: first-match-wins assumes flat_logs is in chronological order."""
    # Build {principal: [flat_entry, ...]} for enabler-method entries only
    enablers: dict[str, list[dict]] = {}
    for entry in flat_logs:
        if entry.get("methodName") in ENABLER_METHODS:
            p = entry.get("principalEmail", "")
            enablers.setdefault(p, []).append(entry)

    for change in changes:
        candidates = enablers.get(change.principal, [])
        for entry in candidates:
            ts_raw = entry.get("timestamp", "")
            if not ts_raw:
                continue
            enabler_ts = _parse_ts(ts_raw)
            delta = (change.timestamp - enabler_ts).total_seconds()
            if 0 < delta <= window_seconds:
                # ponytail: first match wins; multiple enablers → use earliest in window if needed
                change.labels["enabler"] = {
                    "method": entry.get("methodName", ""),
                    "enabler_ts": ts_raw,
                }
                break

    return changes
