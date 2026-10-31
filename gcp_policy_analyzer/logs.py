from datetime import datetime, timezone

from gcp_policy_analyzer.diff import Change
from gcp_policy_analyzer.loaders import _parse_ts


def filter_log_entries(
    entries: list[dict],
    *,
    principal: str | None = None,
    methods: list[str] | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[dict]:
    """
    Filter log entries by principal email, method names, and time window.

    Args:
        entries: list of log entry dicts (with keys like principalEmail, methodName, timestamp)
        principal: filter by exact principalEmail match (optional)
        methods: filter by methodName in this list (optional)
        start: earliest timestamp (UTC-aware, optional)
        end: latest timestamp (UTC-aware, optional)

    Returns:
        filtered list of entries
    """
    result = []

    for entry in entries:
        # Filter by principal
        if principal is not None and entry.get("principalEmail") != principal:
            continue

        # Filter by method names
        if methods is not None and entry.get("methodName") not in methods:
            continue

        # Filter by time window
        if start is not None or end is not None:
            # Skip entries with missing or empty timestamp
            timestamp_str = entry.get("timestamp", "")
            if not timestamp_str:
                continue
            entry_ts = _parse_ts(timestamp_str)
            if start is not None and entry_ts < start:
                continue
            if end is not None and entry_ts > end:
                continue

        result.append(entry)

    return result


def correlate_changes_with_logs(
    changes: list[Change],
    entries: list[dict],
) -> list[dict]:
    """
    Correlate changes with log entries to attach evidence.

    For each change, returns a dict with:
        "change": the Change object
        "evidence": list of log entries where:
            - principalEmail == change.principal
            - resourceName endswith the last 2 path segments of change.resource
            - |timestamp delta| <= 300 seconds

    Args:
        changes: list of Change objects
        entries: list of log entry dicts

    Returns:
        list of dicts {"change": Change, "evidence": [entries]}
    """
    result = []

    for change in changes:
        evidence = []

        # Extract last 2 path segments from change.resource for matching
        # e.g., "projects/example-prod-project/global/firewalls/prod-allow-tcp-8080"
        # → last 2 segments: "firewalls/prod-allow-tcp-8080"
        resource_parts = change.resource.split("/")
        if len(resource_parts) >= 2:
            resource_suffix = "/".join(resource_parts[-2:])
        else:
            resource_suffix = change.resource

        for entry in entries:
            # Check principal match
            if entry.get("principalEmail") != change.principal:
                continue

            # Check resource match: boundary-aware suffix matching to avoid false positives
            # e.g., "sillyfirewalls/allow-x" should NOT match suffix "firewalls/allow-x"
            resource_name = entry.get("resourceName", "")
            if not (resource_name == resource_suffix or resource_name.endswith("/" + resource_suffix)):
                continue

            # Skip entries with missing or empty timestamp
            timestamp_str = entry.get("timestamp", "")
            if not timestamp_str:
                continue

            # Check timestamp match (within 300 seconds)
            entry_ts = _parse_ts(timestamp_str)
            time_delta = abs((entry_ts - change.timestamp).total_seconds())
            if time_delta > 300:
                continue

            # All conditions met, add to evidence
            evidence.append(entry)

        result.append({
            "change": change,
            "evidence": evidence,
        })

    return result
