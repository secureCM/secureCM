import ipaddress
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

        # Filter by time window (normalize start/end to handle naive datetimes)
        if start is not None or end is not None:
            # Skip entries with missing or empty timestamp
            timestamp_str = entry.get("timestamp", "")
            if not timestamp_str:
                continue
            entry_ts = _parse_ts(timestamp_str)
            _start = _parse_ts(start) if start is not None else None
            _end = _parse_ts(end) if end is not None else None
            if _start is not None and entry_ts < _start:
                continue
            if _end is not None and entry_ts > _end:
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


def correlate_by_actor(
    changes: list[Change],
    entries: list[dict],
    *,
    anomaly_threshold: float = 0.25,
    min_events_for_anomaly: int = 3,
    subnet_bits: int | None = None,
) -> dict:
    """
    Group all activity by principal and surface cross-source correlation signals
    that are hard to spot by eye: caller IPs shared across different actors, and
    caller IPs that are a minority (anomalous) for a given actor.

    This is the needle-finder for multi-step incidents: an external identity and
    a service account that share one caller IP are very likely one operation, even
    when their events are days apart and buried in thousands of routine entries.

    Args:
        changes: list of Change objects (contributes change_count per principal)
        entries: list of log entry dicts (principalEmail, callerIp, methodName, timestamp)
        anomaly_threshold: an IP is anomalous for an actor if it accounts for at most
            this fraction of that actor's IP-bearing log events (default 0.25)
        min_events_for_anomaly: only flag anomalous IPs for actors with at least this
            many log events (avoids noise on actors seen once or twice; default 3)

    Returns:
        {
          "actors": [  # sorted by (len(anomalous_ips), log_count+change_count) desc
            {"actor", "change_count", "log_count", "ips": {ip: count},
             "anomalous_ips": [ip, ...], "methods": [method, ...]},
            ...
          ],
          "shared_ips": {ip: [actor, ...]},  # only IPs seen for >1 distinct actor
        }
    """
    change_counts: dict[str, int] = {}
    for change in changes:
        p = change.principal or ""
        if p:
            change_counts[p] = change_counts.get(p, 0) + 1

    ip_counts: dict[str, dict[str, int]] = {}   # actor -> {ip: count}
    methods: dict[str, set[str]] = {}
    ip_actors: dict[str, set] = {}              # ip -> {actors}
    log_counts: dict[str, int] = {}

    for entry in entries:
        actor = entry.get("principalEmail", "")
        if not actor:
            continue
        log_counts[actor] = log_counts.get(actor, 0) + 1
        ip = entry.get("callerIp")
        if ip:
            ip_counts.setdefault(actor, {})[ip] = ip_counts.setdefault(actor, {}).get(ip, 0) + 1
            ip_actors.setdefault(ip, set()).add(actor)
        method = entry.get("methodName")
        if method:
            methods.setdefault(actor, set()).add(method)

    all_actors = set(change_counts) | set(log_counts)
    actors = []
    for actor in all_actors:
        ips = ip_counts.get(actor, {})
        total = sum(ips.values())
        anomalous = []
        if total >= min_events_for_anomaly:
            anomalous = sorted(
                ip for ip, n in ips.items() if n / total <= anomaly_threshold
            )
        actors.append({
            "actor": actor,
            "change_count": change_counts.get(actor, 0),
            "log_count": log_counts.get(actor, 0),
            "ips": dict(ips),
            "anomalous_ips": anomalous,
            "methods": sorted(methods.get(actor, set())),
        })

    actors.sort(key=lambda a: a["actor"])  # deterministic tiebreaker (stable sort)
    actors.sort(
        key=lambda a: (len(a["anomalous_ips"]), a["log_count"] + a["change_count"]),
        reverse=True,
    )

    shared_ips = {
        ip: sorted(acts) for ip, acts in ip_actors.items() if len(acts) > 1
    }

    result: dict = {"actors": actors, "shared_ips": shared_ips}

    if subnet_bits is not None:
        # Map each actor's IPs to /subnet_bits CIDRs; ignore non-IPv4 / unparseable
        def _mask(ip_str: str) -> str | None:
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.version != 4:
                    return None
                net = ipaddress.ip_network(f"{ip_str}/{subnet_bits}", strict=False)
                return str(net)
            except ValueError:
                return None

        subnet_actors: dict[str, set[str]] = {}  # cidr -> {actors}
        actor_subnets: dict[str, set[str]] = {}  # actor -> {cidrs}
        for actor in all_actors:
            for ip in ip_counts.get(actor, {}):
                cidr = _mask(ip)
                if cidr is None:
                    continue
                subnet_actors.setdefault(cidr, set()).add(actor)
                actor_subnets.setdefault(actor, set()).add(cidr)

        shared_subnets = {
            cidr: sorted(acts) for cidr, acts in subnet_actors.items() if len(acts) > 1
        }
        result["shared_subnets"] = shared_subnets

        # Attach anomalous_subnets per actor: subnets shared with other actors
        for actor_entry in result["actors"]:
            a = actor_entry["actor"]
            my_subnets = actor_subnets.get(a, set())
            anomalous = sorted(c for c in my_subnets if c in shared_subnets)
            actor_entry["anomalous_subnets"] = anomalous

    return result
