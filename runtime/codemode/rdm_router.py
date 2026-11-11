"""RDM-style routing loop for secureCM.

Implements the Recursive Decision Model pattern:
  1. Laya triage routes each change to a surface (iam/firewall/nfp) — see laya_triage.py.
  2. This module runs the analysis loop: for each surface with risky changes, execute
     the targeted detector script in the sandbox.
  3. Run correlation if IAM findings suggest SA key events or multiple actors.

The loop terminates when all surfaces are covered. Each iteration is a typed decision:
"which surface has changes?" → run its detector → collect findings.

Runs OUTSIDE the sandbox (broker process). No external model calls here — the routing
decisions are deterministic given Laya's surface counts from the triage pass.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Literal

from codemode.laya_triage import Surface, _LAYA_AVAILABLE

STEP = Literal["iam", "firewall", "nfp", "correlation", "finish"]

# Templates for each surface — injected with data_path and window at route time
_SCRIPTS: dict[str, str] = {
    "iam": """\
import json
from datetime import datetime, timedelta, timezone
from gcp_policy_analyzer import (
    load_audit_changes, load_log_entries, load_iam_policies,
    detect_privilege_grant, detect_anomalous_actor, redact_sensitive,
)
data = json.load(open("{data_path}"))
end = datetime({year}, {month}, {day}, tzinfo=timezone.utc)
start = end - timedelta(days={window_days})
changes = load_audit_changes(data, start=start, end=end)
policies = load_iam_policies(data)
findings = (
    detect_privilege_grant(policies, changes)
    + detect_anomalous_actor(changes, load_log_entries(data))
)
out = [{{"technique_id": f.technique_id, "severity": f.severity, "resource": f.resource,
        "principal": f.principal, "timestamp": str(f.timestamp), "tactic": f.tactic}} for f in findings]
print(json.dumps(redact_sensitive(out), default=str))
""",
    "firewall": """\
import json
from datetime import datetime, timedelta, timezone
from gcp_policy_analyzer import (
    load_audit_changes, load_vpc_firewall_rules, detect_firewall_exposure, redact_sensitive,
)
data = json.load(open("{data_path}"))
end = datetime({year}, {month}, {day}, tzinfo=timezone.utc)
start = end - timedelta(days={window_days})
changes = load_audit_changes(data, start=start, end=end)
rules = load_vpc_firewall_rules(data)
findings = detect_firewall_exposure(rules, changes)
out = [{{"technique_id": f.technique_id, "severity": f.severity, "resource": f.resource,
        "principal": f.principal, "timestamp": str(f.timestamp), "tactic": f.tactic}} for f in findings]
print(json.dumps(redact_sensitive(out), default=str))
""",
    "nfp": """\
import json
from datetime import datetime, timedelta, timezone
from gcp_policy_analyzer import (
    load_audit_changes, load_network_firewall_policies, detect_firewall_exposure, redact_sensitive,
)
data = json.load(open("{data_path}"))
end = datetime({year}, {month}, {day}, tzinfo=timezone.utc)
start = end - timedelta(days={window_days})
changes = [c for c in load_audit_changes(data, start=start, end=end)
           if c.resource_type == "network_firewall_policy"]
policies = load_network_firewall_policies(data)
findings = detect_firewall_exposure(policies, changes)
out = [{{"technique_id": f.technique_id, "severity": f.severity, "resource": f.resource,
        "principal": f.principal, "timestamp": str(f.timestamp), "tactic": f.tactic}} for f in findings]
print(json.dumps(redact_sensitive(out), default=str))
""",
    "correlation": """\
import json
from datetime import datetime, timedelta, timezone
from gcp_policy_analyzer import (
    load_audit_changes, load_log_entries, correlate_by_actor, redact_sensitive,
)
data = json.load(open("{data_path}"))
end = datetime({year}, {month}, {day}, tzinfo=timezone.utc)
start = end - timedelta(days={window_days})
changes = load_audit_changes(data, start=start, end=end)
corr = correlate_by_actor(changes, load_log_entries(data))
print(json.dumps(redact_sensitive({{"shared_ips": corr["shared_ips"], "top_actors": corr["actors"][:5]}}), default=str))
""",
}

def route_and_run(
    surface_counts: dict[str, int],
    run_script_fn,  # codemode.run_script callable
    data_path: str,
    anchor_date,  # datetime
    window_days: int = 7,
    max_iters: int = 5,  # kept for API compat
) -> list[dict]:
    """Deterministic routing loop driven by Laya surface counts.

    For each surface with risky changes (from laya_triage), run the corresponding
    targeted detector script in the sandbox. Then run correlation if IAM findings
    suggest multi-actor activity.

    Args:
        surface_counts: from laya_triage.surface_counts()
        run_script_fn: the sandbox run_script callable
        data_path: path to the JSON export (accessible inside sandbox)
        anchor_date: analysis end date (UTC datetime)
        window_days: lookback window

    Returns:
        aggregated list of finding dicts (redacted)
    """
    script_vars = {
        "data_path": data_path,
        "year": anchor_date.year,
        "month": anchor_date.month,
        "day": anchor_date.day,
        "window_days": window_days,
    }
    return _run_all(surface_counts, run_script_fn, script_vars)


def _run_all(
    surface_counts: dict[str, int],
    run_script_fn,
    script_vars: dict,
) -> list[dict]:
    """Run detectors for each surface with non-zero change counts.

    Runs correlation after IAM if any IAM findings are present (SA key events,
    anomalous actors, or privilege grants often have shared-IP signal).
    """
    findings: list[dict] = []
    iam_found = False

    for surface in ("iam", "firewall", "nfp"):
        if surface_counts.get(surface, 0) > 0:
            result = run_script_fn(_SCRIPTS[surface].format(**script_vars), timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                try:
                    out = json.loads(result.stdout.strip())
                    if isinstance(out, list):
                        findings.extend(out)
                        if surface == "iam" and out:
                            iam_found = True
                except json.JSONDecodeError:
                    pass

    # Run correlation when IAM findings suggest multi-actor activity
    if iam_found:
        result = run_script_fn(_SCRIPTS["correlation"].format(**script_vars), timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            try:
                out = json.loads(result.stdout.strip())
                if isinstance(out, dict) and (out.get("shared_ips") or out.get("top_actors")):
                    findings.append({"type": "correlation", **out})
            except json.JSONDecodeError:
                pass

    return findings
