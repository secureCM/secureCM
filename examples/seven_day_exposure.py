"""seven_day_exposure.py — surface high-privilege SA exposure over the last 7 days.

Pipeline (per spec):
  1. load changes (7d)
  2. keep BroadenedAccess | RemovedProtection AND is_production
  3. build high-priv SA set from load_iam_policies + score_iam_binding + is_service_account
  4. keep changes whose principal is in the high-priv SA set
  5. sort by compute_blast_radius().score desc
  6. redact_sensitive

Usage:
    python examples/seven_day_exposure.py
"""
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from gcp_policy_analyzer import (
    load_iam_policies,
    load_audit_changes,
    score_iam_binding,
    is_service_account,
    is_production,
    compute_blast_radius,
    redact_sensitive,
    ChangeClass,
    classify_change,
)

FIXTURE = pathlib.Path(__file__).parent.parent / "fixtures" / "synthetic.json"
ANCHOR = datetime(2026, 10, 31, tzinfo=timezone.utc)

with open(FIXTURE) as f:
    data = json.load(f)

# 1. Load changes in 7-day window
end = ANCHOR
start = end - timedelta(days=7)
changes = load_audit_changes(data, start=start, end=end)

# 2. Keep BroadenedAccess / RemovedProtection on production resources
RISKY = {ChangeClass.BroadenedAccess, ChangeClass.RemovedProtection}
risky = [c for c in changes if classify_change(c) in RISKY and is_production(c)]

# 3. Build high-privilege SA set from IAM policies
policies = load_iam_policies(data)
high_priv_sas = set()
for policy in policies:
    for binding in policy.bindings:
        risk = score_iam_binding(binding)
        if risk.is_high_privilege:
            for member in binding.members:
                # strip serviceAccount: prefix for principal matching
                email = member.removeprefix("serviceAccount:")
                if is_service_account(email):
                    high_priv_sas.add(email)

# 4. Keep changes whose principal is a high-priv SA
hits = [c for c in risky if c.principal in high_priv_sas]

# 5. Sort by blast radius score descending
hits.sort(key=lambda c: compute_blast_radius(c).score, reverse=True)

# 6. Serialize and redact
from dataclasses import asdict
output = []
for c in hits:
    br = compute_blast_radius(c)
    output.append({
        "resource": c.resource,
        "action": c.action,
        "principal": c.principal,
        "change_class": classify_change(c).value,
        "timestamp": c.timestamp.isoformat(),
        "blast_radius": asdict(br),
        "risk_delta": c.risk_delta,
    })

print(json.dumps(redact_sensitive(output), indent=2))
