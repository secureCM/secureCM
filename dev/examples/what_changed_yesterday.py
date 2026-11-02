"""what_changed_yesterday.py — show all risky changes from the past 24 hours.

Usage:
    python examples/what_changed_yesterday.py
"""
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

# Allow running from repo root without installing the package (code lives in runtime/)
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent / "runtime"))

from gcp_policy_analyzer import analyze

FIXTURE = pathlib.Path(__file__).parent.parent.parent / "dev" / "fixtures" / "synthetic.json"
# ponytail: use fixture anchor; never datetime.now() — fixtures are static
ANCHOR = datetime(2026, 10, 31, tzinfo=timezone.utc)

with open(FIXTURE) as f:
    data = json.load(f)

end = ANCHOR
start = end - timedelta(days=1)

result = analyze(data, start, end)
print(json.dumps(result, indent=2))
