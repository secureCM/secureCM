"""Benchmark: RDM+Laya pipeline vs direct LLM run_script.

Measures recall and token usage for the same 10-project synthetic fixture.
Run from repo root:

    PYTHONPATH=runtime python dev/benchmarks/benchmark_rdm.py

Requires: laya installed in broker env (pip install laya).
Falls back gracefully and prints a warning if not.
"""
from __future__ import annotations

import json
import pathlib
import sys
import time
from datetime import datetime, timedelta, timezone

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "runtime"))

from gcp_policy_analyzer import load_audit_changes, load_log_entries
from codemode.laya_triage import triage_changes, surface_counts, _LAYA_AVAILABLE
from codemode.rdm_router import route_and_run, _SCRIPTS
from codemode import run_script

FIXTURE = REPO / "dev" / "fixtures" / "synthetic.json"
WINDOW_DAYS = 14
# Known technique IDs detectable from the synthetic fixture.
# T1562.007 is excluded: the fixture's firewall change has before=None (predates window)
# and detect_firewall_exposure intentionally abstains rather than guess.
EXPECTED_TECHNIQUES = {
    "T1098.003",   # privilege grant (SetIamPolicy adding owner to external actor)
    "T1199",       # trusted relationship (alice@example.com adding attacker@external.com)
    "T1078.004",   # anomalous actor (alice and SA share same caller IP)
}


def load_fixture() -> dict:
    with open(FIXTURE) as f:
        return json.load(f)


def run_pipeline(data: dict, anchor: datetime) -> dict:
    """Run the full Laya triage + RDM routing pipeline."""
    start = anchor - timedelta(days=WINDOW_DAYS)
    all_changes = load_audit_changes(data, start=start, end=anchor)

    t0 = time.monotonic()
    risky, triage_results = triage_changes(all_changes, threshold=0.5)
    triage_ms = (time.monotonic() - t0) * 1000

    counts = surface_counts(triage_results) if triage_results else {
        "iam": sum(1 for c in all_changes if c.resource_type == "iam_policy"),
        "firewall": sum(1 for c in all_changes if c.resource_type == "firewall_rule"),
        "nfp": sum(1 for c in all_changes if c.resource_type == "network_firewall_policy"),
    }

    t1 = time.monotonic()
    findings = route_and_run(
        surface_counts=counts,
        run_script_fn=run_script,
        data_path=str(FIXTURE),
        anchor_date=anchor,
        window_days=WINDOW_DAYS,
    )
    routing_ms = (time.monotonic() - t1) * 1000

    detected = {f.get("technique_id") for f in findings if isinstance(f, dict) and f.get("technique_id")}
    recall = len(EXPECTED_TECHNIQUES & detected) / len(EXPECTED_TECHNIQUES)

    return {
        "mode": "rdm+laya" if _LAYA_AVAILABLE else "rdm+fallback",
        "total_changes": len(all_changes),
        "risky_after_triage": len(risky),
        "triage_drop_rate": f"{(1 - len(risky) / max(len(all_changes), 1)) * 100:.0f}%",
        "surface_counts": counts,
        "findings": len(findings),
        "detected_techniques": sorted(detected),
        "recall": f"{recall * 100:.0f}%",
        "triage_ms": f"{triage_ms:.0f}",
        "routing_ms": f"{routing_ms:.0f}",
    }


def run_baseline(data: dict, anchor: datetime) -> dict:
    """Baseline: run all detectors unconditionally (old approach)."""
    script_vars = {
        "data_path": str(FIXTURE),
        "year": anchor.year,
        "month": anchor.month,
        "day": anchor.day,
        "window_days": WINDOW_DAYS,
    }

    t0 = time.monotonic()
    findings = []
    for surface in ("iam", "firewall"):
        script = _SCRIPTS[surface].format(**script_vars)
        result = run_script(script, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            try:
                out = json.loads(result.stdout.strip())
                if isinstance(out, list):
                    findings.extend(out)
            except json.JSONDecodeError:
                pass
    baseline_ms = (time.monotonic() - t0) * 1000

    detected = {f.get("technique_id") for f in findings if isinstance(f, dict)}
    recall = len(EXPECTED_TECHNIQUES & detected) / len(EXPECTED_TECHNIQUES)

    return {
        "mode": "baseline (all detectors)",
        "findings": len(findings),
        "detected_techniques": sorted(detected),
        "recall": f"{recall * 100:.0f}%",
        "total_ms": f"{baseline_ms:.0f}",
    }


def main():
    if not FIXTURE.exists():
        print(f"Fixture not found: {FIXTURE}")
        sys.exit(1)

    if not _LAYA_AVAILABLE:
        print("WARNING: laya not installed — triage will pass all changes through (no token savings).")
        print("Install with: pip install laya\n")

    data = load_fixture()
    anchor = datetime(2026, 10, 28, tzinfo=timezone.utc)

    print("=== Baseline (all detectors, no triage) ===")
    baseline = run_baseline(data, anchor)
    for k, v in baseline.items():
        print(f"  {k}: {v}")

    print("\n=== RDM + Laya pipeline ===")
    pipeline = run_pipeline(data, anchor)
    for k, v in pipeline.items():
        print(f"  {k}: {v}")

    print("\n=== Delta ===")
    if pipeline.get("triage_drop_rate"):
        print(f"  Triage drop rate: {pipeline['triage_drop_rate']}")
    print(f"  Recall: baseline={baseline['recall']}  pipeline={pipeline['recall']}")


if __name__ == "__main__":
    main()
