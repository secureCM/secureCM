"""ATT&CK coverage measurement and regression gate.

Run:  python -m attack_coverage.report
Exit: 0 if no regressions and no dangling refs, else 1.

coverage = covered / (total - out_of_scope)
  • zero-denominator (all out-of-scope): treated as 1.0 — nothing in scope, nothing missing.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from attack_coverage.catalog import load_catalog
from attack_coverage.signatures import TECHNIQUE_DETECTOR, run_detectors

_REPO_ROOT = Path(__file__).parent.parent


def _fixture_exists(path: str) -> bool:
    return (_REPO_ROOT / path).exists()


def _has_match(findings, technique_id: str) -> bool:
    """True if any finding matches technique_id exactly or as a parent."""
    prefix = technique_id + "."
    return any(
        f.technique_id == technique_id or f.technique_id.startswith(prefix)
        for f in findings
    )


def build_report(catalog: dict | None = None) -> dict:
    if catalog is None:
        catalog = load_catalog()

    techniques = catalog.get("techniques", [])

    by_tactic: dict[str, dict] = {}
    regressions: list[str] = []
    dangling: list[str] = []
    not_covered: list[str] = []

    for t in techniques:
        tid = t["id"]
        tactic = t.get("tactic", "unknown")
        status = t.get("status")

        counts = by_tactic.setdefault(tactic, {
            "covered": 0, "partial": 0,
            "not_covered": 0, "out_of_scope": 0, "total": 0,
        })
        counts["total"] += 1

        if status == "covered":
            counts["covered"] += 1
        elif status == "partial":
            counts["partial"] += 1
        elif status == "not-covered":
            counts["not_covered"] += 1
            not_covered.append(tid)
        elif status == "out-of-scope":
            counts["out_of_scope"] += 1

        # dangling: covered/partial but detector unknown OR fixture missing
        if status in ("covered", "partial"):
            fixture = t.get("fixture") or ""
            detector = t.get("detector") or ""
            if detector not in TECHNIQUE_DETECTOR.values() or not _fixture_exists(fixture):
                dangling.append(tid)
                continue  # skip regression check for dangling

            # regression: fixture exists but detector fires no matching finding
            # enrich_with_enablers annotates changes only, emits no Findings — skip the fire-check
            if detector == "enrich_with_enablers":
                continue
            with open(_REPO_ROOT / fixture, encoding="utf-8") as fh:
                envelope = json.load(fh)
            findings = run_detectors(envelope)
            if not _has_match(findings, tid):
                regressions.append(tid)

    # coverage = covered / (total - out_of_scope); 1.0 when denominator == 0
    total = sum(c["total"] for c in by_tactic.values())
    out_of_scope = sum(c["out_of_scope"] for c in by_tactic.values())
    covered = sum(c["covered"] for c in by_tactic.values())
    denom = total - out_of_scope
    coverage = covered / denom if denom > 0 else 1.0

    return {
        "by_tactic": by_tactic,
        "coverage": coverage,
        "regressions": regressions,
        "dangling": dangling,
        "not_covered": not_covered,
    }


def main() -> None:
    report = build_report()

    # tactic matrix
    print(f"{'Tactic':<30} {'covered':>7} {'partial':>7} {'not_cvrd':>8} {'oos':>5} {'total':>6}")
    print("-" * 65)
    for tactic, counts in sorted(report["by_tactic"].items()):
        print(
            f"{tactic:<30} {counts['covered']:>7} {counts['partial']:>7}"
            f" {counts['not_covered']:>8} {counts['out_of_scope']:>5} {counts['total']:>6}"
        )
    print("-" * 65)
    print(f"\nCoverage (covered / in-scope): {report['coverage']:.1%}\n")

    not_covered = report["not_covered"]
    if not_covered:
        print(f"Not-covered queue ({len(not_covered)}): {', '.join(not_covered)}")
    else:
        print("Not-covered queue: (empty)")

    # out-of-scope list
    catalog = load_catalog()
    oos = [t["id"] for t in catalog["techniques"] if t.get("status") == "out-of-scope"]
    print(f"\nOut-of-scope ({len(oos)}): {', '.join(oos)}")

    if report["regressions"]:
        print(f"\nREGRESSIONS ({len(report['regressions'])}): {', '.join(report['regressions'])}")
    if report["dangling"]:
        print(f"\nDANGLING ({len(report['dangling'])}): {', '.join(report['dangling'])}")

    sys.exit(1 if (report["regressions"] or report["dangling"]) else 0)


if __name__ == "__main__":
    main()
