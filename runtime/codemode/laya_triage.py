"""Laya triage + surface routing for Change objects.

Runs OUTSIDE the sandbox (broker process), same import context as mcp_server.py.
Falls back gracefully (returns all changes, empty results) when laya is not installed.

Design:
  - is_risky: deterministic via classify_change (ChangeClass != Neutral/Other).
    Laya's base model is not calibrated for GCP security risk; the library's own
    scoring functions are authoritative here.
  - surface:  Laya Choice (iam/firewall/nfp/other), ~33ms, 85-90% accurate.
    Clear categorical routing is where Laya excels.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

_LAYA_AVAILABLE = False
try:
    import laya as _laya
    _LAYA_AVAILABLE = True
except ImportError:
    pass

Surface = Literal["iam", "firewall", "nfp", "other"]

_ROUTING_QUESTIONS: dict = {
    "surface": {
        "type": "choice",
        "instructions": "Which GCP security surface does this change primarily affect?",
        "criteria": {
            "iam": "IAM policies: role bindings, service account grants, group memberships",
            "firewall": "VPC firewall rules: allow/deny rules, priority, IP ranges, ports",
            "nfp": "Network firewall policies: hierarchical firewall policies",
            "other": "Other or unclassifiable",
        },
    },
}

# ChangeClass values that indicate a potentially risky change
_RISKY_CLASSES = {"BroadenedAccess", "RemovedProtection", "ShadowCreated", "Other"}


@dataclass
class TriageResult:
    change_index: int
    is_risky: bool
    surface: Surface
    surface_probabilities: dict[str, float]
    abstain: bool
    route: str  # "auto" | "review"


def triage_changes(
    changes: list,
    threshold: float = 0.5,  # kept for API compat; not used for noul (removed)
) -> tuple[list, list[TriageResult]]:
    """Return (risky_changes, triage_results).

    is_risky: determined by classify_change (deterministic, library-authoritative).
    surface:  routed by Laya Choice (~33ms per change, zero LLM tokens).
    Falls back to (all changes, []) if laya is not installed.
    """
    if not _LAYA_AVAILABLE:
        return changes, []

    from gcp_policy_analyzer import classify_change, ChangeClass

    agent = _laya.Agent()
    risky: list = []
    results: list[TriageResult] = []

    for i, change in enumerate(changes):
        # Deterministic risk filter — library knows GCP risk better than a general model
        cls = classify_change(change)
        is_risky = cls.value in _RISKY_CLASSES

        # Laya routes to the right detector surface (categorical, Laya is accurate here)
        text = _change_to_text(change)
        out = agent.predict(text, _ROUTING_QUESTIONS)
        surf_ans = out["answers"]["surface"]
        abstain = bool(surf_ans.get("abstain", False))
        route = surf_ans.get("route", "auto")

        result = TriageResult(
            change_index=i,
            is_risky=is_risky,
            surface=surf_ans.get("choice", _resource_type_fallback(change)),
            surface_probabilities=surf_ans.get("probabilities", {}),
            abstain=abstain,
            route=route,
        )
        results.append(result)

        if is_risky or abstain:
            risky.append(change)

    return risky, results


def surface_counts(results: list[TriageResult]) -> dict[str, int]:
    """Aggregate surface votes from triage results (risky changes only)."""
    counts: dict[str, int] = {}
    for r in results:
        if r.is_risky or r.abstain:
            counts[r.surface] = counts.get(r.surface, 0) + 1
    return counts


def _resource_type_fallback(change) -> Surface:
    """Deterministic surface from resource_type when Laya is unavailable."""
    rt = getattr(change, "resource_type", "")
    if rt == "iam_policy":
        return "iam"
    if rt == "firewall_rule":
        return "firewall"
    if rt == "network_firewall_policy":
        return "nfp"
    return "other"


def _change_to_text(change) -> str:
    """Format a Change as natural-language context for Laya routing."""
    parts = [
        f"GCP change.",
        f"Action: {getattr(change, 'action', 'unknown')} {getattr(change, 'resource_type', 'resource')}.",
        f"Resource: {getattr(change, 'resource', 'unknown')}.",
    ]
    after = getattr(change, "after", None)
    if after:
        try:
            parts.append(f"Details: {json.dumps(after)[:200]}.")
        except Exception:
            pass
    return " ".join(parts)
