"""GCP Policy Analyzer — public API."""
from __future__ import annotations

from datetime import datetime

from gcp_policy_analyzer.loaders import (
    load_iam_policies,
    load_vpc_firewall_rules,
    load_network_firewall_policies,
    load_audit_changes,
)
from gcp_policy_analyzer.diff import diff_policies, Change
from gcp_policy_analyzer.scoring import (
    score_rule_exposure,
    score_iam_binding,
    classify_change,
    ChangeClass,
)
from gcp_policy_analyzer.prioritize import (
    prioritize_changes,
    compute_blast_radius,
)
from gcp_policy_analyzer.logs import filter_log_entries, correlate_changes_with_logs
from gcp_policy_analyzer.redact import redact_sensitive, register_redactor
from gcp_policy_analyzer.helpers import is_production, is_service_account, format_report
from gcp_policy_analyzer.fetch import fetch_export, fetch_all, BrokerError

__all__ = [
    "analyze",
    "fetch_export",
    "fetch_all",
    "BrokerError",
    "load_iam_policies",
    "load_vpc_firewall_rules",
    "load_network_firewall_policies",
    "load_audit_changes",
    "diff_policies",
    "Change",
    "score_rule_exposure",
    "score_iam_binding",
    "classify_change",
    "ChangeClass",
    "prioritize_changes",
    "compute_blast_radius",
    "filter_log_entries",
    "correlate_changes_with_logs",
    "redact_sensitive",
    "register_redactor",
    "is_production",
    "is_service_account",
    "format_report",
]


def analyze(
    data: dict,
    start: datetime,
    end: datetime,
    resource_types: list[str] | None = None,
) -> dict:
    """Load, prioritize, and format a report for policy changes in [start, end].

    Args:
        data: raw export dict (from fetch_all or fixture)
        start: window start (UTC-aware)
        end: window end (UTC-aware)
        resource_types: optional filter by resource_type strings from audit_changes records
            (e.g. "vpc_firewall_rule", "iam_policy")

    Returns:
        redacted report dict with keys: summary, prioritized, stats
    """
    all_changes = load_audit_changes(data, resource_types=resource_types, start=start, end=end)
    prioritized = prioritize_changes(all_changes)
    window = f"{start.date()} to {end.date()}"
    report = format_report(prioritized, all_changes=all_changes)
    # Augment summary with window and counts
    report["summary"] = (
        f"{len(prioritized)} risky change(s) out of {len(all_changes)} total "
        f"in window {window}."
    )
    return report
