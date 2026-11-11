"""MCP stdio server for GCP Policy Analyzer codemode.

Exposes three tools:
  describe_capabilities — walks gcp_policy_analyzer.__all__ and returns API summary
  run_script            — executes Python code via codemode.executor.run_script
  run_analysis          — Laya triage + RDM routing + targeted sandbox run (low-token path)
"""
from __future__ import annotations

import inspect
import json
import sys
from datetime import datetime, timezone

import gcp_policy_analyzer
from codemode import run_script

_PATTERN = "fetch → load → classify/score → blast radius → sort → redact"

_PREAMBLE = """\
gcp_policy_analyzer — compose these helpers in a run_script to analyze GCP security data.

REDACTION CONTRACT (read before correlating across turns or data sources):
  Output you get back is redacted. Service-account emails are masked to a STABLE
  form, e.g. ci-runner-07@…  →  sa-a1447b@… . The mask is deterministic: the SAME
  service account always yields the SAME sa-xxxxxx@ string, in IAM bindings, in log
  principalEmail, and in change.principal alike. So JOIN ON THE MASKED STRING
  directly — treat it as the entity id. Do NOT try to reverse it. Human and external
  emails (not *.iam.gserviceaccount.com) and caller IPs are NOT masked.

FINDING MULTI-STEP INCIDENTS (needle in a haystack):
  A single operation often spans several principals, days, and data types. The join
  signal is usually a shared caller IP. correlate_by_actor(changes, log_entries)
  groups activity per principal and returns shared_ips (IPs used by >1 actor) and
  per-actor anomalous_ips — an external identity and a service account sharing one IP
  are almost certainly one actor.

  IMPORTANT: pass load_log_entries(data) as the second argument, NOT data["log_entries"].
  load_log_entries flattens the native protoPayload shape so callerIp is accessible at
  the top level. Raw log_entries have callerIp buried at protoPayload.requestMetadata
  and correlate_by_actor will see no IPs — shared_ips will be empty.

WORKED EXAMPLE (complex question, end to end):
  import json
  from datetime import datetime, timedelta, timezone
  from gcp_policy_analyzer import (
      load_audit_changes, load_log_entries, load_iam_policies, classify_change, ChangeClass,
      score_iam_binding, is_service_account, compute_blast_radius,
      prioritize_changes, correlate_by_actor, redact_sensitive,
  )
  data = json.load(open("/path/to/export.json"))
  now = datetime(2026, 11, 14, tzinfo=timezone.utc)          # anchor; not the real clock
  changes = load_audit_changes(data, start=now - timedelta(days=14), end=now)

  # 1. rank risky changes by blast radius (pass the full envelope as context)
  ranked = prioritize_changes(changes, context=data)

  # 2. identity risk: external grantors, high-priv / toxic grants
  for p in load_iam_policies(data):
      for b in p.bindings:
          r = score_iam_binding(b)
          if r.is_high_privilege or r.toxic_combination:
              ...   # members are masked SA ids or raw human/external emails

  # 3. tie it together — shared caller IP across actors is the smoking gun
  #    load_log_entries flattens protoPayload so callerIp is top-level
  corr = correlate_by_actor(changes, load_log_entries(data))
  print(json.dumps(redact_sensitive({
      "shared_ips": corr["shared_ips"],
      "top_actors": corr["actors"][:5],
  }), indent=2, default=str))

COVERAGE (ATT&CK-tagged detections):
  Scope: IAM bindings, VPC firewall rules, Admin Activity audit logs — three surfaces only.
  Most of the ATT&CK matrix is out-of-scope: endpoints, network traffic, EDR telemetry,
  and any data-plane signals are not present on these control-plane surfaces.

  In-scope techniques detected:
    T1098        Account Manipulation
    T1098.003    Account Manipulation: Additional Cloud Roles
    T1199        Trusted Relationship
    T1562        Impair Defenses
    T1562.007    Impair Defenses: Disable or Modify Cloud Firewall
    T1485        Data Destruction
    T1580        Cloud Infrastructure Discovery
    T1069.003    Permission Groups Discovery: Cloud Groups
    T1078.004    Valid Accounts: Cloud Accounts

  To get ATT&CK-tagged findings for all detectors in one call:
    from attack_coverage.signatures import run_detectors
    findings = run_detectors(envelope)   # envelope is the raw export dict
    # each Finding has .technique_id, .technique_name, .severity, .resource,
    # .principal, .tactic, .timestamp, .evidence (dict of supporting data)

  Coverage: 9 in-scope techniques detected; run `python -m attack_coverage.report` for the live matrix.

API REFERENCE:"""

_TOOLS = [
    {
        "name": "describe_capabilities",
        "description": "List all public symbols in gcp_policy_analyzer with signatures and docstrings.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "run_script",
        "description": "Execute a Python script and return stdout (and stderr/timeout info on failure).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Python source to execute"},
                "timeout": {"type": "integer", "description": "Seconds before timeout (default 60)"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "run_analysis",
        "description": (
            "Low-token analysis path: Laya triage filters changes (zero LLM tokens), "
            "RDM routing selects which detectors to run (Laya choices, ~33ms each), "
            "then targeted scripts execute in the sandbox. "
            "Use this instead of run_script when you want findings without writing orchestration code."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "data_path": {
                    "type": "string",
                    "description": "Absolute path to the GCP export JSON file inside the sandbox.",
                },
                "window_days": {
                    "type": "integer",
                    "description": "Lookback window in days from now (default 7).",
                },
                "triage_threshold": {
                    "type": "number",
                    "description": "Laya risk probability threshold for keeping a change (default 0.5).",
                },
                "anchor_date": {
                    "type": "string",
                    "description": "ISO-8601 UTC date for the analysis window end, e.g. '2026-10-31'. Defaults to now.",
                },
            },
            "required": ["data_path"],
        },
    },
]


def build_capabilities() -> str:
    """Walk gcp_policy_analyzer.__all__ and return a formatted API summary string."""
    lines = [_PREAMBLE, ""]
    for name in gcp_policy_analyzer.__all__:
        obj = getattr(gcp_policy_analyzer, name)
        doc = inspect.getdoc(obj)
        first_line = doc.split("\n")[0] if doc else ""
        if callable(obj):
            try:
                sig = str(inspect.signature(obj))
            except (ValueError, TypeError):
                sig = "(...)"
            lines.append(f"{name}{sig} — {first_line}")
        else:
            lines.append(f"{name} — {first_line}")
    lines.append("")
    lines.append(f"Pattern: {_PATTERN}")
    return "\n".join(lines)


def _ok(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _call_tool(name: str, args: dict) -> dict:
    if name == "describe_capabilities":
        text = build_capabilities()
    elif name == "run_script":
        code = args["code"]
        timeout = int(args.get("timeout", 60))
        result = run_script(code, timeout=timeout)
        if result.returncode != 0 or result.timed_out:
            text = result.stdout
            if result.timed_out:
                text += f"\n[timed out after {timeout}s]"
            elif result.stderr:
                text += f"\n[stderr]\n{result.stderr}"
        else:
            text = result.stdout
        # Redact stdout/stderr before returning — trust boundary
        text = gcp_policy_analyzer.redact_sensitive(text)
    elif name == "run_analysis":
        text = _run_analysis(args)
    else:
        return {"error": {"code": -32602, "message": f"Unknown tool: {name}"}}
    return {"content": [{"type": "text", "text": text}]}


def _run_analysis(args: dict) -> str:
    """Laya triage + RDM routing + targeted sandbox run."""
    from codemode.laya_triage import triage_changes, surface_counts, _LAYA_AVAILABLE
    from codemode.rdm_router import route_and_run

    import os as _os
    data_path = _os.path.abspath(args["data_path"])
    window_days = int(args.get("window_days", 7))
    threshold = float(args.get("triage_threshold", 0.5))
    if args.get("anchor_date"):
        anchor = datetime.fromisoformat(args["anchor_date"]).replace(tzinfo=timezone.utc)
    else:
        anchor = datetime.now(timezone.utc)

    # Load changes in broker process for triage (not the sandbox)
    try:
        import json as _json
        from gcp_policy_analyzer import load_audit_changes
        from datetime import timedelta
        with open(data_path) as f:
            data = _json.load(f)
        start = anchor - timedelta(days=window_days)
        all_changes = load_audit_changes(data, start=start, end=anchor)
    except Exception as exc:
        return f"[run_analysis] Failed to load data: {exc}"

    # Laya triage: filter to risky changes + get surface routing
    risky, triage_results = triage_changes(all_changes, threshold=threshold)
    counts = surface_counts(triage_results) if triage_results else {
        "iam": sum(1 for c in all_changes if c.resource_type == "iam_policy"),
        "firewall": sum(1 for c in all_changes if c.resource_type == "firewall_rule"),
        "nfp": sum(1 for c in all_changes if c.resource_type == "network_firewall_policy"),
    }

    triage_note = (
        f"Laya triage: {len(risky)}/{len(all_changes)} changes flagged as risky. "
        if _LAYA_AVAILABLE else
        f"Laya not installed — processing all {len(all_changes)} changes. "
    )

    # RDM routing loop: Laya decides detectors, targeted scripts run in sandbox
    findings = route_and_run(
        surface_counts=counts,
        run_script_fn=run_script,
        data_path=data_path,
        anchor_date=anchor,
        window_days=window_days,
    )

    result_text = triage_note + f"{len(findings)} finding(s).\n"
    if findings:
        result_text += _json.dumps(findings, indent=2, default=str)

    return gcp_policy_analyzer.redact_sensitive(result_text)


def handle_request(req: dict) -> dict | None:
    """Dispatch a JSON-RPC 2.0 request dict; return response dict or None for notifications."""
    method = req.get("method", "")
    req_id = req.get("id")  # None for notifications

    # JSON-RPC 2.0: requests without "id" are notifications and never get a response
    if "id" not in req:
        return None

    if method == "initialize":
        return _ok(req_id, {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "gcp-policy-analyzer-codemode", "version": "0.1.0"},
            "capabilities": {"tools": {}},
        })

    if method == "tools/list":
        return _ok(req_id, {"tools": _TOOLS})

    if method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        result = _call_tool(tool_name, tool_args)
        if "error" in result:
            return _err(req_id, result["error"]["code"], result["error"]["message"])
        return _ok(req_id, result)

    return _err(req_id, -32601, f"Method not found: {method}")


def main() -> None:
    """Read newline-delimited JSON from stdin, write responses to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            resp = _err(None, -32700, f"Parse error: {exc}")
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue
        resp = handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
