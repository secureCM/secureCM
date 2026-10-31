"""MCP stdio server for GCP Policy Analyzer codemode.

Exposes two tools:
  describe_capabilities — walks gcp_policy_analyzer.__all__ and returns API summary
  run_script            — executes Python code via codemode.executor.run_script
"""
from __future__ import annotations

import inspect
import json
import sys

import gcp_policy_analyzer
from codemode import run_script

_PATTERN = "fetch → load → classify/score → blast radius → sort → redact"

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
]


def build_capabilities() -> str:
    """Walk gcp_policy_analyzer.__all__ and return a formatted API summary string."""
    lines = []
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
    else:
        return {"error": {"code": -32602, "message": f"Unknown tool: {name}"}}
    return {"content": [{"type": "text", "text": text}]}


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
            "serverInfo": {"name": "gcp-policy-analyzer-codemode"},
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
