"""Restricted-subprocess script executor for untrusted model-written code."""

import json
import subprocess
import sys
import tempfile
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# ponytail: repo_root derived from __file__, never from env
_REPO_ROOT = str(Path(__file__).parent.parent)
_DEFAULT_AUDIT = "codemode_audit.jsonl"


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    code: str


def run_script(code: str, *, timeout: int = 60, audit_log: str | None = None) -> ExecutionResult:
    """Run `code` in a clean subprocess; log verbatim to audit file first."""
    if audit_log is None:
        audit_log = os.path.join(_REPO_ROOT, _DEFAULT_AUDIT)

    # Audit BEFORE execution — requirement
    entry = json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "code": code})
    with open(audit_log, "a") as f:
        f.write(entry + "\n")

    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as tmp:
        tmp.write(code)
        tmppath = tmp.name

    try:
        proc = subprocess.run(
            [sys.executable, tmppath],
            capture_output=True,
            timeout=timeout,
            env={"PYTHONPATH": _REPO_ROOT},  # sole entry — clean env, library importable
            cwd=_REPO_ROOT,
            text=True,
        )
        return ExecutionResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            timed_out=False,
            code=code,
        )
    except subprocess.TimeoutExpired as exc:
        return ExecutionResult(
            stdout=exc.stdout or "" if isinstance(exc.stdout, str) else (exc.stdout.decode() if exc.stdout else ""),
            stderr=exc.stderr or "" if isinstance(exc.stderr, str) else (exc.stderr.decode() if exc.stderr else ""),
            returncode=-1,
            timed_out=True,
            code=code,
        )
    finally:
        os.unlink(tmppath)
