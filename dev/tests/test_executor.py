"""Tests for codemode.executor — TDD red phase first, then green."""

import json
import os
import sys
import tempfile
import unittest


class TestExecutor(unittest.TestCase):

    def setUp(self):
        # Each test gets a fresh temp dir for audit files
        self._tmpdir = tempfile.mkdtemp()
        self.audit_log = os.path.join(self._tmpdir, "audit.jsonl")
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run(self, code, **kwargs):
        from codemode import run_script
        if "audit_log" not in kwargs:
            kwargs["audit_log"] = self.audit_log
        return run_script(code, **kwargs)

    # ------------------------------------------------------------------
    def test_runs_script_and_captures_stdout(self):
        result = self._run('print("hi")')
        self.assertEqual(result.stdout, "hi\n")
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)

    def test_timeout_returns_result(self):
        # Write a file in a loop; if child stays alive after run_script the file keeps changing.
        sentinel = os.path.join(self._tmpdir, "tick.txt")
        code = (
            "import time, pathlib\n"
            f"p = pathlib.Path({sentinel!r})\n"
            "while True:\n"
            "    p.write_text(str(time.time()))\n"
            "    time.sleep(0.05)\n"
        )
        result = self._run(code, timeout=1)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, -1)
        # child must be dead: mtime must stop advancing after run_script returns
        import time
        mtime1 = os.path.getmtime(sentinel) if os.path.exists(sentinel) else None
        time.sleep(0.3)
        mtime2 = os.path.getmtime(sentinel) if os.path.exists(sentinel) else None
        self.assertEqual(mtime1, mtime2, "child process still running after timeout")

    def test_failing_script_captured(self):
        result = self._run("raise ValueError('boom')")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ValueError", result.stderr)
        self.assertFalse(result.timed_out)

    def test_env_is_clean(self):
        # HOME should not be set inside the subprocess
        code = "import os, sys; v = os.environ.get('HOME', ''); print(repr(v))"
        result = self._run(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        # printed value should be empty string repr or None repr
        printed = result.stdout.strip()
        self.assertIn(printed, ("''", "None"), f"HOME leaked into child env: {printed}")

    def test_code_logged_verbatim(self):
        code = 'print("logged")'
        self._run(code)
        with open(self.audit_log) as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertTrue(lines, "audit log is empty")
        entry = json.loads(lines[-1])
        self.assertEqual(entry["code"], code)
        self.assertIn("ts", entry)

    def test_executionresult_has_code_field(self):
        code = 'print("x")'
        result = self._run(code)
        self.assertEqual(result.code, code)

    def test_default_audit_log_in_cwd(self):
        """When audit_log=None, file lands in caller's cwd (cwd-relative)."""
        from codemode import run_script
        orig = os.getcwd()
        os.chdir(self._tmpdir)
        self.addCleanup(os.chdir, orig)
        run_script('pass', audit_log=None)
        expected = os.path.join(self._tmpdir, "codemode_audit.jsonl")
        self.assertTrue(os.path.exists(expected))


if __name__ == "__main__":
    unittest.main()
