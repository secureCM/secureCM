"""Tests for canonical example scripts — run via subprocess."""
import json
import subprocess
import sys
import unittest
import pathlib

REPO_ROOT = str(pathlib.Path(__file__).parent.parent)
YESTERDAY_SCRIPT = str(pathlib.Path(REPO_ROOT) / "examples" / "what_changed_yesterday.py")
SEVEN_DAY_SCRIPT = str(pathlib.Path(REPO_ROOT) / "examples" / "seven_day_exposure.py")


def _run_script(path):
    result = subprocess.run(
        [sys.executable, path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result


class TestYesterdayExample(unittest.TestCase):
    def test_yesterday_example_outputs_ranked_json(self):
        result = _run_script(YESTERDAY_SCRIPT)
        self.assertEqual(result.returncode, 0, msg=f"stderr: {result.stderr}")

        out = json.loads(result.stdout)

        # Must have expected shape
        self.assertIn("summary", out)
        self.assertIn("prioritized", out)
        self.assertIn("stats", out)

        # Ranks must be ascending integers (1, 2, 3, ...)
        ranks = [p["rank"] for p in out["prioritized"]]
        if ranks:
            self.assertEqual(ranks, list(range(1, len(ranks) + 1)))


class TestSevenDayExample(unittest.TestCase):
    def test_seven_day_example_nonempty_and_redacted(self):
        result = _run_script(SEVEN_DAY_SCRIPT)
        self.assertEqual(result.returncode, 0, msg=f"stderr: {result.stderr}")

        out = json.loads(result.stdout)
        dumped = result.stdout  # raw JSON string for redaction checks

        # Must have at least 1 hit
        self.assertGreaterEqual(len(out), 1, "Expected at least 1 high-priv SA change")

        # Raw SA emails must be absent
        self.assertNotIn("terraform-deployer@example-prod-project.iam.gserviceaccount.com", dumped)
        self.assertNotIn("sa-demo@example-prod-project.iam.gserviceaccount.com", dumped)
        self.assertNotIn("terraform-deployer@", dumped)
        self.assertNotIn("sa-demo@", dumped)

        # Ranks must descend by score (or at minimum scores are non-increasing)
        scores = [item.get("blast_radius", {}).get("score", 0) for item in out]
        for i in range(len(scores) - 1):
            self.assertGreaterEqual(scores[i], scores[i + 1],
                                    f"scores not descending: {scores}")
