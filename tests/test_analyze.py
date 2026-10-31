"""Tests for analyze() entry point."""
import json
import unittest
from datetime import datetime, timezone, timedelta

FIXTURE_ANCHOR = datetime(2026, 10, 31, tzinfo=timezone.utc)


def _load_fixture():
    import pathlib
    p = pathlib.Path(__file__).parent.parent / "fixtures" / "synthetic.json"
    with open(p) as f:
        return json.load(f)


class TestAnalyze(unittest.TestCase):
    def setUp(self):
        from gcp_policy_analyzer import analyze
        self.analyze = analyze
        self.data = _load_fixture()

    def test_analyze_shape_and_redaction(self):
        end = FIXTURE_ANCHOR
        start = end - timedelta(days=7)
        result = self.analyze(self.data, start, end)

        # Required top-level keys
        self.assertIn("summary", result)
        self.assertIn("prioritized", result)
        self.assertIn("stats", result)

        # Summary is a non-empty string
        self.assertIsInstance(result["summary"], str)
        self.assertTrue(len(result["summary"]) > 0)

        # stats has required sub-keys
        stats = result["stats"]
        self.assertIn("total_changes", stats)
        self.assertIn("risky", stats)
        self.assertIn("neutral", stats)
        self.assertIn("principals", stats)

        # Redaction: no raw SA emails in JSON output
        dumped = json.dumps(result)
        self.assertNotIn("terraform-deployer@example-prod-project.iam.gserviceaccount.com", dumped)
        self.assertNotIn("sa-demo@example-prod-project.iam.gserviceaccount.com", dumped)
        # Local parts must also be absent
        self.assertNotIn("terraform-deployer@", dumped)
        self.assertNotIn("sa-demo@", dumped)

    def test_analyze_window_respects_bounds(self):
        # Only yesterday's changes (2026-10-30) should appear
        end = FIXTURE_ANCHOR
        start = end - timedelta(days=1)
        result_1d = self.analyze(self.data, start, end)

        # 7-day window includes more changes
        start_7d = end - timedelta(days=7)
        result_7d = self.analyze(self.data, start_7d, end)

        # 1-day window should have fewer or equal total_changes than 7-day
        self.assertLessEqual(
            result_1d["stats"]["total_changes"],
            result_7d["stats"]["total_changes"],
        )

        # Out-of-window change (2026-10-21) must not appear in 7-day window
        # (anchor - 7d = 2026-10-24, so 2026-10-21 is excluded)
        # total_changes in 7d should not count the 2026-10-21 entry
        # We know fixture has 5 audit_changes; the 2026-10-21 one is outside 7d window
        self.assertLessEqual(result_7d["stats"]["total_changes"], 4)
