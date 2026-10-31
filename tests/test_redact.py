import unittest
from datetime import datetime, timezone
from gcp_policy_analyzer.redact import (
    redact_sensitive,
    register_redactor,
    clear_redactors,
    SECRET_PATTERNS,
)
from gcp_policy_analyzer.loaders import IamBinding, IamPolicy
from gcp_policy_analyzer.diff import Change


class TestRedactSensitive(unittest.TestCase):

    def tearDown(self):
        """Clear registered redactors after each test."""
        clear_redactors()

    def test_sa_email_masked_deterministically(self):
        """SA email local@proj.iam.gserviceaccount.com → sa-{hash}@proj.iam.gserviceaccount.com."""
        email = "my-sa@my-project.iam.gserviceaccount.com"
        obj1 = {"email": email}
        obj2 = {"email": email}

        result1 = redact_sensitive(obj1)
        result2 = redact_sensitive(obj2)

        # Both should produce identical masks
        self.assertEqual(result1["email"], result2["email"])
        # Original email should not appear
        self.assertNotIn(email, result1["email"])
        # Should match pattern sa-xxxxxx@proj.iam.gserviceaccount.com
        self.assertTrue(result1["email"].startswith("sa-"))
        self.assertTrue(result1["email"].endswith("@my-project.iam.gserviceaccount.com"))

    def test_salt_changes_hash(self):
        """Different salts produce different hashes for same email."""
        email = "my-sa@my-project.iam.gserviceaccount.com"

        result_a = redact_sensitive({"email": email}, salt="a")
        result_b = redact_sensitive({"email": email}, salt="b")

        # Different salts should produce different masks
        self.assertNotEqual(result_a["email"], result_b["email"])
        # Both should still match the pattern
        self.assertTrue(result_a["email"].startswith("sa-"))
        self.assertTrue(result_b["email"].startswith("sa-"))

    def test_long_path_shortened(self):
        """Paths with 4+ segments shortened to last 2."""
        obj = {
            "long_path": "projects/my-proj/global/firewalls/my-fw",
            "short_path": "projects/my-proj",
        }

        result = redact_sensitive(obj)

        # Long path shortened
        self.assertEqual(result["long_path"], ".../firewalls/my-fw")
        # Short path unchanged
        self.assertEqual(result["short_path"], "projects/my-proj")

    def test_secret_string_redacted(self):
        """API keys and private keys redacted to [REDACTED]."""
        obj = {
            "api_key": "AIzaSyDummyKeyWith35MoreCharacters1234567",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBA...",
        }

        result = redact_sensitive(obj)

        # Both should be redacted
        self.assertEqual(result["api_key"], "[REDACTED]")
        self.assertEqual(result["private_key"], "[REDACTED]")

    def test_nested_and_nonstring_values(self):
        """Nested SA emails masked; None/int/datetime/bool preserved."""
        obj = {
            "nested_list": [
                {"email": "my-sa@my-project.iam.gserviceaccount.com"},
                None,
                42,
                True,
            ],
            "nested_dict": {
                "email": "other-sa@other-project.iam.gserviceaccount.com",
                "count": 100,
                "active": False,
            },
            "timestamp": datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc),
        }

        result = redact_sensitive(obj)

        # Nested SA emails should be masked
        self.assertTrue(result["nested_list"][0]["email"].startswith("sa-"))
        self.assertTrue(result["nested_dict"]["email"].startswith("sa-"))
        # Non-string values should be preserved
        self.assertIsNone(result["nested_list"][1])
        self.assertEqual(result["nested_list"][2], 42)
        self.assertIs(result["nested_list"][3], True)
        self.assertEqual(result["nested_dict"]["count"], 100)
        self.assertIs(result["nested_dict"]["active"], False)
        # Datetime should be ISO format string
        self.assertEqual(result["timestamp"], "2026-10-31T12:00:00+00:00")

    def test_register_redactor_runs(self):
        """Custom redactors registered via decorator are applied."""

        @register_redactor
        def redact_ips(obj):
            if isinstance(obj, str) and obj == "10.0.0.5":
                return "10.0.0.0/24"
            return obj

        result = redact_sensitive({"ip": "10.0.0.5"})
        self.assertEqual(result["ip"], "10.0.0.0/24")


if __name__ == "__main__":
    unittest.main()
