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
        """Paths with 4+ segments shortened to last 2; <4 segments unchanged."""
        obj = {
            "four_segments": "a/b/c/d",  # 4 parts: should shorten
            "three_segments": "a/b/c",  # 3 parts: should not shorten
            "five_segments": "projects/my-proj/global/firewalls/my-fw",  # 5 parts: should shorten
        }

        result = redact_sensitive(obj)

        # Boundary: exactly 4 segments should be shortened
        self.assertEqual(result["four_segments"], ".../c/d")
        # Boundary: 3 segments should NOT be shortened
        self.assertEqual(result["three_segments"], "a/b/c")
        # More than 4 should also shorten
        self.assertEqual(result["five_segments"], ".../firewalls/my-fw")

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
        """Custom redactors are whole-object transformers applied after built-ins."""

        @register_redactor
        def mask_ips(obj):
            # Recursively replace "10.0.0.5" anywhere in the object
            if isinstance(obj, str):
                return obj.replace("10.0.0.5", "10.0.0.0/24")
            elif isinstance(obj, dict):
                return {k: mask_ips(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [mask_ips(item) for item in obj]
            return obj

        # Test that custom redactor applies to nested values (proves it runs on final walked result)
        result = redact_sensitive({"servers": [{"ip": "10.0.0.5"}, {"ip": "10.0.0.5"}]})
        self.assertEqual(result["servers"][0]["ip"], "10.0.0.0/24")
        self.assertEqual(result["servers"][1]["ip"], "10.0.0.0/24")


    # ---- C1 probe tests ----

    def test_pem_body_with_slashes_is_redacted(self):
        """C1: PEM block whose base64 contains '/' must be [REDACTED], not path-shortened."""
        # fake PEM header triggers the pattern; base64 body contains slashes
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC/BKS\nABCD1234/+xyz\n-----END PRIVATE KEY-----"
        result = redact_sensitive(pem)
        self.assertEqual(result, "[REDACTED]")
        self.assertNotIn("MIIEvQ", result)
        self.assertNotIn("BAQEFAASC", result)

    def test_api_key_in_url_is_redacted(self):
        """C1: API key embedded in a URL must be [REDACTED] — not path-shortened."""
        # AIza + exactly 35 alphanum/_/- chars = valid Google API key pattern
        url = "https://example.com/maps/key?key=AIzaSyDummyKeyWith35MoreCharacters1234567"
        result = redact_sensitive(url)
        self.assertEqual(result, "[REDACTED]")
        self.assertNotIn("AIza", result)

    # ---- C2 probe tests ----

    def test_multiple_sa_emails_in_sentence_both_masked(self):
        """C2: sentence containing two SA emails — both must be masked, neither local part present."""
        s = "x@p.iam.gserviceaccount.com and y@p.iam.gserviceaccount.com"
        result = redact_sensitive(s)
        self.assertNotIn("x@", result)
        self.assertNotIn("y@", result)
        # both masked occurrences present
        self.assertIn("sa-", result)
        self.assertIn("@p.iam.gserviceaccount.com", result)

    def test_path_not_shortened_when_contains_at(self):
        """C2 order: a masked SA-email string should not be path-shortened (it contains @)."""
        s = "my-sa@p.iam.gserviceaccount.com"
        result = redact_sensitive(s)
        # must be masked, not ".../..."
        self.assertTrue(result.startswith("sa-"))
        self.assertNotIn("...", result)

    def test_plain_path_still_shortened(self):
        """Path-shortening still applies to bare resource paths (no spaces, no @)."""
        result = redact_sensitive("projects/my-proj/global/firewalls/my-fw")
        self.assertEqual(result, ".../firewalls/my-fw")

    def test_path_with_spaces_not_shortened(self):
        """Paths with spaces are not path-shortened (they're not bare resource paths)."""
        result = redact_sensitive("see projects/my-proj/global/firewalls/my-fw for details")
        # should be returned as-is (no secrets, no SA emails)
        self.assertIn("projects/my-proj", result)
        self.assertNotIn("...", result)


if __name__ == "__main__":
    unittest.main()
