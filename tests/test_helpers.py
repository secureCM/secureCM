"""Tests for helpers.py — TDD, Task 3."""
import unittest

from gcp_policy_analyzer.helpers import is_production, is_service_account


class TestIsProduction(unittest.TestCase):
    def test_is_production_label_only(self):
        # labeled prod → True
        class Obj:
            labels = {"env": "prod"}
        self.assertTrue(is_production(Obj()))

    def test_name_without_label_is_false(self):
        # name "prod-core" with no label → False
        class Obj:
            labels = {}
            name = "prod-core"
        self.assertFalse(is_production(Obj()))

    def test_production_value_also_matches(self):
        self.assertTrue(is_production({"labels": {"environment": "production"}}))

    def test_dict_with_prod_label(self):
        self.assertTrue(is_production({"labels": {"env": "prod"}}))

    def test_dict_without_prod_label(self):
        self.assertFalse(is_production({"labels": {"env": "dev"}}))

    def test_custom_keys_and_values(self):
        self.assertTrue(is_production(
            {"labels": {"tier": "live"}},
            label_keys=("tier",),
            label_values=("live",),
        ))

    def test_non_string_label_value_does_not_raise(self):
        """I9: non-string label values (int, bool) must not raise."""
        obj = {"labels": {"env": 1}}  # int value
        try:
            result = is_production(obj)
        except (AttributeError, TypeError) as exc:
            self.fail(f"is_production raised with non-string label value: {exc}")
        self.assertFalse(result)  # 1 != "prod"

    def test_uppercase_custom_label_value_matches(self):
        """I10: custom label_values with uppercase should match lowercase stored label."""
        self.assertTrue(is_production(
            {"labels": {"env": "prod"}},
            label_values=("PROD",),
        ))

    def test_uppercase_stored_label_matches_default(self):
        """I10: stored label 'PROD' should match default label_values."""
        self.assertTrue(is_production({"labels": {"env": "PROD"}}))


class TestIsServiceAccount(unittest.TestCase):
    def test_is_service_account_prefix_and_domain(self):
        self.assertTrue(is_service_account(
            "serviceAccount:sa@project.iam.gserviceaccount.com"
        ))

    def test_bare_sa_email(self):
        self.assertTrue(is_service_account("sa@project.iam.gserviceaccount.com"))

    def test_user_email_is_false(self):
        self.assertFalse(is_service_account("user:alice@example.com"))

    def test_regular_email_is_false(self):
        self.assertFalse(is_service_account("alice@example.com"))

    def test_dict_member(self):
        self.assertTrue(is_service_account(
            {"member": "serviceAccount:sa@project.iam.gserviceaccount.com"}
        ))
