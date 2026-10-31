"""Production and service-account predicates. Label-only detection, no name heuristics."""
from __future__ import annotations

PROD_LABEL_KEYS: tuple[str, ...] = ("env", "environment")
PROD_LABEL_VALUES: tuple[str, ...] = ("prod", "production")


def _get_labels(obj) -> dict:
    if isinstance(obj, dict):
        return obj.get("labels", {})
    return getattr(obj, "labels", {})


def is_production(
    obj,
    *,
    label_keys: tuple[str, ...] | None = None,
    label_values: tuple[str, ...] | None = None,
) -> bool:
    """True iff obj has a label whose key is in label_keys and value in label_values."""
    keys = label_keys if label_keys is not None else PROD_LABEL_KEYS
    values = label_values if label_values is not None else PROD_LABEL_VALUES
    labels = _get_labels(obj)
    return any(labels.get(k, "").lower() in values for k in keys)


def is_service_account(member: str | dict) -> bool:
    """True iff member (string or dict with 'member' key) is a GCP service account."""
    if isinstance(member, dict):
        member = member.get("member", "")
    # strip prefix
    email = member.removeprefix("serviceAccount:").removeprefix("user:").removeprefix("group:")
    return email.endswith(".gserviceaccount.com")
