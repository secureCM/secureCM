"""
Redact sensitive data from GCP policy objects.

redact_sensitive is the trust boundary: all output passed to LLMs goes through it.
- Deterministic masking (same input → same mask, when salt=None)
- Recursive walk over dicts/lists/dataclasses
- Registered custom redactors applied after built-ins
- Pure function: never mutates input
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Callable

# Secret patterns: matched strings redacted to [REDACTED]
SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),  # Google API key
    re.compile(r"-----BEGIN( [A-Z]+)? PRIVATE KEY-----"),  # Private key PEM header
]

# Registry of custom redactors (functions that transform values)
_REDACTORS: list[Callable[[Any], Any]] = []


def register_redactor(fn: Callable[[Any], Any]) -> Callable[[Any], Any]:
    """Decorator to register a custom redactor function.

    Custom redactors run after built-ins, on outermost object only.
    Function receives a value, returns transformed value or original if no match.
    """
    _REDACTORS.append(fn)
    return fn


def clear_redactors() -> None:
    """Clear all registered custom redactors (for test isolation)."""
    _REDACTORS.clear()


def redact_sensitive(
    obj: Any,
    *,
    patterns: list[re.Pattern] | None = None,
    salt: str | None = None,
) -> Any:
    """Recursively redact sensitive data from obj, returning a copy.

    Masking rules:
    - SA emails (local@proj.iam.gserviceaccount.com) → sa-{hash}@proj.iam.gserviceaccount.com
      where hash = sha256((salt or "")+email).hexdigest()[:6]
    - Paths with 4+ "/" segments → ".../last_two_segments"
    - Strings matching SECRET_PATTERNS (or custom patterns) → "[REDACTED]"
    - Datetimes → isoformat()
    - Dataclasses → asdict first, then recurse
    - Custom redactors (registered) run after built-ins on final walked result

    Args:
        obj: Any object (dict, list, dataclass, str, etc.)
        patterns: Custom SECRET_PATTERNS to use (default: built-in SECRET_PATTERNS)
        salt: Salt for deterministic hashing (default: "")

    Returns:
        Copy of obj with sensitive data masked.
    """
    if salt is None:
        salt = ""
    if patterns is None:
        patterns = SECRET_PATTERNS

    result = _redact_recursive(obj, patterns, salt)
    # Apply registered custom redactors to the final walked result, in order
    for redactor in _REDACTORS:
        result = redactor(result)
    return result


def _redact_recursive(obj: Any, patterns: list[re.Pattern], salt: str) -> Any:
    """Internal recursive walk (built-in rules only; custom redactors run after at top level)."""
    # Dataclass → asdict first
    if is_dataclass(obj) and not isinstance(obj, type):
        obj = asdict(obj)

    # Datetime → isoformat
    if isinstance(obj, datetime):
        return obj.isoformat()

    # Dict → recurse on values
    if isinstance(obj, dict):
        return {k: _redact_recursive(v, patterns, salt) for k, v in obj.items()}

    # List → recurse on elements
    if isinstance(obj, list):
        return [_redact_recursive(item, patterns, salt) for item in obj]

    # String: check SA email, path, secret patterns
    if isinstance(obj, str):
        # SA email: local@proj.iam.gserviceaccount.com
        if "@" in obj and ".iam.gserviceaccount.com" in obj:
            if _is_sa_email(obj):
                return _mask_sa_email(obj, salt)

        # Path with 4+ segments
        if "/" in obj:
            segments = obj.split("/")
            if len(segments) >= 4:
                return f".../{segments[-2]}/{segments[-1]}"

        # Secret patterns
        for pattern in patterns:
            if pattern.search(obj):
                return "[REDACTED]"

        return obj

    # Non-string, non-container: preserve as-is
    return obj


def _is_sa_email(s: str) -> bool:
    """Check if string looks like SA email."""
    # Simple heuristic: contains @ and .iam.gserviceaccount.com
    parts = s.split("@")
    if len(parts) == 2:
        local, domain = parts
        return ".iam.gserviceaccount.com" in domain
    return False


def _mask_sa_email(email: str, salt: str) -> str:
    """Mask SA email: my-sa@proj.iam.gserviceaccount.com → sa-{hash}@proj.iam.gserviceaccount.com."""
    # Extract local and domain parts
    local, domain = email.split("@", 1)

    # Hash with salt
    hash_input = salt + email
    hash_hex = hashlib.sha256(hash_input.encode()).hexdigest()[:6]

    return f"sa-{hash_hex}@{domain}"


