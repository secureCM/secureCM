"""Load and validate the ATT&CK coverage catalog."""
import json
import os
from typing import Optional

_DEFAULT_CATALOG = os.path.join(os.path.dirname(__file__), "attack_catalog.json")


def load_catalog(path: Optional[str] = None) -> dict:
    """Return the parsed catalog dict. Uses bundled catalog if path is None."""
    with open(path or _DEFAULT_CATALOG, encoding="utf-8") as f:
        return json.load(f)


def validate_catalog(catalog: dict) -> list[str]:
    """Return a list of problem strings; empty means valid."""
    problems = []
    seen_ids: set[str] = set()

    for t in catalog.get("techniques", []):
        tid = t.get("id", "<missing id>")

        if tid in seen_ids:
            problems.append(f"duplicate id: {tid}")
        seen_ids.add(tid)

        status = t.get("status")
        if status == "out-of-scope":
            if not t.get("reason"):
                problems.append(f"{tid}: out-of-scope entry missing reason")
        elif status in ("covered", "partial"):
            if not t.get("detector"):
                problems.append(f"{tid}: covered/partial entry missing detector")
            if not t.get("fixture"):
                problems.append(f"{tid}: covered/partial entry missing fixture")
        else:
            problems.append(f"{tid}: unknown status '{status}'")

    return problems
