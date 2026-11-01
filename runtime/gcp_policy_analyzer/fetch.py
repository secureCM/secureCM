"""Credential-less broker client.

Fetches policy data from the broker over plain HTTP/HTTPS.
No auth headers, no env reads, no retries — by design.
"""
import json
from urllib.parse import urlencode, urljoin
from urllib.request import urlopen
from urllib.error import URLError

MAX_PAGES = 1000
MAX_RESPONSE_BYTES = 50 * 1024 * 1024  # 50 MB

_RESOURCE_TYPES = (
    "iam_policies",
    "vpc_firewall_rules",
    "network_firewall_policies",
    "log_entries",
)


class BrokerError(Exception):
    """Raised on non-200 responses or malformed JSON from the broker."""


def fetch_export(
    base_url: str,
    resource_type: str,
    scope: str,
    *,
    start=None,
    end=None,
    timeout: int = 30,
) -> dict:
    """GET {base_url}/export?type=…&scope=…[&start=…&end=…], follows pagination."""
    params = {"type": resource_type, "scope": scope}
    if start is not None:
        params["start"] = start.isoformat() if hasattr(start, "isoformat") else start
    if end is not None:
        params["end"] = end.isoformat() if hasattr(end, "isoformat") else end

    merged: dict = {}
    page_token = None
    pages_fetched = 0

    while True:
        if pages_fetched >= MAX_PAGES:
            raise BrokerError(f"pagination exceeded {MAX_PAGES} pages for {urljoin(base_url.rstrip('/') + '/', 'export')}")

        if page_token:
            params["pageToken"] = page_token
        elif "pageToken" in params:
            del params["pageToken"]

        url = urljoin(base_url.rstrip("/") + "/", "export") + "?" + urlencode(params)

        try:
            with urlopen(url, timeout=timeout) as resp:
                status = resp.status
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except URLError as exc:
            raise BrokerError(f"Request failed for {url}: {exc}") from exc

        if status != 200:
            raise BrokerError(f"Broker returned {status} for {url}")

        if len(raw) > MAX_RESPONSE_BYTES:
            raise BrokerError(f"Response exceeds {MAX_RESPONSE_BYTES} bytes for {url}")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BrokerError(f"Invalid JSON from {url}: {exc}") from exc

        page_token = data.pop("nextPageToken", None)

        # ponytail: per-type keys are non-overlapping by contract, last-writer-wins
        for key, val in data.items():
            if isinstance(val, list) and key in merged and isinstance(merged[key], list):
                merged[key].extend(val)
            else:
                merged[key] = val

        pages_fetched += 1
        if not page_token:
            break

    return merged


def fetch_all(base_url: str, scope: str, *, timeout: int = 30) -> dict:
    """Fetch all resource types and merge into one envelope dict."""
    result: dict = {}
    for rtype in _RESOURCE_TYPES:
        data = fetch_export(base_url, rtype, scope, timeout=timeout)
        result.update(data)
    return result
