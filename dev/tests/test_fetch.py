"""Tests for fetch.py — credential-less broker client."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from gcp_policy_analyzer.fetch import BrokerError, fetch_all, fetch_export


class _Handler(BaseHTTPRequestHandler):
    """Stub HTTP handler; behaviour set via class-level dict keyed by path."""

    routes: dict = {}  # set per-test, guarded by routes_lock
    routes_lock = threading.Lock()

    def log_message(self, *_):  # silence test output
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        key = (parsed.path, params.get("type", [""])[0], params.get("pageToken", [None])[0])
        with _Handler.routes_lock:
            if key not in self.routes:
                self.send_response(404)
                self.end_headers()
                return
            status, body = self.routes[key]
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())


class TestFetch(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        """Clear routes before each test."""
        with _Handler.routes_lock:
            _Handler.routes = {}

    def tearDown(self):
        """Clear routes after each test."""
        with _Handler.routes_lock:
            _Handler.routes = {}

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}"

    def test_fetch_export_returns_envelope(self):
        payload = {"vpc_firewall_rules": [{"id": "fw-1"}]}
        _Handler.routes[("/export", "vpc_firewall_rules", None)] = (200, json.dumps(payload))
        result = fetch_export(self.base_url, "vpc_firewall_rules", "projects/demo")
        self.assertEqual(result, payload)

    def test_pagination_followed(self):
        page1 = {"iam_policies": [{"id": "a"}], "nextPageToken": "tok1"}
        page2 = {"iam_policies": [{"id": "b"}]}
        _Handler.routes[("/export", "iam_policies", None)] = (200, json.dumps(page1))
        _Handler.routes[("/export", "iam_policies", "tok1")] = (200, json.dumps(page2))
        result = fetch_export(self.base_url, "iam_policies", "projects/demo")
        self.assertEqual(result["iam_policies"], [{"id": "a"}, {"id": "b"}])
        self.assertNotIn("nextPageToken", result)

    def test_non_200_raises_brokererror(self):
        _Handler.routes[("/export", "audit_changes", None)] = (403, json.dumps({"error": "forbidden"}))
        with self.assertRaises(BrokerError) as ctx:
            fetch_export(self.base_url, "audit_changes", "projects/demo")
        msg = str(ctx.exception)
        self.assertIn("403", msg)
        self.assertIn(self.base_url, msg)

    def test_bad_json_raises_brokererror(self):
        _Handler.routes[("/export", "log_entries", None)] = (200, b"not json{{{")
        with self.assertRaises(BrokerError) as ctx:
            fetch_export(self.base_url, "log_entries", "projects/demo")
        msg = str(ctx.exception)
        self.assertIn(self.base_url, msg)

    def test_fetch_all_merges_resource_types(self):
        types = ("iam_policies", "vpc_firewall_rules", "network_firewall_policies",
                 "log_entries")
        for t in types:
            _Handler.routes[("/export", t, None)] = (200, json.dumps({t: [{"t": t}]}))
        result = fetch_all(self.base_url, "projects/demo")
        for t in types:
            self.assertIn(t, result)
            self.assertEqual(result[t], [{"t": t}])

    def test_pagination_exceeds_max_pages(self):
        """Pagination that exceeds MAX_PAGES raises BrokerError."""
        import gcp_policy_analyzer.fetch as fetch_module
        original_max = fetch_module.MAX_PAGES
        try:
            fetch_module.MAX_PAGES = 3
            # Set up 4 pages (exceeds limit of 3)
            _Handler.routes[("/export", "iam_policies", None)] = (200, json.dumps({"iam_policies": [{"id": "1"}], "nextPageToken": "p1"}))
            _Handler.routes[("/export", "iam_policies", "p1")] = (200, json.dumps({"iam_policies": [{"id": "2"}], "nextPageToken": "p2"}))
            _Handler.routes[("/export", "iam_policies", "p2")] = (200, json.dumps({"iam_policies": [{"id": "3"}], "nextPageToken": "p3"}))
            _Handler.routes[("/export", "iam_policies", "p3")] = (200, json.dumps({"iam_policies": [{"id": "4"}]}))
            with self.assertRaises(BrokerError) as ctx:
                fetch_export(self.base_url, "iam_policies", "projects/demo")
            msg = str(ctx.exception)
            self.assertIn("pagination exceeded", msg)
            self.assertIn("3", msg)
        finally:
            fetch_module.MAX_PAGES = original_max

    def test_response_exceeds_max_bytes(self):
        """Response exceeding MAX_RESPONSE_BYTES raises BrokerError."""
        import gcp_policy_analyzer.fetch as fetch_module
        original_max = fetch_module.MAX_RESPONSE_BYTES
        try:
            fetch_module.MAX_RESPONSE_BYTES = 100  # Small limit for testing
            # Create a large payload
            large_payload = json.dumps({"data": "x" * 1000})
            _Handler.routes[("/export", "iam_policies", None)] = (200, large_payload)
            with self.assertRaises(BrokerError) as ctx:
                fetch_export(self.base_url, "iam_policies", "projects/demo")
            msg = str(ctx.exception)
            self.assertIn("exceeds", msg)
            self.assertIn(self.base_url, msg)
        finally:
            fetch_module.MAX_RESPONSE_BYTES = original_max

    def test_fetch_all_requests_log_entries_not_audit_changes(self):
        """fetch_all issues a log_entries request and no audit_changes request."""
        import gcp_policy_analyzer.fetch as fetch_module
        tracked_types = []
        original_fetch_export = fetch_module.fetch_export

        def track_fetch_export(base_url, resource_type, scope, **kwargs):
            tracked_types.append(resource_type)
            return original_fetch_export(base_url, resource_type, scope, **kwargs)

        try:
            fetch_module.fetch_export = track_fetch_export
            types = ("iam_policies", "vpc_firewall_rules", "network_firewall_policies", "log_entries")
            for t in types:
                _Handler.routes[("/export", t, None)] = (200, json.dumps({t: []}))
            fetch_all(self.base_url, "projects/demo")
            self.assertIn("log_entries", tracked_types)
            self.assertNotIn("audit_changes", tracked_types)
        finally:
            fetch_module.fetch_export = original_fetch_export

    def test_fetch_returns_native_verbatim(self):
        """fetch_export returns native JSON unchanged (no flattening client-side)."""
        # Stub returns a native LogEntry structure with nested objects
        native_response = {
            "log_entries": [
                {
                    "name": "projects/test/logs/cloudresourcemanager.googleapis.com/activity",
                    "timestamp": "2025-01-01T00:00:00Z",
                    "jsonPayload": {
                        "methodName": "storage.buckets.create",
                        "resourceName": "projects/test/buckets/my-bucket",
                        "metadata": {
                            "labels": {"env": "prod"}
                        }
                    },
                    "severity": "NOTICE"
                }
            ]
        }
        _Handler.routes[("/export", "log_entries", None)] = (200, json.dumps(native_response))
        result = fetch_export(self.base_url, "log_entries", "projects/test")
        # Assert verbatim return: exact same structure, no transformations
        self.assertEqual(result, native_response)
        # Confirm nested structure is preserved
        self.assertEqual(len(result["log_entries"]), 1)
        entry = result["log_entries"][0]
        self.assertEqual(entry["jsonPayload"]["metadata"]["labels"], {"env": "prod"})
