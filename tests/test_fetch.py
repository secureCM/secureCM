"""Tests for fetch.py — credential-less broker client."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from gcp_policy_analyzer.fetch import BrokerError, fetch_all, fetch_export


class _Handler(BaseHTTPRequestHandler):
    """Stub HTTP handler; behaviour set via class-level dict keyed by path."""

    routes: dict = {}  # set in setUpClass

    def log_message(self, *_):  # silence test output
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        key = (parsed.path, params.get("type", [""])[0], params.get("pageToken", [None])[0])
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
        _Handler.routes = {}
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

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
        with self.assertRaises(BrokerError):
            fetch_export(self.base_url, "log_entries", "projects/demo")

    def test_fetch_all_merges_resource_types(self):
        types = ("iam_policies", "vpc_firewall_rules", "network_firewall_policies",
                 "audit_changes", "log_entries")
        for t in types:
            _Handler.routes[("/export", t, None)] = (200, json.dumps({t: [{"t": t}]}))
        result = fetch_all(self.base_url, "projects/demo")
        for t in types:
            self.assertIn(t, result)
            self.assertEqual(result[t], [{"t": t}])
