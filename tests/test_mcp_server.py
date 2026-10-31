"""Tests for codemode/mcp_server.py — handle_request pure JSON-RPC 2.0."""
import unittest


class TestMcpServer(unittest.TestCase):
    def setUp(self):
        from codemode.mcp_server import handle_request
        self.handle = handle_request

    def test_initialize_and_tools_list(self):
        # initialize
        resp = self.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertEqual(resp["id"], 1)
        self.assertEqual(resp["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(resp["result"]["serverInfo"]["name"], "gcp-policy-analyzer-codemode")

        # notifications/initialized → None
        notif = self.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertIsNone(notif)

        # tools/list — must have exactly describe_capabilities and run_script
        resp2 = self.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = resp2["result"]["tools"]
        names = {t["name"] for t in tools}
        self.assertIn("describe_capabilities", names)
        self.assertIn("run_script", names)
        self.assertEqual(len(names), 2)

    def test_describe_capabilities_lists_api(self):
        resp = self.handle({
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": {"name": "describe_capabilities", "arguments": {}},
        })
        text = resp["result"]["content"][0]["text"]
        self.assertIn("analyze(", text)
        self.assertIn("redact_sensitive(", text)
        self.assertIn("fetch → load → classify/score → blast radius → sort → redact", text)

    def test_run_script_tool_executes(self):
        resp = self.handle({
            "jsonrpc": "2.0", "id": 4,
            "method": "tools/call",
            "params": {"name": "run_script", "arguments": {"code": "print(1+1)"}},
        })
        text = resp["result"]["content"][0]["text"]
        self.assertIn("2", text)

    def test_unknown_method_error(self):
        resp = self.handle({"jsonrpc": "2.0", "id": 5, "method": "no_such_method"})
        self.assertEqual(resp["error"]["code"], -32601)
        self.assertEqual(resp["id"], 5)

    def test_unknown_tool_error(self):
        resp = self.handle({
            "jsonrpc": "2.0", "id": 6,
            "method": "tools/call",
            "params": {"name": "no_such_tool", "arguments": {}},
        })
        self.assertEqual(resp["error"]["code"], -32602)
        self.assertEqual(resp["id"], 6)
        self.assertIn("Unknown tool", resp["error"]["message"])

    def test_run_script_redacts_sa_email_in_stdout(self):
        """C3: run_script must redact SA emails in stdout before returning."""
        code = 'print("terraform-deployer@example-prod-project.iam.gserviceaccount.com")'
        resp = self.handle({
            "jsonrpc": "2.0", "id": 7,
            "method": "tools/call",
            "params": {"name": "run_script", "arguments": {"code": code}},
        })
        text = resp["result"]["content"][0]["text"]
        self.assertNotIn("terraform-deployer", text)
        self.assertIn("sa-", text)

    def test_initialize_has_version(self):
        """I14: initialize result must include serverInfo.version."""
        resp = self.handle({"jsonrpc": "2.0", "id": 8, "method": "initialize", "params": {}})
        self.assertEqual(resp["result"]["serverInfo"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
