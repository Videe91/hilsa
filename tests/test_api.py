import json
import threading
import time
import unittest
from urllib.request import Request, urlopen

from agentic_security.api import create_server


class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server("127.0.0.1", 18080)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.02)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def post(self, path: str, payload: dict) -> dict:
        req = Request(
            f"http://127.0.0.1:18080{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def get(self, path: str):
        with urlopen(f"http://127.0.0.1:18080{path}") as resp:
            return json.loads(resp.read().decode("utf-8"))

    def test_authorize_low_risk(self):
        body = self.post("/authorize", {"agent_id": "agent-1", "action": "read_repo", "resource": "repo/a"})
        self.assertEqual(body["decision"], "allow")
        self.assertIsNotNone(body["token"])

    def test_authorize_high_risk_requires_approval(self):
        body = self.post("/authorize", {"agent_id": "agent-1", "action": "deploy_prod", "resource": "svc/x"})
        self.assertEqual(body["decision"], "require_approval")
        self.assertIsNone(body["token"])

    def test_kill_switch_revokes_token(self):
        auth = self.post("/authorize", {"agent_id": "agent-9", "action": "read_repo", "resource": "repo/a"})
        token = auth["token"]

        before = self.post("/tokens/validate", {"token": token, "agent_id": "agent-9"})
        self.assertTrue(before["valid"])

        ks = self.post("/kill-switch/agent-9", {})
        self.assertGreaterEqual(ks["revoked"], 1)

        after = self.post("/tokens/validate", {"token": token, "agent_id": "agent-9"})
        self.assertFalse(after["valid"])

    def test_audit_events_returns_entries(self):
        self.post("/authorize", {"agent_id": "agent-a", "action": "read_repo", "resource": "repo/z"})
        events = self.get("/audit/events")
        self.assertGreaterEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
