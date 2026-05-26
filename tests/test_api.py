import json
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from agentic_security.api import API_TOKEN, create_server


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

    def post(self, path: str, payload: dict, token: str | None = API_TOKEN) -> tuple[int, dict]:
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(
            f"http://127.0.0.1:18080{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    def get(self, path: str, token: str | None = API_TOKEN):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(f"http://127.0.0.1:18080{path}", headers=headers, method="GET")
        try:
            with urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    def test_unauthorized_request_rejected(self):
        status, body = self.post("/authorize", {"agent_id": "a", "action": "read_repo", "resource": "r"}, token=None)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "unauthorized")

    def test_authorize_low_risk(self):
        status, body = self.post("/authorize", {"agent_id": "agent-1", "action": "read_repo", "resource": "repo/a"})
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "allow")
        self.assertIsNotNone(body["token"])
        self.assertIn("request_id", body)

    def test_invalid_payload_returns_400(self):
        status, body = self.post("/authorize", {"agent_id": "", "action": "read_repo", "resource": "repo/a"})
        self.assertEqual(status, 400)
        self.assertTrue(body["error"].startswith("invalid_payload"))

    def test_authorize_high_risk_requires_approval(self):
        status, body = self.post("/authorize", {"agent_id": "agent-1", "action": "deploy_prod", "resource": "svc/x"})
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "require_approval")
        self.assertIsNone(body["token"])

    def test_kill_switch_revokes_token(self):
        _, auth = self.post("/authorize", {"agent_id": "agent-9", "action": "read_repo", "resource": "repo/a"})
        token = auth["token"]

        _, before = self.post("/tokens/validate", {"token": token, "agent_id": "agent-9"})
        self.assertTrue(before["valid"])

        status, ks = self.post("/kill-switch/agent-9", {})
        self.assertEqual(status, 200)
        self.assertGreaterEqual(ks["revoked"], 1)

        _, after = self.post("/tokens/validate", {"token": token, "agent_id": "agent-9"})
        self.assertFalse(after["valid"])

    def test_audit_events_returns_entries(self):
        self.post("/authorize", {"agent_id": "agent-a", "action": "read_repo", "resource": "repo/z"})
        status, payload = self.get("/audit/events")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(payload["events"]), 1)


if __name__ == "__main__":
    unittest.main()
