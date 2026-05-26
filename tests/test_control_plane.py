import unittest

from agentic_security.control_plane import ControlPlane
from agentic_security.models import DecisionInput


class TestControlPlane(unittest.TestCase):
    def setUp(self) -> None:
        self.cp = ControlPlane()

    def test_low_risk_action_allowed_and_token_minted(self):
        result = self.cp.authorize(DecisionInput("agent-1", "read_repo", "repo/x", {}))
        self.assertEqual(result["decision"], "allow")
        self.assertIsNotNone(result["token"])

    def test_high_risk_requires_approval(self):
        result = self.cp.authorize(DecisionInput("agent-1", "deploy_prod", "service/a", {}))
        self.assertEqual(result["decision"], "require_approval")
        self.assertIsNone(result["token"])

    def test_high_risk_with_approval_gets_constrained_allow(self):
        result = self.cp.authorize(
            DecisionInput("agent-1", "deploy_prod", "service/a", {"approved": "true"})
        )
        self.assertEqual(result["decision"], "allow_with_constraints")
        self.assertIsNotNone(result["token"])

    def test_kill_switch_revokes_tokens(self):
        allowed = self.cp.authorize(DecisionInput("agent-1", "read_repo", "repo/x", {}))
        token = allowed["token"]
        self.assertTrue(self.cp.tokens.validate(token, "agent-1"))
        revoked = self.cp.kill_switch("agent-1")
        self.assertGreaterEqual(revoked, 1)
        self.assertFalse(self.cp.tokens.validate(token, "agent-1"))


if __name__ == "__main__":
    unittest.main()
