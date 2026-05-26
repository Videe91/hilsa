import unittest

from agentic_security.models import DecisionInput
from agentic_security.policy import PolicyEngine


class TestPolicyEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine()

    def test_suspended_session_is_denied(self):
        result = self.engine.evaluate(
            DecisionInput("agent-1", "read_repo", "repo/a", {"suspended": "true"})
        )
        self.assertEqual(result.decision.value, "deny")
        self.assertIn("agent_session_suspended", result.reasons)

    def test_high_risk_action_requires_approval_without_flag(self):
        result = self.engine.evaluate(DecisionInput("agent-1", "read_secret", "secret/x", {}))
        self.assertEqual(result.decision.value, "require_approval")
        self.assertIn("high_risk_action_requires_approval", result.reasons)

    def test_high_risk_action_allowed_with_constraints_when_approved(self):
        result = self.engine.evaluate(
            DecisionInput("agent-1", "read_secret", "secret/x", {"approved": "true"})
        )
        self.assertEqual(result.decision.value, "allow_with_constraints")
        self.assertEqual(result.constraints.get("ttl_seconds"), "120")
        self.assertIn("high_risk_action_approved", result.reasons)

    def test_high_sensitivity_context_adds_read_only_constraint(self):
        result = self.engine.evaluate(
            DecisionInput("agent-1", "read_repo", "repo/a", {"sensitivity": "high"})
        )
        self.assertEqual(result.decision.value, "allow_with_constraints")
        self.assertEqual(result.constraints.get("mode"), "read_only")

    def test_default_allow_for_low_risk_action(self):
        result = self.engine.evaluate(DecisionInput("agent-1", "read_repo", "repo/a", {}))
        self.assertEqual(result.decision.value, "allow")
        self.assertEqual(result.reasons, ["default_allow"])


if __name__ == "__main__":
    unittest.main()
