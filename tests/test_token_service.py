import time
import unittest

from agentic_security.tokens import TokenService


class TestTokenService(unittest.TestCase):
    def setUp(self) -> None:
        self.tokens = TokenService()

    def test_mint_and_validate_success(self):
        token = self.tokens.mint("agent-1", "read_repo", "repo/a", ttl_seconds=10)
        self.assertTrue(self.tokens.validate(token.token, "agent-1"))

    def test_validate_fails_for_wrong_agent(self):
        token = self.tokens.mint("agent-1", "read_repo", "repo/a", ttl_seconds=10)
        self.assertFalse(self.tokens.validate(token.token, "agent-2"))

    def test_validate_fails_for_unknown_token(self):
        self.assertFalse(self.tokens.validate("missing", "agent-1"))

    def test_revoke_existing_token(self):
        token = self.tokens.mint("agent-1", "read_repo", "repo/a", ttl_seconds=10)
        self.assertTrue(self.tokens.revoke(token.token))
        self.assertFalse(self.tokens.validate(token.token, "agent-1"))

    def test_revoke_unknown_token_returns_false(self):
        self.assertFalse(self.tokens.revoke("missing"))

    def test_revoke_agent_revokes_only_target_agent_tokens(self):
        token_a1 = self.tokens.mint("agent-1", "read_repo", "repo/a", ttl_seconds=10)
        token_a2 = self.tokens.mint("agent-1", "read_repo", "repo/b", ttl_seconds=10)
        token_b1 = self.tokens.mint("agent-2", "read_repo", "repo/c", ttl_seconds=10)

        revoked_count = self.tokens.revoke_agent("agent-1")

        self.assertEqual(revoked_count, 2)
        self.assertFalse(self.tokens.validate(token_a1.token, "agent-1"))
        self.assertFalse(self.tokens.validate(token_a2.token, "agent-1"))
        self.assertTrue(self.tokens.validate(token_b1.token, "agent-2"))

    def test_expired_token_fails_validation(self):
        token = self.tokens.mint("agent-1", "read_repo", "repo/a", ttl_seconds=0)
        time.sleep(0.01)
        self.assertFalse(self.tokens.validate(token.token, "agent-1"))


if __name__ == "__main__":
    unittest.main()
