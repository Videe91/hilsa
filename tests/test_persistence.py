import os
import tempfile
import unittest

from agentic_security.control_plane import ControlPlane
from agentic_security.models import DecisionInput


class TestPersistence(unittest.TestCase):
    def test_tokens_and_audit_persist_across_instances(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "mvp.db")
            cp1 = ControlPlane(db_path=db)
            out = cp1.authorize(DecisionInput("agent-p", "read_repo", "repo/x", {}))
            token = out["token"]
            self.assertIsNotNone(token)

            cp2 = ControlPlane(db_path=db)
            self.assertTrue(cp2.tokens.validate(token, "agent-p"))
            events = cp2.audit.list_events()
            self.assertGreaterEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
