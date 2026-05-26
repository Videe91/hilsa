import unittest

from agentic_security.audit import AuditLog


class TestAuditLog(unittest.TestCase):
    def setUp(self) -> None:
        self.log = AuditLog()

    def test_record_adds_event_and_list_returns_copy(self):
        self.log.record(
            agent_id="agent-1",
            action="read_repo",
            resource="repo/a",
            decision="allow",
            reasons=["default_allow"],
            metadata={"env": "dev"},
        )

        events = self.log.list_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].agent_id, "agent-1")

        # ensure list copy semantics
        events.clear()
        self.assertEqual(len(self.log.list_events()), 1)


if __name__ == "__main__":
    unittest.main()
