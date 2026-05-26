from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class AuditEvent:
    ts: float
    agent_id: str
    action: str
    resource: str
    decision: str
    reasons: List[str]
    metadata: Dict[str, str]


class AuditLog:
    def __init__(self, repository=None) -> None:
        self.repository = repository
        self._events = [] if repository is None else None

    def record(self, *, agent_id: str, action: str, resource: str, decision: str, reasons: List[str], metadata: Dict[str, str]) -> AuditEvent:
        event = AuditEvent(time.time(), agent_id, action, resource, decision, list(reasons), dict(metadata))
        if self.repository is not None:
            self.repository.save(event)
        else:
            self._events.append(event)
        return event

    def list_events(self) -> List[AuditEvent]:
        if self.repository is not None:
            return self.repository.list_events()
        return list(self._events)
