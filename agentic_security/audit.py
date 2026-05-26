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
    def __init__(self) -> None:
        self._events: List[AuditEvent] = []

    def record(
        self,
        *,
        agent_id: str,
        action: str,
        resource: str,
        decision: str,
        reasons: List[str],
        metadata: Dict[str, str],
    ) -> AuditEvent:
        event = AuditEvent(
            ts=time.time(),
            agent_id=agent_id,
            action=action,
            resource=resource,
            decision=decision,
            reasons=list(reasons),
            metadata=dict(metadata),
        )
        self._events.append(event)
        return event

    def list_events(self) -> List[AuditEvent]:
        return list(self._events)
