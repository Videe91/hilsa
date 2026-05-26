from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class CapabilityToken:
    token: str
    agent_id: str
    action: str
    resource: str
    expires_at: float
    revoked: bool = False


class TokenService:
    def __init__(self) -> None:
        self._tokens: Dict[str, CapabilityToken] = {}

    def mint(self, agent_id: str, action: str, resource: str, ttl_seconds: int = 300) -> CapabilityToken:
        token = secrets.token_urlsafe(24)
        record = CapabilityToken(
            token=token,
            agent_id=agent_id,
            action=action,
            resource=resource,
            expires_at=time.time() + ttl_seconds,
        )
        self._tokens[token] = record
        return record

    def validate(self, token: str, agent_id: str) -> bool:
        record = self._tokens.get(token)
        if not record or record.revoked:
            return False
        if record.agent_id != agent_id:
            return False
        return time.time() < record.expires_at

    def revoke(self, token: str) -> bool:
        record = self._tokens.get(token)
        if not record:
            return False
        record.revoked = True
        return True

    def revoke_agent(self, agent_id: str) -> int:
        count = 0
        for record in self._tokens.values():
            if record.agent_id == agent_id and not record.revoked:
                record.revoked = True
                count += 1
        return count
