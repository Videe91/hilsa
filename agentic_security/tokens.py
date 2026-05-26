from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class CapabilityToken:
    token: str
    agent_id: str
    action: str
    resource: str
    expires_at: float
    revoked: bool = False


class TokenService:
    def __init__(self, repository=None) -> None:
        self.repository = repository
        self._tokens = {} if repository is None else None

    def mint(self, agent_id: str, action: str, resource: str, ttl_seconds: int = 300) -> CapabilityToken:
        token = secrets.token_urlsafe(24)
        record = CapabilityToken(token, agent_id, action, resource, time.time() + ttl_seconds)
        if self.repository is not None:
            self.repository.save(record)
        else:
            self._tokens[token] = record
        return record

    def _get(self, token: str) -> Optional[CapabilityToken]:
        if self.repository is not None:
            return self.repository.get(token)
        return self._tokens.get(token)

    def validate(self, token: str, agent_id: str) -> bool:
        record = self._get(token)
        if not record or record.revoked or record.agent_id != agent_id:
            return False
        return time.time() < record.expires_at

    def revoke(self, token: str) -> bool:
        if self.repository is not None:
            return self.repository.revoke(token)
        record = self._tokens.get(token)
        if not record:
            return False
        record.revoked = True
        return True

    def revoke_agent(self, agent_id: str) -> int:
        if self.repository is not None:
            return self.repository.revoke_agent(agent_id)
        count = 0
        for record in self._tokens.values():
            if record.agent_id == agent_id and not record.revoked:
                record.revoked = True
                count += 1
        return count
