from __future__ import annotations

from .audit import AuditLog
from .models import Decision, DecisionInput, DecisionResult
from .policy import PolicyEngine
from .tokens import TokenService


class ControlPlane:
    def __init__(self) -> None:
        self.policy = PolicyEngine()
        self.tokens = TokenService()
        self.audit = AuditLog()

    def authorize(self, request: DecisionInput) -> dict:
        result: DecisionResult = self.policy.evaluate(request)

        token = None
        if result.decision in {Decision.ALLOW, Decision.ALLOW_WITH_CONSTRAINTS}:
            ttl = int(result.constraints.get("ttl_seconds", "300"))
            token = self.tokens.mint(request.agent_id, request.action, request.resource, ttl_seconds=ttl)

        self.audit.record(
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            decision=result.decision.value,
            reasons=result.reasons,
            metadata=request.context,
        )

        return {
            "decision": result.decision.value,
            "reasons": result.reasons,
            "constraints": result.constraints,
            "token": token.token if token else None,
            "expires_at": token.expires_at if token else None,
        }

    def kill_switch(self, agent_id: str) -> int:
        revoked = self.tokens.revoke_agent(agent_id)
        self.audit.record(
            agent_id=agent_id,
            action="kill_switch",
            resource="*",
            decision="revoked",
            reasons=["operator_triggered_kill_switch"],
            metadata={},
        )
        return revoked
