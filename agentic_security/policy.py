from __future__ import annotations

from .models import Decision, DecisionInput, DecisionResult


class PolicyEngine:
    """Simple rules-based policy engine for MVP."""

    HIGH_RISK_ACTIONS = {"deploy_prod", "read_secret", "delete_repo"}

    def evaluate(self, request: DecisionInput) -> DecisionResult:
        reasons = []
        constraints = {}

        if request.context.get("suspended") == "true":
            return DecisionResult(Decision.DENY, ["agent_session_suspended"])

        if request.action in self.HIGH_RISK_ACTIONS:
            if request.context.get("approved") == "true":
                reasons.append("high_risk_action_approved")
                constraints["ttl_seconds"] = "120"
                return DecisionResult(Decision.ALLOW_WITH_CONSTRAINTS, reasons, constraints)
            return DecisionResult(Decision.REQUIRE_APPROVAL, ["high_risk_action_requires_approval"])

        if request.context.get("sensitivity") == "high":
            reasons.append("high_sensitivity_read_only")
            constraints["mode"] = "read_only"
            return DecisionResult(Decision.ALLOW_WITH_CONSTRAINTS, reasons, constraints)

        return DecisionResult(Decision.ALLOW, ["default_allow"])
