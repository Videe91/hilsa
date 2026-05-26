from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    ALLOW_WITH_CONSTRAINTS = "allow_with_constraints"


@dataclass(frozen=True)
class DecisionInput:
    agent_id: str
    action: str
    resource: str
    context: Dict[str, str] = field(default_factory=dict)


@dataclass
class DecisionResult:
    decision: Decision
    reasons: List[str]
    constraints: Dict[str, str] = field(default_factory=dict)
