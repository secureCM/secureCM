from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Change:
    resource: str
    resource_type: str            # "firewall_rule" | "iam_policy" | "network_firewall_policy"
    action: str                   # "CREATE" | "UPDATE" | "DELETE"
    before: dict | None
    after: dict | None
    timestamp: datetime           # always UTC-aware
    principal: str
    risk_delta: int = 0
    labels: dict = field(default_factory=dict)
