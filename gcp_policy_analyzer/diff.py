from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Change:
    change_id: str
    resource_name: str
    resource_type: str          # "firewall_rule" | "iam_policy" | "network_firewall_policy"
    operation: str              # "CREATE" | "UPDATE" | "DELETE"
    principal: str
    timestamp: datetime         # always UTC-aware
    caller_ip: str = ""
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)
    labels: dict = field(default_factory=dict)
