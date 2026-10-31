from dataclasses import dataclass, field
from datetime import datetime, timezone


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


def diff_policies(old: list, new: list, resource_type: str) -> list[Change]:
    """
    Diff two snapshots of policies/rules and return Change records.

    For IAM policies, keyed by 'resource'.
    For VPC/Network firewall, keyed by 'name'.

    Args:
        old: list of old policy/rule dicts
        new: list of new policy/rule dicts
        resource_type: one of "iam_policy", "firewall_rule", "network_firewall_policy"

    Returns:
        list of Change records with action in {"CREATE", "UPDATE", "DELETE"}
    """
    # Determine key field based on resource type
    key_field = "resource" if resource_type == "iam_policy" else "name"

    # Build maps keyed by the appropriate field
    old_map = {item[key_field]: item for item in old}
    new_map = {item[key_field]: item for item in new}

    changes = []
    now = datetime.now(timezone.utc)

    # CREATE: keys only in new
    for key in new_map:
        if key not in old_map:
            changes.append(Change(
                resource=key,
                resource_type=resource_type,
                action="CREATE",
                before={},
                after=new_map[key],
                timestamp=now,
                principal="",
                labels={}
            ))

    # UPDATE: keys in both, but data differs
    for key in old_map:
        if key in new_map:
            old_item = old_map[key]
            new_item = new_map[key]
            if old_item != new_item:
                changes.append(Change(
                    resource=key,
                    resource_type=resource_type,
                    action="UPDATE",
                    before=old_item,
                    after=new_item,
                    timestamp=now,
                    principal="",
                    labels={}
                ))

    # DELETE: keys only in old
    for key in old_map:
        if key not in new_map:
            changes.append(Change(
                resource=key,
                resource_type=resource_type,
                action="DELETE",
                before=old_map[key],
                after={},
                timestamp=now,
                principal="",
                labels={}
            ))

    return changes
