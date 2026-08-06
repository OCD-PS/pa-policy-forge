import json


POLICY_LIST_FIELDS = ("from", "to", "source", "destination", "application", "service", "tag")


def apply_bulk_operations(policy: dict, operations: dict) -> dict:
    changed = json.loads(json.dumps(policy))
    for field in POLICY_LIST_FIELDS:
        current = list(changed[field])
        remove = operations.get(field, {}).get("remove", [])
        add = operations.get(field, {}).get("add", [])
        current = [value for value in current if value not in remove]
        for value in add:
            if value not in current:
                current.append(value)
        changed[field] = current or (["any"] if field != "tag" else [])
    for field in ("action", "disabled", "log_setting", "profile_group"):
        if operations.get(field) is not None:
            changed[field] = operations[field]
    return changed
