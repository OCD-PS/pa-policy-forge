import json


POLICY_LIST_FIELDS = (
    "from", "to", "source", "destination", "source_user", "destination_user",
    "source_hip", "destination_hip", "application", "service", "category", "tag",
)


def apply_bulk_operations(policy: dict, operations: dict) -> dict:
    changed = json.loads(json.dumps(policy))
    for field in POLICY_LIST_FIELDS:
        current = list(changed.get(field, []))
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
    description_append = (operations.get("description_append") or "").strip()
    if description_append:
        changed["description"] = " ".join(part for part in ((changed.get("description") or "").strip(), description_append) if part)
    return changed
