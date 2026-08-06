import unittest

from app.policy_bulk import POLICY_LIST_FIELDS, apply_bulk_operations


class PolicyBulkTests(unittest.TestCase):
    def test_empty_operations_do_not_invent_fields_for_nat(self):
        policy = {"id": "n1", "name": "NAT-1", "from": ["Trust"], "source_translation": {"dynamic": "interface-address"}}
        operations = {field: {"add": [], "remove": []} for field in POLICY_LIST_FIELDS}
        changed = apply_bulk_operations(policy, operations)
        self.assertEqual(changed, policy)

    def test_remove_preserves_other_values_and_fields(self):
        policy = {
            "from": ["Trust", "DMZ"], "to": ["Internet"], "source": ["any"], "destination": ["any"],
            "application": ["ssl"], "service": ["application-default"], "tag": ["existing"],
            "action": "allow", "disabled": False, "log_setting": "forward", "profile_group": "best-practice",
        }
        operations = {field: {"add": [], "remove": []} for field in ("from", "to", "source", "destination", "application", "service", "tag")}
        operations["from"]["remove"] = ["Trust"]
        operations["application"]["add"] = ["web-browsing"]
        operations.update(action=None, disabled=None, log_setting=None, profile_group=None)
        changed = apply_bulk_operations(policy, operations)
        self.assertEqual(changed["from"], ["DMZ"])
        self.assertEqual(changed["application"], ["ssl", "web-browsing"])
        self.assertEqual(changed["to"], ["Internet"])
        self.assertEqual(policy["from"], ["Trust", "DMZ"])

    def test_description_is_appended_without_replacing_existing_text(self):
        policy = {
            "from": ["Trust"], "to": ["Internet"], "source": ["any"], "destination": ["any"],
            "source_user": ["any"], "destination_user": ["any"], "source_hip": ["any"],
            "destination_hip": ["any"], "application": ["ssl"], "service": ["application-default"],
            "category": ["any"], "tag": [], "description": "Bestaande tekst", "action": "allow",
            "disabled": False, "log_setting": "forward", "profile_group": "best-practice",
        }
        operations = {field: {"add": [], "remove": []} for field in policy if isinstance(policy[field], list)}
        operations.update(action=None, disabled=None, log_setting=None, profile_group=None, description_append="Nieuwe tekst")
        changed = apply_bulk_operations(policy, operations)
        self.assertEqual(changed["description"], "Bestaande tekst Nieuwe tekst")


if __name__ == "__main__": unittest.main()
