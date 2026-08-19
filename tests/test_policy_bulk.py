import unittest

from app.policy_bulk import POLICY_LIST_FIELDS, apply_bulk_operations, apply_single_replacements


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

    def test_single_edit_preserves_unedited_nat_configuration(self):
        policy = {
            "id": "nat-1", "name": "NAT-1", "from": ["Trust"], "to": ["Internet"],
            "source": ["any"], "destination": ["public-ip"], "service": ["any"],
            "source_translation": {"dynamic_ip_and_port": {"interface_address": {}}},
            "destination_translation": {"translated_address": "server-1", "translated_port": "443"},
        }
        changed = apply_single_replacements(policy, {"from": ["Clients"], "disabled": True})
        self.assertEqual(changed["from"], ["Clients"])
        self.assertTrue(changed["disabled"])
        self.assertEqual(changed["source_translation"], policy["source_translation"])
        self.assertEqual(changed["destination_translation"], policy["destination_translation"])

    def test_nat_bulk_replaces_only_explicit_translation_fields(self):
        policy = {
            "id": "nat-1", "name": "NAT-1", "from": ["Trust"], "to": ["Internet"],
            "source": ["any"], "destination": ["public-ip"], "service": ["any"],
            "nat_type": "ipv4", "to_interface": "ethernet1/1",
            "source_translation": {"dynamic_ip_and_port": {"interface_address": {}}},
            "destination_translation": {"translated_address": "server-1", "translated_port": 443},
        }
        changed = apply_bulk_operations(policy, {
            "source_translation": {"dynamic_ip": {"translated_address": ["pool-1"]}},
            "destination_translation": {"translated_address": "server-2", "translated_port": 8443},
        })
        self.assertEqual(changed["source_translation"], {"dynamic_ip": {"translated_address": ["pool-1"]}})
        self.assertEqual(changed["destination_translation"]["translated_address"], "server-2")
        self.assertEqual(changed["from"], ["Trust"])
        self.assertEqual(changed["to_interface"], "ethernet1/1")


if __name__ == "__main__": unittest.main()
