import unittest

from app.policy_bulk import apply_bulk_operations


class PolicyBulkTests(unittest.TestCase):
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


if __name__ == "__main__": unittest.main()
