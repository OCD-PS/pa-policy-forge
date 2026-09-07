import unittest

from app.migration import MigrationModel, Policy, migration_best_practices


class MigrationGuidanceTests(unittest.TestCase):
    def policy(self, name, disabled=False):
        return Policy(name, disabled=disabled, from_zones=["Trust"], to_zones=["Untrust"],
                      application=["ssl"], service=["application-default"], description="Reviewed intent")

    def test_preserving_mixed_source_states_is_not_an_all_disabled_failure(self):
        model = MigrationModel("checkpoint", "source", security_rules=[
            self.policy("Enabled rule"), self.policy("Disabled rule", True),
        ], nat_rules=[self.policy("Enabled NAT")])
        before = [rule.disabled for rule in [*model.security_rules, *model.nat_rules]]
        practices = migration_best_practices(model)
        check = next(item for item in practices["checks"] if item["code"] == "policy-state-review")
        self.assertTrue(check["informational"])
        self.assertFalse(check["remediable"])
        self.assertIn("2 enabled en 1 disabled", check["detail"])
        self.assertIn("bronstatus behouden is toegestaan", check["detail"])
        self.assertIn("controleer enabled regels vóór push", check["detail"])
        self.assertEqual(practices["failed"], 0)
        self.assertEqual(practices["remediable"], 0)
        self.assertEqual([rule.disabled for rule in [*model.security_rules, *model.nat_rules]], before)
        self.assertNotIn("imported-disabled", [item["code"] for item in practices["checks"]])

    def test_all_disabled_is_information_not_a_claim_that_candidate_is_safe(self):
        model = MigrationModel("checkpoint", "source", security_rules=[self.policy("Disabled rule", True)])
        check = next(item for item in migration_best_practices(model)["checks"] if item["code"] == "policy-state-review")
        self.assertTrue(check["informational"])
        self.assertIn("0 enabled en 1 disabled", check["detail"])


if __name__ == "__main__":
    unittest.main()
