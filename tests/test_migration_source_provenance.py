import copy
import json
import unittest

from app import migration as m


def original_interface(name="eth0", address="10.0.0.1/24", source="CP-Gateway"):
    return {"name": name, "interface_type": "ethernet", "source_ref": source, "source_vendor": "checkpoint",
            "source_networks": ["10.0.0.0/24"], "source_addresses": [address], "topology_role": "internal",
            "suggested_zone": "", "mapping_action": "review", "gateway_uid": "fixture-gateway-uid",
            "xml": f'<entry name="{name}"><layer3><ip><entry name="{address}" /></ip></layer3></entry>'}


def edited_model(interfaces):
    nodes = "".join(item["xml"] for item in interfaces)
    xml = f'<config><devices><entry name="localhost.localdomain"><network><interface><ethernet>{nodes}</ethernet></interface></network><vsys><entry name="vsys1" /></vsys></entry></devices></config>'
    return m.parse_vendor("panos", xml.encode(), "source.tar")


class MigrationSourceProvenanceTests(unittest.TestCase):
    def test_editor_sync_keeps_cp_guard_and_saved_interface_zone_selector(self):
        original = m.MigrationModel("checkpoint", "source.tar", interfaces=[original_interface()])
        edited = edited_model(original.interfaces)
        edited.security_rules.append(m.Policy("edited-rule", source=["10.0.0.8"], disabled=False))
        before_original, before_edited = original.as_dict(), edited.as_dict()
        result = m.restore_migration_source_topology(original, edited)
        item = result.interfaces[0]
        self.assertEqual(item["source_vendor"], "checkpoint")
        self.assertEqual(item["source_ref"], "CP-Gateway")
        self.assertEqual(item["source_networks"], ["10.0.0.0/24"])
        self.assertEqual(item["gateway_uid"], "fixture-gateway-uid")
        self.assertEqual(item["xml"], edited.interfaces[0]["xml"])
        selector = m.item_selector(original.interfaces[0])
        rules = [{"kind": "interfaces", "selector": selector, "operation": "topology_map", "value": "ethernet1/1"},
                 {"kind": "interfaces", "selector": selector, "operation": "set_interface_zone", "value": json.dumps({"zone": "Trust", "create": True})}]
        assigned = m.apply_transform_rules(result, rules)
        self.assertEqual(assigned.security_rules[0].from_zones, ["Trust"])
        self.assertFalse(assigned.security_rules[0].disabled)
        self.assertEqual(original.as_dict(), before_original)
        self.assertEqual(edited.as_dict(), before_edited)

    def test_changed_interface_ip_updates_network_instead_of_inheriting_stale_subnet(self):
        original = m.MigrationModel("checkpoint", "source.tar", interfaces=[original_interface()])
        edited = edited_model([original_interface(address="192.0.2.12/28")])
        result = m.restore_migration_source_topology(original, edited)
        self.assertEqual(result.interfaces[0]["source_networks"], ["192.0.2.0/28"])
        self.assertEqual(result.interfaces[0]["source_addresses"], ["192.0.2.12/28"])
        self.assertEqual(result.interfaces[0]["source_ref"], "CP-Gateway")

    def test_removed_ip_and_active_dhcp_clear_old_static_evidence(self):
        original = m.MigrationModel("checkpoint", "source.tar", interfaces=[original_interface()])
        for xml in ('<entry name="eth0"><layer3 /></entry>',
                    '<entry name="eth0"><layer3><dhcp-client><enable>yes</enable></dhcp-client><ip><entry name="10.0.0.1/24" /></ip></layer3></entry>'):
            with self.subTest(xml=xml):
                edited = edited_model([{"xml": xml}])
                result = m.restore_migration_source_topology(original, edited)
                self.assertEqual(result.interfaces[0]["source_addresses"], [])
                self.assertEqual(result.interfaces[0]["source_networks"], [])

    def test_subinterface_network_is_not_assigned_to_parent(self):
        original = m.MigrationModel("checkpoint", "source.tar", interfaces=[original_interface()])
        xml = '<entry name="eth0"><layer3><ip><entry name="10.0.0.1/24" /></ip><units><entry name="eth0.20"><ip><entry name="192.0.2.1/24" /></ip></entry></units></layer3></entry>'
        result = m.restore_migration_source_topology(original, edited_model([{"xml": xml}]))
        self.assertEqual(result.interfaces[0]["source_networks"], ["10.0.0.0/24"])

    def test_renamed_or_new_cp_interface_remains_review_without_old_selector(self):
        original = m.MigrationModel("checkpoint", "source.tar", interfaces=[original_interface()])
        edited = edited_model([original_interface(name="eth-new", address="192.0.2.1/24")])
        result = m.restore_migration_source_topology(original, edited)
        item = result.interfaces[0]
        self.assertEqual(item["source_vendor"], "checkpoint")
        self.assertEqual(item["mapping_action"], "review")
        self.assertEqual(item["source_ref"], "Device network")
        self.assertNotIn("gateway_uid", item)
        self.assertEqual(item["source_networks"], ["192.0.2.0/24"])

    def test_ambiguous_original_interface_name_never_inherits_a_gateway(self):
        original = m.MigrationModel("checkpoint", "source.tar", interfaces=[original_interface(source="A"), original_interface(source="B")])
        result = m.restore_migration_source_topology(original, edited_model([original_interface()]))
        self.assertEqual(result.interfaces[0]["source_ref"], "Device network")
        self.assertNotIn("gateway_uid", result.interfaces[0])

    def test_ambiguous_new_name_never_duplicates_original_identity(self):
        original = m.MigrationModel("checkpoint", "source.tar", interfaces=[original_interface()])
        edited = edited_model([original_interface()])
        edited.interfaces.append({**edited.interfaces[0], "source_ref": "Template another"})
        result = m.restore_migration_source_topology(original, edited)
        self.assertEqual([item["source_ref"] for item in result.interfaces], ["Device network", "Template another"])
        self.assertTrue(all(item["source_vendor"] == "checkpoint" for item in result.interfaces))

    def test_existing_panos_context_matches_exact_provenance(self):
        original = edited_model([original_interface()])
        original.interfaces[0]["source_ref"] = "Template original"
        edited = copy.deepcopy(original)
        edited.interfaces[0]["xml"] = '<entry name="eth0"><layer3 /></entry>'
        result = m.restore_migration_source_topology(original, edited)
        self.assertEqual(result.as_dict(), edited.as_dict())
        self.assertNotIn("source_vendor", result.interfaces[0])

    def test_new_edited_object_and_rule_values_are_not_replaced_by_source(self):
        original = m.MigrationModel("checkpoint", "source.tar", interfaces=[original_interface()],
                                    addresses=[m.Address("host", "10.0.0.8")], security_rules=[m.Policy("rule")])
        edited = edited_model(original.interfaces)
        edited.addresses.append(m.Address("host", "192.0.2.8"))
        edited.security_rules.append(m.Policy("rule", action="deny", disabled=False))
        result = m.restore_migration_source_topology(original, edited)
        self.assertEqual(result.addresses[0].value, "192.0.2.8")
        self.assertEqual(result.security_rules[0].action, "deny")
        self.assertFalse(result.security_rules[0].disabled)


if __name__ == "__main__":
    unittest.main()
