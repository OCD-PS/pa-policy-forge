import json
import unittest
import xml.etree.ElementTree as ET

from app import migration as m


def target_xml(extra_routes="", extra_interfaces=""):
    return f'''<config><devices><entry name="localhost.localdomain"><network>
      <interface><ethernet>
        <entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/16"/></ip></layer3></entry>
        <entry name="ethernet1/2"><layer3><ip><entry name="172.16.0.1/24"/></ip></layer3></entry>
        <entry name="ethernet1/3"><layer3><ip><entry name="198.51.100.1/24"/></ip></layer3></entry>
        {extra_interfaces}
      </ethernet><tunnel><units><entry name="tunnel.10"><ip><entry name="192.0.2.1/30"/></ip></entry></units></tunnel></interface>
      <virtual-router><entry name="default"><interface><member>ethernet1/1</member><member>ethernet1/2</member><member>ethernet1/3</member></interface>
        <routing-table><ip><static-route><entry name="default"><destination>0.0.0.0/0</destination><interface>ethernet1/3</interface></entry>{extra_routes}</static-route></ip></routing-table>
      </entry></virtual-router></network><vsys><entry name="vsys1"><zone>
        <entry name="Trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
        <entry name="DMZ"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
        <entry name="Untrust"><network><layer3><member>ethernet1/3</member></layer3></network></entry>
      </zone></entry></vsys></entry></devices></config>'''.encode()


def source_interface(name, network):
    return {"name": name, "source_ref": "gateway", "source_vendor": "checkpoint",
            "source_networks": [network], "mapping_action": "review",
            "xml": f'<entry name="{name}"><layer3/></entry>'}


def assignment(name, target, zone):
    selector = f"{name}|||gateway"
    return [
        {"kind": "interfaces", "selector": selector, "operation": "topology_map", "value": target},
        {"kind": "interfaces", "selector": selector, "operation": "set_interface_zone", "value": json.dumps({"zone": zone, "create": True})},
    ]


class TopologyAuditTests(unittest.TestCase):
    def test_zone_requires_explicit_target_interface_mapping(self):
        model = m.MigrationModel("checkpoint", "source", interfaces=[source_interface("eth0", "10.0.0.0/24")],
                                 security_rules=[m.Policy("rule", source=["10.0.0.8"])])
        mapped = m.apply_transform_rules(model, assignment("eth0", "ethernet1/1", "Trust")[1:])
        self.assertEqual(mapped.zones, [])
        self.assertEqual(mapped.security_rules[0].from_zones, ["any"])

    def test_unassigned_specific_interface_blocks_assigned_aggregate(self):
        model = m.MigrationModel("checkpoint", "source", interfaces=[
            source_interface("eth0", "10.0.0.0/8"), source_interface("eth1", "10.1.0.0/24")],
            security_rules=[m.Policy("specific", source=["10.1.0.8"]), m.Policy("aggregate", source=["10.0.0.0/8"])])
        mapped = m.apply_transform_rules(model, assignment("eth0", "ethernet1/1", "Trust"))
        self.assertTrue(all(rule.from_zones == ["any"] for rule in mapped.security_rules))

    def test_negated_address_cannot_infer_its_contained_zone(self):
        model = m.MigrationModel("checkpoint", "source", interfaces=[source_interface("eth0", "10.0.0.0/24")],
                                 security_rules=[m.Policy("rule", source=["10.0.0.8"], original={"source-negate": True})])
        mapped = m.apply_transform_rules(model, assignment("eth0", "ethernet1/1", "Trust"))
        self.assertEqual(mapped.security_rules[0].from_zones, ["any"])

    def test_security_destination_is_not_inferred_from_pre_nat_address(self):
        model = m.MigrationModel("checkpoint", "source", interfaces=[source_interface("eth0", "198.51.100.0/24")],
            security_rules=[m.Policy("inbound", destination=["198.51.100.10"])],
            nat_rules=[m.Policy("dnat", policy_type="nat", destination=["198.51.100.10"],
                                destination_translation={"translated_address": "10.0.0.10"}, disabled=False)])
        mapped = m.apply_transform_rules(model, assignment("eth0", "ethernet1/1", "Untrust"))
        self.assertEqual(mapped.security_rules[0].to_zones, ["any"])
        self.assertEqual(mapped.nat_rules[0].to_zones, ["Untrust"])

    def test_nat_resolves_every_member_instead_of_global_longest_prefix(self):
        rule = m.Policy("two-zones", policy_type="nat", destination=["10.0.0.10", "172.16.0.10"])
        model = m.MigrationModel("checkpoint", "source", nat_rules=[rule])
        report = m.auto_map_nat_topology(target_xml(), model)
        self.assertEqual(report["review"], 1)
        self.assertEqual(rule.to_zones, ["any"])

    def test_unknown_group_member_prevents_partial_nat_inference(self):
        rule = m.Policy("mixed", policy_type="nat", destination=["mixed"])
        model = m.MigrationModel("checkpoint", "source", nat_rules=[rule],
                                 address_groups=[m.AddressGroup("mixed", ["10.0.0.10", "unknown.example.net"])])
        self.assertEqual(m.auto_map_nat_topology(target_xml(), model)["review"], 1)

    def test_conflicting_address_names_prevent_nat_inference(self):
        model = m.MigrationModel("checkpoint", "source", nat_rules=[m.Policy("conflict", policy_type="nat", destination=["host"])],
                                 addresses=[m.Address("host", "10.0.0.10"), m.Address("host", "172.16.0.10")])
        self.assertEqual(m.auto_map_nat_topology(target_xml(), model)["review"], 1)

    def test_unassigned_interface_is_not_hidden_by_default_route(self):
        extra = '<entry name="ethernet1/4"><layer3><ip><entry name="203.0.113.1/24"/></ip></layer3></entry>'
        model = m.MigrationModel("checkpoint", "source", nat_rules=[m.Policy("unassigned", policy_type="nat", destination=["203.0.113.8"])])
        self.assertEqual(m.auto_map_nat_topology(target_xml(extra_interfaces=extra), model)["review"], 1)

    def test_specific_static_route_precedes_default(self):
        routes = '<entry name="dmz-remote"><destination>203.0.113.0/24</destination><interface>ethernet1/2</interface></entry>'
        rule = m.Policy("remote", policy_type="nat", destination=["203.0.113.8"])
        model = m.MigrationModel("checkpoint", "source", nat_rules=[rule])
        m.auto_map_nat_topology(target_xml(extra_routes=routes), model)
        self.assertEqual(rule.to_zones, ["DMZ"])

    def test_unresolved_nexthop_route_blocks_default_fallback(self):
        routes = '<entry name="remote"><destination>203.0.113.0/24</destination><nexthop><ip-address>10.0.0.2</ip-address></nexthop></entry>'
        model = m.MigrationModel("checkpoint", "source", nat_rules=[m.Policy("remote", policy_type="nat", destination=["203.0.113.8"])])
        self.assertEqual(m.auto_map_nat_topology(target_xml(extra_routes=routes), model)["review"], 1)

    def test_any_destination_does_not_prove_default_egress(self):
        model = m.MigrationModel("checkpoint", "source", nat_rules=[m.Policy("any", policy_type="nat")])
        self.assertEqual(m.auto_map_nat_topology(target_xml(), model)["review"], 1)

    def test_ipv6_does_not_use_ipv4_default_route(self):
        model = m.MigrationModel("checkpoint", "source", nat_rules=[m.Policy("v6", policy_type="nat", destination=["2001:db8::8"])])
        self.assertEqual(m.auto_map_nat_topology(target_xml(), model)["review"], 1)

    def test_nat_inference_preserves_explicit_interface_and_ignore(self):
        model = m.MigrationModel("checkpoint", "source", nat_rules=[
            m.Policy("manual-if", policy_type="nat", destination=["203.0.113.8"], to_interface="ethernet1/9"),
            m.Policy("ignored", policy_type="nat", destination=["203.0.113.8"], mapping_action="ignore")])
        m.auto_map_nat_topology(target_xml(), model)
        self.assertEqual(model.nat_rules[0].to_interface, "ethernet1/9")
        self.assertEqual(model.nat_rules[0].to_zones, ["any"])
        self.assertEqual(model.nat_rules[1].mapping_action, "ignore")

    def test_known_public_address_can_use_unambiguous_default(self):
        rule = m.Policy("outbound", policy_type="nat", source=["10.0.0.8"], destination=["203.0.113.8"])
        model = m.MigrationModel("checkpoint", "source", nat_rules=[rule])
        self.assertEqual(m.auto_map_nat_topology(target_xml(), model)["mapped"], 1)
        self.assertEqual((rule.from_zones, rule.to_zones, rule.to_interface), (["Trust"], ["Untrust"], "ethernet1/3"))

    @staticmethod
    def panorama(reference="used", extra_reference=""):
        device = ET.fromstring(target_xml()).find("./devices/entry")
        first = ET.tostring(device, encoding="unicode")
        second = first.replace("Trust", "WrongTemplate").replace("Untrust", "WrongInternet")
        return f'''<config><devices><entry name="localhost.localdomain"><device-group>
          <entry name="parent"><reference-template>{reference}</reference-template></entry>
          <entry name="selected"><parent-dg>parent</parent-dg></entry></device-group>
          <template><entry name="used"><config><devices>{first}</devices></config></entry>
          <entry name="unrelated"><config><devices>{second}</devices></config></entry></template>{extra_reference}
        </entry></devices></config>'''.encode()

    def test_panorama_only_uses_inherited_reference_template(self):
        rule = m.Policy("scope", policy_type="nat", source=["10.0.0.8"], destination=["203.0.113.8"])
        model = m.MigrationModel("checkpoint", "source", nat_rules=[rule])
        m.auto_map_nat_topology(self.panorama(), model, "selected", True)
        self.assertEqual((rule.from_zones, rule.to_zones), (["Trust"], ["Untrust"]))

    def test_panorama_without_reference_does_not_guess_another_template(self):
        model = m.MigrationModel("checkpoint", "source", nat_rules=[m.Policy("scope", policy_type="nat", destination=["10.0.0.8"])])
        self.assertEqual(m.auto_map_nat_topology(self.panorama(""), model, "selected", True)["review"], 1)

    def test_unresolved_stack_does_not_blend_template_overrides(self):
        stack = '<template-stack><entry name="stack"><templates><member>used</member><member>unrelated</member></templates></entry></template-stack>'
        model = m.MigrationModel("checkpoint", "source", nat_rules=[m.Policy("scope", policy_type="nat", destination=["10.0.0.8"])])
        self.assertEqual(m.auto_map_nat_topology(self.panorama("stack", stack), model, "selected", True)["review"], 1)

    def test_scoped_target_inventory_includes_units_not_ip_names(self):
        extra = '<entry name="ethernet1/4"><layer3><units><entry name="ethernet1/4.10"><ip><entry name="10.10.0.1/24"/></ip></entry></units></layer3></entry>'
        names = m.migration_topology_targets(target_xml(extra_interfaces=extra))
        self.assertIn("tunnel.10", names["interfaces"])
        self.assertIn("ethernet1/4.10", names["interfaces"])
        self.assertNotIn("10.10.0.1/24", names["interfaces"])
        self.assertEqual(set(names), m.MIGRATION_TOPOLOGY_KINDS)


if __name__ == "__main__":
    unittest.main()
