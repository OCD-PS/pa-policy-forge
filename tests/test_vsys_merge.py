import unittest
import xml.etree.ElementTree as ET

from app.offline_config import parse_snapshot
from app.vsys_merge import (
    VsysMergeError,
    analyze_panos_vsys_merge,
    merge_panos_vsys_config,
)


MULTI_VSYS = b'''<config version="12.1.0">
  <mgt-config><users><entry name="admin"><phash>keep-this-hash</phash></entry></users></mgt-config>
  <shared><tag><entry name="Existing"><color>color1</color></entry></tag></shared>
  <devices><entry name="localhost.localdomain">
    <network>
      <interface><ethernet>
        <entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/30"/></ip></layer3></entry>
        <entry name="ethernet1/2"><layer3><ip><entry name="10.0.0.2/30"/></ip></layer3></entry>
        <entry name="ethernet1/3"><layer3><ip><entry name="198.51.100.1/24"/></ip></layer3></entry>
      </ethernet></interface>
      <virtual-router><entry name="default"><interface><member>ethernet1/1</member><member>ethernet1/2</member><member>ethernet1/3</member></interface></entry></virtual-router>
    </network>
    <vsys>
      <entry name="vsys1"><vsys-id>1</vsys-id>
        <import><network><interface><member>ethernet1/1</member></interface><virtual-router><member>default</member></virtual-router></network></import>
        <zone>
          <entry name="Servers"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
          <entry name="Transit"><network><external><member>vsys2</member></external></network></entry>
        </zone>
        <address><entry name="web"><ip-netmask>10.1.0.10/32</ip-netmask></entry></address>
        <address-group><entry name="web-group"><static><member>web</member></static></entry></address-group>
        <rulebase><security><rules><entry name="servers-to-transit"><from><member>Servers</member></from><to><member>Transit</member></to><source><member>web</member></source><destination><member>any</member></destination><action>allow</action></entry></rules><default-rule><action>deny</action></default-rule></security></rulebase>
      </entry>
      <entry name="vsys2"><vsys-id>2</vsys-id>
        <import><network><interface><member>ethernet1/2</member></interface><virtual-router><member>default</member></virtual-router></network></import>
        <zone>
          <entry name="Transit"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
          <entry name="Internet"><network><layer3><member>ethernet1/3</member></layer3></network></entry>
        </zone>
        <address><entry name="web"><ip-netmask>10.1.0.10/32</ip-netmask></entry></address>
        <address-group><entry name="web-group"><static><member>web</member></static></entry></address-group>
        <service><entry name="tcp-443"><protocol><tcp><port>443</port></tcp></protocol></entry></service>
        <rulebase><security><rules><entry name="transit-to-internet"><from><member>Transit</member></from><to><member>Internet</member></to><source><member>any</member></source><destination><member>web-group</member></destination><action>allow</action></entry></rules><default-rule><action>drop</action></default-rule></security></rulebase>
      </entry>
      <entry name="vsys3"><vsys-id>3</vsys-id>
        <zone><entry name="Admin"><network><layer3><member>loopback.1</member></layer3></network></entry></zone>
        <import><network><virtual-router><member>default</member></virtual-router></network></import>
        <rulebase><security><rules><entry name="admin-to-servers"><from><member>Admin</member></from><to><member>Servers</member></to><source><member>any</member></source><destination><member>web</member></destination><action>allow</action></entry></rules><default-rule><action>drop</action></default-rule></security></rulebase>
      </entry>
    </vsys>
  </entry></devices>
</config>'''


def zone_mappings():
    return {
        ("vsys1", "Servers"): "Servers",
        ("vsys1", "Transit"): "Transit",
        ("vsys2", "Transit"): "Transit",
        ("vsys2", "Internet"): "Internet",
        ("vsys3", "Admin"): "Admin",
    }


class VsysMergeTests(unittest.TestCase):
    def test_analysis_flags_possible_transit_but_does_not_claim_it_as_fact(self):
        report = analyze_panos_vsys_merge(MULTI_VSYS)
        self.assertEqual(report["vsys_count"], 3)
        self.assertEqual(report["policy_total"], 3)
        self.assertEqual(report["possible_transit_subnets"][0]["subnet"], "10.0.0.0/30")
        self.assertEqual(report["possible_transit_subnets"][0]["vsys"], ["vsys1", "vsys2"])
        self.assertEqual(report["network_inventory"][0], {"name": "Interfaces", "count": 3})

    def test_merge_preserves_config_and_rehomes_only_owned_items(self):
        before = MULTI_VSYS
        result, plan = merge_panos_vsys_config(
            before,
            target_vsys="vsys1",
            vsys_order=["vsys3", "vsys1", "vsys2"],
            default_rule_source="vsys1",
            zone_mappings=zone_mappings(),
        )
        root, snapshot = parse_snapshot(result, expected_kind="panos")
        self.assertEqual(snapshot.vsys, ["vsys1"])
        self.assertEqual(plan["removed_vsys"], ["vsys2", "vsys3"])
        self.assertEqual(plan["policy_total"], 3)
        self.assertEqual(plan["shareable_objects_moved"], 3)
        self.assertEqual(plan["shared_objects_reused"], 2)
        self.assertEqual(
            [rule.get("name") for rule in root.findall("./devices/entry/vsys/entry/rulebase/security/rules/entry")],
            ["admin-to-servers", "servers-to-transit", "transit-to-internet"],
        )
        self.assertEqual(
            [member.text for member in root.findall("./devices/entry/vsys/entry/rulebase/security/rules/entry/from/member")],
            ["Admin", "Servers", "Transit"],
        )
        self.assertEqual(
            [member.text for member in root.findall("./devices/entry/vsys/entry/rulebase/security/rules/entry/to/member")],
            ["Servers", "Transit", "Internet"],
        )
        self.assertEqual(
            [entry.get("name") for entry in root.findall("./devices/entry/vsys/entry/zone/entry")],
            ["Admin", "Servers", "Transit", "Internet"],
        )
        self.assertIsNone(root.find("./devices/entry/vsys/entry/zone/entry[@name='Transit']/network/external"))
        self.assertEqual(len(root.findall("./shared/address/entry[@name='web']")), 1)
        self.assertEqual(len(root.findall("./shared/address-group/entry[@name='web-group']")), 1)
        self.assertIsNotNone(root.find("./shared/service/entry[@name='tcp-443']"))
        self.assertEqual(root.findtext("./devices/entry/vsys/entry/rulebase/security/default-rule/action"), "deny")
        self.assertIsNotNone(root.find("./devices/entry/network/virtual-router/entry[@name='default']"))
        self.assertEqual(root.findtext("./mgt-config/users/entry[@name='admin']/phash"), "keep-this-hash")
        self.assertEqual(MULTI_VSYS, before)

    def test_conflicting_shared_object_aborts_without_changing_source(self):
        conflict = MULTI_VSYS.replace(b"10.1.0.10/32", b"10.1.0.11/32", 1)
        with self.assertRaisesRegex(VsysMergeError, "verschillende inhoud"):
            merge_panos_vsys_config(
                conflict,
                target_vsys="vsys1",
                vsys_order=["vsys1", "vsys2", "vsys3"],
                default_rule_source="vsys1",
                zone_mappings=zone_mappings(),
            )
        self.assertIn(b"name=\"vsys3\"", conflict)

    def test_vsys1_is_required_to_survive(self):
        with self.assertRaisesRegex(VsysMergeError, "blijvende doel-VSYS"):
            merge_panos_vsys_config(
                MULTI_VSYS,
                target_vsys="vsys2",
                vsys_order=["vsys1", "vsys2", "vsys3"],
                default_rule_source="vsys1",
                zone_mappings=zone_mappings(),
            )
        with self.assertRaisesRegex(VsysMergeError, "geen vsys1"):
            analyze_panos_vsys_merge(MULTI_VSYS.replace(b'name="vsys1"', b'name="vsys01"', 1))

    def test_invalid_or_duplicate_numeric_vsys_ids_are_rejected(self):
        invalid_id = MULTI_VSYS.replace(b"<vsys-id>2</vsys-id>", b"<vsys-id>256</vsys-id>", 1)
        with self.assertRaisesRegex(VsysMergeError, "Ongeldig VSYS-ID"):
            analyze_panos_vsys_merge(invalid_id)

        duplicate_id = MULTI_VSYS.replace(b"<vsys-id>2</vsys-id>", b"<vsys-id>1</vsys-id>", 1)
        with self.assertRaisesRegex(VsysMergeError, "dubbele VSYS-ID"):
            analyze_panos_vsys_merge(duplicate_id)

    def test_duplicate_interface_assignment_aborts(self):
        conflict = MULTI_VSYS.replace(
            b"<member>ethernet1/2</member></interface><virtual-router>",
            b"<member>ethernet1/1</member></interface><virtual-router>",
        )
        with self.assertRaisesRegex(VsysMergeError, "Interfaces kunnen niet"):
            merge_panos_vsys_config(
                conflict,
                target_vsys="vsys1",
                vsys_order=["vsys1", "vsys2", "vsys3"],
                default_rule_source="vsys1",
                zone_mappings=zone_mappings(),
            )

    def test_duplicate_policy_name_aborts(self):
        conflict = MULTI_VSYS.replace(b"name=\"transit-to-internet\"", b"name=\"servers-to-transit\"")
        with self.assertRaisesRegex(VsysMergeError, "Policynaam"):
            merge_panos_vsys_config(
                conflict,
                target_vsys="vsys1",
                vsys_order=["vsys1", "vsys2", "vsys3"],
                default_rule_source="vsys1",
                zone_mappings=zone_mappings(),
            )

    def test_external_zone_must_map_to_a_local_zone(self):
        mappings = zone_mappings()
        mappings[("vsys1", "Transit")] = "Transit-External"
        with self.assertRaisesRegex(VsysMergeError, "Externe zone"):
            merge_panos_vsys_config(
                MULTI_VSYS,
                target_vsys="vsys1",
                vsys_order=["vsys1", "vsys2", "vsys3"],
                default_rule_source="vsys1",
                zone_mappings=mappings,
            )

    def test_requires_all_scopes_and_zone_mappings(self):
        with self.assertRaisesRegex(VsysMergeError, "elke VSYS precies één keer"):
            merge_panos_vsys_config(
                MULTI_VSYS,
                target_vsys="vsys1",
                vsys_order=["vsys1", "vsys2"],
                default_rule_source="vsys1",
                zone_mappings=zone_mappings(),
            )
        with self.assertRaisesRegex(VsysMergeError, "doelzone"):
            merge_panos_vsys_config(
                MULTI_VSYS,
                target_vsys="vsys1",
                vsys_order=["vsys1", "vsys2", "vsys3"],
                default_rule_source="vsys1",
                zone_mappings={**zone_mappings(), ("vsys2", "Internet"): ""},
            )

    def test_panorama_is_not_treated_as_multi_vsys(self):
        with self.assertRaisesRegex(VsysMergeError, "standalone PAN-OS"):
            analyze_panos_vsys_merge(
                b'<config><devices><entry name="localhost.localdomain"><device-group><entry name="DG"/></device-group></entry></devices></config>'
            )

    def test_ten_vsys_are_processed_from_config_without_a_fixed_two_vsys_assumption(self):
        root = ET.fromstring(MULTI_VSYS)
        container = root.find("./devices/entry/vsys")
        expected_names = [f"vsys{number}" for number in range(1, 11)]
        for number in range(4, 11):
            name = f"vsys{number}"
            scope = ET.SubElement(container, "entry", {"name": name})
            ET.SubElement(scope, "vsys-id").text = str(number)
            zone = ET.SubElement(ET.SubElement(scope, "zone"), "entry", {"name": f"Zone{number}"})
            ET.SubElement(ET.SubElement(zone, "network"), "layer3")
            rulebase = ET.SubElement(scope, "rulebase")
            security = ET.SubElement(rulebase, "security")
            rules = ET.SubElement(security, "rules")
            policy = ET.SubElement(rules, "entry", {"name": f"policy-{number}"})
            ET.SubElement(ET.SubElement(policy, "from"), "member").text = f"Zone{number}"
            ET.SubElement(ET.SubElement(policy, "to"), "member").text = "any"
            ET.SubElement(ET.SubElement(policy, "source"), "member").text = "any"
            ET.SubElement(ET.SubElement(policy, "destination"), "member").text = "any"
            ET.SubElement(policy, "action").text = "allow"

        source = ET.tostring(root, encoding="utf-8")
        mappings = zone_mappings()
        for number in range(4, 11):
            mappings[(f"vsys{number}", f"Zone{number}")] = f"Zone{number}"
        result, plan = merge_panos_vsys_config(
            source,
            target_vsys="vsys1",
            vsys_order=expected_names,
            default_rule_source="vsys1",
            zone_mappings=mappings,
        )
        _, snapshot = parse_snapshot(result, expected_kind="panos")
        self.assertEqual(snapshot.vsys, ["vsys1"])
        self.assertEqual(plan["policy_total"], 10)


if __name__ == "__main__":
    unittest.main()
