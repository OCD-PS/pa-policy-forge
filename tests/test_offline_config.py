import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.offline_config import (
    OfflineConfigError, available_scopes, available_templates, configuration_inventory, parse_snapshot,
    policy_fingerprint, render_set_commands, replace_policy_in_snapshot,
    referenced_template, scoped_objects, scoped_policies,
)


PANORAMA = b'''<config version="12.1.2"><shared><address><entry name="shared-a"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address></shared><devices><entry name="localhost.localdomain"><device-group><entry name="Parent"><pre-rulebase><security><rules><entry name="allow-parent"/></rules></security></pre-rulebase></entry><entry name="Child"><parent-dg>Parent</parent-dg><reference-template>Branch-Stack</reference-template><post-rulebase><nat><rules><entry name="nat-child"/></rules></nat></post-rulebase><address><entry name="child-a"><ip-netmask>10.0.0.2/32</ip-netmask></entry></address></entry></device-group><template><entry name="Base"/><entry name="Branch"/></template><template-stack><entry name="Branch-Stack"><templates><member>Branch</member><member>Base</member></templates></entry></template-stack></entry></devices></config>'''

PANOS = b'''<config version="11.2.4"><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"/></ethernet></interface></network><vsys><entry name="vsys1"><zone><entry name="Trust"/><entry name="Internet"/></zone><rulebase><security><rules><entry name="allow-web"><from><member>Trust</member></from></entry></rules></security></rulebase></entry><entry name="vsys2"/></vsys></entry></devices></config>'''

INHERITED = b'''<config version="12.1"><shared><address><entry name="shared-a"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address><pre-rulebase><security><rules><entry name="shared-rule"><from><member>any</member></from><custom-unknown>keep-me</custom-unknown></entry></rules></security></pre-rulebase></shared><devices><entry name="localhost.localdomain"><device-group><entry name="Parent"><parent-dg>Shared</parent-dg><pre-rulebase><security><rules><entry name="parent-rule"><from><member>Trust</member></from></entry></rules></security></pre-rulebase><address><entry name="parent-a"><ip-netmask>10.0.0.2/32</ip-netmask></entry></address></entry><entry name="Child"><parent-dg>Parent</parent-dg><pre-rulebase><security><rules><entry name="child-rule"><from><member>Clients</member></from><to><member>Internet</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>web-browsing</member></application><service><member>application-default</member></service><action>allow</action><custom-unknown>preserve</custom-unknown></entry></rules></security></pre-rulebase></entry></device-group></entry></devices></config>'''


class OfflineConfigTests(unittest.TestCase):
    def test_panorama_inventory_preserves_hierarchy_and_templates(self):
        _, snapshot = parse_snapshot(PANORAMA, expected_kind="panorama")
        self.assertEqual(snapshot.kind, "panorama")
        self.assertEqual(snapshot.version, "12.1.2")
        child = next(item for item in snapshot.device_groups if item["name"] == "Child")
        self.assertEqual(child["parent"], "Parent")
        self.assertEqual(child["reference_template"], "Branch-Stack")
        self.assertEqual(snapshot.templates, ["Base", "Branch"])
        self.assertEqual(snapshot.template_stacks[0]["templates"], ["Branch", "Base"])
        self.assertEqual(available_templates(snapshot), ["Base", "Branch", "Branch-Stack"])
        self.assertEqual(referenced_template(snapshot, "Child"), "Branch-Stack")

    def test_standalone_inventory_lists_all_vsys(self):
        _, snapshot = parse_snapshot(PANOS, expected_kind="panos")
        self.assertEqual(snapshot.vsys, ["vsys1", "vsys2"])
        self.assertEqual(snapshot.counts["interfaces"], 1)
        self.assertEqual(snapshot.counts["zones"], 2)

    def test_wrong_profile_flavor_is_rejected(self):
        with self.assertRaises(OfflineConfigError):
            parse_snapshot(PANORAMA, expected_kind="panos")

    def test_unsafe_xml_is_rejected(self):
        xml = b'<!DOCTYPE config [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><config><x>&xxe;</x></config>'
        with self.assertRaises(OfflineConfigError):
            parse_snapshot(xml)

    def test_set_export_has_vsys_context_and_members(self):
        commands = render_set_commands(PANOS)
        self.assertIn("set vsys vsys1 zone Trust", commands)
        self.assertIn("set vsys vsys1 rulebase security rules allow-web from Trust", commands)

    def test_scope_inventory_and_panorama_inheritance(self):
        _, snapshot = parse_snapshot(INHERITED)
        self.assertEqual(available_scopes(snapshot), ["Shared", "Parent", "Child"])
        _, policies = scoped_policies(INHERITED, "Child", "security", "pre")
        self.assertEqual([item["name"] for item in policies], ["shared-rule", "parent-rule", "child-rule"])
        self.assertEqual([item["editable"] for item in policies], [False, False, True])
        _, objects = scoped_objects(INHERITED, "Child", "addresses")
        self.assertEqual([item["name"] for item in objects], ["shared-a", "parent-a"])
        self.assertTrue(all(not item["editable"] for item in objects))

    def test_policy_replacement_is_version_safe_and_preserves_unknown_xml(self):
        _, policies = scoped_policies(INHERITED, "Child", "security", "pre")
        child = policies[-1]
        replacement = child["_xml"].replace("<action>allow</action>", "<action>deny</action>")
        updated = replace_policy_in_snapshot(
            INHERITED, "Child", "security", "pre", "child-rule",
            policy_fingerprint(child), replacement,
        )
        self.assertIn(b"<action>deny</action>", updated)
        self.assertIn(b"<custom-unknown>preserve</custom-unknown>", updated)
        self.assertIn(b"<custom-unknown>keep-me</custom-unknown>", updated)
        with self.assertRaises(OfflineConfigError):
            replace_policy_in_snapshot(INHERITED, "Child", "security", "pre", "child-rule", "wrong", replacement)

    def test_standalone_network_inventory_uses_device_and_vsys_contexts(self):
        inventory = configuration_inventory(PANOS, "vsys1")
        by_name = {item["name"]: item for item in inventory["network"]}
        self.assertEqual(by_name["Interfaces"]["entries"], 1)
        self.assertEqual(by_name["Zones"]["entries"], 2)


if __name__ == "__main__":
    unittest.main()
