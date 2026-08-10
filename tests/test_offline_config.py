import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.offline_config import (
    OfflineConfigError, apply_configuration_changes, apply_object_changes, available_scopes, available_templates,
    configuration_inventory, configuration_records, parse_snapshot,
    object_fingerprint, policy_fingerprint, render_set_commands, replace_policy_in_snapshot,
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

    def test_policy_replacement_can_rename_but_rejects_a_duplicate_name(self):
        _, policies = scoped_policies(INHERITED, "Child", "security", "pre")
        child = policies[-1]
        renamed = child["_xml"].replace('name="child-rule"', 'name="renamed-rule"')
        updated = replace_policy_in_snapshot(
            INHERITED, "Child", "security", "pre", "child-rule",
            policy_fingerprint(child), renamed,
        )
        self.assertIn(b'<entry name="renamed-rule">', updated)
        self.assertNotIn(b'<entry name="child-rule">', updated)

        duplicate_source = INHERITED.replace(
            b'<entry name="child-rule">',
            b'<entry name="existing-rule"/><entry name="child-rule">',
        )
        _, duplicate_policies = scoped_policies(duplicate_source, "Child", "security", "pre")
        original = next(item for item in duplicate_policies if item["name"] == "child-rule")
        duplicate = original["_xml"].replace('name="child-rule"', 'name="existing-rule"')
        with self.assertRaises(OfflineConfigError):
            replace_policy_in_snapshot(
                duplicate_source, "Child", "security", "pre", "child-rule",
                policy_fingerprint(original), duplicate,
            )

    def test_standalone_network_inventory_uses_device_and_vsys_contexts(self):
        inventory = configuration_inventory(PANOS, "vsys1")
        by_name = {item["name"]: item for item in inventory["network"]}
        self.assertEqual(by_name["Interfaces"]["entries"], 1)
        self.assertEqual(by_name["Zones"]["entries"], 2)

    def test_network_records_are_editable_and_preserve_unknown_xml(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1" custom="keep"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3><comment>old</comment><link-state>auto</link-state><future-node><value>preserve</value></future-node></entry></ethernet></interface></network><vsys><entry name="vsys1"><zone><entry name="Trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone></entry></vsys></entry></devices></config>'''
        _, records = configuration_records(source, "vsys1", "", "network", "interfaces")
        self.assertEqual([record["name"] for record in records], ["ethernet1/1"])
        interface = records[0]
        fields = {field["label"]: field for field in interface["edit_fields"]}
        updated = apply_configuration_changes(source, [{
            "operation": "update", "locator": interface["locator"],
            "fingerprint": interface["fingerprint"], "name": "ethernet1/2",
            "updates": [
                {"path": fields["Comment"]["path"], "kind": "text", "value": "changed"},
                {"path": fields["Link State"]["path"], "kind": "text", "value": "up"},
            ],
        }])
        self.assertIn(b'<entry name="ethernet1/2" custom="keep">', updated)
        self.assertIn(b"<comment>changed</comment>", updated)
        self.assertIn(b"<future-node>", updated)
        self.assertIn(b"<value>preserve</value>", updated)

    def test_panorama_template_stack_records_keep_concrete_owner(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><device-group><entry name="Branch-DG"/></device-group><template><entry name="Base"><config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><comment>base</comment></entry></ethernet></interface></network></entry></devices></config></entry><entry name="Branch"><config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><zone><entry name="Clients"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone></entry></vsys></entry></devices></config></entry></template><template-stack><entry name="Branch-Stack"><templates><member>Branch</member><member>Base</member></templates></entry></template-stack></entry></devices></config>'''
        _, interfaces = configuration_records(source, "Branch-DG", "Branch-Stack", "network", "interfaces")
        _, zones = configuration_records(source, "Branch-DG", "Branch-Stack", "network", "zones")
        self.assertEqual([(item["name"], item["owner"]) for item in interfaces], [("ethernet1/1", "Base")])
        self.assertEqual([(item["name"], item["owner"]) for item in zones], [("Clients", "Branch")])

    def test_configuration_records_can_duplicate_and_delete_multiple_siblings(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><comment>one</comment></entry><entry name="ethernet1/2"><comment>two</comment></entry><entry name="ethernet1/3"><comment>three</comment></entry></ethernet></interface></network><vsys><entry name="vsys1"/></vsys></entry></devices></config>'''
        _, records = configuration_records(source, "vsys1", "", "network", "interfaces")
        first = records[0]
        duplicated = apply_configuration_changes(source, [{
            "operation": "create", "locator": first["locator"], "fingerprint": first["fingerprint"],
            "name": "ethernet1/4", "updates": [],
        }])
        self.assertIn(b'<entry name="ethernet1/4">', duplicated)
        _, after = configuration_records(duplicated, "vsys1", "", "network", "interfaces")
        removed = apply_configuration_changes(duplicated, [
            {"operation": "delete", "locator": item["locator"], "fingerprint": item["fingerprint"]}
            for item in after if item["name"] in {"ethernet1/2", "ethernet1/3"}
        ])
        self.assertNotIn(b'<entry name="ethernet1/2">', removed)
        self.assertNotIn(b'<entry name="ethernet1/3">', removed)
        self.assertIn(b'<entry name="ethernet1/4">', removed)

    def test_protected_device_values_never_reach_editor_fields(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>fw-a</hostname><password>secret-value</password></system></deviceconfig><mgt-config><users><entry name="admin"><phash>hash-value</phash></entry></users></mgt-config><vsys><entry name="vsys1"/></vsys></entry></devices></config>'''
        _, setup = configuration_records(source, "vsys1", "", "device", "setup")
        protected = [field for field in setup[0]["edit_fields"] if field["kind"] == "protected"]
        self.assertTrue(protected)
        self.assertNotIn("secret-value", repr(setup[0]["edit_fields"]))

    def test_offline_object_create_update_delete_preserves_unknown_fields(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="old"><ip-netmask>192.0.2.1/32</ip-netmask><custom-field>keep</custom-field></entry></address></entry></vsys></entry></devices></config>'''
        _, objects = scoped_objects(source, "vsys1", "addresses")
        old = objects[0]
        updated = apply_object_changes(source, "vsys1", "addresses", [{
            "operation": "update", "original_name": "old", "fingerprint": object_fingerprint(old),
            "replacement_xml": '<entry name="renamed"><ip-netmask>192.0.2.2/32</ip-netmask><description>changed</description></entry>',
        }, {
            "operation": "create", "original_name": "", "fingerprint": "",
            "replacement_xml": '<entry name="new"><fqdn>example.test</fqdn></entry>',
        }])
        self.assertIn(b'<entry name="renamed">', updated)
        self.assertIn(b'<custom-field>keep</custom-field>', updated)
        self.assertIn(b'<entry name="new">', updated)
        _, after = scoped_objects(updated, "vsys1", "addresses")
        new = next(item for item in after if item["name"] == "new")
        deleted = apply_object_changes(updated, "vsys1", "addresses", [{
            "operation": "delete", "original_name": "new", "fingerprint": object_fingerprint(new),
        }])
        self.assertNotIn(b'<entry name="new">', deleted)

    def test_generic_object_editor_updates_nested_fields_without_raw_xml_loss(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><region><entry name="Belgium" code="be"><address><member>192.0.2.0/24</member><member>198.51.100.0/24</member></address><enabled>yes</enabled><nested preserve="true"><label>old</label></nested></entry></region></entry></vsys></entry></devices></config>'''
        _, objects = scoped_objects(source, "vsys1", "regions")
        region = objects[0]
        fields = {field["label"]: field for field in region["edit_fields"]}
        self.assertEqual(fields["Address"]["values"], ["192.0.2.0/24", "198.51.100.0/24"])
        updated = apply_object_changes(source, "vsys1", "regions", [{
            "operation": "update", "original_name": "Belgium",
            "fingerprint": object_fingerprint(region), "name": "Belgium-custom",
            "generic_updates": [
                {"path": fields["Address"]["path"], "kind": "members", "values": ["203.0.113.0/24"]},
                {"path": fields["Enabled"]["path"], "kind": "boolean", "value": "no"},
                {"path": fields["Nested / Label"]["path"], "kind": "text", "value": "new"},
            ],
        }])
        self.assertIn(b'<entry name="Belgium-custom" code="be">', updated)
        self.assertIn(b'<member>203.0.113.0/24</member>', updated)
        self.assertIn(b'<enabled>no</enabled>', updated)
        self.assertIn(b'<nested preserve="true">', updated)
        self.assertIn(b'<label>new</label>', updated)


if __name__ == "__main__":
    unittest.main()
