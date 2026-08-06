import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.offline_config import OfflineConfigError, parse_snapshot, render_set_commands


PANORAMA = b'''<config version="12.1.2"><shared><address><entry name="shared-a"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address></shared><devices><entry name="localhost.localdomain"><device-group><entry name="Parent"><pre-rulebase><security><rules><entry name="allow-parent"/></rules></security></pre-rulebase></entry><entry name="Child"><parent-dg>Parent</parent-dg><reference-template>Branch-Stack</reference-template><post-rulebase><nat><rules><entry name="nat-child"/></rules></nat></post-rulebase><address><entry name="child-a"><ip-netmask>10.0.0.2/32</ip-netmask></entry></address></entry></device-group><template><entry name="Base"/><entry name="Branch"/></template><template-stack><entry name="Branch-Stack"><templates><member>Branch</member><member>Base</member></templates></entry></template-stack></entry></devices></config>'''

PANOS = b'''<config version="11.2.4"><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"/></ethernet></interface></network><vsys><entry name="vsys1"><zone><entry name="Trust"/><entry name="Internet"/></zone><rulebase><security><rules><entry name="allow-web"><from><member>Trust</member></from></entry></rules></security></rulebase></entry><entry name="vsys2"/></vsys></entry></devices></config>'''


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


if __name__ == "__main__":
    unittest.main()
