import unittest
import xml.etree.ElementTree as ET

from app.offline_config import merge_config_xml


class ConfigThreeWayMergeTests(unittest.TestCase):
    def test_description_edit_keeps_concurrent_policy_member_removal(self):
        base = b"""<config><devices><entry name='fw'><vsys><entry name='vsys2'><rulebase><security><rules>
          <entry name='Allow-app'><description>old</description><source><member>CN</member><member>RU</member></source></entry>
        </rules></security></rulebase></entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name='fw'><vsys><entry name='vsys2'><rulebase><security><rules>
          <entry name='Allow-app'><description>Steven description</description><source><member>CN</member><member>RU</member></source></entry>
        </rules></security></rulebase></entry></vsys></entry></devices></config>"""
        current = b"""<config><devices><entry name='fw'><vsys><entry name='vsys2'><rulebase><security><rules>
          <entry name='Allow-app'><description>old</description><source><member>RU</member></source></entry>
        </rules></security></rulebase></entry></vsys></entry></devices></config>"""

        merged, conflicts = merge_config_xml(base, desired, current)

        self.assertEqual(conflicts, [])
        root = ET.fromstring(merged)
        rule = root.find(".//vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='Allow-app']")
        self.assertEqual(rule.findtext("description"), "Steven description")
        self.assertEqual([item.text for item in rule.findall("source/member")], ["RU"])

    def test_conflicting_description_edits_fail_closed(self):
        base = b"<config><rule><description>original</description></rule></config>"
        desired = b"<config><rule><description>local</description></rule></config>"
        current = b"<config><rule><description>colleague</description></rule></config>"

        merged, conflicts = merge_config_xml(base, desired, current)

        self.assertEqual(merged, b"")
        self.assertEqual(conflicts, ["/config/rule/description"])

    def test_different_concurrent_member_replacements_fail_closed(self):
        base = b"<config><rule><source><member>CN</member></source></rule></config>"
        desired = b"<config><rule><source><member>RU</member></source></rule></config>"
        current = b"<config><rule><source><member>US</member></source></rule></config>"

        merged, conflicts = merge_config_xml(base, desired, current)

        self.assertEqual(merged, b"")
        self.assertEqual(conflicts, ["/config/rule/source/member-list"])

    def test_preserves_independent_shared_scope_change(self):
        base = b"<config><shared><address><entry name='old'><ip-netmask>192.0.2.1</ip-netmask></entry></address></shared><devices><entry name='fw'><vsys><entry name='vsys1'><rule/></entry></vsys></entry></devices></config>"
        desired = b"<config><shared><address><entry name='old'><ip-netmask>192.0.2.1</ip-netmask></entry></address></shared><devices><entry name='fw'><vsys><entry name='vsys1'><rule><description>local</description></rule></entry></vsys></entry></devices></config>"
        current = b"<config><shared><address><entry name='old'><ip-netmask>192.0.2.1</ip-netmask></entry><entry name='colleague'><ip-netmask>192.0.2.2</ip-netmask></entry></address></shared><devices><entry name='fw'><vsys><entry name='vsys1'><rule/></entry></vsys></entry></devices></config>"

        merged, conflicts = merge_config_xml(base, desired, current)

        self.assertEqual(conflicts, [])
        root = ET.fromstring(merged)
        self.assertIsNotNone(root.find("./shared/address/entry[@name='colleague']"))
        self.assertEqual(root.findtext("./devices/entry/vsys/entry/rule/description"), "local")


if __name__ == "__main__":
    unittest.main()
