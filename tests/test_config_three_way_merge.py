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

    def test_partial_candidate_member_rewrites_complete_the_workspace_draft(self):
        base = b"""<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
          <rulebase><security><rules><entry name='FULL_ACCESS_IP'><source>
            <member>old-a</member><member>old-b</member><member>keep</member>
          </source></entry></rules></security></rulebase>
          <address-group><entry name='CameraSport'><static>
            <member>old-camera-a</member><member>old-camera-b</member><member>keep-camera</member>
          </static></entry></address-group>
        </entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
          <rulebase><security><rules><entry name='FULL_ACCESS_IP'><source>
            <member>new-a</member><member>new-b</member><member>keep</member>
          </source></entry></rules></security></rulebase>
          <address-group><entry name='CameraSport'><static>
            <member>new-camera-a</member><member>new-camera-b</member><member>keep-camera</member>
          </static></entry></address-group>
        </entry></vsys></entry></devices></config>"""
        # The candidate reflects a subset of the draft's replacements, as can
        # happen when an earlier incremental push stopped partway through.
        current = b"""<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
          <rulebase><security><rules><entry name='FULL_ACCESS_IP'><source>
            <member>new-a</member><member>old-b</member><member>keep</member>
          </source></entry></rules></security></rulebase>
          <address-group><entry name='CameraSport'><static>
            <member>new-camera-a</member><member>old-camera-b</member><member>keep-camera</member>
          </static></entry></address-group>
        </entry></vsys></entry></devices></config>"""

        merged, conflicts = merge_config_xml(base, desired, current)

        self.assertEqual(conflicts, [])
        root = ET.fromstring(merged)
        self.assertEqual(
            [item.text for item in root.findall(
                ".//vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='FULL_ACCESS_IP']/source/member"
            )],
            ["new-a", "new-b", "keep"],
        )
        self.assertEqual(
            [item.text for item in root.findall(
                ".//vsys/entry[@name='vsys1']/address-group/entry[@name='CameraSport']/static/member"
            )],
            ["new-camera-a", "new-camera-b", "keep-camera"],
        )

    def test_partial_member_progress_with_unrelated_candidate_edit_still_conflicts(self):
        base = b"<config><rule><source><member>A</member><member>B</member></source></rule></config>"
        desired = b"<config><rule><source><member>C</member><member>D</member></source></rule></config>"
        current = b"<config><rule><source><member>C</member><member>E</member></source></rule></config>"

        merged, conflicts = merge_config_xml(base, desired, current)

        self.assertEqual(merged, b"")
        self.assertEqual(conflicts, ["/config/rule/source/member-list"])

    def test_partial_member_rewrites_merge_in_shared_multi_vsys_and_panorama_scopes(self):
        base = b"""<config><shared><address-group><entry name='Shared-Group'><static>
          <member>old-shared-a</member><member>old-shared-b</member>
        </static></entry></address-group></shared>
        <devices><entry name='localhost.localdomain'>
          <vsys><entry name='vsys2'><rulebase><security><rules><entry name='Vsys-Rule'><source>
            <member>old-vsys-a</member><member>old-vsys-b</member>
          </source></entry></rules></security></rulebase></entry></vsys>
          <device-group><entry name='DG-A'><rulebase><security><rules><entry name='Panorama-Rule'><source>
            <member>old-panorama-a</member><member>old-panorama-b</member>
          </source></entry></rules></security></rulebase></entry></device-group>
        </entry></devices></config>"""
        desired = b"""<config><shared><address-group><entry name='Shared-Group'><static>
          <member>new-shared-a</member><member>new-shared-b</member>
        </static></entry></address-group></shared>
        <devices><entry name='localhost.localdomain'>
          <vsys><entry name='vsys2'><rulebase><security><rules><entry name='Vsys-Rule'><source>
            <member>new-vsys-a</member><member>new-vsys-b</member>
          </source></entry></rules></security></rulebase></entry></vsys>
          <device-group><entry name='DG-A'><rulebase><security><rules><entry name='Panorama-Rule'><source>
            <member>new-panorama-a</member><member>new-panorama-b</member>
          </source></entry></rules></security></rulebase></entry></device-group>
        </entry></devices></config>"""
        current = b"""<config><shared><address-group><entry name='Shared-Group'><static>
          <member>new-shared-a</member><member>old-shared-b</member>
        </static></entry></address-group></shared>
        <devices><entry name='localhost.localdomain'>
          <vsys><entry name='vsys2'><rulebase><security><rules><entry name='Vsys-Rule'><source>
            <member>new-vsys-a</member><member>old-vsys-b</member>
          </source></entry></rules></security></rulebase></entry></vsys>
          <device-group><entry name='DG-A'><rulebase><security><rules><entry name='Panorama-Rule'><source>
            <member>new-panorama-a</member><member>old-panorama-b</member>
          </source></entry></rules></security></rulebase></entry></device-group>
        </entry></devices></config>"""

        merged, conflicts = merge_config_xml(base, desired, current)

        self.assertEqual(conflicts, [])
        root = ET.fromstring(merged)
        self.assertEqual(
            [item.text for item in root.findall(
                "./shared/address-group/entry[@name='Shared-Group']/static/member"
            )],
            ["new-shared-a", "new-shared-b"],
        )
        self.assertEqual(
            [item.text for item in root.findall(
                ".//vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='Vsys-Rule']/source/member"
            )],
            ["new-vsys-a", "new-vsys-b"],
        )
        self.assertEqual(
            [item.text for item in root.findall(
                ".//device-group/entry[@name='DG-A']/rulebase/security/rules/entry[@name='Panorama-Rule']/source/member"
            )],
            ["new-panorama-a", "new-panorama-b"],
        )

    def test_pan_os_merge_rewrites_ignore_member_order_only_changes(self):
        base = b"""<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
          <rulebase><security><rules><entry name='FULL_ACCESS_IP'><source>
            <member>old-address</member><member>unchanged-address</member>
          </source></entry></rules></security></rulebase>
          <address-group><entry name='CameraSport'><static>
            <member>old-camera-address</member><member>unchanged-camera-address</member>
          </static></entry></address-group>
        </entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
          <rulebase><security><rules><entry name='FULL_ACCESS_IP'><source>
            <member>canonical-address</member><member>unchanged-address</member>
          </source></entry></rules></security></rulebase>
          <address-group><entry name='CameraSport'><static>
            <member>canonical-camera-address</member><member>unchanged-camera-address</member>
          </static></entry></address-group>
        </entry></vsys></entry></devices></config>"""
        # The live candidate has the same memberships as the merged draft but
        # PAN-OS returned them in a different order. That is not a field conflict.
        current = b"""<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
          <rulebase><security><rules><entry name='FULL_ACCESS_IP'><source>
            <member>unchanged-address</member><member>canonical-address</member>
          </source></entry></rules></security></rulebase>
          <address-group><entry name='CameraSport'><static>
            <member>unchanged-camera-address</member><member>canonical-camera-address</member>
          </static></entry></address-group>
        </entry></vsys></entry></devices></config>"""

        merged, conflicts = merge_config_xml(base, desired, current)

        self.assertEqual(conflicts, [])
        root = ET.fromstring(merged)
        self.assertEqual(
            [item.text for item in root.findall(
                ".//vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='FULL_ACCESS_IP']/source/member"
            )],
            ["canonical-address", "unchanged-address"],
        )
        self.assertEqual(
            [item.text for item in root.findall(
                ".//vsys/entry[@name='vsys1']/address-group/entry[@name='CameraSport']/static/member"
            )],
            ["canonical-camera-address", "unchanged-camera-address"],
        )

    def test_pan_os_merge_rewrite_survives_reordered_unchanged_candidate_members(self):
        base = b"""<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
          <rulebase><security><rules><entry name='FULL_ACCESS_IP'><source>
            <member>old-address</member><member>keep-address</member>
          </source></entry></rules></security></rulebase>
          <address-group><entry name='CameraSport'><static>
            <member>old-camera-address</member><member>keep-camera-address</member>
          </static></entry></address-group>
        </entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
          <rulebase><security><rules><entry name='FULL_ACCESS_IP'><source>
            <member>canonical-address</member><member>keep-address</member>
          </source></entry></rules></security></rulebase>
          <address-group><entry name='CameraSport'><static>
            <member>canonical-camera-address</member><member>keep-camera-address</member>
          </static></entry></address-group>
        </entry></vsys></entry></devices></config>"""
        # The candidate still has the baseline memberships, but PAN-OS has
        # returned each member list in a different order. The workspace rewrite
        # should apply without treating this as a concurrent field edit.
        current = b"""<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
          <rulebase><security><rules><entry name='FULL_ACCESS_IP'><source>
            <member>keep-address</member><member>old-address</member>
          </source></entry></rules></security></rulebase>
          <address-group><entry name='CameraSport'><static>
            <member>keep-camera-address</member><member>old-camera-address</member>
          </static></entry></address-group>
        </entry></vsys></entry></devices></config>"""

        merged, conflicts = merge_config_xml(base, desired, current)

        self.assertEqual(conflicts, [])
        root = ET.fromstring(merged)
        self.assertEqual(
            [item.text for item in root.findall(
                ".//vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='FULL_ACCESS_IP']/source/member"
            )],
            ["canonical-address", "keep-address"],
        )
        self.assertEqual(
            [item.text for item in root.findall(
                ".//vsys/entry[@name='vsys1']/address-group/entry[@name='CameraSport']/static/member"
            )],
            ["canonical-camera-address", "keep-camera-address"],
        )

    def test_member_order_is_ignored_but_duplicate_counts_still_conflict(self):
        base = b"<config><rule><source><member>A</member><member>A</member></source></rule></config>"
        desired = b"<config><rule><source><member>A</member><member>B</member></source></rule></config>"
        current = b"<config><rule><source><member>B</member><member>A</member><member>A</member></source></rule></config>"

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
