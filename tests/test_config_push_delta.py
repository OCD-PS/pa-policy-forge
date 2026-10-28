import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-push-delta-test-"))
os.environ.setdefault("PPF_SYSLOG_PORT", "55142")
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "unit-test-bootstrap-password")

from app import main


class ConfigPushDeltaTests(unittest.TestCase):
    def test_changed_syslog_server_profile_is_one_edit_at_profile_entry(self):
        current = b"""<config><shared><log-settings><syslog><entry name="Pa_Policy_Forge"><server /></entry></syslog></log-settings></shared></config>"""
        desired = b"""<config><shared><log-settings><syslog><entry name="Pa_Policy_Forge"><server><entry name="PolicyForge"><server>10.74.80.46</server><transport>UDP</transport><port>514</port><format>BSD</format><facility>LOG_USER</facility></entry></server></entry></syslog></log-settings></shared></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        change = changes[0]
        self.assertEqual(change["action"], "edit")
        self.assertEqual(
            change["xpath"],
            "/config/shared/log-settings/syslog/entry[@name='Pa_Policy_Forge']",
        )
        payload = ET.fromstring(change["element"])
        self.assertEqual(payload.tag, "entry")
        self.assertEqual(payload.attrib["name"], "Pa_Policy_Forge")
        self.assertEqual(payload.findtext("./server/entry/server"), "10.74.80.46")

    def test_vsys_policy_edit_sets_only_changed_field_at_rule_xpath(self):
        current = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules><entry name="Allow"><action>deny</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules><entry name="Allow"><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        change = changes[0]
        self.assertEqual(change["action"], "set")
        self.assertEqual(
            change["xpath"],
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='Allow']",
        )
        self.assertEqual(change["scope"], "vsys1")
        self.assertEqual(change["family"], "policy:security")
        payload = ET.fromstring(f"<patch>{change['element']}</patch>")
        self.assertEqual([child.tag for child in payload], ["action"])
        self.assertEqual(payload.findtext("action"), "allow")

    def test_policy_any_to_object_replaces_the_complete_source_list(self):
        current = b"""<config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys1\"><rulebase><security><rules><entry name=\"salto toegang\"><source><member>any</member></source><destination><member>any</member></destination><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys1\"><rulebase><security><rules><entry name=\"salto toegang\"><source><member>CN</member></source><destination><member>any</member></destination><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        change = changes[0]
        self.assertEqual(change["action"], "edit")
        self.assertEqual(
            change["xpath"],
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='salto toegang']/source",
        )
        self.assertEqual(change["scope"], "vsys1")
        payload = ET.fromstring(change["element"])
        self.assertEqual(payload.tag, "source")
        self.assertEqual([member.text for member in payload.findall("member")], ["CN"])

    def test_policy_object_to_any_replaces_the_complete_source_list(self):
        current = b"""<config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys1\"><rulebase><security><rules><entry name=\"salto toegang\"><source><member>CN</member><member>RU</member></source><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys1\"><rulebase><security><rules><entry name=\"salto toegang\"><source><member>any</member></source><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["action"], "edit")
        payload = ET.fromstring(changes[0]["element"])
        self.assertEqual([member.text for member in payload.findall("member")], ["any"])

    def test_panorama_policy_member_replacement_keeps_device_group_scope(self):
        current = b"""<config><devices><entry name=\"localhost.localdomain\"><device-group><entry name=\"HQ\"><pre-rulebase><security><rules><entry name=\"Allow\"><source><member>any</member></source><action>allow</action></entry></rules></security></pre-rulebase></entry></device-group></entry></devices></config>"""
        desired = b"""<config><devices><entry name=\"localhost.localdomain\"><device-group><entry name=\"HQ\"><pre-rulebase><security><rules><entry name=\"Allow\"><source><member>CN</member></source><action>allow</action></entry></rules></security></pre-rulebase></entry></device-group></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["action"], "edit")
        self.assertEqual(changes[0]["scope"], "HQ")
        self.assertEqual(changes[0]["family"], "policy:security")
        self.assertEqual(changes[0]["xpath"], "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='HQ']/pre-rulebase/security/rules/entry[@name='Allow']/source")

    def test_shared_policy_member_replacement_keeps_shared_scope(self):
        current = b"""<config><shared><pre-rulebase><security><rules><entry name=\"Allow\"><destination><member>any</member></destination><action>allow</action></entry></rules></security></pre-rulebase></shared></config>"""
        desired = b"""<config><shared><pre-rulebase><security><rules><entry name=\"Allow\"><destination><member>10.10.102.56</member></destination><action>allow</action></entry></rules></security></pre-rulebase></shared></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["action"], "edit")
        self.assertEqual(changes[0]["scope"], "Shared")
        self.assertEqual(changes[0]["family"], "policy:security")
        payload = ET.fromstring(changes[0]["element"])
        self.assertEqual(payload.tag, "destination")
        self.assertEqual([member.text for member in payload.findall("member")], ["10.10.102.56"])

    def test_policy_set_fields_are_batched_into_one_api_write(self):
        current = b"<config><shared><pre-rulebase><security><rules><entry name='Allow'><action>allow</action><disabled>no</disabled></entry></rules></security></pre-rulebase></shared></config>"
        desired = b"<config><shared><pre-rulebase><security><rules><entry name='Allow'><action>deny</action><disabled>yes</disabled></entry></rules></security></pre-rulebase></shared></config>"

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["action"], "set")
        self.assertEqual(changes[0]["scope"], "Shared")
        payload = ET.fromstring(f"<patch>{changes[0]['element']}</patch>")
        self.assertEqual(
            [(child.tag, child.text) for child in payload],
            [("action", "deny"), ("disabled", "yes")],
        )

    def test_disabling_existing_security_rule_is_selectable(self):
        current = b"""<config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys2\"><rulebase><security><rules><entry name=\"Allow trusted clients\"><action>allow</action><disabled>no</disabled></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys2\"><rulebase><security><rules><entry name=\"Allow trusted clients\"><action>allow</action><disabled>yes</disabled></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["action"], "set")
        self.assertEqual(changes[0]["scope"], "vsys2")
        self.assertEqual(changes[0]["family"], "policy:security")
        self.assertEqual(changes[0]["selection_key"], '["vsys2","policy:security"]')
        self.assertEqual(ET.fromstring(changes[0]["element"]).text, "yes")

    def test_policy_rename_is_selectable_when_pan_os_response_metadata_is_present(self):
        current = b"""<config version=\"12.1.0\" admin=\"admin\" dirtyId=\"14\" time=\"2026/10/23 10:13:50\"><shared><certificate><entry name=\"fw-cert\"><private-key>old-placeholder</private-key></entry></certificate></shared><devices admin=\"admin\" dirtyId=\"14\" time=\"2026/10/23 10:13:50\"><entry name=\"localhost.localdomain\" admin=\"admin\" dirtyId=\"14\" time=\"2026/10/23 10:13:50\"><vsys admin=\"admin\" dirtyId=\"14\" time=\"2026/10/23 10:13:50\"><entry name=\"vsys1\" admin=\"admin\" dirtyId=\"14\" time=\"2026/10/23 10:13:50\"><rulebase><security><rules><entry name=\"Block_US_RU_CN_TO_DMZ-F5\"><action>deny</action></entry></rules></security></rulebase></entry><entry name=\"vsys2\"><rulebase><security><rules><entry name=\"Unchanged\"><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""
        desired = b"""<config version=\"12.1.0\"><shared><certificate><entry name=\"fw-cert\"><private-key>new-placeholder</private-key></entry></certificate></shared><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys1\"><rulebase><security><rules><entry name=\"Block_US_RU_CN_TO_DMZ-F5 test\"><action>deny</action></entry></rules></security></rulebase></entry><entry name=\"vsys2\"><rulebase><security><rules><entry name=\"Unchanged\"><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(
            {(change["action"], change["scope"], change["family"]) for change in changes},
            {
                ("set", "vsys1", "policy:security"),
                ("delete", "vsys1", "policy:security"),
                ("edit", "Shared", "protected"),
            },
        )
        self.assertTrue(all(change["xpath"] != "/config/devices" for change in changes))
        for change in changes:
            if not change["element"]:
                continue
            payload = ET.fromstring(change["element"])
            self.assertTrue(all(
                not {"admin", "dirtyId", "time"}.intersection(node.attrib)
                for node in payload.iter()
            ))

    def test_panorama_pre_rule_rename_ignores_response_metadata(self):
        current = b"""<config><devices admin=\"admin\" dirtyId=\"8\" time=\"2026/10/23 10:13:50\"><entry name=\"localhost.localdomain\" admin=\"admin\" dirtyId=\"8\" time=\"2026/10/23 10:13:50\"><device-group admin=\"admin\" dirtyId=\"8\" time=\"2026/10/23 10:13:50\"><entry name=\"HQ\" admin=\"admin\" dirtyId=\"8\" time=\"2026/10/23 10:13:50\"><pre-rulebase><security><rules><entry name=\"Old shared rule\"><action>allow</action></entry></rules></security></pre-rulebase></entry></device-group></entry></devices></config>"""
        desired = b"""<config><devices><entry name=\"localhost.localdomain\"><device-group><entry name=\"HQ\"><pre-rulebase><security><rules><entry name=\"Renamed shared rule\"><action>allow</action></entry></rules></security></pre-rulebase></entry></device-group></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(
            {(change["action"], change["scope"], change["family"]) for change in changes},
            {
                ("set", "HQ", "policy:security"),
                ("delete", "HQ", "policy:security"),
            },
        )

    def test_shared_policy_rename_ignores_response_metadata(self):
        current = b"""<config><shared admin=\"admin\" dirtyId=\"9\" time=\"2026/10/23 10:13:50\"><pre-rulebase><security><rules><entry name=\"Old shared rule\"><action>allow</action></entry></rules></security></pre-rulebase></shared></config>"""
        desired = b"""<config><shared><pre-rulebase><security><rules><entry name=\"Renamed shared rule\"><action>allow</action></entry></rules></security></pre-rulebase></shared></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(
            {(change["action"], change["scope"], change["family"]) for change in changes},
            {
                ("set", "Shared", "policy:security"),
                ("delete", "Shared", "policy:security"),
            },
        )

    def test_new_shared_syslog_profile_is_one_set_at_profile_collection(self):
        current = b"""<config><shared><log-settings><syslog /></log-settings></shared></config>"""
        desired = b"""<config><shared><log-settings><syslog><entry name="Pa_Policy_Forge"><server><entry name="PolicyForge"><server>10.74.80.46</server><transport>UDP</transport><port>514</port></entry></server></entry></syslog></log-settings></shared></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        change = changes[0]
        self.assertEqual(change["action"], "set")
        self.assertEqual(change["xpath"], "/config/shared/log-settings/syslog")
        payload = ET.fromstring(change["element"])
        self.assertEqual(payload.tag, "entry")
        self.assertEqual(payload.attrib["name"], "Pa_Policy_Forge")
        self.assertEqual(payload.find("./server/entry").attrib["name"], "PolicyForge")


    def test_legacy_shared_syslog_profile_uses_pan_os_log_settings_path(self):
        current = b"""<config><shared><log-settings><syslog /></log-settings></shared></config>"""
        desired = b"""<config><shared><server-profile><syslog><entry name="Pa_Policy_Forge"><server><entry name="PolicyForge"><server>10.74.80.46</server><transport>UDP</transport><port>514</port></entry></server></entry></syslog></server-profile></shared></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["action"], "set")
        self.assertEqual(changes[0]["xpath"], "/config/shared/log-settings/syslog")
        self.assertEqual(changes[0]["family"], "device:log-settings")
        payload = ET.fromstring(changes[0]["element"])
        self.assertEqual(payload.tag, "entry")
        self.assertEqual(payload.attrib["name"], "Pa_Policy_Forge")

    def test_preparsed_desired_config_matches_xml_path_without_mutating_cached_root(self):
        current = b"<config><shared><log-settings><syslog /></log-settings></shared></config>"
        desired = b"<config><shared><server-profile><syslog><entry name=\"Pa_Policy_Forge\"><server /></entry></syslog></server-profile></shared></config>"
        desired_root, _ = main.parse_snapshot(desired, expected_kind="panos")

        expected = main.config_push_delta(current, desired)
        actual = main.config_push_delta(current, desired, desired_root=desired_root)

        self.assertEqual(actual, expected)
        self.assertIsNotNone(desired_root.find("./shared/server-profile/syslog"))
        self.assertIsNone(desired_root.find("./shared/log-settings/syslog"))

    def test_preview_candidate_cache_reuses_only_the_recent_read(self):
        main._candidate_preview_cache.clear()
        profile = {"id": 37, "updated_at": "2026-10-23T12:00:00Z"}
        candidate = b"<config><shared /></config>"
        try:
            with patch.object(main, "fetch_panos_candidate_xml", return_value=("", "", None, candidate)) as fetch:
                first = main.fetch_panos_candidate_xml_for_preview(profile)
                second = main.fetch_panos_candidate_xml_for_preview(profile)

            self.assertEqual(first, (candidate, False))
            self.assertEqual(second, (candidate, True))
            fetch.assert_called_once_with(profile)
        finally:
            main._candidate_preview_cache.clear()


    def test_admin_role_ui_permission_catalogs_are_not_pushable_device_profiles(self):
        current = b"""<config><shared><admin-role><entry name="Read only"><role><device><webui><device><server-profile><dns /><syslog /></server-profile><log-settings><system><enable>yes</enable></system></log-settings></device></webui></device></role></entry></admin-role></shared><predefined><admin-role><entry name="securityadmin"><role><device><webui><device><server-profile><ldap /></server-profile><log-settings><traffic><enable>yes</enable></traffic></log-settings></device></webui></device></role></entry></admin-role></predefined></config>"""
        desired = b"""<config><shared><admin-role><entry name="Read only"><role><device><webui><device><server-profile><radius /></server-profile></device></webui></device></role></entry></admin-role></shared><predefined><admin-role><entry name="securityadmin"><role><device><webui><device><server-profile><syslog /></server-profile><log-settings><system><enable>no</enable></system></log-settings></device></webui></device></role></entry></admin-role></predefined></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(changes, [])

    def test_multi_vsys_additions_are_diffed_per_named_entry(self):
        current = b"""<config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys1\"><address><entry name=\"Existing1\"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address><rulebase><security><rules><entry name=\"Keep1\"><action>allow</action></entry></rules></security></rulebase></entry><entry name=\"vsys2\"><address><entry name=\"Existing2\"><ip-netmask>192.0.2.2/32</ip-netmask></entry></address><rulebase><security><rules><entry name=\"Keep2\"><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys1\"><address><entry name=\"Existing1\"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address><rulebase><security><rules><entry name=\"Keep1\"><action>allow</action></entry></rules></security></rulebase></entry><entry name=\"vsys2\"><address><entry name=\"Existing2\"><ip-netmask>192.0.2.2/32</ip-netmask></entry><entry name=\"PF_E2E_ADDR\"><ip-netmask>203.0.113.79/32</ip-netmask></entry></address><rulebase><security><rules><entry name=\"Keep2\"><action>allow</action></entry><entry name=\"PF_E2E_RULE\"><action>deny</action><disabled>yes</disabled></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)
        address = next(change for change in changes if change["name"] == "PF_E2E_ADDR")
        rule = next(change for change in changes if change["name"] == "PF_E2E_RULE" and change["action"] == "set")

        self.assertEqual((address["action"], address["scope"], address["family"]), ("set", "vsys2", "object:address"))
        self.assertEqual((rule["scope"], rule["family"]), ("vsys2", "policy:security"))
        self.assertFalse(any(change["action"] == "move" for change in changes))
        self.assertFalse(any(change["family"] == "other:configuration" for change in changes))


    def test_device_container_indentation_does_not_hide_vsys_changes(self):
        current = b"""<config>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1"><address /></entry>
        <entry name="vsys2"><address><entry name="Existing"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address><rulebase><security><rules><entry name="Keep"><action>allow</action></entry></rules></security></rulebase></entry>
      </vsys>
    </entry>
  </devices>
</config>"""
        desired = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address /></entry><entry name="vsys2"><address><entry name="Existing"><ip-netmask>192.0.2.1/32</ip-netmask></entry><entry name="PF_E2E_ADDR"><ip-netmask>203.0.113.79/32</ip-netmask></entry></address><rulebase><security><rules><entry name="Keep"><action>allow</action></entry><entry name="PF_E2E_RULE"><action>deny</action><disabled>yes</disabled></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(
            {(change["action"], change["name"], change["scope"], change["family"]) for change in changes},
            {
                ("set", "PF_E2E_ADDR", "vsys2", "object:address"),
                ("set", "PF_E2E_RULE", "vsys2", "policy:security"),
            },
        )


    def test_inserted_policy_moves_only_the_new_rule_to_its_anchor(self):
        current = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2"><rulebase><security><rules><entry name="Keep1"><action>allow</action></entry><entry name="Keep2"><action>deny</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2"><rulebase><security><rules><entry name="Keep1"><action>allow</action></entry><entry name="PF_E2E_RULE"><action>deny</action><disabled>yes</disabled></entry><entry name="Keep2"><action>deny</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)
        moves = [change for change in changes if change["action"] == "move"]

        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0]["name"], "PF_E2E_RULE")
        self.assertEqual(moves[0]["where"], "after")
        self.assertEqual(moves[0]["dst"], "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='Keep1']")


    def test_appending_named_entries_does_not_edit_the_previous_entry_tail(self):
        current = b"""<config>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys2">
          <address>
            <entry name="srvfixsnmp_10_10_101_186">
              <ip-netmask>10.10.101.186</ip-netmask>
            </entry>
          </address>
          <rulebase><security><rules>
            <entry name="cleanup-rule"><from><member>any</member></from><to><member>any</member></to><action>drop</action></entry>
          </rules></security></rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>"""
        desired = b"""<config>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys2">
          <address>
            <entry name="srvfixsnmp_10_10_101_186">
              <ip-netmask>10.10.101.186</ip-netmask>
            </entry>
            <entry name="PF_E2E_ADDR"><ip-netmask>203.0.113.78/32</ip-netmask></entry>
          </address>
          <rulebase><security><rules>
            <entry name="cleanup-rule"><from><member>any</member></from><to><member>any</member></to><action>drop</action></entry>
            <entry name="PF_E2E_RULE"><action>allow</action><disabled>yes</disabled></entry>
          </rules></security></rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(
            {(change["action"], change["name"], change["scope"], change["family"]) for change in changes},
            {
                ("set", "PF_E2E_ADDR", "vsys2", "object:address"),
                ("set", "PF_E2E_RULE", "vsys2", "policy:security"),
            },
        )


    def test_specific_policy_members_replace_exclusive_wildcards(self):
        policy = {
            "from": ["any", "Trust"], "to": ["any", "Server"],
            "source": ["any", "test-host"], "destination": ["any", "test-group"],
            "application": ["any", "ssl"], "service": ["application-default", "tcp-8443"],
            "source_user": ["any", "test-user"], "source_hip": ["any", "compliant"],
            "destination_user": ["any", "test-service-user"],
            "destination_hip": ["any", "managed"], "category": ["any", "business"],
            "untouched": ["any"],
        }

        normalized = main.normalize_policy_wildcard_members(policy)

        self.assertEqual(normalized["source"], ["test-host"])
        self.assertEqual(normalized["destination"], ["test-group"])
        self.assertEqual(normalized["service"], ["tcp-8443"])
        self.assertEqual(normalized["from"], ["Trust"])
        self.assertEqual(normalized["application"], ["ssl"])
        self.assertEqual(normalized["untouched"], ["any"])
        self.assertEqual(policy["source"], ["any", "test-host"])


if __name__ == "__main__":
    unittest.main()
