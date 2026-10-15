import os
import tempfile
import unittest
import xml.etree.ElementTree as ET

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

    def test_vsys_policy_edit_keeps_complete_config_xpath_and_owner(self):
        current = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules><entry name="Allow"><action>deny</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules><entry name="Allow"><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        change = changes[0]
        self.assertEqual(change["action"], "edit")
        self.assertEqual(
            change["xpath"],
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='Allow']",
        )
        self.assertEqual(change["scope"], "vsys1")
        self.assertEqual(change["family"], "policy:security")

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


    def test_inserted_policy_moves_only_the_new_rule_to_its_anchor(self):
        current = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2"><rulebase><security><rules><entry name="Keep1"><action>allow</action></entry><entry name="Keep2"><action>deny</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""
        desired = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2"><rulebase><security><rules><entry name="Keep1"><action>allow</action></entry><entry name="PF_E2E_RULE"><action>deny</action><disabled>yes</disabled></entry><entry name="Keep2"><action>deny</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""

        changes = main.config_push_delta(current, desired)
        moves = [change for change in changes if change["action"] == "move"]

        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0]["name"], "PF_E2E_RULE")
        self.assertEqual(moves[0]["where"], "after")
        self.assertEqual(moves[0]["dst"], "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='Keep1']")


if __name__ == "__main__":
    unittest.main()
