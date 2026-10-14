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
        current = b"""<config><shared><server-profile><syslog><entry name="Pa_Policy_Forge"><server /></entry></syslog></server-profile></shared></config>"""
        desired = b"""<config><shared><server-profile><syslog><entry name="Pa_Policy_Forge"><server><entry name="PolicyForge"><server>10.74.80.46</server><transport>UDP</transport><port>514</port><format>BSD</format><facility>LOG_USER</facility></entry></server></entry></syslog></server-profile></shared></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        change = changes[0]
        self.assertEqual(change["action"], "edit")
        self.assertEqual(
            change["xpath"],
            "/config/shared/server-profile/syslog/entry[@name='Pa_Policy_Forge']",
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
        current = b"""<config><shared><server-profile><syslog /></server-profile></shared></config>"""
        desired = b"""<config><shared><server-profile><syslog><entry name="Pa_Policy_Forge"><server><entry name="PolicyForge"><server>10.74.80.46</server><transport>UDP</transport><port>514</port></entry></server></entry></syslog></server-profile></shared></config>"""

        changes = main.config_push_delta(current, desired)

        self.assertEqual(len(changes), 1)
        change = changes[0]
        self.assertEqual(change["action"], "set")
        self.assertEqual(change["xpath"], "/config/shared/server-profile/syslog")
        payload = ET.fromstring(change["element"])
        self.assertEqual(payload.tag, "entry")
        self.assertEqual(payload.attrib["name"], "Pa_Policy_Forge")
        self.assertEqual(payload.find("./server/entry").attrib["name"], "PolicyForge")


if __name__ == "__main__":
    unittest.main()
