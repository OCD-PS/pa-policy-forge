import json
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-adapter-test-"))
os.environ.setdefault("PPF_SYSLOG_PORT", "55141")

from app import main


class TargetAdapterTests(unittest.TestCase):
    def profile(self, target, **settings):
        defaults = {"device_group": "Branches", "rulebase": "pre", "vsys": "vsys2", "endpoint": "https://example.invalid"}
        defaults.update(settings)
        return {"target_type": target, "settings_json": json.dumps(defaults), "secret_blob": b""}

    def test_panorama_policy_xpath_uses_device_group_and_pre_rulebase(self):
        xpath = main.panos_policy_xpath(self.profile("panorama"), "nat")
        self.assertIn("device-group/entry[@name='Branches']/pre-rulebase/nat/rules", xpath)

    def test_profile_without_firewall_serial_has_no_flow_identity(self):
        profile = {"serial": "", "settings_json": json.dumps({"passive_serial": ""})}
        self.assertEqual(main.profile_serials(profile), [])

    def test_standalone_policy_xpath_uses_vsys_rulebase(self):
        xpath = main.panos_policy_xpath(self.profile("panos"), "decryption")
        self.assertIn("vsys/entry[@name='vsys2']/rulebase/decryption/rules", xpath)

    def test_xml_policy_update_preserves_nat_translation(self):
        policy = main.xml_entry_to_policy(main.ET.fromstring("<entry name='NAT-1'><from><member>Trust</member></from><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation><disabled>no</disabled></entry>"), "nat")
        policy["from"] = ["Clients"]
        result = main.ET.fromstring(main.update_xml_policy(policy))
        self.assertEqual(result.findtext("./from/member"), "Clients")
        self.assertEqual(result.findtext("./source-translation/dynamic-ip-and-port/interface-address/interface"), "ethernet1/1")

    def test_panorama_write_is_candidate_edit_only(self):
        profile = self.profile("panorama")
        policy = main.xml_entry_to_policy(main.ET.fromstring("<entry name='NAT-1'><from><member>Trust</member></from></entry>"), "nat")
        with patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.panos_api_post", return_value="<response status='success'><result/></response>") as request, patch("app.main.policy_api.require_success"):
            main.write_target_policy(profile, "nat", policy)
        params = request.call_args.args[1]
        self.assertEqual(params["type"], "config")
        self.assertEqual(params["action"], "edit")
        self.assertNotIn("commit", params.values())

    def test_panorama_new_objects_default_to_shared(self):
        profile = self.profile("panorama")
        draft = {"object_type": "addresses", "operation": "create", "payload": {"name": "Web", "ip_netmask": "192.0.2.10/32"}}
        with patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.panos_api_post", return_value="<response status='success'><result/></response>") as request, patch("app.main.policy_api.require_success"):
            main.write_panos_object_draft(profile, draft)
        self.assertEqual(request.call_args.args[1]["xpath"], "/config/shared/address")

    def test_scm_nat_payload_preserves_translation(self):
        raw = {"id": "n1", "name": "NAT-1", "from": ["Trust"], "source_translation": {"dynamic_ip_and_port": {"interface_address": {"interface": "ethernet1/1"}}}}
        policy = main.normalize_policy(raw, "nat")
        policy["from"] = ["Clients"]
        payload = main.target_policy_payload(policy, {"folder": "Branch"}, "nat")
        self.assertEqual(payload["from"], ["Clients"])
        self.assertEqual(payload["source_translation"], raw["source_translation"])
        self.assertEqual(payload["folder"], "Branch")

    def test_standalone_zone_scope_uses_vsys(self):
        base = main.panos_object_bases(self.profile("panos"), "zones")[0]
        self.assertIn("vsys/entry[@name='vsys2']", base)

    def test_panorama_zone_scope_uses_device_group_reference_template(self):
        responses = ["<response status='success'><result><entry name='Branches'><reference-templates><member>Branch-Template</member></reference-templates></entry></result></response>", "<response status='success'><result/></response>"]
        with patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.policy_api.api_get", side_effect=responses):
            base = main.panos_object_bases(self.profile("panorama"), "zones")[0]
        self.assertIn("template/entry[@name='Branch-Template']", base)
        self.assertIn("vsys/entry[@name='vsys2']", base)

    def test_panorama_without_reference_template_keeps_zones_freeform(self):
        response = "<response status='success'><result><entry name='Branches'/></result></response>"
        with patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.policy_api.api_get", return_value=response):
            self.assertEqual(main.panos_object_bases(self.profile("panorama"), "zones"), [])

    def test_zone_xml_preserves_type_interfaces_and_profiles(self):
        xml = main.ET.fromstring(main.object_payload_xml({"name": "Clients", "network": {"layer3": ["ethernet1/1"]}, "enable_user_identification": True, "zone_protection_profile": "strict"}))
        self.assertEqual(xml.findtext("./network/layer3/member"), "ethernet1/1")
        self.assertEqual(xml.findtext("./enable-user-identification"), "yes")
        self.assertEqual(xml.findtext("./zone-protection-profile"), "strict")

    def test_panorama_zone_create_uses_template_candidate(self):
        profile = self.profile("panorama")
        draft = {"object_type": "zones", "operation": "create", "payload": {"name": "Clients", "network": {"layer3": []}}}
        with patch("app.main.panos_object_bases", return_value=["/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Branch-Template']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys2']"]), patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.panos_api_post", return_value="<response status='success'><result/></response>") as request, patch("app.main.policy_api.require_success"):
            main.write_panos_object_draft(profile, draft)
        params = request.call_args.args[1]
        self.assertIn("template/entry[@name='Branch-Template']", params["xpath"])
        self.assertEqual(params["action"], "set")


if __name__ == "__main__":
    unittest.main()
