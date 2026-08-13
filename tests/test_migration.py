import json
import os
import tempfile
import unittest

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-migration-test-"))
os.environ.setdefault("PPF_SYSLOG_PORT", "55149")
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "unit-test-bootstrap-password")

from app.migration import PARSERS, MigrationError, merge_model_into_panos_xml, parse_vendor, panos_fragment, reconcile_model, scm_items
from app import main


class MigrationTests(unittest.TestCase):
    def test_all_approved_vendor_adapters_are_registered(self):
        self.assertEqual(set(PARSERS), {"cisco-asa", "cisco-ios", "checkpoint", "fortinet", "juniper-srx", "generic"})

    def test_fortinet_objects_and_policy_map_to_neutral_model_and_scm(self):
        config = b'''config firewall address
edit "web01"
set subnet 10.0.0.10 255.255.255.255
next
end
config firewall service custom
edit "HTTPS-CUSTOM"
set tcp-portrange 8443
next
end
config firewall policy
edit 7
set name "Clients-to-web"
set srcintf "trust"
set dstintf "dmz"
set srcaddr "all"
set dstaddr "web01"
set service "HTTPS-CUSTOM"
set action accept
set nat enable
next
end'''
        model = parse_vendor("fortinet", config, "fortigate.conf")
        self.assertEqual(model.addresses[0].value, "10.0.0.10/32")
        self.assertEqual(model.security_rules[0].destination, ["web01"])
        mapped = scm_items(model)
        self.assertEqual([item["kind"] for item in mapped], ["addresses", "services", "policy:security", "policy:nat"])
        self.assertEqual(mapped[-2]["payload"]["from"], ["trust"])
        self.assertIn("source_translation", mapped[-1]["payload"])

    def test_fortinet_vip_maps_to_destination_nat_for_scm(self):
        model = parse_vendor("fortinet", b'''config firewall vip
edit "web-vip"
set extip 203.0.113.10
set mappedip 10.0.0.10
set mappedport 443
next
end''', "forti.conf")
        self.assertEqual(len(model.nat_rules), 1)
        nat_item = next(item for item in scm_items(model) if item["kind"] == "policy:nat")
        self.assertEqual(nat_item["payload"]["destination_translation"]["translated_port"], "443")

    def test_asa_acl_and_object_are_parsed(self):
        model = parse_vendor("cisco-asa", b'''object network WEB
 host 192.0.2.10
access-list OUT extended permit tcp any object WEB eq 443''', "asa.txt")
        self.assertEqual(model.addresses[0].name, "WEB")
        self.assertEqual(model.security_rules[0].service, ["tcp-443"])

    def test_ios_acl_is_parsed(self):
        model = parse_vendor("cisco-ios", b'''ip access-list extended EDGE
 permit tcp any host 203.0.113.10 eq 443''', "ios.txt")
        self.assertEqual(len(model.security_rules), 1)
        self.assertEqual(model.security_rules[0].name, "EDGE-2")

    def test_checkpoint_json_is_parsed(self):
        data = {"objects": [{"type": "host", "name": "srv", "ipv4-address": "192.0.2.4"}, {"type": "group", "name": "servers", "members": ["srv", {"name": "db"}]}], "rulebase": [{"type": "access-rule", "name": "allow-srv", "source": ["Any"], "destination": ["srv"], "service": ["https"], "action": "Accept"}]}
        model = parse_vendor("checkpoint", json.dumps(data).encode(), "checkpoint.json")
        self.assertEqual(model.addresses[0].name, "srv")
        self.assertEqual(model.address_groups[0].members, ["srv", "db"])
        self.assertEqual(model.security_rules[0].action, "allow")

    def test_srx_set_commands_are_parsed(self):
        model = parse_vendor("juniper-srx", b'''set security address-book global address app1 198.51.100.10/32
set security policies from-zone trust to-zone untrust policy web match source-address any
set security policies from-zone trust to-zone untrust policy web match destination-address app1
set security policies from-zone trust to-zone untrust policy web match application junos-https
set security policies from-zone trust to-zone untrust policy web then permit''', "srx.set")
        self.assertEqual(model.addresses[0].name, "app1")
        self.assertEqual(model.security_rules[0].from_zones, ["trust"])

    def test_panos_fragment_supports_panorama_and_standalone(self):
        model = parse_vendor("generic", b'[{"name":"srv","value":"192.0.2.1/32"}]', "generic.json")
        panorama = panos_fragment(model, "Branches", True, "post").decode()
        standalone = panos_fragment(model, "vsys2", False).decode()
        self.assertIn('<device-group><entry name="Branches"><post-rulebase>', panorama)
        self.assertIn('<vsys><entry name="vsys2"><rulebase>', standalone)

    def test_scm_reconciliation_reuses_equivalent_address_and_rewrites_policy(self):
        model = parse_vendor("fortinet", b'''config firewall address
edit "old-web"
set subnet 192.0.2.10 255.255.255.255
next
end
config firewall policy
edit 1
set name "to-web"
set srcaddr "all"
set dstaddr "old-web"
set service "ALL"
next
end''', "forti.conf")
        reconciled, plan = reconcile_model(model, {
            "addresses": [{"name": "existing-web", "ip_netmask": "192.0.2.10/32"}],
            "address-groups": [], "services": [], "service-groups": [],
            "policy:security": [], "policy:nat": [],
        })
        self.assertEqual(reconciled.addresses, [])
        self.assertEqual(reconciled.security_rules[0].destination, ["existing-web"])
        self.assertEqual(plan["reuse"], 1)

    def test_scm_reconciliation_reuses_equivalent_group_after_member_rewrite(self):
        model = parse_vendor("fortinet", b'''config firewall address
edit "imported-web"
set subnet 192.0.2.10 255.255.255.255
next
end
config firewall addrgrp
edit "imported-servers"
set member "imported-web"
next
end
config firewall policy
edit 1
set name "to-servers"
set srcaddr "all"
set dstaddr "imported-servers"
set service "ALL"
next
end''', "forti.conf")
        reconciled, plan = reconcile_model(model, {
            "addresses": [{"name": "existing-web", "ip_netmask": "192.0.2.10/32"}],
            "address-groups": [{"name": "existing-servers", "static": ["existing-web"]}],
            "services": [], "service-groups": [], "policy:security": [], "policy:nat": [],
        })
        self.assertEqual(reconciled.addresses, [])
        self.assertEqual(reconciled.address_groups, [])
        self.assertEqual(reconciled.security_rules[0].destination, ["existing-servers"])
        self.assertEqual(plan["reuse"], 2)

    def test_offline_merge_preserves_base_and_blocks_incompatible_name_collision(self):
        base = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="existing"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address><rulebase/></entry></vsys></entry></devices></config>'''
        equivalent = parse_vendor("generic", b'[{"name":"imported","value":"192.0.2.10/32"}]', "generic.json")
        merged, plan = merge_model_into_panos_xml(base, equivalent, "vsys1")
        self.assertIn(b'name="existing"', merged)
        self.assertNotIn(b'name="imported"', merged)
        self.assertEqual(plan["renamed_references"], {"imported": "existing"})
        conflict = parse_vendor("generic", b'[{"name":"existing","value":"198.51.100.1/32"}]', "generic.json")
        with self.assertRaises(MigrationError):
            merge_model_into_panos_xml(base, conflict, "vsys1")

    def test_operational_device_pages_are_not_in_navigation(self):
        for label in ("Licenses", "Dynamic Updates", "Software"):
            self.assertNotIn(label, main.WORKSPACE_DEVICE_NAV)

    def test_migration_routes_and_templates_are_protected_and_compile(self):
        main.app.jinja_env.get_template("migration.html")
        main.app.jinja_env.get_template("migration_preview.html")
        client = main.app.test_client()
        for path in ("/migration", "/migration/projects/1"):
            response = client.get(path, base_url="https://forge.test")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["Location"], "/login")

    def test_migration_home_renders_after_login(self):
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(cookie_name, serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}), domain="forge.test", secure=True)
        response = client.get("/migration", base_url="https://forge.test")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Migratieprojecten", page)
        self.assertIn("Expedition-inspired", page)
        self.assertIn("SCM, Panorama of standalone PAN-OS", page)


if __name__ == "__main__":
    unittest.main()
