import json
import io
import os
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-migration-test-"))
os.environ.setdefault("PPF_SYSLOG_PORT", "55149")
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "unit-test-bootstrap-password")

from app.migration import Address, MigrationModel, PARSERS, MigrationError, apply_merge_rules, apply_transform_rules, merge_inventory, merge_model_into_panos_xml, migration_base_xml, migration_collision_report, migration_zone_names, parse_vendor, panos_fragment, reconcile_model, scm_items, set_panos_ha_mode
from app import main

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class MigrationTests(unittest.TestCase):
    def test_all_approved_vendor_adapters_are_registered(self):
        self.assertEqual(set(PARSERS), {"panos", "panos-csv", "cisco-asa", "cisco-ios", "checkpoint", "fortinet", "juniper-srx", "algosec", "stonesoft", "generic"})

    def test_panos_csv_imports_objects_services_and_rules(self):
        addresses=parse_vendor("panos-csv",b'name,type,value\nweb,address,10.0.0.10/32\n',"addresses.csv")
        services=parse_vendor("panos-csv",b'name,type,protocol,port\nweb-https,service,tcp,443\n',"services.csv")
        rules=parse_vendor("panos-csv",b'name,type,source_zone,destination_zone,source,destination,application,service,action\nallow-web,security,Trust,DMZ,any,web,ssl,web-https,allow\n',"rules.csv")
        self.assertEqual(addresses.addresses[0].value,"10.0.0.10/32")
        self.assertEqual(services.services[0].port,"443")
        self.assertEqual(rules.security_rules[0].to_zones,["DMZ"])

    def test_panos_full_config_imports_interfaces_zones_objects_and_rules(self):
        source = b'''<config version="11.1.0"><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/12"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3></entry></ethernet></interface></network><vsys><entry name="vsys1"><zone><entry name="Trust"><network><layer3><member>ethernet1/12</member></layer3></network></entry></zone><address><entry name="server"><ip-netmask>10.0.0.10/32</ip-netmask></entry></address><service><entry name="tcp-8443"><protocol><tcp><port>8443</port></tcp></protocol></entry></service><rulebase><security><rules><entry name="allow-server"><from><member>Trust</member></from><to><member>Trust</member></to><source><member>any</member></source><destination><member>server</member></destination><application><member>ssl</member></application><service><member>application-default</member></service><action>allow</action></entry></rules></security><nat><rules><entry name="dnat-server"><from><member>Untrust</member></from><to><member>Untrust</member></to><source><member>any</member></source><destination><member>192.0.2.10</member></destination><service>tcp-8443</service><destination-translation><translated-address>server</translated-address><translated-port>8443</translated-port></destination-translation></entry></rules></nat></rulebase></entry></vsys></entry></devices></config>'''
        model = parse_vendor("panos", source, "pa-5210.xml")
        self.assertEqual(model.counts()["interfaces"], 1)
        self.assertEqual(model.interfaces[0]["name"], "ethernet1/12")
        self.assertEqual(model.zones[0]["name"], "Trust")
        self.assertEqual(model.addresses[0].name, "server")
        self.assertEqual(model.security_rules[0].name, "allow-server")
        self.assertEqual(model.nat_rules[0].service, ["tcp-8443"])
        self.assertEqual(model.nat_rules[0].destination_translation["translated_port"], "8443")

        base = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet/></interface></network><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        merged, plan = merge_model_into_panos_xml(base, model, "vsys1")
        self.assertIn(b'<entry name="ethernet1/12">', merged)
        self.assertIn(b'<zone>', merged)
        self.assertIn(b'<entry name="allow-server">', merged)
        self.assertIn(b'<service>tcp-8443</service>', merged)
        self.assertNotIn(b'<application><member>any</member></application>', merged)
        self.assertEqual(plan["create"], 6)

    def test_panos_import_preserves_extended_objects_policies_and_network(self):
        source=b'''<config><devices><entry name="localhost.localdomain"><network><virtual-router><entry name="default"><protocol/></entry></virtual-router><tunnel><ipsec><entry name="vpn-a"><auto-key/></entry></ipsec></tunnel></network><vsys><entry name="vsys1"><application><entry name="custom-app"><signature/></entry></application><tag><entry name="Blue"><color>color1</color></entry></tag><profiles><url-filtering><entry name="URL-Allow"><allow><member>example.com</member></allow></entry></url-filtering></profiles><rulebase><qos><rules><entry name="qos-1"><from><member>Trust</member></from></entry></rules></qos></rulebase></entry></vsys></entry></devices></config>'''
        model=parse_vendor("panos",source,"extended.xml")
        self.assertEqual(model.counts()["applications"],1)
        self.assertEqual(model.counts()["tags"],1)
        self.assertEqual(model.counts()["security_profiles"],1)
        self.assertEqual(model.counts()["qos_rules"],1)
        self.assertEqual(model.counts()["virtual_routers"],1)
        self.assertEqual(model.counts()["ipsec_tunnels"],1)
        base=b'''<config><devices><entry name="localhost.localdomain"><network/><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        merged,plan=merge_model_into_panos_xml(base,model,"vsys1")
        self.assertIn(b'custom-app',merged); self.assertIn(b'URL-Allow',merged)
        self.assertIn(b'qos-1',merged); self.assertIn(b'vpn-a',merged)
        self.assertEqual(plan["conflicts"],[])

    def test_expedition_style_merge_rewrites_references(self):
        model=parse_vendor("generic",b'[{"name":"server-old","value":"10.0.0.1/32"},{"name":"server-main","value":"10.0.0.1/32"}]',"objects.json")
        candidates=merge_inventory(model)
        self.assertTrue(any(item["kind"]=="addresses" and item["reason"]=="value" for item in candidates))
        merged=apply_merge_rules(model,[{"kind":"addresses","master":"server-main|||","members":["server-main|||","server-old|||"]}])
        self.assertEqual([item.name for item in merged.addresses],["server-main"])

    def test_same_name_conflict_keeps_selected_source_as_master(self):
        model=MigrationModel("merged","two sources",addresses=[Address("shared","10.0.0.1/32",source_ref="A"),Address("shared","10.0.0.2/32",source_ref="B")])
        candidates=merge_inventory(model)
        self.assertTrue(any(item["reason"]=="name" and len(item["items"])==2 for item in candidates))
        merged=apply_merge_rules(model,[{"kind":"addresses","master":"shared|||B","members":["shared|||A","shared|||B"]}])
        self.assertEqual(len(merged.addresses),1)
        self.assertEqual(merged.addresses[0].value,"10.0.0.2/32")

    def test_rename_transform_changes_object_identity(self):
        model=MigrationModel("merged","source",addresses=[Address("old-server","10.0.0.3/32",source_ref="A")])
        transformed=apply_transform_rules(model,[{"operation":"rename","kind":"addresses","selector":"old-server|||A","value":"new-server"}])
        self.assertEqual(transformed.addresses[0].name,"new-server")

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

    def test_checkpoint_rich_export_maps_dual_stack_access_and_nat(self):
        source = (FIXTURES / "checkpoint-rich.json").read_bytes()
        model = parse_vendor("checkpoint", source, "checkpoint-rich.json")
        self.assertEqual(model.counts()["addresses"], 9)
        self.assertEqual(model.counts()["address_groups"], 3)
        self.assertEqual(model.counts()["services"], 3)
        self.assertEqual(model.counts()["service_groups"], 1)
        self.assertEqual(model.counts()["security_rules"], 2)
        self.assertEqual(model.counts()["nat_rules"], 2)
        self.assertEqual(next(group for group in model.address_groups if group.name == "Atlas-Dual-Host").members, ["Atlas-Dual-Host-ipv4", "Atlas-Dual-Host-ipv6"])
        self.assertEqual(next(service for service in model.services if service.name == "Atlas-TCP-High").port, "1025-65535")
        allow = next(rule for rule in model.security_rules if rule.name == "Clients-to-Atlas")
        self.assertEqual(allow.source, ["Atlas-Clients", "Atlas-Admin-Range"])
        self.assertEqual(allow.destination, ["Atlas-Servers"])
        self.assertEqual(allow.service, ["Atlas-App-Services"])
        self.assertEqual(allow.action, "allow")
        self.assertIn("Track: Log", allow.description)
        disabled = next(rule for rule in model.security_rules if rule.name == "Disabled-Admin-Drop")
        self.assertTrue(disabled.disabled)
        self.assertEqual(disabled.action, "deny")
        hide = next(rule for rule in model.nat_rules if rule.name == "Atlas-Clients-Hide-NAT")
        self.assertEqual(hide.source_translation, {"dynamic_ip_and_port": {"translated_address": ["Atlas-NAT-Public"]}})
        inbound = next(rule for rule in model.nat_rules if rule.name == "Atlas-Inbound-Static-NAT")
        self.assertEqual(inbound.destination_translation, {"translated_address": "Atlas-Web-Internal", "translated_port": "8443"})
        self.assertTrue(any("application/user mapping" in item for item in model.unsupported))
        self.assertTrue(any("veld content vereist review" in item for item in model.warnings))

        base = migration_base_xml(model, "vsys1")
        merged, plan = merge_model_into_panos_xml(base, model, "vsys1")
        root, _ = main.parse_snapshot(merged, expected_kind="panos")
        self.assertEqual(len(root.findall(".//vsys/entry/rulebase/security/rules/entry")), 2)
        self.assertEqual(len(root.findall(".//vsys/entry/rulebase/nat/rules/entry")), 2)
        self.assertIsNotNone(root.find(".//vsys/entry/address/entry[@name='Atlas-Wildcard']/ip-wildcard"))
        self.assertGreater(plan["create"], 15)

    def test_checkpoint_show_package_tar_uses_one_global_uid_dictionary(self):
        documents = {
            "Standard_objects.json": [
                {"type": "CpmiAnyObject", "uid": "any", "name": "Any"},
                {"type": "CpmiAnyObject", "uid": "original", "name": "Original"},
            ],
            "Access-Management_server.json": {
                "objects-dictionary": [
                    {"type": "rulebaseaction", "uid": "action-accept", "name": "Accept"},
                    {"type": "track", "uid": "track-log", "name": "Log"},
                    {"type": "host", "uid": "host-web", "name": "Web", "ipv4-address": "192.0.2.10"},
                    {"type": "service-tcp", "uid": "svc-https", "name": "HTTPS", "port": "443"},
                ],
                "rulebase": [
                    {"type": "access-rule", "uid": "rule-1", "name": "Allow Web", "source": ["any"], "destination": ["host-web"], "service": ["svc-https"], "action": "action-accept", "track": {"uid": "track-log"}},
                ],
            },
            "Standard_NAT-Management_server.json": [
                {"type": "nat-rule", "uid": "nat-1", "name": "Web NAT", "original-source": ["any"], "original-destination": ["host-web"], "original-service": ["svc-https"], "translated-source": ["original"], "translated-destination": ["original"], "translated-service": ["original"]},
            ],
        }
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            for name, document in documents.items():
                raw = json.dumps(document).encode()
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        model = parse_vendor("checkpoint", payload.getvalue(), "show_package.tar")
        self.assertEqual(model.counts()["addresses"], 1)
        self.assertEqual(model.counts()["services"], 1)
        self.assertEqual(model.counts()["security_rules"], 1)
        self.assertEqual(model.counts()["nat_rules"], 1)
        self.assertEqual(model.security_rules[0].destination, ["Web"])
        self.assertEqual(model.security_rules[0].service, ["HTTPS"])
        self.assertEqual(model.security_rules[0].action, "allow")
        self.assertIn("Track: Log", model.security_rules[0].description)
        self.assertTrue(any("globale UID-dictionary" in message for message in model.warnings))

    def test_checkpoint_show_package_rejects_parent_traversal(self):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            raw = b"[]"
            info = tarfile.TarInfo("../objects.json")
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
        with self.assertRaises(MigrationError):
            parse_vendor("checkpoint", payload.getvalue(), "show_package.tar")

    def test_checkpoint_duplicate_long_rule_names_receive_bounded_suffixes(self):
        long_name = "A Check Point rule name that is deliberately longer than sixty three characters"
        documents = {
            "Standard_objects.json": [
                {"type": "rulebaseaction", "uid": "accept", "name": "Accept"},
            ],
            "Layer-Management_server.json": [
                {"type": "access-rule", "uid": f"rule-{number}", "name": long_name, "action": "accept"}
                for number in range(3)
            ],
        }
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            for name, document in documents.items():
                raw = json.dumps(document).encode()
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        model = parse_vendor("checkpoint", payload.getvalue(), "show_package.tar")
        self.assertEqual(len(model.security_rules), 3)
        self.assertEqual(len({rule.name for rule in model.security_rules}), 3)
        self.assertTrue(all(len(rule.name) <= 63 for rule in model.security_rules))

    def test_panos_to_panos_rich_config_preserves_every_supported_family(self):
        base = (FIXTURES / "panos-rich-base.xml").read_bytes()
        source = (FIXTURES / "panos-rich-source.xml").read_bytes()
        model = parse_vendor("panos", source, "panos-rich-source.xml")
        expected_counts = {
            "addresses": 4, "address_groups": 1, "services": 2, "service_groups": 1,
            "security_rules": 1, "nat_rules": 1, "interfaces": 5, "zones": 2,
            "applications": 1, "application_groups": 1, "application_filters": 1,
            "tags": 1, "regions": 1, "schedules": 1, "external_dynamic_lists": 1,
            "custom_url_categories": 1, "security_profiles": 9,
            "security_profile_groups": 1, "log_forwarding_profiles": 1,
            "authentication_enforcement": 1, "qos_rules": 1, "pbf_rules": 1,
            "decryption_rules": 1, "application_override_rules": 1,
            "authentication_rules": 1, "dos_rules": 1, "tunnel_inspection_rules": 1,
            "vlans": 1, "virtual_routers": 1, "logical_routers": 1,
            "virtual_wires": 1, "ipsec_tunnels": 1, "ike_gateways": 1,
            "network_profiles": 3, "globalprotect_portals": 1,
            "globalprotect_gateways": 1, "device_configuration": 1,
        }
        counts = model.counts()
        for kind, expected in expected_counts.items():
            self.assertEqual(counts.get(kind), expected, kind)

        merged, plan = merge_model_into_panos_xml(base, model, "vsys1")
        root, snapshot = main.parse_snapshot(merged, expected_kind="panos")
        self.assertEqual(snapshot.vsys, ["vsys1"])
        self.assertEqual(len(root.findall(".//devices/entry/network/interface/*/entry")), 7)
        self.assertEqual({entry.get("name") for entry in root.findall(".//vsys/entry/zone/entry")}, {"Trust", "Untrust", "DMZ", "VPN"})
        self.assertIsNotNone(root.find(".//vsys/entry/rulebase/security/rules/entry[@name='Atlas-DMZ-Allow']/profile-setting"))
        self.assertEqual(root.findtext(".//vsys/entry/rulebase/security/rules/entry[@name='Atlas-DMZ-Allow']/log-setting"), "Atlas-Log")
        self.assertIsNotNone(root.find(".//devices/entry/network/tunnel/ipsec/entry[@name='Atlas-IPSec']"))
        self.assertIsNotNone(root.find(".//vsys/entry/profiles/url-filtering/entry[@name='Atlas-URL']"))
        self.assertIsNotNone(root.find(".//vsys/entry/rulebase/pbf/rules/entry[@name='Atlas-PBF']"))
        self.assertIsNotNone(root.find(".//devices/entry/plugins/entry[@name='atlas-plugin']"))
        self.assertGreater(plan["create"], 40)

    def test_panos_sdwan_rules_are_deliberately_not_migrated(self):
        base = b'''<config><devices><entry name="localhost.localdomain"><device-group><entry name="DG-Test"><pre-rulebase><sdwan><rules><entry name="Existing-SDWAN"/></rules></sdwan></pre-rulebase></entry></device-group></entry></devices></config>'''
        source = b'''<config><devices><entry name="localhost.localdomain"><device-group><entry name="DG-Source"><pre-rulebase><sdwan><rules><entry name="Source-SDWAN"/></rules></sdwan></pre-rulebase></entry></device-group></entry></devices></config>'''
        model = parse_vendor("panos", source, "panorama-with-sdwan.xml")
        self.assertNotIn("sdwan_rules", model.extras)
        self.assertTrue(any("SD-WAN policy Source-SDWAN wordt bewust niet gemigreerd" in item for item in model.unsupported))

        merged, plan = merge_model_into_panos_xml(base, model, "DG-Test", True, "pre")
        root = ET.fromstring(merged)
        names = [entry.get("name") for entry in root.findall(".//device-group/entry[@name='DG-Test']/pre-rulebase/sdwan/rules/entry")]
        self.assertEqual(names, ["Existing-SDWAN"])
        self.assertEqual(plan["conflicts"], [])

    def test_collision_report_ignores_source_provenance(self):
        left = MigrationModel("panos", "left", addresses=[Address("same", "192.0.2.1/32", source_ref="left")])
        right = MigrationModel("panos", "right", addresses=[Address("same", "192.0.2.1/32", source_ref="right")])
        report = migration_collision_report(left, right)
        self.assertEqual(report["addresses"]["identical"], 1)
        self.assertEqual(report["addresses"]["conflicts"], 0)

    def test_existing_ha_config_can_switch_to_active_passive(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><deviceconfig><high-availability><group><group-id>1</group-id><mode><active-active><device-id>0</device-id></active-active></mode><peer-ip>192.0.2.2</peer-ip></group><enabled>yes</enabled></high-availability></deviceconfig><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        converted, report = set_panos_ha_mode(source, "active-passive")
        root = ET.fromstring(converted)
        self.assertIsNotNone(root.find(".//high-availability/group/mode/active-passive"))
        self.assertIsNone(root.find(".//high-availability/group/mode/active-active"))
        self.assertEqual(root.findtext(".//high-availability/group/peer-ip"), "192.0.2.2")
        self.assertEqual(report, {"topology": "active-passive", "ha_nodes": 1, "changed": 1, "ha_missing": False})

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

    def test_new_standalone_config_can_be_built_without_imported_panos_xml(self):
        model = parse_vendor("fortinet", b'''config firewall address
edit "atlas-web"
set subnet 10.10.10.10 255.255.255.255
next
end
config firewall policy
edit 1
set name "clients-to-atlas"
set srcintf "Trust"
set dstintf "DMZ"
set srcaddr "all"
set dstaddr "atlas-web"
set service "ALL"
set action accept
next
end''', "atlas-a.conf")
        base = migration_base_xml(model, "vsys1")
        merged, plan = merge_model_into_panos_xml(base, model, "vsys1")
        root, snapshot = main.parse_snapshot(merged, expected_kind="panos")
        self.assertEqual(snapshot.vsys, ["vsys1"])
        self.assertEqual({entry.get("name") for entry in root.findall(".//vsys/entry/zone/entry")}, {"Trust", "DMZ"})
        self.assertIsNotNone(root.find(".//address/entry[@name='atlas-web']"))
        self.assertIsNotNone(root.find(".//rulebase/security/rules/entry[@name='clients-to-atlas']"))
        self.assertEqual(plan["create"], 2)

    def test_generated_config_preview_counts_policy_referenced_zones(self):
        model = MigrationModel(
            "fortinet",
            "atlas",
            zones=[{"name": "DMZ", "xml": '<entry name="DMZ" />'}],
            security_rules=[main.Policy("allow", from_zones=["Trust"], to_zones=["DMZ"])],
        )
        self.assertEqual(migration_zone_names(model), ["DMZ", "Trust"])

    def test_new_panorama_config_generates_referenced_template_for_zones(self):
        model = MigrationModel("fortinet", "atlas", security_rules=[main.Policy("allow", from_zones=["Trust"], to_zones=["DMZ"])])
        base = migration_base_xml(model, "Atlas-DG", panorama=True)
        merged, _ = merge_model_into_panos_xml(base, model, "Atlas-DG", panorama=True)
        root, snapshot = main.parse_snapshot(merged, expected_kind="panorama")
        self.assertEqual(snapshot.device_groups[0]["name"], "Atlas-DG")
        self.assertEqual(snapshot.device_groups[0]["reference_template"], "PPF-Migration-Template")
        self.assertEqual({entry.get("name") for entry in root.findall(".//template/entry/config/devices/entry/vsys/entry/zone/entry")}, {"Trust", "DMZ"})

    def test_create_merged_workspace_generates_and_remembers_zero_base(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS zero base test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,created_at,updated_at) VALUES(?,?,?,?)",
                ("testatlas-zero", profile_id, stamp, stamp),
            ).lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        project = main.migration_project_row(project_id)
        model = parse_vendor("generic", b'[{"name":"atlas-host","value":"192.0.2.40/32"}]', "atlas.json")
        workspace_id, plan = main.create_merged_workspace(profile, project, model)
        with main.db() as conn:
            refreshed = conn.execute("SELECT * FROM migration_projects WHERE id=?", (project_id,)).fetchone()
            base_workspace = conn.execute("SELECT * FROM config_workspaces WHERE id=?", (refreshed["base_workspace_id"],)).fetchone()
        self.assertEqual(base_workspace["source"], "migration-generated-base")
        self.assertNotEqual(workspace_id, base_workspace["id"])
        self.assertEqual(plan["create"], 1)

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
        self.assertNotIn("Expedition-inspired", page)

    def test_active_active_project_renders_and_exports_two_outputs(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS AA output test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,topology,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("AA output test", profile_id, "active-active", stamp, stamp),
            ).lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        workspace_a = main.store_config_workspace(profile, "AA node 1", "aa-node-1.xml", xml, "migration-output")
        workspace_b = main.store_config_workspace(profile, "AA node 2", "aa-node-2.xml", xml, "migration-output")
        output_a = main.store_migration_output(project_id, workspace_a, "AA node 1", "active-active", "node 1", sanity={"ha_mode": "active-active"})
        output_b = main.store_migration_output(project_id, workspace_b, "AA node 2", "active-active", "node 2", collisions={"interfaces": {"conflicts": 2, "conflict_names": ["ethernet1/1", "ethernet1/2"]}})

        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(cookie_name, serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}), domain="forge.test", secure=True)
        page = client.get(f"/migration/projects/{project_id}", base_url="https://forge.test")
        self.assertEqual(page.status_code, 200)
        self.assertIn("AA node 1", page.get_data(as_text=True))
        self.assertIn("AA node 2", page.get_data(as_text=True))
        self.assertIn("2 conflicten", page.get_data(as_text=True))
        for output_id in (output_a, output_b):
            self.assertEqual(client.get(f"/migration/projects/{project_id}/outputs/{output_id}/xml", base_url="https://forge.test").status_code, 200)
            self.assertEqual(client.get(f"/migration/projects/{project_id}/outputs/{output_id}/set", base_url="https://forge.test").status_code, 200)

    def test_project_page_renders_duplicate_candidates_from_two_sources(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS duplicate UI test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,created_at,updated_at) VALUES(?,?,?,?)",
                ("duplicate-ui", profile_id, stamp, stamp),
            ).lastrowid
        main.store_migration_source(project_id, "generic", "source-a", MigrationModel("generic", "source-a", addresses=[Address("dns-a", "192.0.2.53/32", source_ref="source-a")]))
        main.store_migration_source(project_id, "generic", "source-b", MigrationModel("generic", "source-b", addresses=[Address("dns-b", "192.0.2.53/32", source_ref="source-b")]))
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(cookie_name, serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}), domain="forge.test", secure=True)
        response = client.get(f"/migration/projects/{project_id}", base_url="https://forge.test")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Search &amp; Merge", page)
        self.assertIn("dns-a", page)
        self.assertIn("dns-b", page)

    def test_panos_upload_becomes_full_base_workspace_and_ui_defaults_are_checked(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS migration test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,created_at,updated_at) VALUES(?,?,?,?)",
                ("5210 naar 460", profile_id, stamp, stamp),
            ).lastrowid
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(cookie_name, serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}), domain="forge.test", secure=True)
        source = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><layer3/></entry></ethernet></interface></network><vsys><entry name="vsys1"><zone><entry name="Trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone><rulebase/></entry></vsys></entry></devices></config>'''
        response = client.post(
            f"/migration/projects/{project_id}/source",
            base_url="https://forge.test",
            data={"csrf": "migration-test-csrf", "vendor": "panos", "config_file": (io.BytesIO(source), "pa-5210.xml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        with main.db() as conn:
            project = conn.execute("SELECT * FROM migration_projects WHERE id=?", (project_id,)).fetchone()
            workspace = conn.execute("SELECT * FROM config_workspaces WHERE id=?", (project["base_workspace_id"],)).fetchone()
        self.assertIsNotNone(workspace)
        self.assertEqual(workspace["source"], "migration-import")
        self.assertIn(b'ethernet1/1', main.workspace_config_path(workspace).read_bytes())

        page = client.get(f"/migration/projects/{project_id}", base_url="https://forge.test").get_data(as_text=True)
        self.assertIn("Palo Alto PAN-OS / Panorama XML", page)
        self.assertIn('class="migration-kind-menu"', page)
        self.assertNotIn('class="migration-kind-menu" open', page)
        self.assertIn("<summary>Configuratie</summary>", page)
        self.assertIn('name="kind" value="interfaces" checked', page)
        self.assertIn('name="kind" value="zones" checked', page)
        self.assertIn('name="source_id"', page)
        self.assertIn("XML", page)
        self.assertIn("Set commands", page)
        self.assertIn("Nieuwe configuratie (vanaf nul)", page)
        self.assertNotIn("Interfaces en zones zijn beschikbaar", page)
        self.assertNotIn("standaard alles geselecteerd", page)


if __name__ == "__main__":
    unittest.main()
