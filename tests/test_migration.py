import json
import io
import os
import re
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-migration-test-"))
os.environ.setdefault("PPF_SYSLOG_PORT", "55149")
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "unit-test-bootstrap-password")

from app.migration import Address, MigrationModel, PARSERS, MigrationError, apply_family_mappings, apply_merge_rules, apply_transform_rules, auto_map_nat_topology, merge_inventory, merge_model_into_panos_xml, migration_analysis, migration_api_plan, migration_base_xml, migration_best_practices, migration_collision_report, migration_discovery, migration_filter_inventory, migration_health_dashboard, migration_review_findings, migration_zone_names, panos_candidate_analysis, parse_vendor, panos_fragment, reconcile_model, scm_items, set_panos_ha_mode
from app import main

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class MigrationTests(unittest.TestCase):
    def test_checkpoint_protocol_signatures_become_app_ids(self):
        source = json.dumps({
            "objects": [
                {"uid": "svc-rdp", "type": "service-tcp", "name": "Remote_Desktop_Protocol-Protocol-Signature", "port": "Any"},
                {"uid": "svc-ssh", "type": "service-tcp", "name": "ssh_version_2-Protocol-Signature", "port": "Any"},
            ],
            "rulebase": [
                {"uid": "rule-1", "type": "access-rule", "name": "allow-admin", "action": "Accept", "enabled": True, "service": ["svc-rdp", "svc-ssh"]},
            ],
        }).encode()
        model = parse_vendor("checkpoint", source, "policy.json")
        self.assertEqual(model.services, [])
        self.assertEqual(model.security_rules[0].application, ["ms-rdp", "ssh"])
        self.assertEqual(model.security_rules[0].service, ["application-default"])

    def test_management_invariants_read_root_level_administrators(self):
        config = b'''<config><mgt-config><users><entry name="admin"><phash>hash-a</phash></entry></users></mgt-config><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>lab-fw</hostname><ip-address>192.0.2.10</ip-address><netmask>255.255.255.0</netmask><default-gateway>192.0.2.1</default-gateway></system></deviceconfig></entry></devices></config>'''
        values = main.panos_management_invariants(config)
        self.assertEqual(values["ip-address"], "192.0.2.10")
        self.assertEqual(values["administrators"], {"admin": "hash-a"})

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

    def test_family_mapping_can_ignore_or_require_review(self):
        model=MigrationModel(
            "generic","source",
            addresses=[Address("server","10.0.0.3/32")],
            services=[main.Service("https","tcp","443")],
        )
        mapped=apply_family_mappings(model,[
            {"kind":"addresses","action":"ignore"},
            {"kind":"services","action":"review"},
        ])
        self.assertEqual(mapped.addresses,[])
        self.assertEqual(len(mapped.services),1)
        self.assertTrue(any("Services" in item for item in mapped.warnings))

    def test_family_mapping_annotates_create_and_map_target_context(self):
        model=MigrationModel(
            "generic","source",
            addresses=[Address("server","10.0.0.3/32")],
            services=[main.Service("https","tcp","443")],
        )
        mapped=apply_family_mappings(model,[
            {"kind":"addresses","action":"create","target_context":"vsys2"},
            {"kind":"services","action":"map","target_context":"Shared"},
        ])
        self.assertEqual(mapped.addresses[0].mapping_action,"create")
        self.assertEqual(mapped.addresses[0].target_context,"vsys2")
        self.assertEqual(mapped.services[0].mapping_action,"map")
        self.assertEqual(mapped.services[0].target_context,"Shared")

    def test_panos_merge_routes_create_and_map_to_their_selected_contexts(self):
        base = b'''<config><shared><address><entry name="shared-server"><ip-netmask>10.0.0.3/32</ip-netmask></entry></address></shared><devices><entry name="localhost.localdomain"><device-group><entry name="Existing"/></device-group></entry></devices></config>'''
        model = MigrationModel("generic", "source", addresses=[
            Address("legacy-server", "10.0.0.3/32", target_context="Shared", mapping_action="map"),
            Address("new-server", "10.0.0.4/32", target_context="New-DG", mapping_action="create"),
        ])
        merged, plan = merge_model_into_panos_xml(base, model, "Existing", panorama=True)
        root = ET.fromstring(merged)
        self.assertIsNone(root.find('./shared/address/entry[@name="legacy-server"]'))
        self.assertIsNotNone(root.find('./shared/address/entry[@name="shared-server"]'))
        self.assertIsNotNone(root.find('./devices/entry/device-group/entry[@name="New-DG"]/address/entry[@name="new-server"]'))
        self.assertEqual(plan["reuse"], 1)
        self.assertEqual(plan["target_contexts"], ["Shared", "New-DG"])

    def test_map_mapping_refuses_to_create_a_missing_target(self):
        base = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        model = MigrationModel("generic", "source", addresses=[
            Address("missing", "10.0.0.9/32", target_context="vsys1", mapping_action="map"),
        ])
        with self.assertRaises(MigrationError):
            merge_model_into_panos_xml(base, model, "vsys1")

    def test_topology_mapping_rewrites_policy_and_removes_source_definition(self):
        model=MigrationModel(
            "panos","source",
            zones=[{"name":"inside","source_ref":"source","xml":'<entry name="inside"><network><layer3/></network></entry>'}],
            security_rules=[main.Policy("allow",from_zones=["inside"],to_zones=["outside"])],
        )
        selector="inside|||source"
        transformed=apply_transform_rules(model,[
            {"operation":"topology_map","kind":"zones","selector":selector,"value":"Trust"}
        ])
        self.assertEqual(transformed.zones,[])
        self.assertEqual(transformed.security_rules[0].from_zones,["Trust"])

    def test_expedition_style_filters_support_and_or_and_regex(self):
        model=MigrationModel(
            "generic","source",
            addresses=[Address("prod-web","10.0.0.3/32",source_ref="fw-a"),Address("test-db","10.0.1.3/32",source_ref="fw-b")],
            security_rules=[main.Policy("allow-prod",source=["prod-web"],disabled=True)],
        )
        result=migration_filter_inventory(model,[
            {"field":"name","operator":"starts_with","value":"prod"},
            {"field":"source_ref","operator":"equals","value":"fw-a"},
        ],"and")
        self.assertEqual([item["name"] for item in result],["prod-web"])
        result=migration_filter_inventory(model,[
            {"field":"name","operator":"regex","value":"^test"},
            {"field":"disabled","operator":"equals","value":"yes"},
        ],"or")
        self.assertEqual({item["name"] for item in result},{"test-db","allow-prod"})

    def test_disabled_filter_accepts_only_explicit_yes_or_no(self):
        model = MigrationModel(
            "generic", "source", security_rules=[main.Policy("allow", disabled=True)]
        )
        with self.assertRaises(MigrationError):
            migration_filter_inventory(model, [
                {"field": "disabled", "operator": "equals", "value": "true"},
            ])
        with self.assertRaises(MigrationError):
            migration_filter_inventory(model, [
                {"field": "disabled", "operator": "contains", "value": "yes"},
            ])
        result = migration_filter_inventory(model, [
            {"field": "disabled", "operator": "equals", "value": "yes"},
        ])
        self.assertEqual([item["name"] for item in result], ["allow"])

    def test_policy_zone_transform_replaces_only_selected_side(self):
        model = MigrationModel(
            "checkpoint", "source",
            security_rules=[main.Policy("allow", from_zones=["any"], to_zones=["any"], source_ref="rule-1")],
        )
        transformed = apply_transform_rules(model, [{
            "operation": "set_from_zones",
            "kind": "security_rules",
            "selector": "allow|||rule-1",
            "value": json.dumps(["Trust"]),
        }])
        self.assertEqual(transformed.security_rules[0].from_zones, ["Trust"])
        self.assertEqual(transformed.security_rules[0].to_zones, ["any"])

    def test_review_findings_expose_affected_policy_items(self):
        model = MigrationModel(
            "checkpoint", "source",
            security_rules=[main.Policy("allow", from_zones=["any"], to_zones=["any"], source_ref="rule-1")],
        )
        review = migration_review_findings(model)
        finding = next(item for item in review["findings"] if item["code"] == "zone-mapping")
        self.assertEqual(finding["anchor"], "topology-mapping")
        self.assertEqual(finding["affected"][0]["name"], "allow")

    def test_policy_zone_mapping_route_uses_existing_target_zone(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS zone mapping", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        base = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><zone><entry name="Trust"><network><layer3/></network></entry><entry name="DMZ"><network><layer3/></network></entry></zone><rulebase/></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "Zone base", "base.xml", base, "test")
        with main.db() as conn:
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,base_workspace_id,owner,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                ("zone-map", profile_id, workspace_id, "admin", stamp, stamp),
            ).lastrowid
        source_id = main.store_migration_source(
            project_id, "checkpoint", "source.tar",
            MigrationModel(
                "checkpoint", "source.tar",
                security_rules=[main.Policy("allow", from_zones=["any"], to_zones=["any"], source_ref="rule-1")],
            ),
        )
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(
                main.app.config["SESSION_COOKIE_NAME"],
                serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}),
                domain="forge.test", secure=True,
            )
        response = client.post(
            f"/migration/projects/{project_id}/policy-zones",
            base_url="https://forge.test",
            data={
                "csrf": "migration-test-csrf",
                "policy_key": "security_rules|||allow|||rule-1",
                "from_zone": ["Trust", "DMZ"],
            },
        )
        self.assertEqual(response.status_code, 302)
        mapped = main.selected_migration_model(project_id, [source_id])
        self.assertEqual(mapped.security_rules[0].from_zones, ["Trust", "DMZ"])
        self.assertEqual(mapped.security_rules[0].to_zones, ["any"])

    def test_health_best_practices_discovery_and_api_plan_are_review_only(self):
        model=MigrationModel(
            "generic","source",
            addresses=[Address("web","192.0.2.10/32"),Address("fqdn","portal.example.net",value_type="fqdn")],
            security_rules=[main.Policy("allow-web",destination=["web"],application=["any"],service=["any"],disabled=False)],
        )
        health=migration_health_dashboard(model)
        practices=migration_best_practices(model)
        discovery=migration_discovery(model)
        api_plan=migration_api_plan(model,"panos","vsys1")
        self.assertGreaterEqual(health["total"],3)
        self.assertGreater(practices["failed"],0)
        self.assertIn("192.0.2.10/32",discovery["networks"])
        self.assertIn("portal.example.net",discovery["fqdns"])
        self.assertTrue(api_plan)
        self.assertTrue(all(item["status"]=="staged" for item in api_plan))
        self.assertTrue(all(item["method"]=="SET" for item in api_plan))

    def test_saved_transform_survives_import_editor_source_ref_change(self):
        model=MigrationModel(
            "merged",
            "source",
            addresses=[Address("old-server","10.0.0.3/32",source_ref="VSYS vsys1")],
            address_groups=[main.AddressGroup("servers",["old-server"])],
            security_rules=[main.Policy("allow-to-server",destination=["old-server"])],
        )
        transformed=apply_transform_rules(model,[{"operation":"rename","kind":"addresses","selector":"old-server|||line 3","value":"new-server"}])
        self.assertEqual(transformed.addresses[0].name,"new-server")
        self.assertEqual(transformed.address_groups[0].members,["new-server"])
        self.assertEqual(transformed.security_rules[0].destination,["new-server"])

    def test_saved_merge_choice_survives_import_editor_source_ref_change(self):
        model=MigrationModel(
            "merged",
            "source",
            services=[
                main.Service("dns-a","udp","53",source_ref="VSYS vsys1"),
                main.Service("dns-b","udp","53",source_ref="VSYS vsys1"),
            ],
            service_groups=[main.ServiceGroup("dns-services",["dns-a","dns-b"])],
            security_rules=[main.Policy("allow-dns",service=["dns-b"])],
        )
        merged=apply_merge_rules(model,[{"kind":"services","master":"dns-a|||line 10","members":["dns-a|||line 10","dns-b|||line 20"]}])
        self.assertEqual([item.name for item in merged.services],["dns-a"])
        self.assertEqual(merged.service_groups[0].members,["dns-a"])
        self.assertEqual(merged.security_rules[0].service,["dns-a"])

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
        review = migration_review_findings(model)
        self.assertTrue(any(item["code"] == "nat-interface-mapping" and item["severity"] == "critical" for item in review["findings"]))

    def test_fortinet_vip_maps_to_destination_nat_for_scm(self):
        model = parse_vendor("fortinet", b'''config firewall vip
edit "web-vip"
set extip 203.0.113.10
set mappedip 10.0.0.10
set mappedport 443
next
end''', "forti.conf")
        self.assertEqual(len(model.nat_rules), 1)
        self.assertEqual(model.nat_rules[0].service, ["any"])
        nat_item = next(item for item in scm_items(model) if item["kind"] == "policy:nat")
        self.assertEqual(nat_item["payload"]["destination_translation"]["translated_port"], "443")

    def test_fortinet_crypto_blocks_are_skipped_without_parsing_or_retention(self):
        config = b'''config vpn certificate local
edit "factory-certificate"
set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
THIS-MUST-NEVER-BE-RETAINED
-----END ENCRYPTED PRIVATE KEY-----"
set certificate "-----BEGIN CERTIFICATE-----
THIS-CERTIFICATE-MUST-BE-REENTERED
-----END CERTIFICATE-----"
next
end
config firewall address
edit "web01"
set subnet 10.0.0.10 255.255.255.255
next
end'''
        model = parse_vendor("fortinet", config, "fortigate-with-crypto.conf")
        serialized = json.dumps(model.as_dict())
        self.assertEqual(model.addresses[0].value, "10.0.0.10/32")
        self.assertNotIn("THIS-MUST-NEVER-BE-RETAINED", serialized)
        self.assertNotIn("THIS-CERTIFICATE-MUST-BE-REENTERED", serialized)
        self.assertTrue(any("Fortinet cryptomateriaal overgeslagen" in message for message in model.warnings))
        review = migration_review_findings(model)
        self.assertTrue(any(item["code"] == "fortinet-crypto-reentry" for item in review["findings"]))

    def test_panos_to_panos_keeps_existing_encrypted_material_opaque(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><deviceconfig><system><opaque-secret>ENCRYPTED-PANOS-VALUE</opaque-secret></system></deviceconfig><vsys><entry name="vsys1"><address><entry name="server"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address><rulebase/></entry></vsys></entry></devices></config>'''
        model = parse_vendor("panos", source, "panos.xml")
        merged, _ = merge_model_into_panos_xml(source, model, "vsys1")
        self.assertIn(b"ENCRYPTED-PANOS-VALUE", merged)

    def test_full_candidate_analysis_includes_broken_base_references(self):
        candidate = b'''<config><predefined><application><entry name="ssl"/></application></predefined><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="server"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address><rulebase><security><rules><entry name="base-broken"><from><member>any</member></from><to><member>any</member></to><source><member>missing-base-object</member></source><destination><member>server</member></destination><application><member>missing-base-app</member></application><service><member>application-default</member></service><action>allow</action></entry><entry name="valid"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>server</member></destination><application><member>ssl</member></application><service><member>application-default</member></service><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''
        analysis = panos_candidate_analysis(candidate)
        self.assertIn("missing-base-object", analysis["unresolved_references"])
        self.assertIn("missing-base-app", analysis["unresolved_references"])
        self.assertEqual(analysis["unresolved_application_references"], ["missing-base-app"])
        self.assertNotIn("ssl", analysis["unresolved_references"])

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
        self.assertEqual(model.address_groups[0].members, ["srv"])
        self.assertIn("db", model.address_groups[0].description)
        self.assertEqual(model.security_rules[0].action, "allow")
        self.assertFalse(model.security_rules[0].disabled)
        self.assertEqual(model.security_rules[0].tags, [])
        self.assertNotIn("tags", model.extras)

    def test_checkpoint_unknown_action_is_disabled_and_blocks_review(self):
        data = {"rulebase": [{"type": "access-rule", "uid": "layer-1", "name": "Nested Layer", "action": "Inner Layer"}]}
        model = parse_vendor("checkpoint", json.dumps(data).encode(), "checkpoint.json")
        self.assertTrue(model.security_rules[0].disabled)
        self.assertEqual(model.security_rules[0].action, "deny")
        self.assertIn("REVIEW:", model.security_rules[0].description)
        tag_name = "OCD-Review-Unsupported-Action"
        self.assertEqual(model.security_rules[0].tags, [tag_name])
        self.assertEqual([item["name"] for item in model.extras["tags"]], [tag_name])
        self.assertTrue(any("niet-ondersteunde Check Point actie" in message for message in model.warnings))
        review = migration_review_findings(model)
        self.assertTrue(any(item["code"] == "unsupported-actions" and item["severity"] == "critical" for item in review["findings"]))
        fragment = ET.fromstring(panos_fragment(model))
        self.assertIsNotNone(fragment.find(f"./devices/entry/vsys/entry/tag/entry[@name='{tag_name}']"))
        self.assertEqual(
            fragment.findtext("./devices/entry/vsys/entry/rulebase/security/rules/entry/tag/member"), tag_name
        )
        security_item = next(item for item in scm_items(model) if item["kind"] == "policy:security")
        self.assertEqual(security_item["payload"]["tag"], [tag_name])
        api_plan = migration_api_plan(model, "scm", "folder")
        self.assertEqual(api_plan[0]["kind"], "tags")
        self.assertLess(
            next(index for index, item in enumerate(api_plan) if item["kind"] == "tags"),
            next(index for index, item in enumerate(api_plan) if item["kind"] == "policy:security"),
        )

    def test_scm_creates_checkpoint_review_tag_before_tagged_policy(self):
        data = {"rulebase": [{"type": "access-rule", "uid": "layer-1", "name": "Nested Layer", "action": "Inner Layer"}]}
        model = parse_vendor("checkpoint", json.dumps(data).encode(), "checkpoint.json")
        scm = type("SCM", (), {"scm_api_base": "https://api.example", "scm_rulebase": "pre"})()
        with patch.object(main, "migration_scm_container", return_value=(scm, "token", {"folder": "Shared"})), \
             patch.object(main.policy_api, "scm_http_request") as request_call, \
             patch.object(main, "invalidate_profile_caches"):
            count = main.apply_scm_migration({"id": 42}, model)
        self.assertEqual(count, 2)
        payloads = [call.kwargs["payload"] for call in request_call.call_args_list]
        self.assertEqual(payloads[0]["name"], "OCD-Review-Unsupported-Action")
        self.assertEqual(payloads[1]["tag"], ["OCD-Review-Unsupported-Action"])

    def test_review_findings_always_require_engineer_acknowledgement(self):
        model = MigrationModel("generic", "source", security_rules=[main.Policy("allow-any", disabled=False)])
        review = migration_review_findings(model)
        self.assertFalse(review["ready_for_push"])
        self.assertEqual(review["status"], "review_required")
        self.assertTrue(any(item["code"] == "engineer-review" for item in review["findings"]))
        self.assertTrue(any(item["code"] == "zone-mapping" for item in review["findings"]))

    def test_nat_translation_addresses_are_counted_as_used(self):
        model = MigrationModel(
            "fortinet",
            "nat-source",
            addresses=[Address("public-mapped", "10.0.0.10/32")],
            nat_rules=[main.Policy(
                "dnat",
                policy_type="nat",
                destination_translation={"translated_address": "public-mapped", "translated_port": "8443"},
            )],
        )
        analysis = migration_analysis(model)
        self.assertNotIn("public-mapped", analysis["unused_addresses"])
        self.assertNotIn("public-mapped", analysis["unresolved_references"])

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

    def test_checkpoint_dns_hosts_and_applications_map_to_panos_families(self):
        administrative_domain = {"uid": "domain-1", "name": "SMC User", "domain-type": "domain"}
        data = {
            "objects": [
                {"type": "dns-domain", "uid": "dns-1", "name": ".example.com", "domain": administrative_domain},
                {"type": "checkpoint-host", "uid": "mgmt-1", "name": "management", "ipv4-address": "192.0.2.10"},
                {
                    "type": "simple-cluster",
                    "uid": "cluster-1",
                    "name": "cluster",
                    "ipv4-address": "192.0.2.20",
                    "cluster-members": [
                        {"uid": "nested-member-1", "name": "nested-member", "ip-address": "192.0.2.22"},
                    ],
                },
                {"uid": "member-1", "name": "member", "ip-address": "192.0.2.21"},
                {"type": "application-site", "uid": "app-1", "name": "Dropbox"},
                {"type": "service-icmp", "uid": "icmp-1", "name": "echo-request"},
            ],
            "rulebase": [
                {"type": "access-rule", "name": "Applications", "service": ["app-1", "icmp-1"], "action": "Accept"},
            ],
        }
        model = parse_vendor("checkpoint", json.dumps(data).encode(), "checkpoint.json")
        addresses = {item.name: item.value for item in model.addresses}
        self.assertEqual(addresses["example.com"], "example.com")
        self.assertEqual(addresses["management"], "192.0.2.10/32")
        self.assertEqual(addresses["cluster"], "192.0.2.20/32")
        self.assertEqual(addresses["member"], "192.0.2.21/32")
        self.assertEqual(addresses["nested-member"], "192.0.2.22/32")
        self.assertTrue(any("DNS-domain objecten" in warning for warning in model.warnings))
        rule = model.security_rules[0]
        self.assertEqual(rule.application, ["dropbox-base", "ping"])
        self.assertEqual(rule.service, ["application-default"])
        self.assertFalse(rule.disabled)
        analysis = migration_analysis(model)
        self.assertEqual(analysis["unresolved_references"], [])

    def test_checkpoint_candidate_removes_unsafe_references_and_preserves_policy_status(self):
        data = {
            "objects": [
                {"type": "host", "uid": "host-1", "name": "server", "ipv4-address": "192.0.2.10"},
                {"type": "access-role", "uid": "role-1", "name": "Developers"},
                {"type": "application-site", "uid": "app-1", "name": "Dropbox"},
                {"type": "application-site-category", "uid": "category-1", "name": "File-Storage"},
                {"type": "group", "uid": "group-1", "name": "servers", "members": ["host-1", "missing-1"]},
            ],
            "rulebase": [{
                "type": "access-rule", "uid": "rule-1", "name": "unsafe-rule",
                "source": ["role-1"], "destination": ["host-1", "Internet"],
                "service": ["app-1", "category-1"], "action": "Accept",
            }],
            "nat-rulebase": [{
                "type": "nat-rule", "uid": "nat-1", "name": "unsafe-nat",
                "original-source": ["role-1"], "original-destination": ["host-1"],
                "translated-source": ["missing-translation"], "method": "static",
            }],
        }
        model = parse_vendor("checkpoint", json.dumps(data).encode(), "checkpoint.json")
        security = model.security_rules[0]
        self.assertFalse(security.disabled)
        self.assertEqual(security.source, ["any"])
        self.assertEqual(security.destination, ["server"])
        self.assertEqual(security.application, ["dropbox-base"])
        self.assertIn("Developers", security.description)
        self.assertIn("Internet", security.description)
        self.assertIn("File-Storage", security.description)
        nat = model.nat_rules[0]
        self.assertFalse(nat.disabled)
        self.assertEqual(nat.source, ["any"])
        self.assertEqual(nat.source_translation, {})
        self.assertIn("missing-translation", nat.description)
        self.assertEqual(model.address_groups[0].members, ["server"])
        self.assertEqual(migration_analysis(model)["unresolved_references"], [])

    def test_checkpoint_url_like_fqdns_and_group_any_become_review_items(self):
        data = {"objects": [
            {"type": "dns-domain", "uid": "bad", "name": "bad-url", "domain": "example.com/path"},
            {"type": "dns-domain", "uid": "good", "name": "good-host", "domain": "host.example.com"},
            {"type": "group", "uid": "group", "name": "mixed", "members": ["bad", "good", "any"]},
        ]}
        model = parse_vendor("checkpoint", json.dumps(data).encode(), "checkpoint.json")
        self.assertEqual([item.name for item in model.addresses], ["good-host"])
        self.assertEqual(model.address_groups[0].members, ["good-host"])
        self.assertEqual(len(model.extras["migration_review_items"]), 1)
        findings = {item["code"]: item for item in migration_review_findings(model)["findings"]}
        self.assertEqual(findings["invalid-fqdn-review"]["count"], 1)

    def test_checkpoint_predefined_applications_are_not_false_unresolved(self):
        candidate = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules><entry name="allow-update"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>ms-update</member></application><service><member>application-default</member></service><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''
        analysis = panos_candidate_analysis(candidate)
        self.assertNotIn("ms-update", analysis["unresolved_application_references"])

    def test_nat_topology_is_inferred_only_from_unambiguous_target(self):
        target = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry><entry name="ethernet1/2"><layer3><ip><entry name="198.51.100.1/24"/></ip></layer3></entry></ethernet></interface><virtual-router><entry name="default"><routing-table><ip><static-route><entry name="default"><destination>0.0.0.0/0</destination><interface>ethernet1/2</interface></entry></static-route></ip></routing-table></entry></virtual-router></network><vsys><entry name="vsys1"><zone><entry name="Trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry><entry name="Untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone><rulebase/></entry></vsys></entry></devices></config>'''
        model = MigrationModel(
            "checkpoint", "source",
            addresses=[Address("inside", "10.0.0.10/32")],
            nat_rules=[main.Policy("outbound", policy_type="nat", source=["inside"], destination=["any"], service=["any"])],
        )
        result = auto_map_nat_topology(target, model)
        self.assertEqual(result["mapped"], 1)
        self.assertEqual(model.nat_rules[0].from_zones, ["Trust"])
        self.assertEqual(model.nat_rules[0].to_zones, ["Untrust"])
        self.assertEqual(model.nat_rules[0].to_interface, "ethernet1/2")

    def test_unresolved_nat_topology_is_review_only_and_not_rendered(self):
        target = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        model = MigrationModel(
            "checkpoint", "source",
            nat_rules=[main.Policy("needs-map", policy_type="nat", service=["any"])],
        )
        result = auto_map_nat_topology(target, model)
        self.assertEqual(result["review"], 1)
        self.assertEqual(model.nat_rules[0].mapping_action, "review")
        fragment = panos_fragment(model)
        self.assertNotIn(b'entry name="needs-map"', fragment)

    def test_migration_analysis_ignores_any_in_object_groups(self):
        model = MigrationModel(
            "checkpoint",
            "checkpoint.json",
            address_groups=[main.AddressGroup("address-any", ["any"])],
            service_groups=[main.ServiceGroup("service-any", ["any", "application-default"])],
        )
        self.assertNotIn("any", migration_analysis(model)["unresolved_references"])

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

    def test_checkpoint_uuid_only_rule_names_become_readable(self):
        documents = {
            "Standard_objects.json": [{"type": "rulebaseaction", "uid": "accept", "name": "Accept"}],
            "Network-Management_server.json": [
                {"type": "access-rule", "uid": "f6ebaf22-70e8-4af4-a227-955cd1f2c51f", "action": "accept"},
                {"type": "access-rule", "uid": "172ee45c-50fd-4ef4-83b5-364d55c9c42a", "action": "accept"},
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
        self.assertEqual([rule.name for rule in model.security_rules], ["Access-Network-1", "Access-Network-2"])

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

    def test_scm_reconciliation_requires_approval_for_cross_name_reuse(self):
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
        self.assertEqual([item.name for item in reconciled.addresses], ["old-web"])
        self.assertEqual(reconciled.security_rules[0].destination, ["old-web"])
        self.assertEqual(plan["reuse"], 0)
        self.assertEqual(len(plan["suggested_reuses"]), 1)
        approved, approved_plan = reconcile_model(model, {
            "addresses": [{"name": "existing-web", "ip_netmask": "192.0.2.10/32"}],
            "address-groups": [], "services": [], "service-groups": [],
            "policy:security": [], "policy:nat": [],
        }, {plan["suggested_reuses"][0]["key"]})
        self.assertEqual(approved.addresses, [])
        self.assertEqual(approved.security_rules[0].destination, ["existing-web"])
        self.assertEqual(approved_plan["reuse"], 1)

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
        target = {
            "addresses": [{"name": "existing-web", "ip_netmask": "192.0.2.10/32"}],
            "address-groups": [{"name": "existing-servers", "static": ["existing-web"]}],
            "services": [], "service-groups": [], "policy:security": [], "policy:nat": [],
        }
        _, first_plan = reconcile_model(model, target)
        address_key = first_plan["suggested_reuses"][0]["key"]
        _, second_plan = reconcile_model(model, target, {address_key})
        group_key = next(item["key"] for item in second_plan["suggested_reuses"] if item["kind"] == "address-groups")
        reconciled, plan = reconcile_model(model, target, {address_key, group_key})
        self.assertEqual(reconciled.addresses, [])
        self.assertEqual(reconciled.address_groups, [])
        self.assertEqual(reconciled.security_rules[0].destination, ["existing-servers"])
        self.assertEqual(plan["reuse"], 2)

    def test_offline_merge_preserves_base_and_blocks_incompatible_name_collision(self):
        base = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="existing"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address><rulebase/></entry></vsys></entry></devices></config>'''
        equivalent = parse_vendor("generic", b'[{"name":"imported","value":"192.0.2.10/32"}]', "generic.json")
        merged, plan = merge_model_into_panos_xml(base, equivalent, "vsys1")
        self.assertIn(b'name="existing"', merged)
        self.assertIn(b'name="imported"', merged)
        self.assertEqual(plan["renamed_references"], {})
        self.assertEqual(len(plan["suggested_reuses"]), 1)
        approved, approved_plan = merge_model_into_panos_xml(
            base, equivalent, "vsys1", approved_reuses={plan["suggested_reuses"][0]["key"]}
        )
        self.assertNotIn(b'name="imported"', approved)
        self.assertEqual(approved_plan["renamed_references"], {"imported": "existing"})
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
        project_source, _, _ = main.app.jinja_env.loader.get_source(main.app.jinja_env, "migration.html")
        self.assertIn("output.sanity.superseded", project_source)
        self.assertIn("Er is een nieuwere candidate beschikbaar.", project_source)
        self.assertIn("static',filename='app.js',v=asset_version", project_source)
        preview_source, _, _ = main.app.jinja_env.loader.get_source(main.app.jinja_env, "migration_preview.html")
        self.assertIn('name="review_acknowledged"', preview_source)
        self.assertIn("static',filename='app.js',v=asset_version", preview_source)
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

    def test_migration_project_renders_refreshed_catalogs(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS catalog render test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,created_at,updated_at) VALUES(?,?,?,?)",
                ("catalog-render", profile_id, stamp, stamp),
            ).lastrowid
            conn.execute(
                "INSERT INTO migration_catalogs(project_id,kind,items_json,updated_at) VALUES(?,?,?,?)",
                (project_id, "applications", json.dumps([{"name": "ssl"}]), stamp),
            )
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(
                cookie_name,
                serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}),
                domain="forge.test",
                secure=True,
            )
        response = client.get(f"/migration/projects/{project_id}", base_url="https://forge.test")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Applications", page)
        self.assertIn("· 1", page)

    def test_candidate_apply_is_blocked_server_side_without_review_acknowledgement(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS review gate test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,created_at,updated_at) VALUES(?,?,?,?)",
                ("review-gate", profile_id, stamp, stamp),
            ).lastrowid
            before = conn.execute("SELECT COUNT(*) FROM config_workspaces WHERE profile_id=?", (profile_id,)).fetchone()[0]
        model = MigrationModel("generic", "review-source", addresses=[Address("review-host", "192.0.2.55/32")])
        draft_id = "review-gate-test"
        draft_path = main.OBJECT_DRAFTS / f"migration-{draft_id}.json"
        draft_path.write_text(json.dumps({
            "project_id": project_id,
            "target_profile_id": profile_id,
            "source_ids": [],
            "model": model.as_dict(),
            "fingerprint": model.fingerprint(),
            "plan": {},
            "review": migration_review_findings(model),
            "project_revision": main.migration_project_revision(project_id),
            "project_updated_at": stamp,
            "profile_settings_fingerprint": __import__("hashlib").sha256(
                json.dumps({"vsys": "vsys1"}).encode()
            ).hexdigest(),
            "base_workspace_id": 0,
            "base_fingerprint": "",
            "created_at": stamp,
        }))
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(cookie_name, serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}), domain="forge.test", secure=True)

        blocked = client.post(
            f"/migration/drafts/{draft_id}/apply",
            base_url="https://forge.test",
            data={"csrf": "migration-test-csrf"},
        )
        self.assertEqual(blocked.status_code, 302)
        with main.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM config_workspaces WHERE profile_id=?", (profile_id,)).fetchone()[0], before)
        self.assertTrue(draft_path.exists())

        accepted = client.post(
            f"/migration/drafts/{draft_id}/apply",
            base_url="https://forge.test",
            data={"csrf": "migration-test-csrf", "review_acknowledged": "reviewed"},
        )
        self.assertEqual(accepted.status_code, 302)
        with main.db() as conn:
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM config_workspaces WHERE profile_id=?", (profile_id,)).fetchone()[0], before)
            output = conn.execute("SELECT * FROM migration_outputs WHERE project_id=?", (project_id,)).fetchone()
        self.assertIsNotNone(output)
        self.assertIn("PAN-OS candidate", output["label"])
        self.assertFalse(draft_path.exists())

    def test_central_scm_application_catalog_settings_are_encrypted_and_reused(self):
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(cookie_name, serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}), domain="forge.test", secure=True)
        with patch("app.main.refresh_default_application_catalog_async", return_value=True):
            response = client.post(
                "/settings/application-catalog",
                base_url="https://forge.test",
                data={
                    "csrf": "migration-test-csrf",
                    "enabled": "on",
                    "client_id": "catalog-client",
                    "client_secret": "catalog-secret-value",
                    "tsg_id": "123456789",
                    "folder": "All",
                    "interval_hours": "24",
                },
            )
        self.assertEqual(response.status_code, 302)
        with main.db() as conn:
            row = conn.execute("SELECT * FROM system_settings WHERE setting_key='application_catalog'").fetchone()
        self.assertIsNotNone(row)
        self.assertNotIn(b"catalog-secret-value", bytes(row["secret_blob"]))
        decrypted = json.loads(main.fernet.decrypt(row["secret_blob"]).decode())
        self.assertEqual(decrypted["client_id"], "catalog-client")
        self.assertEqual(decrypted["client_secret"], "catalog-secret-value")

        applications = [{"name": "ssl"}, {"name": "web-browsing"}, {"name": "ssl"}]
        with patch("app.main.fetch_scm_objects", return_value=applications):
            self.assertEqual(main.refresh_default_application_catalog(), 2)
        settings = main.application_catalog_configuration()
        self.assertEqual(settings["item_count"], 2)
        self.assertFalse(settings["last_error"])
        with patch("app.main.refresh_catalog_async") as refresh:
            catalog = main.cached_application_catalog({"id": 987654, "target_type": "panos"})
        refresh.assert_not_called()
        self.assertEqual([item["name"] for item in catalog["items"]], ["ssl", "web-browsing"])

    def test_imported_vendor_source_opens_full_workspace_editor_and_syncs_back(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS import editor test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,created_at,updated_at) VALUES(?,?,?,?)",
                ("editable-import", profile_id, stamp, stamp),
            ).lastrowid
        model = parse_vendor("fortinet", b'''config firewall address
edit "web01"
set subnet 192.0.2.10 255.255.255.255
next
end
config firewall policy
edit 1
set name "allow-web"
set srcintf "Trust"
set dstintf "DMZ"
set srcaddr "all"
set dstaddr "web01"
set service "HTTPS"
set action accept
next
end''', "editable-fortigate.conf")
        source_id = main.store_migration_source(project_id, "fortinet", model.source_name, model)
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(cookie_name, serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}), domain="forge.test", secure=True)
        response = client.post(
            f"/migration/projects/{project_id}/sources/{source_id}/edit",
            base_url="https://forge.test",
            data={"csrf": "migration-test-csrf"},
        )
        self.assertEqual(response.status_code, 302)
        with main.db() as conn:
            source = conn.execute("SELECT * FROM migration_sources WHERE id=?", (source_id,)).fetchone()
        workspace_id = int(source["staging_workspace_id"])
        self.assertGreater(workspace_id, 0)

        policy_page = client.get(
            f"/config-workspaces/{workspace_id}/edit?workspace_view=policies&policy_kind=security",
            base_url="https://forge.test",
        ).get_data(as_text=True)
        self.assertIn("Importeditor", policy_page)
        self.assertIn("allow-web", policy_page)
        self.assertIn("Bulk edit", policy_page)
        self.assertIn("Gebruik wijzigingen in migratie", policy_page)
        self.assertNotIn(">API push<", policy_page)
        object_page = client.get(
            f"/config-workspaces/{workspace_id}/edit?workspace_view=objects&object_type=addresses",
            base_url="https://forge.test",
        ).get_data(as_text=True)
        self.assertIn("web01", object_page)
        self.assertIn("+ Add", object_page)
        self.assertIn("− Delete", object_page)

        saved = client.post(
            f"/config-workspaces/{workspace_id}/policies/preview",
            base_url="https://forge.test",
            data={
                "csrf": "migration-test-csrf", "scope": "vsys1",
                "direct_save": "yes",
                "policy_kind": "security", "rulebase": "standard",
                "policy_name": "allow-web", "name": "allow-web-edited",
                "from": "Trust", "to": "DMZ", "source": "any",
                "destination": "web01", "source_user": "any",
                "destination_user": "any", "source_hip": "any",
                "destination_hip": "any", "category": "any",
                "application": "any", "service": "HTTPS", "action": "allow",
                "description": "edited before migration merge",
            },
        )
        self.assertEqual(saved.status_code, 302)
        with main.db() as conn:
            edited_source = conn.execute("SELECT * FROM migration_sources WHERE id=?", (source_id,)).fetchone()
        edited_workspace_id = int(edited_source["staging_workspace_id"])
        self.assertNotEqual(edited_workspace_id, workspace_id)
        edited_page = client.get(
            f"/config-workspaces/{edited_workspace_id}/edit?workspace_view=policies&policy_kind=security",
            base_url="https://forge.test",
        ).get_data(as_text=True)
        self.assertIn("allow-web-edited", edited_page)
        self.assertIn("Gebruik wijzigingen in migratie", edited_page)
        self.assertNotIn(">API push<", edited_page)

        synced = client.post(
            f"/migration/projects/{project_id}/sources/{source_id}/sync-workspace",
            base_url="https://forge.test",
            data={"csrf": "migration-test-csrf"},
        )
        self.assertEqual(synced.status_code, 302)
        refreshed = main.migration_model(main.migration_source_row(source_id))
        self.assertEqual(refreshed.vendor, "fortinet")
        self.assertEqual(refreshed.security_rules[0].name, "allow-web-edited")
        project_page = client.get(f"/migration/projects/{project_id}", base_url="https://forge.test").get_data(as_text=True)
        self.assertIn("Open importeditor", project_page)

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
        self.assertIn("Collision report · 2", page.get_data(as_text=True))
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
        self.assertIn("REVIEW VERPLICHT", page)
        self.assertIn("Niet klaar voor push", page)

    def test_source_import_can_preserve_or_override_policy_status(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS import status test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,owner,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("policy-status-import", profile_id, "admin", stamp, stamp),
            ).lastrowid
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(
                main.app.config["SESSION_COOKIE_NAME"],
                serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}),
                domain="forge.test", secure=True,
            )
        source = json.dumps({
            "rulebase": [
                {"type": "access-rule", "uid": "enabled", "name": "Enabled rule", "action": "Accept", "enabled": True},
                {"type": "access-rule", "uid": "disabled", "name": "Disabled rule", "action": "Accept", "enabled": False},
            ],
            "nat-rulebase": [
                {"type": "nat-rule", "uid": "nat-enabled", "name": "Enabled NAT", "enabled": True,
                 "original-source": ["any"], "original-destination": ["any"], "original-service": ["any"],
                 "translated-source": ["original"], "translated-destination": ["original"],
                 "translated-service": ["original"]},
            ],
        }).encode()

        preserved = client.post(
            f"/migration/projects/{project_id}/source",
            base_url="https://forge.test",
            data={
                "csrf": "migration-test-csrf", "vendor": "checkpoint",
                "config_file": (io.BytesIO(source), "preserve.json"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(preserved.status_code, 302)
        with main.db() as conn:
            preserved_source = conn.execute(
                "SELECT * FROM migration_sources WHERE project_id=? ORDER BY id DESC LIMIT 1", (project_id,)
            ).fetchone()
        preserved_model = main.migration_model(preserved_source)
        self.assertEqual([rule.disabled for rule in preserved_model.security_rules], [False, True])
        self.assertEqual([rule.disabled for rule in preserved_model.nat_rules], [False])

        overridden = client.post(
            f"/migration/projects/{project_id}/source",
            base_url="https://forge.test",
            data={
                "csrf": "migration-test-csrf", "vendor": "checkpoint", "force_disable_policies": "yes",
                "config_file": (io.BytesIO(source), "override.json"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(overridden.status_code, 302)
        with main.db() as conn:
            overridden_source = conn.execute(
                "SELECT * FROM migration_sources WHERE project_id=? ORDER BY id DESC LIMIT 1", (project_id,)
            ).fetchone()
        overridden_model = main.migration_model(overridden_source)
        self.assertEqual([rule.disabled for rule in overridden_model.security_rules], [True, True])
        self.assertEqual([rule.disabled for rule in overridden_model.nat_rules], [False])
        self.assertTrue(any("Importoverride" in warning for warning in overridden_model.warnings))

        page = client.get(f"/migration/projects/{project_id}", base_url="https://forge.test").get_data(as_text=True)
        self.assertIn('name="force_disable_policies"', page)
        self.assertNotIn('name="force_disable_policies" value="yes" checked', page)
        self.assertIn("hun enabled/disabled-status uit de bronconfiguratie behouden", page)

    def test_offline_project_builds_candidate_without_device_and_can_attach_target(self):
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(
                main.app.config["SESSION_COOKIE_NAME"],
                serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}),
                domain="forge.test", secure=True,
            )

        created = client.post(
            "/migration/projects", base_url="https://forge.test",
            data={"csrf": "migration-test-csrf", "name": "offline-no-device", "target_profile_id": "offline-panos"},
        )
        self.assertEqual(created.status_code, 302)
        with main.db() as conn:
            project = conn.execute(
                "SELECT migration_projects.*,profiles.system,profiles.target_type FROM migration_projects "
                "JOIN profiles ON profiles.id=migration_projects.target_profile_id WHERE migration_projects.name=?",
                ("offline-no-device",),
            ).fetchone()
        project_id = int(project["id"])
        self.assertEqual(project["system"], 1)
        self.assertEqual(project["target_type"], "panos")
        self.assertNotIn("Offline PAN-OS", client.get("/", base_url="https://forge.test").get_data(as_text=True))

        source = b'''name,type,value,source_zone,destination_zone,source,destination,application,service,action
web,address,192.0.2.10/32,,,,,,,
allow-web,security,,Trust,Untrust,any,web,ssl,application-default,allow
'''
        imported = client.post(
            f"/migration/projects/{project_id}/source", base_url="https://forge.test",
            data={
                "csrf": "migration-test-csrf", "vendor": "panos-csv",
                "config_file": (io.BytesIO(source), "offline.csv"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(imported.status_code, 302)
        with main.db() as conn:
            source_id = int(conn.execute(
                "SELECT id FROM migration_sources WHERE project_id=?", (project_id,)
            ).fetchone()["id"])
        preview = client.post(
            f"/migration/projects/{project_id}/preview", base_url="https://forge.test",
            data={
                "csrf": "migration-test-csrf", "source_id": str(source_id),
                "kind": ["addresses", "security_rules"],
            },
        )
        self.assertEqual(preview.status_code, 200)
        match = re.search(r'action="/migration/drafts/([^/]+)/apply"', preview.get_data(as_text=True))
        self.assertIsNotNone(match)
        applied = client.post(
            f"/migration/drafts/{match.group(1)}/apply", base_url="https://forge.test",
            data={"csrf": "migration-test-csrf", "review_acknowledged": "reviewed"},
        )
        self.assertEqual(applied.status_code, 302)
        with main.db() as conn:
            output = conn.execute(
                "SELECT migration_outputs.*,config_workspaces.profile_id,profiles.system FROM migration_outputs "
                "JOIN config_workspaces ON config_workspaces.id=migration_outputs.workspace_id "
                "JOIN profiles ON profiles.id=config_workspaces.profile_id WHERE migration_outputs.project_id=?",
                (project_id,),
            ).fetchone()
        self.assertIsNotNone(output)
        self.assertEqual(output["system"], 1)
        exported = client.get(
            f"/migration/projects/{project_id}/export-candidate/xml", base_url="https://forge.test"
        )
        self.assertEqual(exported.status_code, 200)
        self.assertIn(b'entry name="allow-web"', exported.data)
        workspace_page = client.get(
            f"/config-workspaces/{output['workspace_id']}/edit", base_url="https://forge.test"
        ).get_data(as_text=True)
        self.assertIn("Geen push target", workspace_page)

        stamp = main.now()
        with main.db() as conn:
            target_id = int(conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("Later PAN-OS target", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid)
        attached = client.post(
            f"/migration/projects/{project_id}/target", base_url="https://forge.test",
            data={"csrf": "migration-test-csrf", "target_profile_id": str(target_id)},
        )
        self.assertEqual(attached.status_code, 302)
        with main.db() as conn:
            updated = conn.execute(
                "SELECT target_profile_id,base_workspace_id FROM migration_projects WHERE id=?", (project_id,)
            ).fetchone()
            source_row = conn.execute(
                "SELECT staging_workspace_id FROM migration_sources WHERE id=?", (source_id,)
            ).fetchone()
            output_row = conn.execute(
                "SELECT sanity_json FROM migration_outputs WHERE id=?", (output["id"],)
            ).fetchone()
        self.assertEqual(updated["target_profile_id"], target_id)
        self.assertIsNone(updated["base_workspace_id"])
        self.assertIsNone(source_row["staging_workspace_id"])
        self.assertTrue(json.loads(output_row["sanity_json"])["target_changed"])

    def test_offline_panorama_target_builds_full_xml_without_device(self):
        with main.db() as conn:
            profile = main.migration_target_profile(conn, "offline-panorama")
        self.assertEqual(profile["system"], 1)
        self.assertEqual(profile["target_type"], "panorama")
        settings = main.profile_settings(profile)
        model = MigrationModel(
            "generic", "offline-panorama",
            addresses=[Address("server", "192.0.2.10/32")],
            security_rules=[main.Policy(
                "allow-server", from_zones=["Trust"], to_zones=["DMZ"],
                destination=["server"], disabled=False,
            )],
        )
        base = migration_base_xml(model, settings["device_group"], panorama=True)
        merged, plan = merge_model_into_panos_xml(
            base, model, settings["device_group"], panorama=True, rulebase=settings["rulebase"]
        )
        self.assertGreater(plan["create"], 0)
        root = ET.fromstring(merged)
        self.assertIsNotNone(root.find("./devices/entry/device-group/entry[@name='Offline']"))
        self.assertIsNotNone(root.find(".//pre-rulebase/security/rules/entry[@name='allow-server']"))

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
        self.assertIn("Migration Control Center", page)
        self.assertIn("Bron- en doelmapping", page)
        self.assertIn("Interfaces, zones en routing mappen", page)
        self.assertIn("Filters en selecties", page)
        self.assertIn("Bulk refactor", page)
        self.assertIn("Catalogi en discovery", page)
        self.assertIn("Snippets, rollen en audit", page)
        self.assertIn('class="migration-kind-menu"', page)
        self.assertNotIn('class="migration-kind-menu" open', page)
        self.assertIn("<summary>Configuratie</summary>", page)
        self.assertIn('name="kind" value="interfaces" checked', page)
        self.assertIn('name="kind" value="zones" checked', page)
        self.assertIn('name="source_id"', page)
        self.assertIn("XML", page)
        self.assertNotIn("Set commands", page)
        self.assertIn("Nieuwe configuratie (vanaf nul)", page)
        self.assertNotIn("Interfaces en zones zijn beschikbaar", page)
        self.assertNotIn("standaard alles geselecteerd", page)
        cleared = client.post(
            f"/migration/projects/{project_id}/base",
            base_url="https://forge.test",
            data={"csrf": "migration-test-csrf", "base_workspace_id": ""},
        )
        self.assertEqual(cleared.status_code, 302)
        with main.db() as conn:
            self.assertIsNone(conn.execute("SELECT base_workspace_id FROM migration_projects WHERE id=?", (project_id,)).fetchone()["base_workspace_id"])

    def test_live_target_pull_becomes_base_without_duplicate_migration_source(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS live base test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,created_at,updated_at) VALUES(?,?,?,?)",
                ("live-base-only", profile_id, stamp, stamp),
            ).lastrowid
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(cookie_name, serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}), domain="forge.test", secure=True)
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        pulled_model = parse_vendor("panos", xml, "live-candidate.xml")
        with patch("app.main.live_profile_migration_source", return_value=(pulled_model, xml)):
            response = client.post(
                f"/migration/projects/{project_id}/source-profile",
                base_url="https://forge.test",
                data={"csrf": "migration-test-csrf", "source_profile_id": str(profile_id)},
            )
        self.assertEqual(response.status_code, 302)
        with main.db() as conn:
            project = conn.execute("SELECT * FROM migration_projects WHERE id=?", (project_id,)).fetchone()
            source_count = conn.execute("SELECT COUNT(*) count FROM migration_sources WHERE project_id=?", (project_id,)).fetchone()["count"]
            workspace = conn.execute("SELECT * FROM config_workspaces WHERE id=?", (project["base_workspace_id"],)).fetchone()
        self.assertEqual(source_count, 0)
        self.assertIsNotNone(workspace)
        self.assertEqual(workspace["source"], "migration-api")

    def test_candidate_export_uses_latest_generated_output(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS latest output test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,created_at,updated_at) VALUES(?,?,?,?)",
                ("latest-output-export", profile_id, stamp, stamp),
            ).lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        main.store_migration_source(
            project_id, "generic", "would-recompute.json",
            MigrationModel("generic", "would-recompute.json", addresses=[Address("wrong-object", "192.0.2.1/32")]),
        )
        latest_xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="latest-output"><ip-netmask>192.0.2.2/32</ip-netmask></entry></address><rulebase/></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "Latest output", "latest.xml", latest_xml, "migration-output")
        main.store_migration_output(project_id, workspace_id, "Latest output")
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(cookie_name, serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}), domain="forge.test", secure=True)
        response = client.get(f"/migration/projects/{project_id}/export-candidate/xml", base_url="https://forge.test")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, main.workspace_config_path(main.workspace_row(workspace_id)).read_bytes())
        self.assertIn(b"latest-output", response.data)
        self.assertNotIn(b"wrong-object", response.data)

    def test_merge_preview_blocks_when_target_delta_is_zero(self):
        stamp=main.now()
        with main.db() as conn:
            profile_id=conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS zero delta test","panos",json.dumps({"vsys":"vsys1"}),stamp,stamp),
            ).lastrowid
            profile=conn.execute("SELECT * FROM profiles WHERE id=?",(profile_id,)).fetchone()
        base=b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="same"><ip-netmask>192.0.2.20/32</ip-netmask></entry></address><rulebase/></entry></vsys></entry></devices></config>'''
        workspace_id=main.store_config_workspace(profile,"Zero delta base","zero.xml",base,"test")
        with main.db() as conn:
            project_id=conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,base_workspace_id,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("zero-delta",profile_id,workspace_id,stamp,stamp),
            ).lastrowid
        source_id=main.store_migration_source(
            project_id,"generic","same.json",
            MigrationModel("generic","same.json",addresses=[Address("same","192.0.2.20/32")]),
        )
        client=main.app.test_client()
        with main.app.test_request_context("/",base_url="https://forge.test"):
            serializer=main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(
                main.app.config["SESSION_COOKIE_NAME"],
                serializer.dumps({"user_id":1,"username":"admin","csrf":"migration-test-csrf"}),
                domain="forge.test",secure=True,
            )
        response=client.post(
            f"/migration/projects/{project_id}/preview",base_url="https://forge.test",
            data={"csrf":"migration-test-csrf","source_id":str(source_id),"kind":"addresses"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code,200)
        self.assertIn("geen wijziging aan de target candidate",response.get_data(as_text=True))

    def test_merge_preview_renders_cross_name_reuse_as_opt_in(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS reuse preview", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        base = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="existing"><ip-netmask>192.0.2.20/32</ip-netmask></entry></address><rulebase/></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "Reuse base", "reuse.xml", base, "test")
        with main.db() as conn:
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,base_workspace_id,owner,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                ("reuse-preview", profile_id, workspace_id, "admin", stamp, stamp),
            ).lastrowid
        source_id = main.store_migration_source(
            project_id, "generic", "source.json",
            MigrationModel("generic", "source.json", addresses=[Address("imported", "192.0.2.20/32")]),
        )
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(
                main.app.config["SESSION_COOKIE_NAME"],
                serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}),
                domain="forge.test", secure=True,
            )
        response = client.post(
            f"/migration/projects/{project_id}/preview",
            base_url="https://forge.test",
            data={"csrf": "migration-test-csrf", "source_id": str(source_id), "kind": "addresses"},
        )
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Voorgesteld objecthergebruik", page)
        self.assertIn('name="approved_reuse"', page)
        self.assertNotIn('name="approved_reuse" checked', page)

    def test_migration_output_workspace_links_back_and_blocks_push_when_review_fails(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS review gate test", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,created_at,updated_at) VALUES(?,?,?,?)",
                ("blocked-output", profile_id, stamp, stamp),
            ).lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "Blocked candidate", "blocked.xml", xml, "migration-output")
        main.store_migration_output(
            project_id, workspace_id, "Blocked candidate",
            sanity={"critical_findings": 1, "unresolved_references": 0, "regenerate_required": False},
        )
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            cookie_name = main.app.config["SESSION_COOKIE_NAME"]
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(cookie_name, serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}), domain="forge.test", secure=True)
        page = client.get(f"/config-workspaces/{workspace_id}/edit", base_url="https://forge.test").get_data(as_text=True)
        self.assertIn("Terug naar migratieproject", page)
        self.assertIn("Migratiecandidate", page)
        self.assertIn("Review vereist", page)
        self.assertNotIn(">API push<", page)
        blocked = client.get(
            f"/config-workspaces/{workspace_id}/push-preview",
            base_url="https://forge.test",
        )
        self.assertEqual(blocked.status_code, 302)
        self.assertIn(f"/migration/projects/{project_id}", blocked.headers["Location"])

    def test_review_gate_follows_candidate_edits_and_requires_audited_resolution(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS persistent gate", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,owner,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("persistent-gate", profile_id, "admin", stamp, stamp),
            ).lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "Candidate", "candidate.xml", xml, "migration-merge")
        output_id = main.store_migration_output(
            project_id, workspace_id, "Candidate",
            sanity={
                "critical_findings": 1,
                "candidate_unresolved_references": 0,
                "critical_review_codes": {
                    "unsupported-actions": {"title": "Policy-acties", "detail": "Controleer acties", "count": 1},
                },
                "regenerate_required": False,
            },
        )
        edited_id = main.store_workspace_edit_version(
            main.workspace_row(workspace_id), xml, "policy edit"
        )
        with main.db() as conn:
            output = conn.execute("SELECT * FROM migration_outputs WHERE id=?", (output_id,)).fetchone()
        self.assertEqual(int(output["workspace_id"]), edited_id)
        self.assertIn("kritieke", main.migration_output_push_block(edited_id)[1])

        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(
                main.app.config["SESSION_COOKIE_NAME"],
                serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}),
                domain="forge.test", secure=True,
            )
        response = client.post(
            f"/migration/projects/{project_id}/outputs/{output_id}/review/unsupported-actions",
            base_url="https://forge.test",
            data={"csrf": "migration-test-csrf", "note": "Actie in candidate gecontroleerd"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(main.migration_output_push_block(edited_id)[1], "")

    def test_bulk_review_resolves_critical_and_warning_codes_with_one_audit_note(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("PANOS bulk review", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,owner,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("bulk-review", profile_id, "admin", stamp, stamp),
            ).lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "Candidate", "candidate.xml", xml, "migration-merge")
        critical = {
            "zone-mapping": {
                "title": "Zone-mapping",
                "detail": "Controleer zones",
                "count": 2,
                "severity": "critical",
            }
        }
        review_codes = {
            **critical,
            "duplicate-policies": {
                "title": "Dubbele policies",
                "detail": "Controleer duplicaten",
                "count": 3,
                "severity": "warning",
            },
        }
        output_id = main.store_migration_output(
            project_id,
            workspace_id,
            "Candidate",
            sanity={
                "critical_findings": 1,
                "candidate_unresolved_references": 0,
                "critical_review_codes": critical,
                "review_codes": review_codes,
                "regenerate_required": False,
            },
        )
        client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            client.set_cookie(
                main.app.config["SESSION_COOKIE_NAME"],
                serializer.dumps({"user_id": 1, "username": "admin", "csrf": "migration-test-csrf"}),
                domain="forge.test",
                secure=True,
            )
        page = client.get(f"/migration/projects/{project_id}", base_url="https://forge.test")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Bulk engineer review", page.data)
        self.assertIn(b"Dubbele policies", page.data)
        resolved = client.post(
            f"/migration/projects/{project_id}/outputs/{output_id}/review-bulk",
            base_url="https://forge.test",
            data={
                "csrf": "migration-test-csrf",
                "review_code": ["zone-mapping", "duplicate-policies"],
                "note": "Zones en duplicaten in candidate gecontroleerd",
                "action": "resolve",
            },
        )
        self.assertEqual(resolved.status_code, 302)
        with main.db() as conn:
            rows = conn.execute(
                "SELECT code,note FROM migration_output_resolutions WHERE output_id=? ORDER BY code",
                (output_id,),
            ).fetchall()
        self.assertEqual([row["code"] for row in rows], ["duplicate-policies", "zone-mapping"])
        self.assertTrue(all(row["note"] == "Zones en duplicaten in candidate gecontroleerd" for row in rows))
        self.assertEqual(main.migration_output_push_block(workspace_id)[1], "")
        reopened = client.post(
            f"/migration/projects/{project_id}/outputs/{output_id}/review-bulk",
            base_url="https://forge.test",
            data={
                "csrf": "migration-test-csrf",
                "review_code": ["duplicate-policies"],
                "action": "reopen",
            },
        )
        self.assertEqual(reopened.status_code, 302)
        self.assertEqual(main.migration_output_push_block(workspace_id)[1], "")
        with main.db() as conn:
            remaining = conn.execute(
                "SELECT code FROM migration_output_resolutions WHERE output_id=? ORDER BY code",
                (output_id,),
            ).fetchall()
        self.assertEqual([row["code"] for row in remaining], ["zone-mapping"])


if __name__ == "__main__":
    unittest.main()
