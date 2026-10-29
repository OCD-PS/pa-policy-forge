import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.offline_config import (
    OfflineConfigError, apply_configuration_changes, apply_object_changes, available_scopes, available_templates,
    configuration_inventory, configuration_records, create_basic_network_entry, parse_snapshot,
    delete_policies_from_snapshot, insert_policy_in_snapshot, move_policies_in_snapshot,
    object_create_record, object_fingerprint, object_record, policy_create_record, policy_fingerprint, render_set_commands, replace_policy_in_snapshot,
    referenced_template, scoped_objects, scoped_object_names, scoped_object_page, scoped_policies,
    scoped_server_profiles, object_reference_index, duplicate_object_groups, merge_duplicate_objects,
    merge_duplicate_object_groups, duplicate_object_groups_across_panos_scopes,
    merge_duplicate_object_groups_to_shared, object_reference_indexes,
)


PANORAMA = b'''<config version="12.1.2"><shared><address><entry name="shared-a"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address></shared><devices><entry name="localhost.localdomain"><device-group><entry name="Parent"><pre-rulebase><security><rules><entry name="allow-parent"/></rules></security></pre-rulebase></entry><entry name="Child"><parent-dg>Parent</parent-dg><reference-template>Branch-Stack</reference-template><post-rulebase><nat><rules><entry name="nat-child"/></rules></nat></post-rulebase><address><entry name="child-a"><ip-netmask>10.0.0.2/32</ip-netmask></entry></address></entry></device-group><template><entry name="Base"/><entry name="Branch"/></template><template-stack><entry name="Branch-Stack"><templates><member>Branch</member><member>Base</member></templates></entry></template-stack></entry></devices></config>'''

PANOS = b'''<config version="11.2.4"><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"/></ethernet></interface></network><vsys><entry name="vsys1"><zone><entry name="Trust"/><entry name="Internet"/></zone><rulebase><security><rules><entry name="allow-web"><from><member>Trust</member></from></entry></rules></security></rulebase></entry><entry name="vsys2"/></vsys></entry></devices></config>'''

INHERITED = b'''<config version="12.1"><shared><address><entry name="shared-a"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address><pre-rulebase><security><rules><entry name="shared-rule"><from><member>any</member></from><custom-unknown>keep-me</custom-unknown></entry></rules></security></pre-rulebase></shared><devices><entry name="localhost.localdomain"><device-group><entry name="Parent"><parent-dg>Shared</parent-dg><pre-rulebase><security><rules><entry name="parent-rule"><from><member>Trust</member></from></entry></rules></security></pre-rulebase><address><entry name="parent-a"><ip-netmask>10.0.0.2/32</ip-netmask></entry></address></entry><entry name="Child"><parent-dg>Parent</parent-dg><pre-rulebase><security><rules><entry name="child-rule"><from><member>Clients</member></from><to><member>Internet</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>web-browsing</member></application><service><member>application-default</member></service><action>allow</action><custom-unknown>preserve</custom-unknown></entry></rules></security></pre-rulebase></entry></device-group></entry></devices></config>'''


class OfflineConfigTests(unittest.TestCase):
    def test_scoped_object_names_match_editor_records_for_shared_and_inherited_scopes(self):
        for xml, scope, object_type in (
            (b'''<config><shared><address><entry name="shared-a"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="local-a"><ip-netmask>192.0.2.2/32</ip-netmask></entry></address></entry></vsys></entry></devices></config>''', "vsys1", "addresses"),
            (PANORAMA, "Child", "addresses"),
        ):
            parsed = parse_snapshot(xml)
            _, records = scoped_objects(xml, scope, object_type, parsed=parsed)
            _, names = scoped_object_names(xml, scope, object_type, parsed=parsed)
            self.assertEqual(names, [record["name"] for record in records])

    def test_unfiltered_object_page_builds_only_visible_records_and_keeps_shared_last(self):
        xml = b'''<config><shared><address>
        <entry name="shared-a"><ip-netmask>192.0.2.1/32</ip-netmask></entry>
        <entry name="shared-b"><ip-netmask>192.0.2.2/32</ip-netmask></entry>
        </address></shared><devices><entry name="localhost.localdomain"><vsys>
        <entry name="vsys1"><address>
        <entry name="local-a"><ip-netmask>192.0.2.3/32</ip-netmask></entry>
        <entry name="local-b"><ip-netmask>192.0.2.4/32</ip-netmask></entry>
        </address></entry><entry name="vsys2"/></vsys></entry></devices></config>'''
        parsed = parse_snapshot(xml)
        with patch("app.offline_config.object_record", wraps=object_record) as build_record:
            _, total, page_count, page, records = scoped_object_page(
                xml, "vsys1", "addresses", 1, 1,
                parsed=parsed, editable_first=True,
            )
            self.assertEqual((total, page_count, page), (4, 4, 1))
            self.assertEqual([item["name"] for item in records], ["local-a"])
            self.assertEqual(build_record.call_count, 1)

        _, total, page_count, page, records = scoped_object_page(
            xml, "vsys1", "addresses", 1, 1,
            parsed=parsed, editable_first=True, selected_name="shared-b",
        )
        self.assertEqual((total, page_count, page), (4, 4, 4))
        self.assertEqual([item["name"] for item in records], ["shared-b"])

        panorama = parse_snapshot(PANORAMA, expected_kind="panorama")
        _, total, page_count, page, records = scoped_object_page(
            PANORAMA, "Child", "addresses", 99, 1, parsed=panorama,
        )
        self.assertEqual((total, page_count, page), (2, 2, 2))
        self.assertEqual([item["name"] for item in records], ["child-a"])
        _, _, _, page, records = scoped_object_page(
            PANORAMA, "Child", "addresses", 1, 1,
            parsed=panorama, selected_name="child-a",
        )
        self.assertEqual((page, [item["name"] for item in records]), (2, ["child-a"]))

    def test_cross_scope_merge_to_shared_preserves_shared_group_refs_and_rewrites_vsys(self):
        source = b'''<config><shared><address>
        <entry name="PublicServer"><ip-netmask>192.0.2.10</ip-netmask></entry>
        </address><address-group><entry name="Publilink_Group"><static><member>PublicServer</member></static></entry></address-group>
        </shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address>
        <entry name="PublicServer-vsys1"><ip-netmask>192.0.2.10</ip-netmask></entry>
        </address><rulebase><security><rules><entry name="allow"><source><member>PublicServer-vsys1</member></source></entry></rules></security></rulebase></entry>
        <entry name="vsys2"><address><entry name="PublicServer-vsys2"><ip-netmask>192.0.2.10</ip-netmask></entry></address>
        <rulebase><nat><rules><entry name="translate"><destination-translation><translated-address>PublicServer-vsys2</translated-address></destination-translation></entry></rules></nat></rulebase></entry>
        </vsys></entry></devices></config>'''
        groups = duplicate_object_groups_across_panos_scopes(source, "addresses")
        group = next(item for item in groups if {obj["name"] for obj in item["objects"]} == {
            "PublicServer", "PublicServer-vsys1", "PublicServer-vsys2",
        })
        self.assertEqual(group["objects"][0]["scope"], "Shared")
        selected = [{"object_type": "addresses", "objects": group["objects"],
                     "master": {"scope": "Shared", "name": "PublicServer"}}]

        merged, summary = merge_duplicate_object_groups_to_shared(source, selected)

        root, _ = parse_snapshot(merged)
        self.assertEqual(root.findall("./shared/address/entry"), [root.find("./shared/address/entry[@name='PublicServer']")])
        self.assertEqual(root.findtext("./shared/address-group/entry/static/member"), "PublicServer")
        self.assertEqual(root.findtext("./devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules/entry/source/member"), "PublicServer")
        self.assertEqual(root.findtext("./devices/entry/vsys/entry[@name='vsys2']/rulebase/nat/rules/entry/destination-translation/translated-address"), "PublicServer")
        self.assertEqual(summary, {"merged": 2, "groups": 1})

    def test_cross_scope_merge_to_shared_resolves_global_path_monitor_reference(self):
        source = b'''<config><shared><address>
        <entry name="8.8.8.8"><ip-netmask>8.8.8.8/32</ip-netmask></entry>
        </address></shared><devices><entry name="localhost.localdomain"><network><virtual-router>
        <entry name="VR1"><routing-table><ip><static-route><entry name="default">
        <path-monitor><monitor-destinations><entry name="dns-monitor"><destination>8.8.8.8</destination></entry></monitor-destinations></path-monitor>
        </entry></static-route></ip></routing-table></entry></virtual-router></network>
        <vsys><entry name="vsys1"><address>
        <entry name="8.8.8.8"><ip-netmask>8.8.8.8/32</ip-netmask></entry>
        </address></entry><entry name="vsys2"/></vsys></entry></devices></config>'''
        group = next(
            item for item in duplicate_object_groups_across_panos_scopes(source, "addresses")
            if {obj["scope"] for obj in item["objects"]} == {"Shared", "vsys1"}
            and {obj["name"] for obj in item["objects"]} == {"8.8.8.8"}
        )

        merged, summary = merge_duplicate_object_groups_to_shared(source, [{
            "object_type": "addresses", "objects": group["objects"],
            "master": {"scope": "Shared", "name": "8.8.8.8"},
        }])

        root, _ = parse_snapshot(merged)
        self.assertEqual(len(root.findall("./shared/address/entry[@name='8.8.8.8']")), 1)
        self.assertIsNone(root.find("./devices/entry/vsys/entry[@name='vsys1']/address/entry[@name='8.8.8.8']"))
        self.assertEqual(
            root.findtext("./devices/entry/network/virtual-router/entry/routing-table/ip/static-route/entry/path-monitor/monitor-destinations/entry/destination"),
            "8.8.8.8",
        )
        self.assertEqual(summary, {"merged": 1, "groups": 1})

        unscoped = source.replace(
            b"</devices></config>",
            b"</devices><rulebase><security><rules><entry name='unscoped'><source>"
            b"<member>8.8.8.8</member></source></entry></rules></security></rulebase></config>",
        )
        unscoped_group = next(
            item for item in duplicate_object_groups_across_panos_scopes(unscoped, "addresses")
            if {obj["scope"] for obj in item["objects"]} == {"Shared", "vsys1"}
            and {obj["name"] for obj in item["objects"]} == {"8.8.8.8"}
        )
        with self.assertRaisesRegex(OfflineConfigError, "geen herkenbare scope"):
            merge_duplicate_object_groups_to_shared(unscoped, [{
                "object_type": "addresses", "objects": unscoped_group["objects"],
                "master": {"scope": "Shared", "name": "8.8.8.8"},
            }])

    def test_cross_scope_merge_can_select_vsys_master_and_rewrites_shared_references(self):
        source = b'''<config><shared><address><entry name="old-shared"><ip-netmask>192.0.2.11</ip-netmask></entry></address>
        <address-group><entry name="Consumers"><static><member>old-shared</member></static></entry></address-group></shared>
        <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="new-master"><ip-netmask>192.0.2.11</ip-netmask></entry></address></entry><entry name="vsys2"/></vsys></entry></devices></config>'''
        group = duplicate_object_groups_across_panos_scopes(source, "addresses")[0]
        selected = [{"object_type": "addresses", "objects": group["objects"],
                     "master": {"scope": "vsys1", "name": "new-master"}}]
        merged, _ = merge_duplicate_object_groups_to_shared(source, selected)
        root, _ = parse_snapshot(merged)
        self.assertIsNotNone(root.find("./shared/address/entry[@name='new-master']"))
        self.assertIsNone(root.find("./shared/address/entry[@name='old-shared']"))
        self.assertEqual(root.findtext("./shared/address-group/entry/static/member"), "new-master")
        self.assertIsNone(root.find("./devices/entry/vsys/entry[@name='vsys1']/address/entry"))

    def test_cross_scope_service_merge_unions_tags_on_shared_master(self):
        source = b'''<config><shared><service><entry name="https"><protocol><tcp><port>443</port></tcp></protocol><tag><member>Blue</member></tag></entry></service></shared>
        <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><service><entry name="web-443"><protocol><tcp><port>443</port></tcp></protocol><tag><member>Green</member></tag></entry></service>
        <rulebase><security><rules><entry name="allow"><service><member>web-443</member></service></entry></rules></security></rulebase></entry><entry name="vsys2"/></vsys></entry></devices></config>'''
        group = duplicate_object_groups_across_panos_scopes(source, "services")[0]
        merged, _ = merge_duplicate_object_groups_to_shared(source, [{
            "object_type": "services", "objects": group["objects"],
            "master": {"scope": "Shared", "name": "https"},
        }])
        root, _ = parse_snapshot(merged)
        self.assertEqual(
            [node.text for node in root.findall("./shared/service/entry/tag/member")],
            ["Blue", "Green"],
        )
        self.assertEqual(root.findtext("./devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules/entry/service/member"), "https")

    def test_cross_scope_merge_rejects_unselected_local_shadow_and_stale_selection(self):
        source = b'''<config><shared><service><entry name="https"><protocol><tcp><port>443</port></tcp></protocol></entry></service></shared>
        <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><service><entry name="web-443"><protocol><tcp><port>443</port></tcp></protocol></entry></service></entry>
        <entry name="vsys2"><service><entry name="https"><protocol><tcp><port>8443</port></tcp></protocol></entry></service></entry></vsys></entry></devices></config>'''
        group = duplicate_object_groups_across_panos_scopes(source, "services")[0]
        selection = {"object_type": "services", "objects": group["objects"],
                     "master": {"scope": "Shared", "name": "https"}}
        with self.assertRaisesRegex(OfflineConfigError, "overschaduwd"):
            merge_duplicate_object_groups_to_shared(source, [selection])
        stale = {**selection, "objects": [{**item, "fingerprint": "0" * 64} for item in group["objects"]]}
        with self.assertRaisesRegex(OfflineConfigError, "gewijzigd"):
            merge_duplicate_object_groups_to_shared(
                source.replace(b'<entry name="https"><protocol><tcp><port>8443', b'<entry name="https"><protocol><tcp><port>443'),
                [stale],
            )

    def test_duplicate_services_rewrite_references_and_deduplicate_members(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><service>
        <entry name="TCP443"><protocol><tcp><port>443</port></tcp></protocol><description>Primary</description><tag><member>Blue</member></tag></entry>
        <entry name="service-https"><protocol><tcp><port>443</port><source-port>0-65535</source-port></tcp></protocol><description>HTTPS service</description><tag><member>Green</member></tag></entry>
        <entry name="443_tcp"><protocol><tcp><port>443</port></tcp></protocol><tag><member>Blue</member></tag></entry>
        <entry name="ssh"><protocol><tcp><port>22</port></tcp></protocol></entry>
        </service><service-group><entry name="web-services"><members><member>TCP443</member><member>service-https</member></members></entry></service-group>
        <rulebase><security><rules><entry name="allow-web"><service><member>TCP443</member><member>service-https</member><member>ssh</member></service></entry></rules></security></rulebase>
        </entry></vsys></entry></devices></config>'''
        groups = duplicate_object_groups(source, "vsys1", "services")
        self.assertEqual(len(groups), 1)
        self.assertEqual({item["name"] for item in groups[0]["objects"]}, {"TCP443", "service-https", "443_tcp"})
        selection = {
            "names": [item["name"] for item in groups[0]["objects"]],
            "master": "service-https",
            "fingerprints": {item["name"]: item["fingerprint"] for item in groups[0]["objects"]},
        }
        merged, summary = merge_duplicate_objects(source, "vsys1", "services", [selection])
        _, objects = scoped_objects(merged, "vsys1", "services")
        self.assertEqual({item["name"] for item in objects}, {"service-https", "ssh"})
        root, _ = parse_snapshot(merged)
        self.assertEqual(
            [member.text for member in root.findall(".//service-group/entry[@name='web-services']/members/member")],
            ["service-https"],
        )
        self.assertEqual(
            [member.text for member in root.findall(".//rules/entry[@name='allow-web']/service/member")],
            ["service-https", "ssh"],
        )
        self.assertEqual(
            [member.text for member in root.findall(".//service/entry[@name='service-https']/tag/member")],
            ["Green", "Blue"],
        )
        self.assertEqual(summary, {"merged": 2, "groups": 1})
        self.assertEqual(object_reference_index(merged, "services", ["TCP443", "443_tcp"]), {"TCP443": [], "443_tcp": []})

    def test_batch_duplicate_merge_updates_multiple_object_families_atomically(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="server-a"><ip-netmask>192.0.2.10</ip-netmask></entry><entry name="server-b"><ip-netmask>192.0.2.10</ip-netmask></entry></address><service><entry name="tcp443"><protocol><tcp><port>443</port></tcp></protocol></entry><entry name="https-alt"><protocol><tcp><port>443</port></tcp></protocol></entry></service><rulebase><security><rules><entry name="allow"><source><member>server-b</member></source><service><member>https-alt</member></service></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''
        selections = []
        for object_type, master in (("addresses", "server-a"), ("services", "tcp443")):
            group = duplicate_object_groups(source, "vsys1", object_type)[0]
            names = [item["name"] for item in group["objects"]]
            selections.append({
                "object_type": object_type,
                "names": names,
                "master": master,
                "fingerprints": {item["name"]: item["fingerprint"] for item in group["objects"]},
            })

        merged, summary = merge_duplicate_object_groups(source, "vsys1", selections)

        root, _ = parse_snapshot(merged)
        self.assertEqual(root.findtext(".//rules/entry/source/member"), "server-a")
        self.assertEqual(root.findtext(".//rules/entry/service/member"), "tcp443")
        _, addresses = scoped_objects(merged, "vsys1", "addresses")
        _, services = scoped_objects(merged, "vsys1", "services")
        self.assertEqual([item["name"] for item in addresses], ["server-a"])
        self.assertEqual([item["name"] for item in services], ["tcp443"])
        self.assertEqual(summary, {"merged": 2, "groups": 2})

    def test_duplicate_objects_with_different_tags_are_not_grouped(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="server-a"><ip-netmask>10.0.0.1</ip-netmask><tag><member>Production</member></tag></entry><entry name="server-b"><ip-netmask>10.0.0.1</ip-netmask><tag><member>Test</member></tag></entry></address></entry></vsys></entry></devices></config>'''
        self.assertEqual(duplicate_object_groups(source, "vsys1", "addresses"), [])

    def test_service_source_port_only_normalizes_the_documented_unrestricted_range(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><service><entry name="omitted"><protocol><tcp><port>443</port></tcp></protocol></entry><entry name="full-range"><protocol><tcp><port>443</port><source-port>0-65535</source-port></tcp></protocol></entry><entry name="excludes-zero"><protocol><tcp><port>443</port><source-port>1-65535</source-port></tcp></protocol></entry></service></entry></vsys></entry></devices></config>'''
        groups = duplicate_object_groups(source, "vsys1", "services")
        self.assertEqual(len(groups), 1)
        self.assertEqual({item["name"] for item in groups[0]["objects"]}, {"omitted", "full-range"})

    def test_panorama_shared_merge_rewrites_pre_and_post_policy_references(self):
        source = b'''<config><shared><service><entry name="tcp443"><protocol><tcp><port>443</port><source-port>1-65535</source-port></tcp></protocol></entry><entry name="https-alt"><protocol><tcp><port>443</port><source-port>1-65535</source-port></tcp></protocol></entry></service><pre-rulebase><security><rules><entry name="pre"><service><member>tcp443</member></service></entry></rules></security></pre-rulebase></shared><devices><entry name="localhost.localdomain"><device-group><entry name="Branch"><post-rulebase><nat><rules><entry name="post"><service><member>https-alt</member></service></entry></rules></nat></post-rulebase></entry></device-group></entry></devices></config>'''
        groups = duplicate_object_groups(source, "Shared", "services")
        self.assertEqual(len(groups), 1)
        selection = {
            "names": [item["name"] for item in groups[0]["objects"]],
            "master": "https-alt",
            "fingerprints": {item["name"]: item["fingerprint"] for item in groups[0]["objects"]},
        }
        merged, _ = merge_duplicate_objects(source, "Shared", "services", [selection])
        root, _ = parse_snapshot(merged)
        self.assertEqual(root.findtext(".//pre-rulebase/security/rules/entry/service/member"), "https-alt")
        self.assertEqual(root.findtext(".//post-rulebase/nat/rules/entry/service/member"), "https-alt")

    def test_tag_merge_rewrites_dynamic_filters_and_deduplicates_policy_tags(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><tag><entry name="blue"><color>color1</color></entry><entry name="blue-alt"><color>color1</color></entry></tag><address-group><entry name="dynamic"><dynamic><filter>'blue' or 'blue-alt'</filter></dynamic></entry></address-group><rulebase><security><rules><entry name="tagged"><tag><member>blue</member><member>blue-alt</member></tag></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''
        group = duplicate_object_groups(source, "vsys1", "tags")[0]
        selection = {
            "names": [item["name"] for item in group["objects"]],
            "master": "blue",
            "fingerprints": {item["name"]: item["fingerprint"] for item in group["objects"]},
        }
        merged, _ = merge_duplicate_objects(source, "vsys1", "tags", [selection])
        root, _ = parse_snapshot(merged)
        self.assertEqual(root.findtext(".//address-group/entry/dynamic/filter"), "'blue' or 'blue'")
        self.assertEqual([item.text for item in root.findall(".//rules/entry/tag/member")], ["blue"])


    def test_duplicate_merge_uses_effective_scope_and_preserves_same_name_in_other_scopes(self):
        source = b'''<config><shared><address><entry name="0_NAC_10_10_130_0_24"><ip-netmask>10.10.130.0/24</ip-netmask></entry></address></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="0_NAC_10_10_130_0_24"><ip-netmask>10.10.130.0/24</ip-netmask></entry><entry name="NAC_Network"><ip-netmask>10.10.130.0/24</ip-netmask></entry></address><rulebase><security><rules><entry name="allow-nac"><source><member>0_NAC_10_10_130_0_24</member></source></entry></rules></security></rulebase></entry><entry name="vsys2"><address><entry name="0_NAC_10_10_130_0_24"><ip-netmask>192.0.2.0/24</ip-netmask></entry></address><rulebase><security><rules><entry name="other-nac"><source><member>0_NAC_10_10_130_0_24</member></source></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''
        groups = duplicate_object_groups(source, "vsys1", "addresses")
        group = next(group for group in groups if {item["name"] for item in group["objects"]} == {
            "0_NAC_10_10_130_0_24", "NAC_Network",
        })
        selection = {
            "names": [item["name"] for item in group["objects"]], "master": "NAC_Network",
            "fingerprints": {item["name"]: item["fingerprint"] for item in group["objects"]},
        }

        merged, _ = merge_duplicate_objects(source, "vsys1", "addresses", [selection])

        root, _ = parse_snapshot(merged)
        self.assertEqual(root.findtext(".//vsys/entry[@name='vsys1']/rulebase/security/rules/entry/source/member"), "NAC_Network")
        self.assertEqual(root.findtext(".//vsys/entry[@name='vsys2']/rulebase/security/rules/entry/source/member"), "0_NAC_10_10_130_0_24")
        self.assertIsNotNone(root.find("./shared/address/entry[@name='0_NAC_10_10_130_0_24']"))
        self.assertIsNotNone(root.find(".//vsys/entry[@name='vsys2']/address/entry[@name='0_NAC_10_10_130_0_24']"))
        self.assertIsNone(root.find(".//vsys/entry[@name='vsys1']/address/entry[@name='0_NAC_10_10_130_0_24']"))

    def test_duplicate_merge_rejects_shadowed_master_and_stale_preview(self):
        source = b'''<config><shared><service><entry name="dup"><protocol><tcp><port>443</port></tcp></protocol></entry></service></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><service><entry name="dup"><protocol><tcp><port>443</port></tcp></protocol></entry><entry name="master"><protocol><tcp><port>443</port></tcp></protocol></entry></service></entry></vsys></entry></devices></config>'''
        groups = duplicate_object_groups(source, "vsys1", "services")
        self.assertEqual(len(groups), 1)
        selection = {
            "names": [item["name"] for item in groups[0]["objects"]], "master": "master",
            "fingerprints": {item["name"]: item["fingerprint"] for item in groups[0]["objects"]},
        }
        merged, _ = merge_duplicate_objects(source, "vsys1", "services", [selection])
        root, _ = parse_snapshot(merged)
        self.assertIsNotNone(root.find("./shared/service/entry[@name='dup']"))
        self.assertIsNone(root.find(".//vsys/entry[@name='vsys1']/service/entry[@name='dup']"))

        unshadowed = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><service><entry name="dup"><protocol><tcp><port>443</port></tcp></protocol></entry><entry name="master"><protocol><tcp><port>443</port></tcp></protocol></entry></service></entry></vsys></entry></devices></config>'''
        stale = dict(selection, fingerprints={"dup": "0" * 64, "master": selection["fingerprints"]["master"]})
        with self.assertRaisesRegex(OfflineConfigError, "intussen gewijzigd"):
            merge_duplicate_objects(unshadowed, "vsys1", "services", [stale])

    def test_duplicate_merge_rejects_master_shadowed_by_reference_scope(self):
        source = b'''<config><shared><address><entry name="alias"><ip-netmask>10.0.0.1/24</ip-netmask></entry><entry name="master"><ip-netmask>10.0.0.1/24</ip-netmask></entry></address></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="master"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address><rulebase><security><rules><entry name="allow"><source><member>alias</member></source></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''
        groups = duplicate_object_groups(source, "Shared", "addresses")
        selection = {
            "names": [item["name"] for item in groups[0]["objects"]], "master": "master",
            "fingerprints": {item["name"]: item["fingerprint"] for item in groups[0]["objects"]},
        }
        with self.assertRaisesRegex(OfflineConfigError, "overschaduwd"):
            merge_duplicate_objects(source, "Shared", "addresses", [selection])

    def test_duplicate_merge_fails_closed_for_selected_reference_without_scope(self):
        source = b'''<config><rulebase><security><rules><entry name="unscoped"><source><member>alias</member></source></entry></rules></security></rulebase><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="alias"><ip-netmask>10.0.0.1/24</ip-netmask></entry><entry name="master"><ip-netmask>10.0.0.1/24</ip-netmask></entry></address></entry></vsys></entry></devices></config>'''
        groups = duplicate_object_groups(source, "vsys1", "addresses")
        selection = {
            "names": [item["name"] for item in groups[0]["objects"]], "master": "master",
            "fingerprints": {item["name"]: item["fingerprint"] for item in groups[0]["objects"]},
        }
        with self.assertRaisesRegex(OfflineConfigError, "geen herkenbare scope"):
            merge_duplicate_objects(source, "vsys1", "addresses", [selection])

    def test_panorama_merge_rewrites_inherited_child_reference_but_preserves_shadow(self):
        source = b'''<config><shared/><devices><entry name="localhost.localdomain"><device-group><entry name="Parent"><address><entry name="alias"><ip-netmask>10.0.0.1/24</ip-netmask></entry><entry name="master"><ip-netmask>10.0.0.1/24</ip-netmask></entry></address></entry><entry name="Child"><parent-dg>Parent</parent-dg><pre-rulebase><security><rules><entry name="inherited"><source><member>alias</member></source></entry></rules></security></pre-rulebase></entry><entry name="ChildShadow"><parent-dg>Parent</parent-dg><address><entry name="alias"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address><pre-rulebase><security><rules><entry name="local"><source><member>alias</member></source></entry></rules></security></pre-rulebase></entry></device-group></entry></devices></config>'''
        groups = duplicate_object_groups(source, "Parent", "addresses")
        selection = {
            "names": [item["name"] for item in groups[0]["objects"]], "master": "master",
            "fingerprints": {item["name"]: item["fingerprint"] for item in groups[0]["objects"]},
        }

        merged, _ = merge_duplicate_objects(source, "Parent", "addresses", [selection])

        root, _ = parse_snapshot(merged)
        self.assertEqual(root.findtext(".//device-group/entry[@name='Child']/pre-rulebase/security/rules/entry/source/member"), "master")
        self.assertEqual(root.findtext(".//device-group/entry[@name='ChildShadow']/pre-rulebase/security/rules/entry/source/member"), "alias")
        self.assertIsNone(root.find(".//device-group/entry[@name='Parent']/address/entry[@name='alias']"))
        self.assertIsNotNone(root.find(".//device-group/entry[@name='ChildShadow']/address/entry[@name='alias']"))

    def test_duplicate_merge_rejects_overlapping_groups(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><service><entry name="one"><protocol><tcp><port>443</port></tcp></protocol></entry><entry name="two"><protocol><tcp><port>443</port></tcp></protocol></entry><entry name="three"><protocol><tcp><port>443</port></tcp></protocol></entry></service></entry></vsys></entry></devices></config>'''
        all_groups = duplicate_object_groups(source, "vsys1", "services")[0]["objects"]
        fingerprints = {item["name"]: item["fingerprint"] for item in all_groups}
        selections = [
            {"names": ["one", "two"], "master": "one", "fingerprints": fingerprints},
            {"names": ["one", "three"], "master": "three", "fingerprints": fingerprints},
        ]
        with self.assertRaisesRegex(OfflineConfigError, "overlappen"):
            merge_duplicate_objects(source, "vsys1", "services", selections)

    def test_reference_index_protects_shared_objects_from_other_vsys(self):
        source = b'''<config><shared><address><entry name="SharedServer"/></address><service><entry name="tcp-8443"/></service><tag><entry name="Prod"/></tag></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules><entry name="allow"><source><member>SharedServer</member></source><service><member>tcp-8443</member></service><tag><member>Prod</member></tag></entry></rules></security></rulebase></entry><entry name="vsys2"><rulebase><nat><rules><entry name="translate"><destination-translation><translated-address>SharedServer</translated-address></destination-translation></entry></rules></nat></rulebase></entry></vsys></entry></devices></config>'''
        addresses = object_reference_index(source, "addresses", ["SharedServer", "unused"])
        services = object_reference_index(source, "services", ["tcp-8443"])
        tags = object_reference_index(source, "tags", ["Prod", "unused"])
        self.assertTrue(any("vsys1" in path for path in addresses["SharedServer"]))
        self.assertTrue(any("vsys2" in path for path in addresses["SharedServer"]))
        self.assertEqual(addresses["unused"], [])
        self.assertTrue(services["tcp-8443"])
        self.assertTrue(tags["Prod"])
        self.assertEqual(tags["unused"], [])

    def test_reference_index_includes_panos_virtual_router_path_monitor_destinations(self):
        source = b'''<config><shared><address><entry name="Google"><ip-netmask>8.8.8.8/32</ip-netmask></entry></address></shared><devices><entry name="localhost.localdomain"><network><virtual-router><entry name="VR_Telenet_Archief"><routing-table><ip><static-route><entry name="default_route"><path-monitor><enable>yes</enable><monitor-destinations><entry name="Google"><enable>yes</enable><destination>Google</destination></entry></monitor-destinations></path-monitor></entry></static-route></ip></routing-table></entry></virtual-router></network></entry></devices></config>'''

        references = object_reference_index(source, "addresses", ["Google"])

        self.assertEqual(
            references["Google"],
            ["/config/devices/entry[@name=localhost.localdomain]/network/virtual-router/entry[@name=VR_Telenet_Archief]/routing-table/ip/static-route/entry[@name=default_route]/path-monitor/monitor-destinations/entry[@name=Google]/destination"],
        )
        malformed = b'''<config><devices><entry name="localhost.localdomain"><network><path-monitor><virtual-router><entry name="VR_Telenet_Archief"><routing-table><ip><static-route><entry name="default_route"><monitor-destinations><entry name="Google"><destination>Google</destination></entry></monitor-destinations></entry></static-route></ip></routing-table></entry></virtual-router></path-monitor></network></entry></devices></config>'''
        self.assertEqual(object_reference_index(malformed, "addresses", ["Google"])["Google"], [])
        wrong_device = source.replace(b"localhost.localdomain", b"other-device")
        self.assertEqual(object_reference_index(wrong_device, "addresses", ["Google"])["Google"], [])
        unnamed_route = source.replace(b'<entry name="default_route">', b"<entry>")
        self.assertEqual(object_reference_index(unnamed_route, "addresses", ["Google"])["Google"], [])

    def test_reference_index_detects_group_members_dynamic_tag_filters_and_cert_use(self):
        source = b'''<config><shared><address-group><entry name="servers"><static><member>server-a</member></static></entry><entry name="dynamic-servers"><dynamic><filter> 'Prod' </filter></dynamic></entry></address-group><certificate><entry name="proxy-cert"><usage>forward-trust</usage></entry></certificate><ssl-decrypt><entry name="decrypt"><forward-trust-certificate>proxy-cert</forward-trust-certificate></entry></ssl-decrypt></shared></config>'''
        self.assertTrue(object_reference_index(source, "addresses", ["server-a"])["server-a"])
        self.assertTrue(object_reference_index(source, "tags", ["Prod"])["Prod"])
        certificate_uses = object_reference_index(source, "certificates", ["proxy-cert"])["proxy-cert"]
        self.assertGreaterEqual(len(certificate_uses), 2)

    def test_reference_index_detects_nested_nat_members_and_documented_certificate_fields(self):
        source = b'''<config><shared><rulebase><nat><rules><entry name="dynamic-nat"><source-translation><dynamic-ip-and-port><translated-address><member>nat-pool</member></translated-address></dynamic-ip-and-port></source-translation></entry></rules></nat></rulebase><ssl-decrypt><trusted-root-CA><member>root-ca</member></trusted-root-CA><forward-trust-certificate><rsa>forward-cert</rsa></forward-trust-certificate></ssl-decrypt></shared></config>'''
        self.assertTrue(object_reference_index(source, "addresses", ["nat-pool"])["nat-pool"])
        self.assertTrue(object_reference_index(source, "certificates", ["root-ca"])["root-ca"])
        self.assertTrue(object_reference_index(source, "certificates", ["forward-cert"])["forward-cert"])

    def test_multi_type_reference_index_covers_shared_groups_and_vsys_policies(self):
        source = b'''<config><shared><address><entry name="10.10.120.100"/></address><address-group><entry name="Servers_HTTP_HTTPS"><static><member>10.10.120.100</member><member>10.10.120.102</member></static></entry></address-group><service-group><entry name="web"><members><member>tcp443</member></members></entry></service-group></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2"><rulebase><security><rules><entry name="allow"><service><member>tcp443</member></service></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''

        references = object_reference_indexes(source, {
            "addresses": ["10.10.120.100", "10.10.120.102", "unused"],
            "services": ["tcp443", "unused-service"],
        })

        self.assertEqual(
            references["addresses"]["10.10.120.100"],
            ["/config/shared/address-group/entry[@name=Servers_HTTP_HTTPS]/static/member"],
        )
        self.assertEqual(
            references["addresses"]["10.10.120.102"],
            ["/config/shared/address-group/entry[@name=Servers_HTTP_HTTPS]/static/member"],
        )
        self.assertEqual(references["addresses"]["unused"], [])
        self.assertEqual(len(references["services"]["tcp443"]), 2)
        self.assertEqual(references["services"]["unused-service"], [])

    def test_multi_type_reference_index_covers_panorama_shared_and_device_groups(self):
        source = b'''<config><shared><address-group><entry name="SharedServers"><static><member>server-a</member></static></entry></address-group></shared><devices><entry name="localhost.localdomain"><device-group><entry name="Parent"><address-group><entry name="ParentServers"><static><member>server-a</member></static></entry></address-group><pre-rulebase><security><rules><entry name="allow"><destination><member>server-a</member></destination></entry></rules></security></pre-rulebase></entry><entry name="Child"><parent-dg>Parent</parent-dg><post-rulebase><nat><rules><entry name="translate"><destination-translation><translated-address>server-a</translated-address></destination-translation></entry></rules></nat></post-rulebase></entry></device-group><template><entry name="Branch"><address-group><entry name="TemplateServers"><static><member>server-a</member></static></entry></address-group></entry></template></entry></devices></config>'''

        references = object_reference_indexes(source, {"addresses": ["server-a"]})

        paths = references["addresses"]["server-a"]
        self.assertTrue(any("/config/shared/address-group/" in path for path in paths))
        self.assertTrue(any("/device-group/entry[@name=Parent]/address-group/" in path for path in paths))
        self.assertTrue(any("/device-group/entry[@name=Parent]/pre-rulebase/" in path for path in paths))
        self.assertTrue(any("/device-group/entry[@name=Child]/post-rulebase/" in path for path in paths))
        self.assertTrue(any("/template/entry[@name=Branch]/address-group/" in path for path in paths))

    def test_empty_network_containers_are_not_fake_records_and_can_be_bootstrapped(self):
        source = b'<config><devices><entry name="localhost.localdomain"><network><interface><ethernet /></interface></network><vsys><entry name="vsys1"><zone /></entry></vsys></entry></devices></config>'
        _, interfaces = configuration_records(source, "vsys1", "", "network", "interfaces")
        _, zones = configuration_records(source, "vsys1", "", "network", "zones")
        self.assertEqual(interfaces, [])
        self.assertEqual(zones, [])
        created = create_basic_network_entry(source, "vsys1", "", "interfaces", "ethernet1/1")
        created = create_basic_network_entry(created, "vsys1", "", "zones", "Trust")
        _, interfaces = configuration_records(created, "vsys1", "", "network", "interfaces")
        _, zones = configuration_records(created, "vsys1", "", "network", "zones")
        self.assertEqual([item["name"] for item in interfaces], ["ethernet1/1"])
        self.assertEqual([item["name"] for item in zones], ["Trust"])

    def test_log_forwarding_profiles_and_destinations_are_structured(self):
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><tag><entry name="investigate"/></tag><log-settings><syslog><entry name="siem"/></syslog><profiles><entry name="forward-all"><description>SIEM</description><enhanced-application-logging>yes</enhanced-application-logging><match-list><entry name="traffic"><log-type>traffic</log-type><filter>(addr.src in 10.0.0.0/8)</filter><send-syslog><member>siem</member></send-syslog><actions><entry name="tag-source"><type><tagging><action>add-tag</action><target>source-address</target><registration>localhost</registration><timeout>60</timeout><tags><member>investigate</member></tags></tagging></type></entry></actions></entry></match-list></entry></profiles></log-settings></entry></vsys></entry></devices></config>'''
        _, profiles = scoped_objects(xml, "vsys1", "log-forwarding")
        self.assertEqual([item["name"] for item in profiles], ["forward-all"])
        self.assertTrue(profiles[0]["enhanced_application_logging"])
        match = profiles[0]["match_list"][0]
        self.assertEqual(match["send_syslog"], ["siem"])
        self.assertEqual(match["actions"][0]["tags"], ["investigate"])
        self.assertEqual(
            scoped_server_profiles(xml, "vsys1"),
            [{"name": "siem", "kind": "syslog-server-profiles", "owner": "vsys1"}],
        )

    def test_panorama_inventory_preserves_hierarchy_and_templates(self):
        _, snapshot = parse_snapshot(PANORAMA, expected_kind="panorama")
        self.assertEqual(snapshot.kind, "panorama")
        self.assertEqual(snapshot.version, "12.1.2")
        child = next(item for item in snapshot.device_groups if item["name"] == "Child")
        self.assertEqual(child["parent"], "Parent")
        self.assertEqual(child["reference_template"], "Branch-Stack")
        self.assertEqual(snapshot.templates, ["Base", "Branch"])
        self.assertEqual(snapshot.template_stacks[0]["templates"], ["Branch", "Base"])
        self.assertEqual(available_templates(snapshot), ["Base", "Branch", "Branch-Stack"])
        self.assertEqual(referenced_template(snapshot, "Child"), "Branch-Stack")

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
        layer3 = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><zone><entry name="Trust"><network><layer3/></network></entry></zone></entry></vsys></entry></devices></config>'''
        self.assertIn("set vsys vsys1 zone Trust network layer3", render_set_commands(layer3))

    def test_scope_inventory_and_panorama_inheritance(self):
        _, snapshot = parse_snapshot(INHERITED)
        self.assertEqual(available_scopes(snapshot), ["Shared", "Parent", "Child"])
        _, policies = scoped_policies(INHERITED, "Child", "security", "pre")
        self.assertEqual([item["name"] for item in policies], ["shared-rule", "parent-rule", "child-rule"])
        self.assertEqual([item["editable"] for item in policies], [False, False, True])
        _, objects = scoped_objects(INHERITED, "Child", "addresses")
        self.assertEqual([item["name"] for item in objects], ["shared-a", "parent-a"])
        self.assertTrue(all(not item["editable"] for item in objects))

    def test_policy_replacement_is_version_safe_and_preserves_unknown_xml(self):
        _, policies = scoped_policies(INHERITED, "Child", "security", "pre")
        child = policies[-1]
        replacement = child["_xml"].replace("<action>allow</action>", "<action>deny</action>")
        updated = replace_policy_in_snapshot(
            INHERITED, "Child", "security", "pre", "child-rule",
            policy_fingerprint(child), replacement,
        )
        self.assertIn(b"<action>deny</action>", updated)
        self.assertIn(b"<custom-unknown>preserve</custom-unknown>", updated)
        self.assertIn(b"<custom-unknown>keep-me</custom-unknown>", updated)
        with self.assertRaises(OfflineConfigError):
            replace_policy_in_snapshot(INHERITED, "Child", "security", "pre", "child-rule", "wrong", replacement)

    def test_policy_replacement_can_rename_but_rejects_a_duplicate_name(self):
        _, policies = scoped_policies(INHERITED, "Child", "security", "pre")
        child = policies[-1]
        renamed = child["_xml"].replace('name="child-rule"', 'name="renamed-rule"')
        updated = replace_policy_in_snapshot(
            INHERITED, "Child", "security", "pre", "child-rule",
            policy_fingerprint(child), renamed,
        )
        self.assertIn(b'<entry name="renamed-rule">', updated)
        self.assertNotIn(b'<entry name="child-rule">', updated)

        duplicate_source = INHERITED.replace(
            b'<entry name="child-rule">',
            b'<entry name="existing-rule"/><entry name="child-rule">',
        )
        _, duplicate_policies = scoped_policies(duplicate_source, "Child", "security", "pre")
        original = next(item for item in duplicate_policies if item["name"] == "child-rule")
        duplicate = original["_xml"].replace('name="child-rule"', 'name="existing-rule"')
        with self.assertRaises(OfflineConfigError):
            replace_policy_in_snapshot(
                duplicate_source, "Child", "security", "pre", "child-rule",
                policy_fingerprint(original), duplicate,
            )

    def test_policy_crud_and_move_preserve_rulebase_order(self):
        seed = policy_create_record("security", "vsys1", "pre")
        new_xml = seed["_xml"].replace('name=""', 'name="new-rule"')
        inserted = insert_policy_in_snapshot(PANOS, "vsys1", "security", "pre", new_xml, "top")
        _, policies = scoped_policies(inserted, "vsys1", "security", "pre")
        self.assertEqual([item["name"] for item in policies], ["new-rule", "allow-web"])
        moved = move_policies_in_snapshot(inserted, "vsys1", "security", "pre", {"new-rule"}, "down")
        _, policies = scoped_policies(moved, "vsys1", "security", "pre")
        self.assertEqual([item["name"] for item in policies], ["allow-web", "new-rule"])
        deleted = delete_policies_from_snapshot(moved, "vsys1", "security", "pre", {"new-rule"})
        _, policies = scoped_policies(deleted, "vsys1", "security", "pre")
        self.assertEqual([item["name"] for item in policies], ["allow-web"])

    def test_standalone_network_inventory_uses_device_and_vsys_contexts(self):
        inventory = configuration_inventory(PANOS, "vsys1")
        by_name = {item["name"]: item for item in inventory["network"]}
        self.assertEqual(by_name["Interfaces"]["entries"], 1)
        self.assertEqual(by_name["Zones"]["entries"], 2)

    def test_network_records_are_editable_and_preserve_unknown_xml(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1" custom="keep"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3><comment>old</comment><link-state>auto</link-state><future-node><value>preserve</value></future-node></entry></ethernet></interface></network><vsys><entry name="vsys1"><zone><entry name="Trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone></entry></vsys></entry></devices></config>'''
        _, records = configuration_records(source, "vsys1", "", "network", "interfaces")
        self.assertEqual([record["name"] for record in records], ["ethernet1/1"])
        interface = records[0]
        fields = {field["label"]: field for field in interface["edit_fields"]}
        updated = apply_configuration_changes(source, [{
            "operation": "update", "locator": interface["locator"],
            "fingerprint": interface["fingerprint"], "name": "ethernet1/2",
            "updates": [
                {"path": fields["Comment"]["path"], "kind": "text", "value": "changed"},
                {"path": fields["Link State"]["path"], "kind": "text", "value": "up"},
            ],
        }])
        self.assertIn(b'<entry name="ethernet1/2" custom="keep">', updated)
        self.assertIn(b"<comment>changed</comment>", updated)
        self.assertIn(b"<future-node>", updated)
        self.assertIn(b"<value>preserve</value>", updated)

    def test_interface_editor_uses_panos_tabs_and_edits_nested_ip_entry(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3><link-state>auto</link-state><lldp><enable>yes</enable></lldp></entry></ethernet></interface></network><vsys><entry name="vsys1"/></vsys></entry></devices></config>'''
        _, records = configuration_records(source, "vsys1", "", "network", "interfaces")
        interface = records[0]
        self.assertEqual(interface["ui_family"], "Ethernet")
        self.assertEqual(interface["ui_tabs"], ["Ethernet Interface", "IPv4", "Advanced", "LLDP"])
        address = next(field for field in interface["edit_fields"] if field["kind"] == "attribute")
        self.assertEqual(address["group"], "IPv4")
        updated = apply_configuration_changes(source, [{
            "operation": "update", "locator": interface["locator"],
            "fingerprint": interface["fingerprint"], "name": interface["name"],
            "updates": [{"path": address["path"], "kind": "attribute", "value": "198.51.100.1/24"}],
        }])
        self.assertIn(b'<entry name="198.51.100.1/24"', updated)

    def test_zone_editor_uses_network_and_identification_tabs(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><network/><vsys><entry name="vsys1"><zone><entry name="Trust"><network><layer3><member>ethernet1/1</member></layer3></network><enable-user-identification>yes</enable-user-identification><enable-device-identification>yes</enable-device-identification></entry></zone></entry></vsys></entry></devices></config>'''
        _, records = configuration_records(source, "vsys1", "", "network", "zones")
        self.assertEqual(records[0]["ui_tabs"], ["General", "Network", "User Identification", "Device Identification"])

    def test_device_editors_use_panos_tabs_and_named_items_remain_creatable(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>fw-a</hostname><timezone>Europe/Brussels</timezone><service><dns-setting><servers><primary>192.0.2.53</primary></servers></dns-setting></service><session><timeout>3600</timeout></session></system></deviceconfig><mgt-config><users><entry name="operator"><authentication-profile>LDAP</authentication-profile><permissions><role-based><superuser>no</superuser></role-based></permissions></entry></users></mgt-config><vsys><entry name="vsys1"/></vsys></entry></devices></config>'''
        _, setup = configuration_records(source, "vsys1", "", "device", "setup")
        _, administrators = configuration_records(source, "vsys1", "", "device", "administrators")
        self.assertEqual(setup[0]["ui_tabs"], ["Management", "Services", "Session"])
        self.assertEqual(administrators[0]["ui_tabs"], ["General", "Authentication", "Administrator Type"])
        self.assertTrue(administrators[0]["is_entry"])

    def test_panorama_template_stack_records_keep_concrete_owner(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><device-group><entry name="Branch-DG"/></device-group><template><entry name="Base"><config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><comment>base</comment></entry></ethernet></interface></network></entry></devices></config></entry><entry name="Branch"><config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><zone><entry name="Clients"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone></entry></vsys></entry></devices></config></entry></template><template-stack><entry name="Branch-Stack"><templates><member>Branch</member><member>Base</member></templates></entry></template-stack></entry></devices></config>'''
        _, interfaces = configuration_records(source, "Branch-DG", "Branch-Stack", "network", "interfaces")
        _, zones = configuration_records(source, "Branch-DG", "Branch-Stack", "network", "zones")
        self.assertEqual([(item["name"], item["owner"]) for item in interfaces], [("ethernet1/1", "Base")])
        self.assertEqual([(item["name"], item["owner"]) for item in zones], [("Clients", "Branch")])

    def test_configuration_records_can_duplicate_and_delete_multiple_siblings(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><comment>one</comment></entry><entry name="ethernet1/2"><comment>two</comment></entry><entry name="ethernet1/3"><comment>three</comment></entry></ethernet></interface></network><vsys><entry name="vsys1"/></vsys></entry></devices></config>'''
        _, records = configuration_records(source, "vsys1", "", "network", "interfaces")
        first = records[0]
        duplicated = apply_configuration_changes(source, [{
            "operation": "create", "locator": first["locator"], "fingerprint": first["fingerprint"],
            "name": "ethernet1/4", "updates": [],
        }])
        self.assertIn(b'<entry name="ethernet1/4">', duplicated)
        _, after = configuration_records(duplicated, "vsys1", "", "network", "interfaces")
        removed = apply_configuration_changes(duplicated, [
            {"operation": "delete", "locator": item["locator"], "fingerprint": item["fingerprint"]}
            for item in after if item["name"] in {"ethernet1/2", "ethernet1/3"}
        ])
        self.assertNotIn(b'<entry name="ethernet1/2">', removed)
        self.assertNotIn(b'<entry name="ethernet1/3">', removed)
        self.assertIn(b'<entry name="ethernet1/4">', removed)

    def test_protected_device_values_never_reach_editor_fields(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>fw-a</hostname><password>secret-value</password></system></deviceconfig><mgt-config><users><entry name="admin"><phash>hash-value</phash></entry></users></mgt-config><vsys><entry name="vsys1"/></vsys></entry></devices></config>'''
        _, setup = configuration_records(source, "vsys1", "", "device", "setup")
        protected = [field for field in setup[0]["edit_fields"] if field["kind"] == "protected"]
        self.assertTrue(protected)
        self.assertNotIn("secret-value", repr(setup[0]["edit_fields"]))

    def test_offline_object_create_update_delete_preserves_unknown_fields(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="old"><ip-netmask>192.0.2.1/32</ip-netmask><custom-field>keep</custom-field></entry></address></entry></vsys></entry></devices></config>'''
        _, objects = scoped_objects(source, "vsys1", "addresses")
        old = objects[0]
        updated = apply_object_changes(source, "vsys1", "addresses", [{
            "operation": "update", "original_name": "old", "fingerprint": object_fingerprint(old),
            "replacement_xml": '<entry name="renamed"><ip-netmask>192.0.2.2/32</ip-netmask><description>changed</description></entry>',
        }, {
            "operation": "create", "original_name": "", "fingerprint": "",
            "replacement_xml": '<entry name="new"><fqdn>example.test</fqdn></entry>',
        }])
        self.assertIn(b'<entry name="renamed">', updated)
        self.assertIn(b'<custom-field>keep</custom-field>', updated)
        self.assertIn(b'<entry name="new">', updated)
        _, after = scoped_objects(updated, "vsys1", "addresses")
        new = next(item for item in after if item["name"] == "new")
        deleted = apply_object_changes(updated, "vsys1", "addresses", [{
            "operation": "delete", "original_name": "new", "fingerprint": object_fingerprint(new),
        }])
        self.assertNotIn(b'<entry name="new">', deleted)

    def test_service_inventory_shows_protocol_and_ports(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><service><entry name="web-alt"><protocol><tcp><source-port>1024-65535</source-port><port>8443</port></tcp></protocol></entry></service><rulebase/></entry></vsys></entry></devices></config>'''
        _, services = scoped_objects(source, "vsys1", "services")
        self.assertEqual(services[0]["values"], ["TCP/8443 · source 1024-65535"])
        self.assertEqual(services[0]["summary"], "TCP/8443 · source 1024-65535")

    def test_zone_inventory_shows_empty_layer3_type(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><network/><vsys><entry name="vsys1"><zone><entry name="Trust"><network><layer3/></network></entry></zone></entry></vsys></entry></devices></config>'''
        _, zones = configuration_records(source, "vsys1", "", "network", "zones")
        self.assertEqual(zones[0]["summary"], "Layer3")

    def test_generic_object_editor_updates_nested_fields_without_raw_xml_loss(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><region><entry name="Belgium" code="be"><address><member>192.0.2.0/24</member><member>198.51.100.0/24</member></address><enabled>yes</enabled><nested preserve="true"><label>old</label></nested></entry></region></entry></vsys></entry></devices></config>'''
        _, objects = scoped_objects(source, "vsys1", "regions")
        region = objects[0]
        fields = {field["label"]: field for field in region["edit_fields"]}
        self.assertEqual(fields["Address"]["values"], ["192.0.2.0/24", "198.51.100.0/24"])
        updated = apply_object_changes(source, "vsys1", "regions", [{
            "operation": "update", "original_name": "Belgium",
            "fingerprint": object_fingerprint(region), "name": "Belgium-custom",
            "generic_updates": [
                {"path": fields["Address"]["path"], "kind": "members", "values": ["203.0.113.0/24"]},
                {"path": fields["Enabled"]["path"], "kind": "boolean", "value": "no"},
                {"path": fields["Nested / Label"]["path"], "kind": "text", "value": "new"},
            ],
        }])
        self.assertIn(b'<entry name="Belgium-custom" code="be">', updated)
        self.assertIn(b'<member>203.0.113.0/24</member>', updated)
        self.assertIn(b'<enabled>no</enabled>', updated)
        self.assertIn(b'<nested preserve="true">', updated)
        self.assertIn(b'<label>new</label>', updated)

    def test_every_generic_object_family_has_a_creatable_panos_seed(self):
        generic_types = {
            "regions", "dynamic-user-groups", "applications", "application-filters",
            "external-dynamic-lists", "hip-objects", "hip-profiles", "custom-url-categories",
            "antivirus", "anti-spyware", "vulnerability-protection", "url-filtering",
            "file-blocking", "wildfire-analysis", "dos-protection", "schedules",
            "security-profile-groups", "authentication", "decryption-profiles",
        }
        source = b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>'
        for object_type in sorted(generic_types):
            with self.subTest(object_type=object_type):
                seed = object_create_record(object_type, "vsys1")
                self.assertIsNotNone(seed)
                self.assertTrue(seed["edit_fields"])
                created = apply_object_changes(source, "vsys1", object_type, [{
                    "operation": "create", "original_name": "", "fingerprint": "",
                    "name": f"new-{object_type}", "generic_updates": [],
                }])
                _, objects = scoped_objects(created, "vsys1", object_type)
                self.assertEqual([item["name"] for item in objects], [f"new-{object_type}"])

    def test_generic_nested_entry_names_are_editable_attributes(self):
        seed = object_create_record("file-blocking", "vsys1")
        rule_name = next(field for field in seed["edit_fields"] if field["label"] == "Rules / Entry / Name")
        self.assertEqual(rule_name["kind"], "attribute")

    def test_security_profile_fields_are_structured_and_secrets_stay_protected(self):
        source = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><profiles><url-filtering><entry name="OCD-URL"><allow><member>business-and-economy</member></allow><block><member>malware</member></block><credential-enforcement><mode><group-mapping>Employees</group-mapping></mode></credential-enforcement></entry></url-filtering></profiles><authentication-profile><entry name="LDAP"><server-profile>LDAP-BDND</server-profile><password>never-render-this</password></entry></authentication-profile></entry></vsys></entry></devices></config>'''
        _, profiles = scoped_objects(source, "vsys1", "url-filtering")
        fields = profiles[0]["edit_fields"]
        self.assertEqual({field["group"] for field in fields}, {"Categories", "User Credential Detection"})
        self.assertEqual(next(field for field in fields if field["label"] == "Allow")["kind"], "members")
        self.assertNotIn("<allow>", repr(profiles[0]["fields"]))
        _, authentication = scoped_objects(source, "vsys1", "authentication")
        protected = next(field for field in authentication[0]["edit_fields"] if field["label"] == "Password")
        self.assertEqual(protected["kind"], "protected")
        self.assertNotIn("never-render-this", repr(authentication[0]["edit_fields"]))
        self.assertNotIn("never-render-this", repr(authentication[0]["fields"]))

    def test_network_editor_exposes_add_flow_for_every_configuration_list(self):
        javascript = (ROOT / "app" / "static" / "app.js").read_text()
        template = (ROOT / "app" / "templates" / "workspace_editor.html").read_text()
        self.assertIn('add.textContent = "+ Add"', javascript)
        # Existing rows remain a fallback; empty lists use a server-owned schema.
        self.assertIn('renderRecord(JSON.parse(base.getAttribute("data-config-record")), true)', javascript)
        self.assertIn('renderRecord(JSON.parse(JSON.stringify(template)), true)', javascript)
        self.assertIn('primary.value = createMode ? "create" : "update"', javascript)
        self.assertIn('nameInput.value = createMode ? "" : item.name', javascript)
        self.assertIn('if (actionbar && !creatableRows.length && !createTemplates.length) actionbar.hidden = true', javascript)
        self.assertIn('if (actionbar && (creatableRows.length || createTemplates.length))', javascript)
        self.assertIn('if config_records or config_create_templates|default([])', template)
        self.assertIn('data-config-create-templates', template)


if __name__ == "__main__":
    unittest.main()
