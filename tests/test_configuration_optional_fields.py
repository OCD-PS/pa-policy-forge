import copy
import hashlib
import unittest
import xml.etree.ElementTree as ET

from app.offline_config import (
    CONFIG_CREATE_SCHEMAS, OfflineConfigError, apply_configuration_changes,
    configuration_records, create_configuration_entry, normalized_config_xml,
)


BASE = b'''<config><mgt-config><users><entry name="admin"><phash>retained-hash</phash></entry></users></mgt-config><devices><entry name="localhost.localdomain"><deviceconfig><system><ip-address>192.0.2.44</ip-address></system></deviceconfig><network><interface><ethernet><entry name="ethernet1/1"><layer3 /></entry></ethernet></interface></network><vsys><entry name="vsys1" /></vsys></entry></devices></config>'''


class ConfigurationOptionalFieldsTests(unittest.TestCase):
    def add(self, variant, name="audit-item"):
        view, section = CONFIG_CREATE_SCHEMAS[variant][:2]
        return create_configuration_entry(BASE, "vsys1", "vsys1", view, section, variant, name)

    def record(self, source, section, name="audit-item", view="network", scope="vsys1", template="vsys1"):
        return next(item for item in configuration_records(source, scope, template, view, section)[1]
                    if item["name"] == name)

    def field(self, record, label, occurrence=0):
        return [field for field in record["edit_fields"] if field.get("technical_label") == label][occurrence]

    def update(self, field, value):
        return {"path": field["path"], "kind": field["kind"],
                "values" if field["kind"] == "members" else "value": value}

    def save(self, source, record, *updates):
        return apply_configuration_changes(source, [{"operation": "update", "locator": record["locator"],
            "fingerprint": record["fingerprint"], "name": record["name"], "updates": list(updates)}])

    def insert(self, parent_path, xml):
        root = ET.fromstring(BASE)
        root.find(parent_path).append(ET.fromstring(xml))
        return ET.tostring(root)

    def test_empty_vlan_reopens_with_interfaces_and_can_save_member(self):
        source = self.add("vlan")
        record = self.record(source, "vlans")
        field = self.field(record, "Interface")
        self.assertEqual(field["kind"], "members")
        self.assertEqual(field["values"], [])
        self.assertTrue(field["optional"])
        self.assertIn("Interfaces", record["ui_tabs"])
        self.assertNotIn(b"<interface />", source)
        result = self.save(source, record, self.update(field, ["ethernet1/1"]))
        node = ET.fromstring(result).find(".//vlan/entry[@name='audit-item']")
        self.assertEqual(node.findtext("./interface/member"), "ethernet1/1")
        self.assertIsNone(node.find("virtual-interface"))
        self.assertEqual(self.field(self.record(result, "vlans"), "Interface")["values"], ["ethernet1/1"])

    def test_read_uses_actual_xml_fingerprint_and_never_modifies_original(self):
        source = self.add("vlan")
        record = self.record(source, "vlans")
        self.assertEqual(record["fingerprint"], hashlib.sha256(record["_xml"].encode()).hexdigest())
        self.assertNotIn("virtual-interface", record["_xml"])
        self.assertEqual(source, self.add("vlan"))
        with self.assertRaisesRegex(OfflineConfigError, "intussen"):
            forged = dict(record, fingerprint="0" * 64)
            self.save(source, forged, self.update(self.field(record, "Interface"), ["ethernet1/1"]))

    def test_untouched_virtual_fields_do_not_materialize_defaults(self):
        for variant in ("vlan", "virtual-router", "logical-router", "zone-layer3", "lldp", "tunnel-interface"):
            with self.subTest(variant=variant):
                name = "tunnel.7" if variant == "tunnel-interface" else "audit-item"
                source = self.add(variant, name)
                section = CONFIG_CREATE_SCHEMAS[variant][1]
                record = self.record(source, section, "Lldp" if variant == "lldp" else name)
                updates = [self.update(field, field.get("values", []) if field["kind"] == "members" else field.get("value", ""))
                           for field in record["edit_fields"] if field["kind"] != "protected"]
                self.assertEqual(self.save(source, record, *updates), normalized_config_xml(ET.fromstring(source)))

    def test_original_unknown_fields_and_numeric_paths_survive_virtual_router_edit(self):
        source = self.insert("./devices/entry/network", '''<virtual-router><entry name="audit-item"><future-option vendor="future"><keep>original</keep><empty /></future-option><password>not-exposed</password><admin-dists><static>5</static></admin-dists></entry></virtual-router>''')
        record = self.record(source, "virtual-routers")
        field = self.field(record, "Interface")
        static = self.field(record, "Admin Dists / Static")
        self.assertEqual(static["path"], "2/0")
        self.assertNotIn("not-exposed", str(record["edit_fields"]))
        result = self.save(source, record, self.update(field, ["ethernet1/1"]), self.update(static, "15"))
        root = ET.fromstring(result)
        node = root.find(".//virtual-router/entry")
        self.assertEqual(node.findtext("./admin-dists/static"), "15")
        self.assertIsNone(node.find("./admin-dists/static-ipv6"))
        self.assertEqual(node.findtext("password"), "not-exposed")
        self.assertEqual(node.find("future-option").get("vendor"), "future")
        self.assertIsNotNone(node.find("./future-option/empty"))
        self.assertIn(b"retained-hash", result)
        self.assertIn(b"192.0.2.44", result)

    def test_syslog_optional_fields_apply_to_each_actual_server(self):
        source = self.insert("./devices/entry/vsys/entry", '''<log-settings><syslog><entry name="audit-item"><server><entry name="first"><server>192.0.2.10</server></entry><entry name="second"><server>192.0.2.11</server><port>601</port></entry></server></entry></syslog></log-settings>''')
        record = self.record(source, "server-profiles", view="device")
        formats = [self.field(record, "Server / Entry / Format", n) for n in (0, 1)]
        self.assertTrue(all(field["optional"] and field["value"] == "" for field in formats))
        self.assertEqual(formats[0]["options"], ["", "BSD", "IETF"])
        result = self.save(source, record, self.update(formats[1], "IETF"))
        servers = ET.fromstring(result).findall(".//syslog/entry/server/entry")
        self.assertEqual([server.get("name") for server in servers], ["first", "second"])
        self.assertIsNone(servers[0].find("format"))
        self.assertEqual(servers[1].findtext("format"), "IETF")
        self.assertIsNone(servers[0].find("transport"))
        self.assertEqual(servers[1].findtext("port"), "601")
        with self.assertRaisesRegex(OfflineConfigError, "opties"):
            self.save(source, record, self.update(formats[0], "not-a-format"))

    def test_zone_retains_type_while_empty_member_field_is_editable(self):
        source = self.insert("./devices/entry/vsys/entry", '<zone><entry name="audit-item"><network><layer3 /></network></entry></zone>')
        record = self.record(source, "zones")
        self.assertEqual(record["summary"], "Layer3")
        field = self.field(record, "Network / Layer3")
        result = self.save(source, record, self.update(field, ["ethernet1/1"]))
        self.assertEqual(ET.fromstring(result).findtext(".//zone/entry/network/layer3/member"), "ethernet1/1")

    def test_absent_boolean_has_blank_choice_without_inventing_false(self):
        source = self.insert("./devices/entry/network", '<profiles><interface-management-profile><entry name="audit-item"><https>yes</https></entry></interface-management-profile></profiles>')
        record = self.record(source, "network-profiles")
        ping = self.field(record, "Ping")
        https = self.field(record, "Https")
        self.assertEqual((ping["kind"], ping["value"], ping["optional"]), ("boolean", "", True))
        self.assertFalse(https.get("optional", False))
        unchanged = self.save(source, record, self.update(ping, ""))
        self.assertIsNone(ET.fromstring(unchanged).find(".//interface-management-profile/entry/ping"))
        result = self.save(source, record, self.update(ping, "yes"))
        self.assertEqual(ET.fromstring(result).findtext(".//interface-management-profile/entry/ping"), "yes")
        self.assertFalse(self.field(self.record(result, "network-profiles"), "Ping").get("optional", False))
        with self.assertRaisesRegex(OfflineConfigError, "boolean"):
            self.save(source, record, self.update(ping, "false"))

    def test_empty_lldp_singleton_reopens_and_saves(self):
        source = self.insert("./devices/entry/network", "<lldp />")
        record = self.record(source, "lldp", "Lldp")
        result = self.save(source, record, self.update(self.field(record, "Enable"), "yes"))
        self.assertEqual(ET.fromstring(result).findtext(".//network/lldp/enable"), "yes")

    def test_other_interface_and_authentication_union_choices_not_augmented(self):
        source = self.insert("./devices/entry/vsys/entry", '<authentication-profile><entry name="audit-item"><method><radius><server-profile>radius-existing</server-profile></radius></method></entry></authentication-profile>')
        root = ET.fromstring(source)
        interface = root.find(".//ethernet/entry")
        interface.remove(interface.find("layer3"))
        ET.SubElement(interface, "layer2")
        source = ET.tostring(root)
        for section, name, view, absent in (("interfaces", "ethernet1/1", "network", "Layer3"),
                                          ("authentication-profile", "audit-item", "device", "Local Database")):
            record = self.record(source, section, name, view)
            self.assertNotIn(absent, str(record["edit_fields"]))
            self.assertEqual(self.save(source, record), normalized_config_xml(root))

    def test_nested_optional_ip_entry_materializes_only_on_name(self):
        record = self.record(BASE, "interfaces", "ethernet1/1")
        field = self.field(record, "Layer3 / Ip / Entry")
        self.assertEqual(field["kind"], "attribute")
        result = self.save(BASE, record, self.update(field, "192.0.2.1/24"))
        entry = ET.fromstring(result).find(".//ethernet/entry/layer3/ip/entry")
        self.assertEqual(entry.get("name"), "192.0.2.1/24")
        self.assertIsNone(ET.fromstring(result).find(".//ethernet/entry/layer3/mtu"))

    def test_protected_fields_and_unknown_paths_remain_rejected(self):
        source = self.insert("./devices/entry/network", '<virtual-router><entry name="audit-item"><password>keep-this</password></entry></virtual-router>')
        record = self.record(source, "virtual-routers")
        for update in ({"path": "0", "kind": "text", "value": "changed"},
                       {"path": "0", "kind": "protected", "value": "changed"},
                       {"path": "../../../0", "kind": "text", "value": "changed"}):
            with self.subTest(update=update), self.assertRaises(OfflineConfigError):
                self.save(source, record, update)

    def test_subinterface_optional_fields_survive_in_parent_interface_editor(self):
        source = create_configuration_entry(BASE, "vsys1", "vsys1", "network", "interfaces",
                                            "ethernet-subinterface", "ethernet1/1.20")
        record = self.record(source, "interfaces", "ethernet1/1")
        field = self.field(record, "Layer3 / Units / Entry / Ip / Entry")
        result = self.save(source, record, self.update(field, "192.0.2.20/24"))
        node = ET.fromstring(result).find(".//ethernet/entry/layer3/units/entry")
        self.assertEqual(node.find("./ip/entry").get("name"), "192.0.2.20/24")
        self.assertEqual(node.findtext("tag"), "20")

    def test_dhcp_interface_does_not_offer_static_ip_union(self):
        root = ET.fromstring(BASE)
        layer3 = root.find(".//ethernet/entry/layer3")
        layer3.append(ET.fromstring("<dhcp-client><enable>yes</enable></dhcp-client>"))
        source = ET.tostring(root)
        record = self.record(source, "interfaces", "ethernet1/1")
        self.assertNotIn("Layer3 / Ip / Entry", [field.get("technical_label") for field in record["edit_fields"]])
        self.assertEqual(self.save(source, record), normalized_config_xml(root))

    def test_future_existing_enum_is_retained_without_allowing_unknown_new_choice(self):
        source = self.insert("./devices/entry/vsys/entry", '<log-settings><syslog><entry name="audit-item"><server><entry name="future-server"><server>192.0.2.12</server><transport>FUTURE-TLS</transport></entry></server></entry></syslog></log-settings>')
        record = self.record(source, "server-profiles", view="device")
        transport = self.field(record, "Server / Entry / Transport")
        self.assertIn("FUTURE-TLS", transport["options"])
        self.assertEqual(self.save(source, record, self.update(transport, "FUTURE-TLS")), normalized_config_xml(ET.fromstring(source)))
        with self.assertRaisesRegex(OfflineConfigError, "opties"):
            self.save(source, record, self.update(transport, "ANOTHER-FUTURE-TLS"))

    def test_panorama_virtual_fields_keep_template_vsys_owner(self):
        root = ET.fromstring('<config><devices><entry name="localhost.localdomain"><device-group><entry name="edge-dg" /></device-group><template><entry name="edge-template" /></template></entry></devices></config>')
        root.find(".//template/entry").append(copy.deepcopy(ET.fromstring(BASE)))
        source = create_configuration_entry(ET.tostring(root), "edge-dg", "edge-template", "network", "vlans", "vlan", "audit-item")
        record = self.record(source, "vlans", scope="edge-dg", template="edge-template")
        result = self.save(source, record, self.update(self.field(record, "Interface"), ["ethernet1/1"]))
        parsed = ET.fromstring(result)
        self.assertIsNotNone(parsed.find(".//template/entry/config/devices/entry/network/vlan/entry/interface/member"))
        self.assertIsNone(parsed.find("./devices/entry/network"))
        self.assertEqual([node.get("name") for node in parsed.findall(".//template/entry/config/devices/entry/vsys/entry")], ["vsys1"])


if __name__ == "__main__":
    unittest.main()
