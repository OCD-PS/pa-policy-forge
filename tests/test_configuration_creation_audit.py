import copy
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from app.offline_config import (CONFIG_CREATE_SCHEMAS, OfflineConfigError, configuration_create_templates,
                                configuration_records, create_basic_network_entry, create_configuration_entry)


BASE = b'''<config><mgt-config><users><entry name="admin"><phash>retained-hash</phash></entry></users></mgt-config><devices><entry name="localhost.localdomain"><deviceconfig><system><ip-address>192.0.2.44</ip-address></system></deviceconfig><network><interface><ethernet><entry name="ethernet1/1"><layer3 /></entry><entry name="ethernet1/2"><layer3 /></entry></ethernet></interface></network><vsys><entry name="vsys1"><authentication-profile><entry name="existing-auth"><method><none /></method></entry></authentication-profile><server-profile><ldap><entry name="existing-ldap" /></ldap></server-profile><local-user-database><user><entry name="existing-user" /></user></local-user-database></entry></vsys></entry></devices></config>'''


class ConfigurationCreationAuditTests(unittest.TestCase):
    def schema(self, variant, source=BASE, scope="vsys1", template="vsys1"):
        view, section = CONFIG_CREATE_SCHEMAS[variant][:2]
        return next(item for item in configuration_create_templates(source, scope, template, view, section)
                    if item["create_variant"] == variant)

    def update(self, schema, label, value):
        field = next(field for field in schema["edit_fields"] if field.get("technical_label") == label)
        return {"path": field["path"], "kind": field["kind"],
                "values" if field["kind"] == "members" else "value": value}

    def create(self, variant, name="test-item", updates=None, source=BASE, scope="vsys1", template="vsys1"):
        view, section = CONFIG_CREATE_SCHEMAS[variant][:2]
        return create_configuration_entry(source, scope, template, view, section, variant, name, updates)

    def test_empty_sections_offer_typed_add_without_xml(self):
        for variant in CONFIG_CREATE_SCHEMAS:
            with self.subTest(variant=variant):
                schema = self.schema(variant)
                self.assertTrue(schema["edit_fields"])
                self.assertTrue(schema["ui_tabs"])
                self.assertNotIn("_xml", schema)
                self.assertTrue(all(field["kind"] != "protected" for field in schema["edit_fields"]))

    def test_new_vlan_round_trips_through_same_editor(self):
        schema = self.schema("vlan")
        updated = self.create("vlan", updates=[self.update(schema, "Interface", ["ethernet1/1"])])
        _, records = configuration_records(updated, "vsys1", "vsys1", "network", "vlans")
        self.assertEqual([record["name"] for record in records], ["test-item"])
        self.assertTrue(records[0]["editable"])
        self.assertIn("ethernet1/1", str(records[0]["edit_fields"]))
        self.assertNotIn(b"<member />", updated)
        self.assertIn(b"retained-hash", updated)
        self.assertIn(b"192.0.2.44", updated)

    def test_unknown_interface_reference_rejected(self):
        schema = self.schema("vlan")
        with self.assertRaisesRegex(OfflineConfigError, "bestaat niet"):
            self.create("vlan", updates=[self.update(schema, "Interface", ["missing-interface"])])

    def test_known_virtual_wire_requires_two_distinct_interfaces(self):
        schema = self.schema("virtual-wire")
        with self.assertRaisesRegex(OfflineConfigError, "Verplicht"):
            self.create("virtual-wire")
        updates = [self.update(schema, "Interface1", "ethernet1/1"), self.update(schema, "Interface2", "ethernet1/2")]
        result = self.create("virtual-wire", updates=updates)
        self.assertIn(b"<interface2>ethernet1/2</interface2>", result)
        updates[1]["value"] = "ethernet1/1"
        with self.assertRaisesRegex(OfflineConfigError, "verschillende"):
            self.create("virtual-wire", updates=updates)

    def test_device_sequence_requires_existing_profiles(self):
        schema = self.schema("authentication-sequence")
        updates = [self.update(schema, "Authentication Profiles", ["existing-auth"])]
        self.assertIn(b"<member>existing-auth</member>", self.create("authentication-sequence", updates=updates))
        updates[0]["values"] = ["missing-auth"]
        with self.assertRaisesRegex(OfflineConfigError, "bestaat niet"):
            self.create("authentication-sequence", updates=updates)

    def test_ldap_and_local_database_choices_keep_xml_union(self):
        schema = self.schema("authentication-local")
        result = self.create("authentication-local", updates=[self.update(schema, "Allow List", ["all"])])
        self.assertIsNotNone(ET.fromstring(result).find(".//authentication-profile/entry[@name='test-item']/method/local-database"))
        schema = self.schema("authentication-ldap")
        result = self.create("authentication-ldap", updates=[
            self.update(schema, "Method / Ldap / Server Profile", "existing-ldap"),
            self.update(schema, "Allow List", ["all"])])
        self.assertIn(b"<server-profile>existing-ldap</server-profile>", result)

    def test_syslog_profile_created_in_recognized_device_section(self):
        schema = self.schema("syslog-server-profile")
        result = self.create("syslog-server-profile", updates=[self.update(schema, "Server / Entry / Server", "192.0.2.20")])
        _, records = configuration_records(result, "vsys1", "vsys1", "device", "server-profiles")
        self.assertTrue(any(record["name"] == "test-item" for record in records))
        updates = [self.update(schema, "Server / Entry / Server", "192.0.2.20"), self.update(schema, "Server / Entry / Port", "70000")]
        with self.assertRaisesRegex(OfflineConfigError, "tussen"):
            self.create("syslog-server-profile", updates=updates)

    def test_invalid_variant_or_field_cannot_inject_xml_or_management(self):
        with self.assertRaises(OfflineConfigError):
            create_configuration_entry(BASE, "vsys1", "vsys1", "network", "vlans", "../administrators", "evil")
        with self.assertRaises(OfflineConfigError):
            self.create("vlan", updates=[{"path": "../../mgt-config", "kind": "text", "value": "evil"}])
        with self.assertRaises(OfflineConfigError):
            self.create("vlan", updates=[{"path": "0", "kind": "protected", "value": "evil"}])
        with self.assertRaises(OfflineConfigError):
            self.create("vlan", name="bad/name")

    def test_duplicate_names_are_blocked(self):
        result = self.create("vlan")
        with self.assertRaisesRegex(OfflineConfigError, "bestaat al"):
            self.create("vlan", source=result)

    def test_required_nested_name_cannot_be_cleared_after_filling_server(self):
        schema = self.schema("syslog-server-profile")
        with self.assertRaisesRegex(OfflineConfigError, "naam"):
            self.create("syslog-server-profile", updates=[
                self.update(schema, "Server / Entry / Server", "192.0.2.20"),
                self.update(schema, "Server / Entry", "")])

    def test_future_schema_cannot_expose_or_edit_protected_fields(self):
        spec = ("network", "vlans", "device", "network/vlan", "Test schema",
                '<entry name=""><description /><password>test-placeholder</password></entry>', ())
        with patch.dict(CONFIG_CREATE_SCHEMAS, {"test-protected": spec}):
            schema = self.schema("test-protected")
            self.assertNotIn("test-placeholder", str(schema))
            for kind in ("protected", "text"):
                with self.assertRaises(OfflineConfigError):
                    self.create("test-protected", updates=[{"path": "1", "kind": kind, "value": "replacement"}])

    def test_logical_router_uses_vrf_and_preserves_management(self):
        result = self.create("logical-router")
        self.assertIsNotNone(ET.fromstring(result).find(".//logical-router/entry/vrf/entry[@name='default']"))
        self.assertIn(b"retained-hash", result)

    def test_singleton_settings_offer_no_duplicate_add(self):
        result = self.create("lldp", name="")
        self.assertEqual(configuration_create_templates(result, "vsys1", "vsys1", "network", "lldp"), [])
        with self.assertRaisesRegex(OfflineConfigError, "bestaat al"):
            self.create("lldp", source=result, name="")

    def test_interface_unit_hierarchy_and_vsys_import(self):
        for kind, name in (("loopback", "loopback.1"), ("tunnel", "tunnel.1"), ("vlan", "vlan.1")):
            with self.subTest(kind=kind):
                result = create_basic_network_entry(BASE, "vsys1", "vsys1", "interfaces", name, kind)
                root = ET.fromstring(result)
                self.assertIsNotNone(root.find(f"./devices/entry/network/interface/{kind}/units/entry[@name='{name}']"))
                self.assertIn(name, [entry.text for entry in root.findall("./devices/entry/vsys/entry/import/network/interface/member")])
                _, records = configuration_records(result, "vsys1", "vsys1", "network", "interfaces")
                self.assertNotIn("Interfaces", [record["name"] for record in records])

    def test_subinterface_is_nested_under_existing_physical(self):
        result = self.create("ethernet-subinterface", name="ethernet1/1.20")
        node = ET.fromstring(result).find(".//ethernet/entry[@name='ethernet1/1']/layer3/units/entry[@name='ethernet1/1.20']")
        self.assertEqual(node.findtext("tag"), "20")
        with self.assertRaisesRegex(OfflineConfigError, "eerst"):
            self.create("ethernet-subinterface", name="ethernet1/3.20")

    def test_panorama_uses_existing_template_vsys_not_device_group_name(self):
        root = ET.Element("config")
        devices = ET.SubElement(root, "devices")
        device = ET.SubElement(devices, "entry", {"name": "localhost.localdomain"})
        ET.SubElement(ET.SubElement(device, "device-group"), "entry", {"name": "edge-dg"})
        template = ET.SubElement(ET.SubElement(device, "template"), "entry", {"name": "edge-template"})
        template.append(copy.deepcopy(ET.fromstring(BASE)))
        source = ET.tostring(root)
        result = self.create("zone-layer3", source=source, scope="edge-dg", template="edge-template")
        parsed = ET.fromstring(result)
        self.assertEqual([item.get("name") for item in parsed.findall(".//template/entry/config/devices/entry/vsys/entry")], ["vsys1"])
        self.assertIsNotNone(parsed.find(".//template/entry/config/devices/entry/vsys/entry/zone/entry[@name='test-item']"))
        with self.assertRaises(OfflineConfigError):
            self.create("vlan", source=source, scope="edge-dg", template="missing-template")


if __name__ == "__main__":
    unittest.main()
