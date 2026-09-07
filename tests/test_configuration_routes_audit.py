"""Flask integration coverage for typed Network/Device Add on empty XML sections."""
import copy
import html
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch
import xml.etree.ElementTree as ET

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-create-route-import-"))
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "isolated-route-fixture-password")
os.environ.setdefault("PPF_BACKGROUND_WORKERS", "0")
with patch("threading.Thread.start"):
    from app import main


BASE = b'''<config version="11.1.0"><mgt-config><users><entry name="admin"><phash>fixture-retained-hash</phash></entry></users></mgt-config><devices><entry name="localhost.localdomain"><deviceconfig><system><ip-address>192.0.2.44</ip-address></system></deviceconfig><network><interface><ethernet><entry name="ethernet1/1"><layer3 /></entry></ethernet></interface></network><vsys><entry name="vsys1" /></vsys></entry></devices></config>'''


class ConfigurationCreationRouteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="forge-create-route-case-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for name, value in {
            "APP_DB": root / "app.sqlite3", "CONFIG_WORKSPACES": root / "workspaces",
            "POLICY_DRAFTS": root / "policy-drafts", "OBJECT_DRAFTS": root / "object-drafts",
            "MIGRATION_SOURCES": root / "migration-sources",
        }.items():
            if name != "APP_DB":
                value.mkdir()
            patcher = patch.object(main, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        main.init_db()
        self.client = main.app.test_client()
        with main.db() as conn:
            for username in ("owner", "viewer"):
                conn.execute("INSERT INTO users(username,password_hash,must_change) VALUES(?,?,0)",
                             (username, "unused-fixture-hash"))
        self.profile_id, self.project_id, self.workspace_id = self.workspace("panos", BASE, {"vsys": "vsys1"})
        self.authenticate("owner")

    def workspace(self, flavor, xml, settings):
        with main.db() as conn:
            profile_id = conn.execute("""INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at)
                VALUES(?,?,?,'now','now')""", (f"route-fixture-{flavor}", flavor, json.dumps(settings))).lastrowid
            project_id = conn.execute("""INSERT INTO migration_projects(name,target_profile_id,owner,created_at,updated_at)
                VALUES('creation-route-project',?,'owner','now','now')""", (profile_id,)).lastrowid
            conn.execute("INSERT INTO migration_project_roles VALUES(?,?,'viewer','now')", (project_id, "viewer"))
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        workspace_id = main.store_config_workspace(profile, "base", "base.xml", xml, "migration-staging", project_id=project_id)
        with main.db() as conn:
            conn.execute("UPDATE migration_projects SET base_workspace_id=? WHERE id=?", (workspace_id, project_id))
        return profile_id, project_id, workspace_id

    def authenticate(self, username):
        with main.db() as conn:
            user_id = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()[0]
        with self.client.session_transaction() as session:
            session.clear()
            session.update(user_id=user_id, username=username, csrf="route-csrf")

    def page(self, workspace_id=None, view="network", section="vlans", scope="vsys1", template="vsys1"):
        response = self.client.get(f"/config-workspaces/{workspace_id or self.workspace_id}/edit",
                                   query_string={"scope": scope, "template": template, "workspace_view": view, "config_section": section})
        self.addCleanup(response.close)
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def schema(self, variant, **page_options):
        page = self.page(**page_options)
        payload = re.search(r'<script[^>]*data-config-create-templates[^>]*>(.*?)</script>', page, re.S)
        self.assertIsNotNone(payload, "Empty editor must expose server-owned Add schemas")
        return next(item for item in json.loads(payload.group(1)) if item["create_variant"] == variant)

    @staticmethod
    def update(schema, technical_label, value):
        field = next(field for field in schema["edit_fields"] if field["technical_label"] == technical_label)
        return {"path": field["path"], "kind": field["kind"],
                "values" if field["kind"] == "members" else "value": value}

    def post(self, variant="vlan", updates=None, workspace_id=None, view="network", section="vlans",
             scope="vsys1", template="vsys1", name="created-vlan", raw_updates=None):
        response = self.client.post(f"/config-workspaces/{workspace_id or self.workspace_id}/configuration/create-basic", data={
            "csrf": "route-csrf", "scope": scope, "template": template, "workspace_view": view,
            "config_section": section, "variant": variant, "name": name,
            "generic_updates": raw_updates if raw_updates is not None else json.dumps(updates or []),
        })
        self.addCleanup(response.close)
        return response

    def count_workspaces(self):
        with main.db() as conn:
            return conn.execute("SELECT count(*) FROM config_workspaces").fetchone()[0]

    def created_id(self, response, previous=None):
        self.assertEqual(response.status_code, 302)
        location = urlparse(response.location)
        new_id = int(re.search(r"/config-workspaces/(\d+)/edit", location.path).group(1))
        self.assertNotEqual(new_id, previous or self.workspace_id)
        return new_id, parse_qs(location.query)

    def test_empty_vlan_editor_contains_schema_dialog_and_create_endpoint(self):
        page = self.page()
        self.assertIn("data-config-dialog", page)
        self.assertIn("data-config-create-url=", page)
        self.assertIn(f"/config-workspaces/{self.workspace_id}/configuration/create-basic", page)
        schema = self.schema("vlan")
        self.assertTrue(schema["is_entry"])
        self.assertTrue(any(field["kind"] == "members" for field in schema["edit_fields"]))
        self.assertNotIn("fixture-retained-hash", page)

    def test_post_vlan_creates_new_saved_editable_workspace(self):
        schema = self.schema("vlan")
        response = self.post(updates=[self.update(schema, "Interface", ["ethernet1/1"])])
        new_id, query = self.created_id(response)
        self.assertEqual(query["config_section"], ["vlans"])
        self.assertEqual(query["scope"], ["vsys1"])
        self.assertEqual(self.count_workspaces(), 2)
        page = self.page(new_id)
        self.assertIn("Opgeslagen", page)
        self.assertIn("created-vlan", page)
        self.assertIn("data-config-record-edit", page)
        records = [json.loads(html.unescape(raw)) for raw in re.findall(r"data-config-record='([^']*)'", page)]
        self.assertTrue(any(record["name"] == "created-vlan" and record["editable"] for record in records))
        new_xml = main.workspace_config_path(main.workspace_row(new_id)).read_bytes()
        self.assertIn(b"<member>ethernet1/1</member>", new_xml)
        self.assertIn(b"fixture-retained-hash", new_xml)
        self.assertIn(b"192.0.2.44", new_xml)
        old_xml = main.workspace_config_path(main.workspace_row(self.workspace_id)).read_bytes()
        self.assertNotIn(b"created-vlan", old_xml)

    def test_device_local_auth_add_routes_to_device_editor(self):
        schema = self.schema("authentication-local", view="device", section="authentication-profile")
        response = self.post("authentication-local", view="device", section="authentication-profile",
                             name="local-auth", updates=[self.update(schema, "Allow List", ["all"])])
        new_id, query = self.created_id(response)
        self.assertEqual(query["workspace_view"], ["device"])
        page = self.page(new_id, view="device", section="authentication-profile")
        self.assertIn("Opgeslagen", page)
        self.assertIn("local-auth", page)
        root = ET.fromstring(main.workspace_config_path(main.workspace_row(new_id)).read_bytes())
        self.assertIsNotNone(root.find("./devices/entry/vsys/entry/authentication-profile/entry[@name='local-auth']/method/local-database"))

    def test_empty_vlan_add_then_edit_can_fill_optional_interface(self):
        added_id, _ = self.created_id(self.post())
        page = self.page(added_id)
        records = [json.loads(html.unescape(raw)) for raw in re.findall(r"data-config-record='([^']*)'", page)]
        record = next(item for item in records if item["name"] == "created-vlan")
        self.assertIn("Interfaces", record["ui_tabs"])
        field = next(field for field in record["edit_fields"] if field.get("technical_label") == "Interface")
        self.assertTrue(field["optional"])
        response = self.client.post(f"/config-workspaces/{added_id}/configuration/preview", data={
            "csrf": "route-csrf", "scope": "vsys1", "template": "vsys1", "workspace_view": "network",
            "config_section": "vlans", "operation": "update", "locator": record["locator"],
            "name": record["name"], "direct_save": "yes",
            "generic_updates": json.dumps([self.update(record, "Interface", ["ethernet1/1"])]),
        })
        self.addCleanup(response.close)
        edited_id, query = self.created_id(response, added_id)
        self.assertEqual(query["config_section"], ["vlans"])
        self.assertEqual(self.count_workspaces(), 3)
        self.assertIn("Opgeslagen", self.page(edited_id))
        new_xml = main.workspace_config_path(main.workspace_row(edited_id)).read_bytes()
        self.assertEqual(ET.fromstring(new_xml).findtext(".//vlan/entry/interface/member"), "ethernet1/1")
        self.assertIn(b"fixture-retained-hash", new_xml)
        self.assertIsNone(ET.fromstring(new_xml).find(".//vlan/entry/virtual-interface"))
        added_xml = main.workspace_config_path(main.workspace_row(added_id)).read_bytes()
        self.assertIsNone(ET.fromstring(added_xml).find(".//vlan/entry/interface"))

    def test_panorama_add_preserves_template_and_uses_its_existing_vsys(self):
        root = ET.Element("config")
        device = ET.SubElement(ET.SubElement(root, "devices"), "entry", {"name": "localhost.localdomain"})
        ET.SubElement(ET.SubElement(device, "device-group"), "entry", {"name": "edge-dg"})
        template = ET.SubElement(ET.SubElement(device, "template"), "entry", {"name": "edge-template"})
        template.append(copy.deepcopy(ET.fromstring(BASE)))
        _, _, workspace_id = self.workspace("panorama", ET.tostring(root), {"device_group": "edge-dg"})
        self.schema("zone-layer3", workspace_id=workspace_id, section="zones", scope="edge-dg", template="edge-template")
        response = self.post("zone-layer3", workspace_id=workspace_id, section="zones", scope="edge-dg",
                             template="edge-template", name="created-zone")
        new_id, query = self.created_id(response, workspace_id)
        self.assertEqual(query["scope"], ["edge-dg"])
        self.assertEqual(query["template"], ["edge-template"])
        page = self.page(new_id, section="zones", scope="edge-dg", template="edge-template")
        self.assertIn("created-zone", page)
        xml = ET.fromstring(main.workspace_config_path(main.workspace_row(new_id)).read_bytes())
        self.assertEqual([node.get("name") for node in xml.findall(".//template/entry/config/devices/entry/vsys/entry")], ["vsys1"])
        self.assertIsNotNone(xml.find(".//template/entry/config/devices/entry/vsys/entry/zone/entry[@name='created-zone']"))

    def test_forged_variant_and_updates_fail_without_new_workspace(self):
        for options in (
            {"variant": "authentication-local"},
            {"variant": "../../administrators"},
            {"updates": [{"path": "../../mgt-config", "kind": "text", "value": "bad"}]},
            {"updates": [{"path": "0", "kind": "protected", "value": "bad"}]},
            {"raw_updates": '{"path":"0"}'}, {"raw_updates": "not json"},
        ):
            with self.subTest(options=options):
                response = self.post(**options)
                self.assertEqual(response.status_code, 302)
                self.assertIn(f"/config-workspaces/{self.workspace_id}/edit", response.location)
                self.assertEqual(self.count_workspaces(), 1)
        page = self.page()
        self.assertIn("niet toegevoegd", page)

    def test_viewer_cannot_call_add_even_with_valid_csrf_and_schema(self):
        self.authenticate("viewer")
        self.assertIn("Geen configuratie gevonden", self.page())
        response = self.post()
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.count_workspaces(), 1)

    def test_new_version_keeps_viewer_write_restriction(self):
        new_id, _ = self.created_id(self.post())
        self.authenticate("viewer")
        self.assertIn("created-vlan", self.page(new_id))
        self.assertEqual(self.post(workspace_id=new_id, name="unauthorized-vlan").status_code, 404)
        self.assertEqual(self.count_workspaces(), 2)

    def test_authenticated_checkpoint_source_sync_retains_topology_and_transform_selectors(self):
        from app import migration
        interface = {"name": "eth0", "interface_type": "ethernet", "source_vendor": "checkpoint",
            "source_ref": "CP-Gateway", "source_networks": ["10.0.0.0/24"],
            "source_addresses": ["10.0.0.1/24"], "topology_role": "internal", "mapping_action": "review",
            "xml": '<entry name="eth0"><layer3><ip><entry name="10.0.0.1/24" /></ip></layer3></entry>'}
        original = migration.MigrationModel("checkpoint", "full-export.tar", interfaces=[interface],
            warnings=["Fixture topology requires review", "Fixture niet-ondersteunde Check Point actie: custom"],
            unsupported=["Fixture unsupported feature"])
        source_id = main.store_migration_source(self.project_id, "checkpoint", original.source_name, original)
        source_before = main.migration_source_row(source_id)
        original_bytes = Path(source_before["model_path"]).read_bytes()

        root = ET.fromstring(BASE)
        ethernet = root.find(".//network/interface/ethernet")
        ethernet.clear()
        ethernet.append(ET.fromstring(interface["xml"].replace("10.0.0.1/24", "192.0.2.12/28")))
        vsys = root.find(".//vsys/entry")
        fragment = ET.fromstring(migration.panos_fragment(migration.MigrationModel("panos", "edited",
            security_rules=[migration.Policy("edited-rule", source=["192.0.2.8"], disabled=False,
                description="REVIEW: actie custom")]), "vsys1"))
        vsys.append(fragment.find(".//vsys/entry/rulebase"))
        with main.db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (self.profile_id,)).fetchone()
        edited_workspace_id = main.store_config_workspace(profile, "source editor", "source.xml", ET.tostring(root),
                                                          "migration-staging", project_id=self.project_id)
        selector = migration.item_selector(interface)
        transforms = [
            {"operation": "topology_map", "kind": "interfaces", "selector": selector, "value": "ethernet1/1"},
            {"operation": "set_interface_zone", "kind": "interfaces", "selector": selector,
             "value": json.dumps({"zone": "Trust", "create": True})},
        ]
        with main.db() as conn:
            conn.execute("UPDATE migration_sources SET staging_workspace_id=? WHERE id=?", (edited_workspace_id, source_id))
            for transform in transforms:
                conn.execute("INSERT INTO migration_transform_rules(project_id,operation,kind,selector,value,created_at) VALUES(?,?,?,?,?,'now')",
                             (self.project_id, transform["operation"], transform["kind"], transform["selector"], transform["value"]))
            output_id = conn.execute("INSERT INTO migration_outputs(project_id,workspace_id,label,sanity_json,created_at) VALUES(?,?,?,'{}','now')",
                                     (self.project_id, self.workspace_id, "previous-output")).lastrowid
        response = self.client.post(f"/migration/projects/{self.project_id}/sources/{source_id}/sync-workspace",
                                    data={"csrf": "route-csrf"})
        self.addCleanup(response.close)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith(f"/migration/projects/{self.project_id}"))
        with self.client.session_transaction() as session:
            self.assertTrue(any("Wijzigingen uit de importeditor zijn opgenomen" in message for _, message in session.get("_flashes", [])))
        source_after = main.migration_source_row(source_id)
        synced = main.migration_model(source_after)
        self.assertEqual(synced.vendor, "checkpoint")
        self.assertEqual(synced.source_name, "full-export.tar")
        self.assertEqual(synced.interfaces[0]["source_vendor"], "checkpoint")
        self.assertEqual(migration.item_selector(synced.interfaces[0]), selector)
        self.assertEqual(synced.interfaces[0]["source_networks"], ["192.0.2.0/28"])
        self.assertEqual(synced.interfaces[0]["source_addresses"], ["192.0.2.12/28"])
        self.assertEqual(synced.warnings, original.warnings)
        self.assertEqual(synced.unsupported, original.unsupported)
        self.assertNotEqual(source_after["model_path"], source_before["model_path"])
        self.assertEqual(Path(source_before["model_path"]).read_bytes(), original_bytes)
        with main.db() as conn:
            saved_transforms = [dict(row) for row in conn.execute("SELECT operation,kind,selector,value FROM migration_transform_rules WHERE project_id=? ORDER BY id", (self.project_id,))]
            sanity = json.loads(conn.execute("SELECT sanity_json FROM migration_outputs WHERE id=?", (output_id,)).fetchone()[0])
        self.assertEqual(saved_transforms, transforms)
        mapped = migration.apply_transform_rules(synced, saved_transforms)
        self.assertEqual(mapped.security_rules[0].from_zones, ["Trust"])
        self.assertFalse(mapped.security_rules[0].disabled)
        self.assertTrue(sanity["regenerate_required"])
        self.assertTrue(sanity["source_changed"])
        preserved_xml = main.workspace_config_path(main.workspace_row(edited_workspace_id)).read_bytes()
        self.assertIn(b"fixture-retained-hash", preserved_xml)
        self.assertIn(b"192.0.2.44", preserved_xml)


if __name__ == "__main__":
    unittest.main()
