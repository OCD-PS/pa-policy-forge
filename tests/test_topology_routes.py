"""Topology route regressions; isolated data and no listeners or device access."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-topology-audit-"))
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "unit-test-bootstrap-password")
with patch("threading.Thread.start"):
    from app import main
from app.migration import MigrationModel


class TopologyRouteAuditTests(unittest.TestCase):
    def setUp(self):
        stamp = main.now()
        with main.db() as conn:
            profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("Topology audit", "panos", json.dumps({"vsys": "vsys1"}), stamp, stamp),
            ).lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        content = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><layer3><units><entry name="ethernet1/1.10"><tag>10</tag></entry></units></layer3></entry></ethernet></interface></network><vsys><entry name="vsys1"><rulebase/></entry></vsys></entry></devices></config>'''
        base = main.store_config_workspace(profile, "Audit base", "base.xml", content, "test")
        with main.db() as conn:
            self.project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,base_workspace_id,owner,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                ("topology-audit", profile_id, base, "admin", stamp, stamp),
            ).lastrowid
        main.store_migration_source(self.project_id, "checkpoint", "source.json", MigrationModel(
            "checkpoint", "source.json", interfaces=[{
                "name": "bond1.10", "source_ref": "cluster", "source_vendor": "checkpoint",
                "source_networks": ["192.0.2.0/24"], "source_addresses": ["192.0.2.1/24"],
                "xml": '<entry name="bond1.10"><layer3/></entry>', "interface_type": "ethernet",
                "mapping_action": "review",
            }],
        ))
        self.client = main.app.test_client()
        with main.app.test_request_context("/", base_url="https://forge.test"):
            serializer = main.app.session_interface.get_signing_serializer(main.app)
            self.client.set_cookie(main.app.config["SESSION_COOKIE_NAME"], serializer.dumps({
                "user_id": 1, "username": "admin", "csrf": "audit-csrf",
            }), domain="forge.test", secure=True)

    def save(self, **values):
        data = {"csrf": "audit-csrf", "kind": "interfaces", "selector": "bond1.10|||cluster", "action": "map", "target": "ethernet1/1.10", "zone": "Audit Zone"}
        data.update(values)
        return self.client.post(f"/migration/projects/{self.project_id}/topology", base_url="https://forge.test", data=data)

    def transforms(self):
        with main.db() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM migration_transform_rules WHERE project_id=?", (self.project_id,))]

    def test_unknown_target_rejected_without_changing_prior_decision(self):
        self.save()
        before = self.transforms()
        response = self.save(target="ethernet1/99")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.transforms(), before)

    def test_subinterface_target_and_zone_name_with_spaces_preserved(self):
        self.save()
        rows = self.transforms()
        self.assertEqual(next(row["value"] for row in rows if row["operation"] == "topology_map"), "ethernet1/1.10")
        self.assertEqual(json.loads(next(row["value"] for row in rows if row["operation"] == "set_interface_zone"))["zone"], "Audit Zone")

    def test_review_or_ignore_removes_zone_assignment(self):
        for action in ("review", "ignore"):
            with self.subTest(action=action):
                self.save()
                self.save(action=action)
                self.assertNotIn("set_interface_zone", [row["operation"] for row in self.transforms()])

    def test_invalid_zone_name_rejected_instead_of_silent_rename(self):
        for zone in ("any", "A" * 32, "bad/zone", "bad\nzone"):
            with self.subTest(zone=zone):
                self.save(zone=zone)
                self.assertEqual(self.transforms(), [])

    def test_mapped_and_ignored_source_remains_editable(self):
        for action in ("map", "ignore"):
            with self.subTest(action=action):
                self.save(action=action)
                with patch.object(main, "render_template", return_value="ok") as render:
                    response = self.client.get(f"/migration/projects/{self.project_id}", base_url="https://forge.test")
                self.assertEqual(response.status_code, 200)
                rows = render.call_args.kwargs["topology_items"]
                self.assertEqual(rows[0]["selector"], "bond1.10|||cluster")
                self.assertIn("ethernet1/1.10", rows[0]["targets"])

    def test_existing_zone_requires_actual_interface_membership(self):
        with patch.object(main, "migration_project_topology_targets", return_value={
            "interfaces": ["ethernet1/1.10"], "zones": ["Audit Zone"],
            "interface_zone_memberships": {},
        }):
            self.save()
        self.assertEqual(self.transforms(), [])
        with patch.object(main, "migration_project_topology_targets", return_value={
            "interfaces": ["ethernet1/1.10"], "zones": ["Audit Zone"],
            "interface_zone_memberships": {"ethernet1/1.10": ["Audit Zone"]},
        }):
            self.save()
        self.assertEqual(len(self.transforms()), 2)

    def test_interface_already_in_another_zone_rejects_new_assignment(self):
        with patch.object(main, "migration_project_topology_targets", return_value={
            "interfaces": ["ethernet1/1.10"], "zones": ["Other Zone"],
            "interface_zone_memberships": {"ethernet1/1.10": ["Other Zone"]},
        }):
            self.save()
        self.assertEqual(self.transforms(), [])

    def test_scm_workspace_policy_save_messages_are_concise(self):
        source = main.Path(main.__file__).read_text()
        self.assertNotIn('bewaard in een nieuwe workspaceversie.', source)
        self.assertGreaterEqual(source.count('flash("Opgeslagen", "success")'), 6)


if __name__ == "__main__":
    unittest.main()
