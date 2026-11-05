"""Workspace deletion stays local and preserves firewall profiles by default."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-workspace-delete-import-"))
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "fixture-only-bootstrap-password")

from app import main


XML = b'''<config version="12.1.0"><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1"><zone/></entry></vsys>
</entry></devices></config>'''


class WorkspaceDeletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="forge-workspace-delete-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for name, value in {
            "APP_DB": root / "app.sqlite3",
            "CONFIG_WORKSPACES": root / "workspaces",
        }.items():
            if name == "CONFIG_WORKSPACES":
                value.mkdir()
            patcher = patch.object(main, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        main.init_db()
        self.client = main.app.test_client()
        with main.db() as conn:
            conn.execute("UPDATE users SET must_change=0,is_admin=1 WHERE username='admin'")
            self.admin_user_id = int(conn.execute(
                "SELECT id FROM users WHERE username='admin'",
            ).fetchone()[0])
            stamp = main.now()
            self.profile_id = int(conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,secret_blob,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?)",
                (
                    "Delete fixture", "panos",
                    json.dumps({"endpoint": "https://fw.example.invalid", "configured": True,
                                "zones": {"Trust": "internal"}}),
                    b"encrypted-fixture-secret", stamp, stamp,
                ),
            ).lastrowid)
            self.profile = conn.execute("SELECT * FROM profiles WHERE id=?", (self.profile_id,)).fetchone()
        self.workspace_id = main.store_config_workspace(
            self.profile, "Imported config", "firewall.xml", XML, "upload", baseline_xml=XML,
        )
        self.workspace = main.workspace_row(self.workspace_id)
        self.latest_workspace_id = main.store_config_workspace(
            self.profile, "Edited config", "firewall.xml", XML, "edit",
            baseline_workspace=self.workspace, history_parent_id=self.workspace_id,
        )
        main.set_active_config_workspace(self.profile_id, self.latest_workspace_id)
        with self.client.session_transaction(base_url="https://forge.test") as session:
            session.update(user_id=self.admin_user_id, username="admin", must_change=False, csrf="delete-csrf")

    def post_delete(self, workspace_id, choice="keep"):
        return self.client.post(
            f"/config-workspaces/{workspace_id}/delete",
            data={"csrf": "delete-csrf", "remove_profile": choice},
            base_url="https://forge.test",
        )

    def test_workspace_delete_removes_lineage_but_keeps_profile_and_import_path(self):
        paths = [Path(self.workspace["config_path"]), Path(main.workspace_row(self.latest_workspace_id)["config_path"])]
        baseline = Path(self.workspace["baseline_config_path"])

        response = self.post_delete(self.latest_workspace_id)

        self.assertEqual(response.status_code, 302)
        with main.db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (self.profile_id,)).fetchone()
            self.assertIsNotNone(profile)
            self.assertEqual(json.loads(profile["settings_json"])["endpoint"], "https://fw.example.invalid")
            self.assertEqual(profile["secret_blob"], b"encrypted-fixture-secret")
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM config_workspaces WHERE profile_id=?", (self.profile_id,),
            ).fetchone()[0], 0)
        self.assertEqual(main.active_config_workspace_id(profile), 0)
        self.assertTrue(all(not path.exists() for path in [*paths, baseline]))

        chooser = self.client.get(
            f"/?policy_profile={self.profile_id}&policy_source=choose", base_url="https://forge.test",
        )
        html = chooser.get_data(as_text=True)
        self.assertEqual(chooser.status_code, 200)
        self.assertIn("Ophalen", html)
        self.assertIn("XML-configuratie", html)

    def test_profile_removal_deletes_local_workspaces_and_saved_link(self):
        response = self.post_delete(self.latest_workspace_id, "delete")

        self.assertEqual(response.status_code, 302)
        with main.db() as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM profiles WHERE id=?", (self.profile_id,)).fetchone())
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM config_workspaces WHERE profile_id=?", (self.profile_id,),
            ).fetchone()[0], 0)

    def test_profile_removal_is_atomic_when_migration_project_uses_profile(self):
        with main.db() as conn:
            conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,owner,created_at,updated_at) "
                "VALUES('protected project',?,'admin',?,?)",
                (self.profile_id, main.now(), main.now()),
            )

        response = self.post_delete(self.latest_workspace_id, "delete")

        self.assertEqual(response.status_code, 302)
        with main.db() as conn:
            self.assertIsNotNone(conn.execute("SELECT 1 FROM profiles WHERE id=?", (self.profile_id,)).fetchone())
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM config_workspaces WHERE id=?", (self.latest_workspace_id,),
            ).fetchone())

    def test_workspace_removal_is_blocked_when_migration_project_uses_that_history(self):
        with main.db() as conn:
            conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,base_workspace_id,owner,created_at,updated_at) "
                "VALUES('protected project',?,?,'admin',?,?)",
                (self.profile_id, self.latest_workspace_id, main.now(), main.now()),
            )

        response = self.post_delete(self.latest_workspace_id)

        self.assertEqual(response.status_code, 302)
        self.assertIsNotNone(main.workspace_row(self.latest_workspace_id))
        self.assertTrue(Path(self.workspace["config_path"]).exists())

    def test_non_admin_cannot_remove_firewall_profile(self):
        with main.db() as conn:
            editor_id = int(conn.execute(
                "INSERT INTO users(username,password_hash,must_change,is_admin) VALUES('editor','fixture',0,0)"
            ).lastrowid)
        with self.client.session_transaction(base_url="https://forge.test") as session:
            session.update(user_id=editor_id, username="editor", must_change=False, csrf="delete-csrf")

        response = self.post_delete(self.latest_workspace_id, "delete")

        self.assertEqual(response.status_code, 403)
        self.assertIsNotNone(main.workspace_row(self.latest_workspace_id))
        with main.db() as conn:
            self.assertIsNotNone(conn.execute("SELECT 1 FROM profiles WHERE id=?", (self.profile_id,)).fetchone())

    def test_merged_workspace_uses_same_card_grid_and_has_delete_action(self):
        merge_id = main.store_config_workspace(
            self.profile, "Merged config", "merged.xml", XML, "vsys-merge",
        )
        with main.db() as conn:
            conn.execute(
                "UPDATE config_workspaces SET metadata_json=? WHERE id=?",
                (json.dumps({"workspace_access_mode": "shared"}), merge_id),
            )

        response = self.client.get("/", base_url="https://forge.test")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("workspace-selector-card", html)
        self.assertIn(f'data-delete-url="/config-workspaces/{merge_id}/delete"', html)
        self.assertIn("Workspace verwijderen", html)
        self.assertNotIn("Samengevoegde workspaces", html)


if __name__ == "__main__":
    unittest.main()
