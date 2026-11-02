"""Regression coverage for the bounded workspace undo history."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-workspace-undo-import-"))
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "isolated-undo-fixture-password")
os.environ.setdefault("PPF_BACKGROUND_WORKERS", "0")
with patch("threading.Thread.start"):
    from app import main


BASE_XML = (
    b'<config version="11.1.0"><devices><entry name="localhost.localdomain">'
    b'<vsys><entry name="vsys1"><description>base</description></entry></vsys>'
    b'</entry></devices></config>'
)


class WorkspaceUndoTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="forge-workspace-undo-case-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for name, value in {
            "APP_DB": root / "app.sqlite3",
            "CONFIG_WORKSPACES": root / "workspaces",
            "POLICY_DRAFTS": root / "policy-drafts",
            "OBJECT_DRAFTS": root / "object-drafts",
            "MIGRATION_SOURCES": root / "migration-sources",
        }.items():
            if name != "APP_DB":
                value.mkdir()
            patcher = patch.object(main, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        main.app.config.update(TESTING=True)
        main.init_db()
        self.client = main.app.test_client()
        with main.db() as conn:
            self.user_id = conn.execute(
                "INSERT INTO users(username,password_hash,must_change) VALUES(?,?,0)",
                ("undo-owner", "unused-fixture-hash"),
            ).lastrowid
            self.profile_id = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,created_at,updated_at) "
                "VALUES(?,?,?,?,?)",
                ("Undo fixture", "panos", "{}", main.now(), main.now()),
            ).lastrowid
            self.profile = conn.execute("SELECT * FROM profiles WHERE id=?", (self.profile_id,)).fetchone()
        self.base_id = main.store_config_workspace(self.profile, "Base", "undo-base.xml", BASE_XML, "test")
        main.set_active_config_workspace(self.profile_id, self.base_id)
        with self.client.session_transaction() as session:
            session.update(user_id=self.user_id, username="undo-owner", csrf="undo-csrf")

    def edit_version(self, workspace_id, description):
        workspace = main.workspace_row(workspace_id)
        updated_xml = BASE_XML.replace(b">base</description>", f">{description}</description>".encode())
        return main.store_workspace_edit_version(workspace, updated_xml, "test edit")

    def test_undo_restores_previous_workspace_and_keeps_editor_context(self):
        edited_id = self.edit_version(self.base_id, "changed")
        response = self.client.post(
            f"/config-workspaces/{edited_id}/undo",
            data={
                "csrf": "undo-csrf", "scope": "vsys1", "workspace_view": "objects",
                "object_type": "addresses", "object_query": "server", "object_page": "2",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/config-workspaces/{self.base_id}/edit", response.headers["Location"])
        self.assertIn("workspace_view=objects", response.headers["Location"])
        with main.db() as conn:
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (self.profile_id,)).fetchone()
        self.assertEqual(main.active_config_workspace_id(profile), self.base_id)

    def test_workspace_editor_enables_undo_for_migration_base(self):
        with main.db() as conn:
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,owner,created_at,updated_at) "
                "VALUES(?,?,?,?,?)",
                ("Undo migration", self.profile_id, "undo-owner", main.now(), main.now()),
            ).lastrowid
            conn.execute("UPDATE migration_projects SET base_workspace_id=? WHERE id=?", (self.base_id, project_id))
            conn.execute(
                "INSERT INTO config_workspace_projects(workspace_id,project_id,project_identity) "
                "SELECT ?,id,access_identity FROM migration_projects WHERE id=?",
                (self.base_id, project_id),
            )

        edited_id = self.edit_version(self.base_id, "changed")
        response = self.client.get(
            f"/config-workspaces/{edited_id}/edit",
            query_string={"scope": "vsys1", "workspace_view": "objects", "object_type": "addresses"},
        )

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Ongedaan maken", html)
        button = html.split("Ongedaan maken", 1)[0].rsplit("<button", 1)[-1]
        self.assertNotIn("disabled", button)

    def test_history_keeps_current_plus_at_most_fifteen_undo_steps(self):
        workspace_id = self.base_id
        for index in range(20):
            workspace_id = self.edit_version(workspace_id, f"version-{index}")

        chain = main.workspace_history_chain(workspace_id)
        self.assertEqual(len(chain), main.WORKSPACE_UNDO_LIMIT + 1)
        with main.db() as conn:
            retained = conn.execute(
                "SELECT count(*) FROM config_workspaces WHERE profile_id=? AND history_root_id=?",
                (self.profile_id, self.base_id),
            ).fetchone()[0]
            oldest = conn.execute(
                "SELECT history_parent_id FROM config_workspaces WHERE id=?", (chain[-1],)
            ).fetchone()
        self.assertEqual(retained, main.WORKSPACE_UNDO_LIMIT + 1)
        self.assertIsNone(oldest["history_parent_id"])


if __name__ == "__main__":
    unittest.main()
