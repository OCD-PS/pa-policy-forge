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

    def merged_branch(self):
        merged_id = main.store_config_workspace(
            self.profile, "Merged", "undo-merged.xml", BASE_XML, "vsys-merge",
        )
        with main.db() as conn:
            metadata = json.loads(conn.execute(
                "SELECT metadata_json FROM config_workspaces WHERE id=?", (merged_id,),
            ).fetchone()[0])
            metadata["workspace_access_mode"] = "shared"
            conn.execute(
                "UPDATE config_workspaces SET metadata_json=? WHERE id=?", (json.dumps(metadata), merged_id),
            )
        return merged_id

    def test_merged_undo_restores_branch_head_and_allows_further_edits(self):
        merged_id = self.merged_branch()
        first_id = self.edit_version(merged_id, "first")
        second_id = self.edit_version(first_id, "second")
        with patch.object(main, "fetch_panos_candidate_xml", side_effect=AssertionError("offline only")):
            for current_id, expected_text, expected_undo_count in [(second_id, "first", 1), (None, "base", 0)]:
                if current_id is None:
                    current_id = restored_id
                response = self.client.post(
                    f"/config-workspaces/{current_id}/undo", data={"csrf": "undo-csrf"},
                )
                self.assertEqual(response.status_code, 302)
                restored_id = int(response.headers["Location"].split("/config-workspaces/")[1].split("/")[0])
                self.assertNotEqual(restored_id, current_id)
                restored = main.workspace_row(restored_id)
                xml = main.workspace_config_path(restored).read_bytes()
                self.assertIn(f">{expected_text}</description>".encode(), xml)
                self.assertEqual(restored["source"], "vsys-merge")
                self.assertEqual(json.loads(restored["metadata_json"])["workspace_access_mode"], "shared")
                self.assertEqual(len(main.workspace_history_chain(restored_id)) - 1, expected_undo_count)
                with main.db() as conn:
                    profile = conn.execute("SELECT * FROM profiles WHERE id=?", (self.profile_id,)).fetchone()
                    latest_id = conn.execute(
                        "SELECT MAX(id) FROM config_workspaces WHERE source='vsys-merge' AND profile_id=?",
                        (self.profile_id,),
                    ).fetchone()[0]
                self.assertEqual(latest_id, restored_id)
                self.assertEqual(main.active_config_workspace_id(profile), self.base_id)
            edited_id = self.edit_version(restored_id, "after undo")
            self.assertIn(b">after undo</description>", main.workspace_config_path(main.workspace_row(edited_id)).read_bytes())

    def test_stale_merged_undo_cannot_replace_newer_branch_head(self):
        merged_id = self.merged_branch()
        first_id = self.edit_version(merged_id, "first")
        second_id = self.edit_version(first_id, "second")
        response = self.client.post(f"/config-workspaces/{first_id}/undo", data={"csrf": "undo-csrf"})
        self.assertIn(f"/config-workspaces/{first_id}/edit", response.headers["Location"])
        with self.client.session_transaction() as session:
            self.assertTrue(any("verouderd" in message for _, message in session.get("_flashes", [])))
        with main.db() as conn:
            latest_id = conn.execute("SELECT MAX(id) FROM config_workspaces").fetchone()[0]
        self.assertEqual(latest_id, second_id)

    def test_merged_undo_rollback_removes_new_snapshot_and_retains_head(self):
        merged_id = self.merged_branch()
        edited_id = self.edit_version(merged_id, "changed")
        before_files = set(main.CONFIG_WORKSPACES.iterdir())
        with patch.object(main, "advance_migration_staging_workspace", side_effect=RuntimeError("fixture failure")):
            response = self.client.post(f"/config-workspaces/{edited_id}/undo", data={"csrf": "undo-csrf"})
        self.assertIn(f"/config-workspaces/{edited_id}/edit", response.headers["Location"])
        self.assertEqual(set(main.CONFIG_WORKSPACES.iterdir()), before_files)
        self.assertEqual(main.workspace_history_chain(edited_id), [edited_id, merged_id])
        self.edit_version(edited_id, "retry")

    def test_merged_undo_requires_write_access_to_restored_parent(self):
        merged_id = self.merged_branch()
        edited_id = self.edit_version(merged_id, "changed")
        with main.db() as conn:
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,owner,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("Restricted ancestor", self.profile_id, "another-owner", main.now(), main.now()),
            ).lastrowid
            main.link_workspace_project(conn, merged_id, project_id)
        response = self.client.post(f"/config-workspaces/{edited_id}/undo", data={"csrf": "undo-csrf"})
        self.assertIn(f"/config-workspaces/{edited_id}/edit", response.headers["Location"])
        with main.app.test_request_context(method="POST"):
            main.session["username"] = "undo-owner"
            self.assertEqual(main.workspace_history_chain(edited_id), [edited_id])

    def test_project_viewer_cannot_undo_merged_workspace(self):
        merged_id = self.merged_branch()
        with main.db() as conn:
            project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,owner,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("Private merge", self.profile_id, "undo-owner", main.now(), main.now()),
            ).lastrowid
            main.link_workspace_project(conn, merged_id, project_id)
            viewer_id = conn.execute(
                "INSERT INTO users(username,password_hash,must_change) VALUES(?,?,0)",
                ("undo-viewer", "unused-fixture-hash"),
            ).lastrowid
            conn.execute(
                "INSERT INTO migration_project_roles(project_id,username,role,created_at) VALUES(?,?,?,?)",
                (project_id, "undo-viewer", "viewer", main.now()),
            )
        edited_id = self.edit_version(merged_id, "private change")
        with self.client.session_transaction() as session:
            session.update(user_id=viewer_id, username="undo-viewer")
        response = self.client.post(f"/config-workspaces/{edited_id}/undo", data={"csrf": "undo-csrf"})
        self.assertEqual(response.status_code, 404)
        with main.db() as conn:
            self.assertEqual(conn.execute("SELECT MAX(id) FROM config_workspaces").fetchone()[0], edited_id)

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
