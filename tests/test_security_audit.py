"""Bounded security regressions: synthetic data only, no live network calls."""
import io
import json
import os
from pathlib import Path
import tempfile
import tarfile
import unittest
import urllib.error
import urllib.request
import urllib.response
from email.message import Message
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-security-import-"))
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "isolated-security-fixture-password")
os.environ.setdefault("PPF_BACKGROUND_WORKERS", "0")
with patch("threading.Thread.start"):
    from app import main


XML = b"""<config version="11.1.0"><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1"><address><entry name="private-customer-host">
<ip-netmask>192.0.2.10/32</ip-netmask></entry></address></entry></vsys>
</entry></devices></config>"""


class ProjectWorkspaceAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="forge-security-case-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for name, value in {
            "APP_DB": root / "app.sqlite3",
            "CONFIG_WORKSPACES": root / "workspaces",
            "POLICY_DRAFTS": root / "policy-drafts",
            "OBJECT_DRAFTS": root / "object-drafts",
        }.items():
            if name != "APP_DB":
                value.mkdir()
            patcher = patch.object(main, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        main.init_db()
        with main.db() as conn:
            for username in ("owner", "viewer", "editor", "stranger"):
                conn.execute("INSERT INTO users(username,password_hash,must_change) VALUES(?,?,0)",
                             (username, "unused-fixture-hash"))
            self.profile_id = conn.execute("""INSERT INTO profiles
                (name,target_type,settings_json,created_at,updated_at)
                VALUES('fixture','panos','{}','now','now')""").lastrowid
            self.project_id = conn.execute("""INSERT INTO migration_projects
                (name,target_profile_id,owner,created_at,updated_at)
                VALUES('private-project',?,'owner','now','now')""", (self.profile_id,)).lastrowid
            for username, role in (("viewer", "viewer"), ("editor", "editor")):
                conn.execute("INSERT INTO migration_project_roles VALUES(?,?,?,'now')",
                             (self.project_id, username, role))
            self.profile = conn.execute("SELECT * FROM profiles WHERE id=?", (self.profile_id,)).fetchone()
        self.workspace_id = main.store_config_workspace(self.profile, "fixture", "fixture.xml", XML, "migration-staging")
        with main.db() as conn:
            conn.execute("UPDATE migration_projects SET base_workspace_id=? WHERE id=?",
                         (self.workspace_id, self.project_id))
        self.client = main.app.test_client()

    def authenticate(self, username):
        with main.db() as conn:
            user_id = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()[0]
        with self.client.session_transaction() as session:
            session.clear()
            session.update(user_id=user_id, username=username, csrf="test-csrf")

    def export_status(self, workspace_id):
        response = self.client.get(f"/config-workspaces/{workspace_id}/export/xml")
        self.addCleanup(response.close)
        return response.status_code

    def test_unassigned_user_cannot_export_project_workspace_by_id(self):
        self.authenticate("stranger")
        response = self.client.get(f"/config-workspaces/{self.workspace_id}/export/xml")
        self.addCleanup(response.close)
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(b"private-customer-host", response.data)

    def test_viewer_can_export_but_cannot_select_or_delete_workspace(self):
        self.authenticate("viewer")
        self.assertEqual(self.export_status(self.workspace_id), 200)
        for action in ("select", "delete", "push"):
            response = self.client.post(f"/config-workspaces/{self.workspace_id}/{action}", data={"csrf": "test-csrf"})
            self.assertEqual(response.status_code, 404, action)
        self.assertIsNotNone(main.workspace_row(self.workspace_id))

    def test_editor_can_read_and_select_workspace(self):
        self.authenticate("editor")
        self.assertEqual(self.export_status(self.workspace_id), 200)
        self.assertEqual(self.client.post(f"/config-workspaces/{self.workspace_id}/select", data={"csrf": "test-csrf"}).status_code, 302)

    def test_viewer_cannot_apply_guessed_or_shared_policy_draft(self):
        draft = {"workspace_id": self.workspace_id, "operation": "create", "policy_name": "unauthorized", "scope": "vsys1", "kind": "security", "rulebase": "pre", "replacement_xml": "<entry name='unauthorized'/>"}
        (main.POLICY_DRAFTS / "offline-fixture.json").write_text(json.dumps(draft))
        self.authenticate("viewer")
        with patch.object(main, "store_config_workspace") as store:
            self.client.post("/config-workspaces/policy-drafts/fixture/apply", data={"csrf": "test-csrf"})
        store.assert_not_called()

    def test_unassigned_user_cannot_reuse_private_workspace_as_own_base(self):
        with main.db() as conn:
            other = conn.execute("""INSERT INTO migration_projects
                (name,target_profile_id,owner,created_at,updated_at)
                VALUES('other',?,'stranger','now','now')""", (self.profile_id,)).lastrowid
        self.authenticate("stranger")
        self.client.post(f"/migration/projects/{other}/base", data={"csrf": "test-csrf", "base_workspace_id": self.workspace_id})
        with main.db() as conn:
            self.assertIsNone(conn.execute("SELECT base_workspace_id FROM migration_projects WHERE id=?", (other,)).fetchone()[0])

    def test_old_versions_keep_access_controls_after_link_advances(self):
        new_id = main.store_config_workspace(self.profile, "edited", "fixture.xml", XML, "edit")
        main.advance_migration_staging_workspace(self.workspace_id, new_id)
        with main.db() as conn:
            conn.execute("UPDATE migration_projects SET base_workspace_id=? WHERE id=?", (new_id, self.project_id))
        self.authenticate("stranger")
        for workspace_id in (self.workspace_id, new_id):
            self.assertEqual(self.export_status(workspace_id), 404)

    def test_regular_policy_builder_workspace_remains_shared(self):
        workspace_id = main.store_config_workspace(self.profile, "global", "global.xml", XML, "upload")
        self.authenticate("stranger")
        self.assertEqual(self.export_status(workspace_id), 200)

    def test_missing_csrf_rejects_mutations_without_side_effect(self):
        self.authenticate("owner")
        self.assertEqual(self.client.post(f"/config-workspaces/{self.workspace_id}/delete").status_code, 400)
        self.assertIsNotNone(main.workspace_row(self.workspace_id))

    def test_backfill_protects_historical_versions_after_restart(self):
        old_id = main.store_config_workspace(self.profile, "old edit", "fixture.xml", XML, "edit")
        main.init_db()
        self.authenticate("stranger")
        self.assertEqual(self.export_status(old_id), 404)

    def test_deleted_project_does_not_make_old_xml_public(self):
        main.init_db()
        with main.db() as conn:
            conn.execute("DELETE FROM migration_project_roles WHERE project_id=?", (self.project_id,))
            conn.execute("DELETE FROM migration_projects WHERE id=?", (self.project_id,))
        self.authenticate("stranger")
        self.assertEqual(self.export_status(self.workspace_id), 404)

    def test_reused_project_id_does_not_grant_old_xml_to_new_owner(self):
        main.init_db()
        with main.db() as conn:
            conn.execute("DELETE FROM migration_project_roles WHERE project_id=?", (self.project_id,))
            conn.execute("DELETE FROM migration_projects WHERE id=?", (self.project_id,))
            replacement_id = conn.execute("""INSERT INTO migration_projects
                (name,target_profile_id,owner,created_at,updated_at)
                VALUES('replacement',?,'stranger','now','now')""", (self.profile_id,)).lastrowid
        self.assertEqual(replacement_id, self.project_id)
        self.authenticate("stranger")
        self.assertEqual(self.export_status(self.workspace_id), 404)


class CredentialTransportTests(unittest.TestCase):
    def test_redirects_cannot_forward_keys_or_bearer_tokens(self):
        # A fully in-process HTTPS handler: no sockets or external callbacks.
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                seen = []

                class FakeHTTPSHandler(urllib.request.HTTPSHandler):
                    def https_open(self, request):
                        seen.append(request)
                        headers = Message()
                        headers["Location"] = "http://untrusted.example/collect"
                        response = urllib.response.addinfourl(io.BytesIO(b""), headers, request.full_url, status)
                        response.msg = "Redirect"
                        return response

                request = urllib.request.Request("https://configured.example/api", headers={
                    "Authorization": "Bearer fixture-token", "X-PAN-KEY": "fixture-key",
                })
                with patch.object(urllib.request, "HTTPSHandler", FakeHTTPSHandler):
                    with self.assertRaises(urllib.error.HTTPError):
                        main.policy_api.credential_urlopen(request)
                self.assertEqual(len(seen), 1)
                self.assertEqual(seen[0].full_url, "https://configured.example/api")

    def test_non_https_or_embedded_credentials_are_rejected_before_network(self):
        for url in ("http://configured.example/api", "file:///tmp/config", "https://user:password@configured.example/api"):
            with self.subTest(url=url), patch.object(urllib.request, "build_opener") as opener:
                with self.assertRaises(ValueError):
                    main.policy_api.credential_urlopen(urllib.request.Request(url))
                opener.assert_not_called()

    def test_scm_token_errors_do_not_reflect_client_secrets(self):
        from types import SimpleNamespace
        scm = SimpleNamespace(scm_client_id="fixture-id", scm_client_secret="fixture-secret", scm_tsg_id="fixture-tsg", scm_token_url="https://configured.example/token")
        error = urllib.error.HTTPError(scm.scm_token_url, 400, "Bad Request", {}, io.BytesIO(b"fixture-secret"))
        with patch.object(main.policy_api, "credential_urlopen", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                main.policy_api.get_scm_token(scm)
        self.assertNotIn("fixture-secret", str(caught.exception))


class ArchiveBudgetTests(unittest.TestCase):
    def test_ignored_payload_cannot_bypass_decompressed_size_limit(self):
        from app.migration import CheckPointParser, MigrationError
        for kind in (tarfile.REGTYPE, tarfile.DIRTYPE):
            with self.subTest(kind=kind):
                header = tarfile.TarInfo("ignored.bin")
                header.type = kind
                header.size = 100 * 1024 * 1024 + 1
                # Header-only fixture: no large payload is allocated/decompressed.
                archive = io.BytesIO(header.tobuf() + b"\0" * 1024)
                with self.assertRaisesRegex(MigrationError, "100 MiB"):
                    CheckPointParser().parse_bytes(archive.getvalue(), "fixture.tar")

    def test_member_limit_is_checked_without_loading_entire_archive(self):
        from app.migration import CheckPointParser, MigrationError
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            for index in range(1001):
                archive.addfile(tarfile.TarInfo(f"ignored-{index}.txt"))
        with patch.object(tarfile.TarFile, "getmembers", side_effect=AssertionError("unbounded getmembers")):
            with self.assertRaisesRegex(MigrationError, "te veel bestanden"):
                CheckPointParser().parse_bytes(data.getvalue(), "fixture.tar")


if __name__ == "__main__":
    unittest.main()
