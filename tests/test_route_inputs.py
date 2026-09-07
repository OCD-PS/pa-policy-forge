"""Read-route robustness checks; disposable data and no appliance requests."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-route-inputs-"))
os.environ.setdefault("PPF_START_BACKGROUND_WORKERS", "0")
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "test-only-route-bootstrap")
with patch("threading.Thread.start"):
    from app import main


class RouteInputTests(unittest.TestCase):
    def setUp(self):
        main.app.config.update(TESTING=True)
        self.client = main.app.test_client()
        with main.db() as conn:
            user = conn.execute("SELECT id,username FROM users ORDER BY id LIMIT 1").fetchone()
            self.profile = dict(main.migration_target_profile(conn, "offline-panos"))
            self.project_id = conn.execute(
                "INSERT INTO migration_projects(name,target_profile_id,owner,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("Route input audit", self.profile["id"], user["username"], main.now(), main.now()),
            ).lastrowid
        with self.client.session_transaction() as session:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
        with main.app.test_request_context():
            main.session["user_id"] = user["id"]
            main.session["username"] = user["username"]
            self.workspace_id = main.store_config_workspace(
                self.profile, "Route inputs", "route-inputs.xml",
                Path(__file__).with_name("fixtures").joinpath("panos-rich-base.xml").read_bytes(), "test",
            )
        self.catalog = patch.object(main, "cached_application_catalog", return_value={"items":[], "ready":True, "refreshing":False, "error":""})
        self.catalog.start(); self.addCleanup(self.catalog.stop)

    def test_invalid_saved_filter_ids_do_not_raise_500(self):
        for value in ("abc", "1.5", "", "-1", "9" * 50):
            with self.subTest(value=value):
                response = self.client.get(f"/migration/projects/{self.project_id}", query_string={"saved_filter":value})
                self.assertEqual(response.status_code, 200)

    def test_invalid_workspace_pages_and_scope_produce_safe_ui(self):
        for query in (
            {"policy_page":"abc"}, {"policy_page":"-500"}, {"policy_page":"9" * 50},
            {"object_page":"no", "workspace_view":"objects"}, {"object_page":"9" * 50, "workspace_view":"objects"},
            {"workspace_view":"unknown", "policy_kind":"invalid", "rulebase":"invalid"},
            {"template":"missing", "workspace_view":"network"},
        ):
            with self.subTest(query=query):
                response = self.client.get(f"/config-workspaces/{self.workspace_id}/edit", query_string=query)
                self.assertIn(response.status_code, (200, 302))
        response = self.client.get(f"/config-workspaces/{self.workspace_id}/edit?scope=does-not-exist")
        self.assertEqual(response.status_code, 302)

    def test_nonexistent_and_out_of_range_ids_return_404(self):
        for item_id in (999999999, 2**63, 10**50):
            for route in (
                f"/migration/projects/{item_id}", f"/config-workspaces/{item_id}/edit",
                f"/runs/{item_id}", f"/profiles/{item_id}/catalog/applications",
            ):
                with self.subTest(route=route):
                    self.assertEqual(self.client.get(route).status_code, 404)

    def test_invalid_profile_query_ids_do_not_raise_500(self):
        response = self.client.get("/", query_string={name:"not-a-number" for name in ("flow_profile", "run_profile", "edit_profile", "policy_profile")})
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
