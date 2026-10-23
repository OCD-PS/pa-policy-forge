import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-incremental-commit-test-"))
os.environ.setdefault("PPF_SYSLOG_PORT", "55152")
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "unit-test-bootstrap-password")

from app import main


class IncrementalPushCommitTests(unittest.TestCase):
    def setUp(self):
        stamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,secret_blob,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?)",
                ("incremental-commit-test", "panos", json.dumps({"endpoint": "https://fw.example.invalid", "vsys": "vsys1"}), b"", stamp, stamp),
            )
            self.profile_id = int(cursor.lastrowid)
            self.profile = conn.execute("SELECT * FROM profiles WHERE id=?", (self.profile_id,)).fetchone()
        self.candidate_xml = main.normalized_config_xml(main.ET.fromstring(
            b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address/></entry></vsys></entry></devices></config>'
        ))
        desired = b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="e2e-address"><ip-netmask>192.0.2.44/32</ip-netmask></entry></address></entry></vsys></entry></devices></config>'
        self.workspace_id = main.store_config_workspace(
            self.profile, "incremental commit test", "candidate.xml", desired, "test",
        )
        self.client = main.app.test_client()
        with self.client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "admin"
            login["must_change"] = False
            login["csrf"] = "incremental-commit-csrf"
        delta = main.config_push_delta(self.candidate_xml, desired)
        self.selection_key = next(item["selection_key"] for item in delta if item["family"].startswith("object:"))

    def tearDown(self):
        workspace = main.workspace_row(self.workspace_id)
        if workspace:
            Path(workspace["config_path"]).unlink(missing_ok=True)
        with main.db() as conn:
            conn.execute("DELETE FROM config_workspace_commits WHERE workspace_id=?", (self.workspace_id,))
            conn.execute("DELETE FROM config_workspaces WHERE id=?", (self.workspace_id,))
            conn.execute("DELETE FROM profiles WHERE id=?", (self.profile_id,))

    def test_commit_is_opt_in_and_status_checks_are_rate_limited(self):
        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), self.candidate_xml)):
            preview = self.client.get(
                f"/config-workspaces/{self.workspace_id}/push-preview",
                base_url="https://forge.test",
            )
        self.assertEqual(preview.status_code, 200)
        preview_html = preview.get_data(as_text=True)
        self.assertIn('name="commit_after_push" value="yes"', preview_html)
        self.assertNotIn('name="commit_after_push" value="yes" checked', preview_html)

        def api_response(endpoint, params, ctx):
            if params["type"] == "config" and params.get("action") == "set":
                return '<response status="success" code="20"><result/></response>'
            if params["type"] == "op":
                return '<response status="success"><result><job>101</job></result></response>'
            if params["type"] == "commit":
                return '<response status="success" code="19"><result><job>202</job></result></response>'
            self.fail(f"Unexpected PAN-OS API request type: {params['type']}")

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), self.candidate_xml)), \
             patch("app.main.panos_api_post", side_effect=api_response) as api_post, \
             patch("app.main.wait_panos_job", return_value={"status": "FIN", "result": "OK", "details": []}):
            response = self.client.post(
                f"/config-workspaces/{self.workspace_id}/push",
                base_url="https://forge.test",
                data={
                    "csrf": "incremental-commit-csrf",
                    "candidate_sha256": hashlib.sha256(self.candidate_xml).hexdigest(),
                    "family": self.selection_key,
                    "commit_after_push": "yes",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/config-workspaces/{self.workspace_id}/commits/", response.headers["Location"])
        commit_calls = [call.args[1] for call in api_post.call_args_list if call.args[1]["type"] == "commit"]
        self.assertEqual(len(commit_calls), 1)
        self.assertEqual(
            commit_calls[0]["cmd"],
            f"<commit><description>PA Policy Forge incremental push workspace {self.workspace_id}</description></commit>",
        )
        with main.db() as conn:
            commit = conn.execute(
                "SELECT * FROM config_workspace_commits WHERE workspace_id=? ORDER BY id DESC LIMIT 1",
                (self.workspace_id,),
            ).fetchone()
        self.assertEqual(commit["job_id"], "202")
        self.assertEqual(commit["status"], "PEND")

        status_url = response.headers["Location"].replace("https://forge.test", "") + "/status"
        status_page = self.client.get(response.headers["Location"], base_url="https://forge.test")
        self.assertEqual(status_page.status_code, 200)
        self.assertIn("Status wordt maximaal eenmaal per minuut", status_page.get_data(as_text=True))

        # The initial commit timestamp starts the one-minute server-side cooldown.
        with patch("app.main.panos_api_post") as api_post:
            throttled = self.client.get(status_url, base_url="https://forge.test")
        self.assertEqual(throttled.status_code, 200)
        self.assertGreater(throttled.get_json()["retry_after"], 0)
        api_post.assert_not_called()

        with main.db() as conn:
            conn.execute(
                "UPDATE config_workspace_commits SET last_checked_at=? WHERE id=?",
                (main.time.time() - 61, commit["id"]),
            )
        job_responses = [
            '<response status="success"><result><job><id>202</id><status>ACT</status><progress>42</progress><result>PEND</result><warnings><line>Commit running</line></warnings></job></result></response>',
            '<response status="success"><result><job><id>202</id><status>FIN</status><progress>100</progress><result>OK</result><details>Configuration committed successfully</details></job></result></response>',
        ]
        with patch("app.main.panos_profile_context", return_value=({}, "https://fw.example.invalid", "test-key", object())), \
             patch("app.main.panos_api_post", side_effect=job_responses) as api_post:
            active = self.client.get(status_url, base_url="https://forge.test").get_json()
            again = self.client.get(status_url, base_url="https://forge.test").get_json()
            self.assertEqual(active["status"], "ACT")
            self.assertEqual(active["progress"], 42)
            self.assertGreater(again["retry_after"], 0)
            self.assertEqual(api_post.call_count, 1)
            with main.db() as conn:
                conn.execute(
                    "UPDATE config_workspace_commits SET last_checked_at=? WHERE id=?",
                    (main.time.time() - 61, commit["id"]),
                )
            completed = self.client.get(status_url, base_url="https://forge.test").get_json()
            self.assertEqual(completed["status"], "FIN")
            self.assertEqual(completed["result"], "OK")
            self.assertTrue(completed["terminal"])
            self.assertEqual(api_post.call_count, 2)
            self.client.get(status_url, base_url="https://forge.test")
            self.assertEqual(api_post.call_count, 2)

    def test_unchecked_commit_option_never_submits_a_commit(self):
        def api_response(endpoint, params, ctx):
            if params["type"] == "config" and params.get("action") == "set":
                return '<response status="success" code="20"><result/></response>'
            if params["type"] == "op":
                return '<response status="success"><result><job>303</job></result></response>'
            self.fail(f"Unexpected PAN-OS API request type: {params['type']}")

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), self.candidate_xml)), \
             patch("app.main.panos_api_post", side_effect=api_response) as api_post, \
             patch("app.main.wait_panos_job", return_value={"status": "FIN", "result": "OK", "details": []}):
            response = self.client.post(
                f"/config-workspaces/{self.workspace_id}/push",
                base_url="https://forge.test",
                data={
                    "csrf": "incremental-commit-csrf",
                    "candidate_sha256": hashlib.sha256(self.candidate_xml).hexdigest(),
                    "family": self.selection_key,
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertIn("policy-management", response.headers["Location"])
        self.assertFalse(any(call.args[1]["type"] == "commit" for call in api_post.call_args_list))
        with main.db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM config_workspace_commits WHERE workspace_id=?",
                (self.workspace_id,),
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_pan_os_no_changes_to_commit_is_reported_as_noop(self):
        def api_response(endpoint, params, ctx):
            if params["type"] == "config" and params.get("action") == "set":
                return '<response status="success" code="20"><result/></response>'
            if params["type"] == "op":
                return '<response status="success"><result><job>404</job></result></response>'
            if params["type"] == "commit":
                return '<response status="error" code="19"><msg>There are no changes to commit</msg></response>'
            self.fail(f"Unexpected PAN-OS API request type: {params['type']}")

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), self.candidate_xml)), \
             patch("app.main.panos_api_post", side_effect=api_response), \
             patch("app.main.wait_panos_job", return_value={"status": "FIN", "result": "OK", "details": []}):
            response = self.client.post(
                f"/config-workspaces/{self.workspace_id}/push",
                base_url="https://forge.test",
                data={
                    "csrf": "incremental-commit-csrf",
                    "candidate_sha256": hashlib.sha256(self.candidate_xml).hexdigest(),
                    "family": self.selection_key,
                    "commit_after_push": "yes",
                },
            )
        self.assertEqual(response.status_code, 302)
        with main.db() as conn:
            commit = conn.execute(
                "SELECT * FROM config_workspace_commits WHERE workspace_id=? ORDER BY id DESC LIMIT 1",
                (self.workspace_id,),
            ).fetchone()
        payload = main.config_workspace_commit_payload(commit)
        self.assertEqual(payload["status"], "FIN")
        self.assertEqual(payload["result"], "NO_CHANGES")
        self.assertEqual(payload["label"], "Geen wijzigingen om te committen")
        self.assertTrue(payload["terminal"])
