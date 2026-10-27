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
        self.extra_workspace_ids = []
        self.client = main.app.test_client()
        with self.client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "admin"
            login["must_change"] = False
            login["csrf"] = "incremental-commit-csrf"
        delta = main.config_push_delta(self.candidate_xml, desired)
        self.selection_key = next(item["selection_key"] for item in delta if item["family"].startswith("object:"))

    def tearDown(self):
        for workspace_id in [self.workspace_id, *self.extra_workspace_ids]:
            workspace = main.workspace_row(workspace_id)
            if workspace:
                Path(workspace["config_path"]).unlink(missing_ok=True)
                if workspace["baseline_config_path"]:
                    Path(workspace["baseline_config_path"]).unlink(missing_ok=True)
        with main.db() as conn:
            for workspace_id in [self.workspace_id, *self.extra_workspace_ids]:
                conn.execute("DELETE FROM config_workspace_commits WHERE workspace_id=?", (workspace_id,))
                conn.execute("DELETE FROM config_workspaces WHERE id=?", (workspace_id,))
            conn.execute("DELETE FROM profiles WHERE id=?", (self.profile_id,))

    def create_policy_workspace(self, description_current="old"):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2">'
            b'<rulebase><security><rules><entry name="Allow-app"><description>old</description>'
            b'<source><member>CN</member><member>RU</member></source></entry></rules></security></rulebase>'
            b'</entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find(".//rules/entry/description").text = "Steven description"
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "rebase test", "candidate.xml", desired, "api", baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        current_root = main.ET.fromstring(base)
        current_root.find(".//rules/entry/source").remove(
            current_root.find(".//rules/entry/source/member")
        )
        if description_current != "old":
            current_root.find(".//rules/entry/description").text = description_current
        current = main.normalized_config_xml(current_root)
        return workspace_id, base, desired, current

    def test_rebase_preserves_concurrent_member_deletion_and_pushes_local_description(self):
        workspace_id, _, _, current = self.create_policy_workspace()
        self.assertIsNotNone(main.workspace_baseline_config(main.workspace_row(workspace_id)))
        with patch("app.main.fetch_panos_candidate_xml_for_preview", return_value=(current, False)):
            preview = self.client.get(
                f"/config-workspaces/{workspace_id}/push-preview", base_url="https://forge.test",
            )
        self.assertEqual(preview.status_code, 200)
        preview_html = preview.get_data(as_text=True)
        self.assertIn("Niet-botsende wijzigingen zijn behouden", preview_html)
        merged, conflicts = main.merge_panos_candidate_xml(
            main.workspace_baseline_config(main.workspace_row(workspace_id)),
            main.workspace_config_path(main.workspace_row(workspace_id)).read_bytes(), current,
        )
        self.assertEqual(conflicts, [])
        changes = main.config_push_delta(current, merged)
        self.assertEqual(len(changes), 1)
        selection_key = changes[0]["selection_key"]

        def api_response(endpoint, params, ctx):
            if params["type"] == "config":
                return '<response status="success" code="20"><result/></response>'
            if params["type"] == "op":
                return '<response status="success"><result><job>505</job></result></response>'
            self.fail(f"Unexpected PAN-OS request type: {params['type']}")

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), current)), \
             patch("app.main.panos_api_post", side_effect=api_response) as api_post, \
             patch("app.main.wait_panos_job", return_value={"status": "FIN", "result": "OK", "details": []}):
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={
                    "csrf": "incremental-commit-csrf",
                    "candidate_sha256": hashlib.sha256(self.candidate_xml).hexdigest(),
                    "family": selection_key,
                }, follow_redirects=True,
            )
        self.assertIn("naar de candidate geschreven en gevalideerd", response.get_data(as_text=True))
        config_calls = [call.args[1] for call in api_post.call_args_list if call.args[1]["type"] == "config"]
        self.assertEqual(len(config_calls), 1)
        self.assertEqual(config_calls[0]["action"], "set")
        self.assertTrue(config_calls[0]["xpath"].endswith("/entry[@name='Allow-app']"))
        patch_xml = main.ET.fromstring(f"<patch>{config_calls[0]['element']}</patch>")
        self.assertEqual([child.tag for child in patch_xml], ["description"])
        self.assertEqual(patch_xml.findtext("description"), "Steven description")
        self.assertNotIn("source", config_calls[0]["element"])

    def test_conflicting_edit_blocks_push_and_keeps_workspace_draft(self):
        workspace_id, _, _, current = self.create_policy_workspace("colleague description")
        with patch("app.main.fetch_panos_candidate_xml_for_preview", return_value=(current, False)):
            preview = self.client.get(
                f"/config-workspaces/{workspace_id}/push-preview", base_url="https://forge.test",
            )
        self.assertIn("Er zijn conflicterende wijzigingen gevonden", preview.get_data(as_text=True))
        self.assertNotIn('data-incremental-push', preview.get_data(as_text=True))

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), current)), \
             patch("app.main.panos_api_post") as api_post:
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "candidate_sha256": "stale", "family": self.selection_key},
                follow_redirects=True,
            )
        self.assertIn("conflicterende wijzigingen", response.get_data(as_text=True))
        api_post.assert_not_called()
        self.assertTrue(main.workspace_config_path(main.workspace_row(workspace_id)).is_file())

    def test_competing_policy_member_replacements_block_all_candidate_writes(self):
        base_root = main.ET.fromstring(
            b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2">'
            b'<rulebase><security><rules><entry name="Allow-app"><source><member>CN</member>'
            b'</source></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'
        )
        base = main.normalized_config_xml(base_root)
        desired_root = main.ET.fromstring(base)
        desired_root.find(".//rules/entry/source/member").text = "RU"
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "member conflict", "candidate.xml", desired, "api", baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        current_root = main.ET.fromstring(base)
        current_root.find(".//rules/entry/source/member").text = "US"
        current = main.normalized_config_xml(current_root)

        with patch("app.main.fetch_panos_candidate_xml_for_preview", return_value=(current, False)):
            preview = self.client.get(
                f"/config-workspaces/{workspace_id}/push-preview", base_url="https://forge.test",
            )
        self.assertIn("/source/member-list", preview.get_data(as_text=True))

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), current)), \
             patch("app.main.panos_api_post") as api_post:
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "candidate_sha256": "stale"},
                follow_redirects=True,
            )
        self.assertIn("conflicterende wijzigingen", response.get_data(as_text=True))
        api_post.assert_not_called()

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

    def test_protected_only_preview_explains_why_no_family_can_be_selected(self):
        candidate = main.normalized_config_xml(main.ET.fromstring(
            b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="e2e-address"><ip-netmask>192.0.2.44/32</ip-netmask></entry></address></entry></vsys></entry></devices><mgt-config><users><entry name="admin"><phash>redacted-test-value</phash></entry></users></mgt-config></config>'
        ))

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), candidate)):
            response = self.client.get(
                f"/config-workspaces/{self.workspace_id}/push-preview",
                base_url="https://forge.test",
            )

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Beschermd", page)
        self.assertIn("Er zijn alleen beschermde configuratiewijzigingen gevonden", page)
        self.assertNotIn('data-incremental-push', page)
        self.assertNotIn('name="family"', page)

    def test_empty_selection_for_protected_only_diff_has_specific_error(self):
        candidate = main.normalized_config_xml(main.ET.fromstring(
            b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="e2e-address"><ip-netmask>192.0.2.44/32</ip-netmask></entry></address></entry></vsys></entry></devices><mgt-config><users><entry name="admin"><phash>redacted-test-value</phash></entry></users></mgt-config></config>'
        ))

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), candidate)):
            response = self.client.post(
                f"/config-workspaces/{self.workspace_id}/push",
                base_url="https://forge.test",
                data={
                    "csrf": "incremental-commit-csrf",
                    "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
                },
                follow_redirects=True,
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Alle gevonden wijzigingen zijn beschermd en kunnen niet worden gepusht",
            response.get_data(as_text=True),
        )

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
