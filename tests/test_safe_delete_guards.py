import os
import json
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-safe-delete-test-"))
os.environ.setdefault("PPF_SYSLOG_PORT", "55153")
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "unit-test-bootstrap-password")

from app import main


class SafeDeleteGuardTests(unittest.TestCase):
    def test_delete_unused_preview_filters_before_validating_across_targets(self):
        current = [{"id": "used-id", "name": "used"}, {"id": "unused-id", "name": "unused"}]
        for target, scope in (("panos", "vsys1"), ("panos", "vsys2"), ("panos", "Shared"),
                              ("panorama", "Shared"), ("scm", "Parent")):
            with self.subTest(target=target, scope=scope):
                stamp = main.now()
                with main.db() as conn:
                    cursor = conn.execute(
                        "INSERT INTO profiles(name,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                        ("delete-unused-test", target, json.dumps({"vsys": scope}), b"", stamp, stamp),
                    )
                    profile_id = cursor.lastrowid
                client = main.app.test_client()
                with client.session_transaction(base_url="https://forge.test") as login:
                    login.update(user_id=1, username="test", must_change=False, csrf="delete-csrf")
                xml = b'<config><shared><address-group><entry name="consumers"><static><member>used</member></static></entry></address-group></shared></config>'
                draft_path = None
                try:
                    with patch("app.main.fetch_scm_objects", return_value=current), \
                         patch("app.main.fetch_panos_candidate_xml", return_value=("", "", None, xml)), \
                         patch("app.main.scm_object_reference_index", return_value={"used": ["Parent/rule/source"], "unused": []}), \
                         patch("app.main.render_template", return_value="preview") as render:
                        response = client.post(
                            f"/objects/{profile_id}/addresses/delete-preview",
                            data={"csrf": "delete-csrf", "delete_unused": "yes"}, base_url="https://forge.test",
                        )
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(render.call_args.kwargs["delete_objects"], [current[1]])
                        draft_path = main.OBJECT_DRAFTS / (render.call_args.kwargs["draft_id"] + ".json")
                        render.reset_mock()
                        rejected = client.post(
                            f"/objects/{profile_id}/addresses/delete-preview",
                            data={"csrf": "delete-csrf", "object_id": "used-id"}, base_url="https://forge.test",
                        )
                        self.assertEqual(rejected.status_code, 302)
                        render.assert_not_called()
                finally:
                    if draft_path is not None:
                        draft_path.unlink(missing_ok=True)
                    with main.db() as conn:
                        conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_reference_inventory_failure_still_blocks_selected_deletions(self):
        for target in ("panos", "panorama", "scm"):
            with self.subTest(target=target), \
                 patch("app.main.fetch_panos_candidate_xml", side_effect=RuntimeError("unavailable")), \
                 patch("app.main.scm_object_reference_index", side_effect=RuntimeError("unavailable")):
                with self.assertRaisesRegex(ValueError, "niets verwijderd"):
                    main.validate_live_object_deletions({"target_type": target}, "addresses", ["unused"])

    def test_scm_reference_inventory_continues_after_short_page_when_total_requires_it(self):
        responses = [
            {"data": [{"name": "one"}], "total": 2},
            {"data": [{"name": "two"}], "total": 2},
        ]
        with patch("app.main.policy_api.scm_http_request", side_effect=responses) as request:
            items = main.scm_fetch_reference_inventory("/devices", "token", {}, "device")

        self.assertEqual([item["name"] for item in items], ["one", "two"])
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[1].kwargs["params"]["offset"], "1")

    def test_scm_reference_inventory_fails_if_pagination_ends_before_reported_total(self):
        with patch(
            "app.main.policy_api.scm_http_request",
            side_effect=[{"data": [{"name": "one"}], "total": 2}, {"data": [], "total": 2}],
        ) as request:
            with self.assertRaisesRegex(RuntimeError, "eindigde vóór alle resultaten"):
                main.scm_fetch_reference_inventory("/devices", "token", {}, "device")

        self.assertEqual(request.call_count, 2)

    def test_scm_reference_scan_includes_descendant_folder_policy_and_post_rules(self):
        scm = SimpleNamespace(
            scm_object_folder="Parent", scm_folder="Parent", scm_snippet="", scm_device="",
            scm_api_base="https://api.strata.paloaltonetworks.com/config/security/v1", scm_rulebase="pre",
        )
        folders = {
            "data": [
                {"name": "Parent", "parent": "", "snippets": []},
                {"name": "Child", "parent": "Parent", "snippets": []},
            ],
            "total": 2,
        }

        def scm_request(method, endpoint, token, params=None, payload=None):
            if endpoint.endswith("/folders"):
                return folders
            if endpoint.endswith("/snippets"):
                return {"data": [], "total": 0}
            if endpoint.endswith("/devices"):
                return {"data": [{"name": "edge-1", "folder": "Child"}], "total": 1}
            if endpoint.endswith("/security-rules") and (
                (params.get("folder") == "Child" and params.get("position") == "post")
                or (params.get("device") == "edge-1" and params.get("position") == "pre")
            ):
                return {"data": [{"name": "child-rule", "source": ["shared-object"]}], "total": 1}
            return {"data": [], "total": 0}

        with patch("app.main.scm_client", return_value=(scm, "token", "", {})), \
             patch("app.main.policy_api.scm_http_request", side_effect=scm_request):
            references = main.scm_object_reference_index({"id": 1}, "addresses", ["shared-object"])

        self.assertTrue(references["shared-object"])
        self.assertTrue(any("Child/security/post/child-rule/source" in path for path in references["shared-object"]))
        self.assertTrue(any("edge-1/security/pre/child-rule/source" in path for path in references["shared-object"]))

    def test_scm_snippet_or_device_scope_fails_closed(self):
        scm = SimpleNamespace(
            scm_object_folder="Parent", scm_folder="", scm_snippet="SharedSnippet", scm_device="",
            scm_api_base="https://api.strata.paloaltonetworks.com/config/security/v1", scm_rulebase="pre",
        )
        with patch("app.main.scm_client", return_value=(scm, "token", "", {})), \
             patch("app.main.policy_api.scm_http_request") as request:
            with self.assertRaisesRegex(RuntimeError, "niet volledig controleren"):
                main.scm_object_reference_index({"id": 1}, "addresses", ["object-a"])
        request.assert_not_called()

    def test_panos_delete_guard_reads_complete_config(self):
        xml = b'<config><shared><address><entry name="shared-object"/></address></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2"><rulebase><security><rules><entry name="rule"><source><member>shared-object</member></source></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'
        with patch("app.main.fetch_panos_candidate_xml", return_value=("", "", None, xml)) as fetch:
            with self.assertRaisesRegex(ValueError, "nog in gebruik"):
                main.validate_live_object_deletions({"target_type": "panos"}, "addresses", ["shared-object"])
        fetch.assert_called_once()


if __name__ == "__main__":
    unittest.main()
