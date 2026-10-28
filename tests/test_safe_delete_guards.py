import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-safe-delete-test-"))
os.environ.setdefault("PPF_SYSLOG_PORT", "55153")
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "unit-test-bootstrap-password")

from app import main


class SafeDeleteGuardTests(unittest.TestCase):
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
