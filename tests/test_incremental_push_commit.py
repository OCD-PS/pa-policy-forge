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
            baseline_xml=self.candidate_xml,
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

    def test_pan_os_reference_count_error_has_actionable_short_message(self):
        message = main.concise_incremental_push_error(RuntimeError(
            "delete Addresses host-a failed: status='error' code='10' msg=references remain"
        ))
        self.assertEqual(
            message,
            "delete Addresses host-a: PAN-OS kan dit object niet verwijderen zolang er verwijzingen naar bestaan (code 10)",
        )

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

    def test_rebase_preserves_concurrent_zone_address_and_user_group_additions(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<address/><rulebase><security><rules><entry name="Allow-app"><description>old</description>'
            b'<from><member>any</member></from><source><member>any</member></source>'
            b'<destination><member>any</member></destination><source-user><member>any</member></source-user>'
            b'</entry></rules></security></rulebase></entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find(".//rules/entry/description").text = "Forge description"
        desired = main.normalized_config_xml(desired_root)
        current_root = main.ET.fromstring(base)
        address = current_root.find(".//vsys/entry/address")
        address_entry = main.ET.SubElement(address, "entry", {"name": "host-10.10.102.56"})
        main.ET.SubElement(address_entry, "ip-netmask").text = "10.10.102.56"
        rule = current_root.find(".//rules/entry")
        for field, value in (
            ("from", "Trust"),
            ("source", "host-10.10.102.56"),
            ("destination", "server-group"),
            ("source-user", "DOMAIN\\Operations"),
        ):
            field_node = rule.find(field)
            field_node.remove(field_node.find("member"))
            main.ET.SubElement(field_node, "member").text = value
        current = main.normalized_config_xml(current_root)

        merged, conflicts = main.merge_panos_candidate_xml(base, desired, current)

        self.assertEqual(conflicts, [])
        merged_root = main.ET.fromstring(merged)
        merged_rule = merged_root.find(".//rules/entry")
        self.assertIsNotNone(merged_root.find(".//address/entry[@name='host-10.10.102.56']"))
        self.assertEqual(merged_rule.findtext("description"), "Forge description")
        for field, value in (
            ("from", "Trust"),
            ("source", "host-10.10.102.56"),
            ("destination", "server-group"),
            ("source-user", "DOMAIN\\Operations"),
        ):
            self.assertEqual(merged_rule.findtext(f"{field}/member"), value)
        changes = main.config_push_delta(current, merged)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["action"], "set")
        self.assertEqual(main.ET.fromstring(changes[0]["element"]).text.strip(), "Forge description")

    def test_legacy_workspace_without_candidate_baseline_cannot_push_stale_policy_fields(self):
        stale = main.normalized_config_xml(main.ET.fromstring(
            b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<rulebase><security><rules><entry name="Salto toegang">'
            b'<description>Forge description</description><source><member>any</member>'
            b'<member>Old-address-object</member></source></entry></rules></security></rulebase>'
            b'</entry></vsys></entry></devices></config>'
        ))
        workspace_id = main.store_config_workspace(
            self.profile, "legacy candidate workspace", "candidate.xml", stale, "edit",
        )
        self.extra_workspace_ids.append(workspace_id)

        with patch("app.main.fetch_panos_candidate_xml_for_preview") as fetch_candidate:
            preview = self.client.get(
                f"/config-workspaces/{workspace_id}/push-preview",
                base_url="https://forge.test", follow_redirects=True,
            )

        message = "geen oorspronkelijke candidate-snapshot"
        self.assertIn(message, preview.get_data(as_text=True))
        fetch_candidate.assert_not_called()

        with patch("app.main.fetch_panos_candidate_xml") as fetch_candidate, \
             patch("app.main.panos_api_post") as api_post:
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push",
                base_url="https://forge.test", follow_redirects=True,
                data={
                    "csrf": "incremental-commit-csrf",
                    "candidate_sha256": "ignored-without-baseline",
                    "family": '["vsys1","policy:security"]',
                },
            )

        self.assertIn(message, response.get_data(as_text=True))
        fetch_candidate.assert_not_called()
        api_post.assert_not_called()

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

    def test_deleted_object_is_rechecked_against_references_added_after_workspace_pull(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<address><entry name="late-reference"><ip-netmask>192.0.2.99/32</ip-netmask></entry></address>'
            b'</entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find(".//address/entry[@name='late-reference']").clear()
        desired_root.find(".//address").remove(desired_root.find(".//address/entry"))
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "object delete rebase", "candidate.xml", desired, "api", baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        current_root = main.ET.fromstring(base)
        rulebase = main.ET.SubElement(current_root.find(".//vsys/entry"), "rulebase")
        security = main.ET.SubElement(rulebase, "security")
        rules = main.ET.SubElement(security, "rules")
        rule = main.ET.SubElement(rules, "entry", {"name": "colleague-rule"})
        source = main.ET.SubElement(rule, "source")
        main.ET.SubElement(source, "member").text = "late-reference"
        current = main.normalized_config_xml(current_root)
        selected = next(
            item for item in main.config_push_delta(current, desired)
            if item["family"] == "object:address" and item["action"] == "delete"
        )

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), current)), \
             patch("app.main.panos_api_post") as api_post:
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push",
                base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": selected["selection_key"]},
                follow_redirects=True,
            )

        self.assertIn("objecten zijn nog in gebruik", response.get_data(as_text=True))
        api_post.assert_not_called()

    def test_delete_referenced_by_shared_address_group_is_blocked_before_any_write(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared><address><entry name="10.10.120.100"><ip-netmask>10.10.120.100/32</ip-netmask>'
            b'</entry><entry name="10.10.120.102"><ip-netmask>10.10.120.102/32</ip-netmask></entry></address>'
            b'<address-group><entry name="Servers_HTTP_HTTPS"><static><member>10.10.120.100</member>'
            b'<member>10.10.120.102</member></static></entry></address-group></shared>'
            b'<devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find("./shared/address").clear()
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "shared group references block delete", "candidate.xml", desired,
            "api", baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        deletion = next(
            item for item in main.config_push_delta(base, desired)
            if item["action"] == "delete" and item["family"] == "object:address"
        )

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post") as api_post:
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": deletion["selection_key"]},
                follow_redirects=True,
            )

        message = response.get_data(as_text=True)
        self.assertIn("objecten zijn nog in gebruik", message)
        self.assertIn("Servers_HTTP_HTTPS", message)
        self.assertIn("10.10.120.100", message)
        api_post.assert_not_called()

    def test_delete_with_reference_removal_requires_policy_family_selection(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<address><entry name="delete-me"><ip-netmask>192.0.2.99/32</ip-netmask></entry></address>'
            b'<rulebase><security><rules><entry name="allow-delete-me"><source><member>delete-me</member>'
            b'</source></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find(".//address/entry[@name='delete-me']").clear()
        desired_root.find(".//address").remove(desired_root.find(".//address/entry"))
        desired_root.find(".//rules").clear()
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "delete with dependent reference change", "candidate.xml", desired,
            "api", baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        changes = main.config_push_delta(base, desired)
        object_delete = next(item for item in changes if item["family"] == "object:address")
        self.assertTrue(any(item["family"] == "policy:security" for item in changes))

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post") as api_post:
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": object_delete["selection_key"]},
                follow_redirects=True,
            )

        message = response.get_data(as_text=True)
        self.assertIn("selecteer Security policies", message)
        api_post.assert_not_called()

    def test_native_multi_move_preserves_references_when_moving_vsys_object_to_shared(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<address><entry name="A_first"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
            b'<entry name="0_NAC_10_10_130_0_24"><ip-netmask>10.10.130.0/24</ip-netmask>'
            b'</entry></address><rulebase><security><rules><entry name="Migrated sites to Untrust">'
            b'<source><member>0_NAC_10_10_130_0_24</member></source></entry></rules></security></rulebase>'
            b'</entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        local_collection = desired_root.find("./devices/entry/vsys/entry/address")
        for local_entry in list(local_collection):
            local_collection.remove(local_entry)
        shared = desired_root.find("./shared")
        address = main.ET.SubElement(shared, "address")
        first_shared_entry = main.ET.SubElement(address, "entry", {"name": "A_first"})
        main.ET.SubElement(first_shared_entry, "ip-netmask").text = "192.0.2.1/32"
        shared_entry = main.ET.SubElement(address, "entry", {"name": "0_NAC_10_10_130_0_24"})
        main.ET.SubElement(shared_entry, "ip-netmask").text = "10.10.130.0/24"
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "merge object into Shared", "candidate.xml", desired, "api", baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        changes = main.config_push_delta(base, desired)
        selected = list(dict.fromkeys(item["selection_key"] for item in changes))
        self.assertEqual({item["action"] for item in changes}, {"set", "delete"})
        shared_addition = next(item for item in changes if item["action"] == "set" and item["scope"] == "Shared")
        self.assertEqual(shared_addition["name"], "A_first")
        self.assertIn("0_NAC_10_10_130_0_24", main.config_push_change_names(shared_addition))

        def api_response(endpoint, params, ctx):
            if params["type"] == "config":
                return '<response status="success" code="20"><result/></response>'
            if params["type"] == "op":
                return '<response status="success"><result><job>606</job></result></response>'
            self.fail(f"Unexpected PAN-OS request type: {params['type']}")

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post", side_effect=api_response) as api_post, \
             patch("app.main.wait_panos_job", return_value={"status": "FIN", "result": "OK", "details": []}):
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": selected}, follow_redirects=True,
            )

        self.assertIn("naar de candidate geschreven en gevalideerd", response.get_data(as_text=True))
        config_calls = [call.args[1] for call in api_post.call_args_list if call.args[1]["type"] == "config"]
        self.assertEqual(len(config_calls), 2)
        self.assertEqual({call["action"] for call in config_calls}, {"multi-move"})
        moved_names = {
            node.text for call in config_calls
            for node in main.ET.fromstring(f"<fragment>{call['element']}</fragment>").findall("./selected-list/source/member")
        }
        self.assertEqual(moved_names, {"A_first", "0_NAC_10_10_130_0_24"})
        for call in config_calls:
            fragment = main.ET.fromstring(f"<fragment>{call['element']}</fragment>")
            self.assertEqual(fragment.findtext("./all-errors"), "no")

    def test_native_move_then_edit_handles_changed_object_without_delete(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<address><entry name="move-me"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address>'
            b'<rulebase><security><rules><entry name="uses-move-me"><source><member>move-me</member>'
            b'</source></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        local = desired_root.find("./devices/entry/vsys/entry[@name='vsys1']/address")
        entry = local.find("./entry[@name='move-me']")
        local.remove(entry)
        entry.find("./ip-netmask").text = "192.0.2.2/32"
        main.ET.SubElement(desired_root.find("./shared"), "address").append(entry)
        desired = main.normalized_config_xml(desired_root)
        chosen = main.config_push_delta(base, desired)

        plan, moved = main.panos_scope_move_plan(
            base, desired, chosen, {node: kind for kind, node in main.OBJECT_NODES.items()},
        )

        self.assertEqual([item["action"] for item in plan], ["multi-move", "edit"])
        self.assertEqual(moved, {("addresses", "move-me")})
        self.assertTrue(plan[1]["xpath"].endswith("/address/entry[@name='move-me']"))
        self.assertIn("192.0.2.2/32", plan[1]["element"])
        self.assertEqual(
            main.ET.fromstring(f"<fragment>{plan[0]['element']}</fragment>").findtext("./all-errors"),
            "no",
        )

    def test_native_multi_move_preserves_vsys2_policy_references_to_shared(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared/><devices><entry name="localhost.localdomain"><vsys>'
            b'<entry name="vsys1"><address/></entry><entry name="vsys2">'
            b'<address><entry name="aaa-first"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
            b'<entry name="XIQ-NL-GCP"><ip-netmask>198.51.100.45/32</ip-netmask></entry></address>'
            b'<rulebase><security><rules><entry name="Explore-Access Points-to-XIQ-RadSec">'
            b'<destination><member>XIQ-NL-GCP</member></destination></entry></rules></security></rulebase>'
            b'</entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        local_collection = desired_root.find("./devices/entry/vsys/entry[@name='vsys2']/address")
        local_entries = list(local_collection)
        for local_entry in local_entries:
            local_collection.remove(local_entry)
        shared_collection = main.ET.SubElement(desired_root.find("./shared"), "address")
        for local_entry in local_entries:
            shared_collection.append(local_entry)
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "move vsys2 destination object to Shared", "candidate.xml", desired, "api", baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        changes = main.config_push_delta(base, desired)
        selected = list(dict.fromkeys(item["selection_key"] for item in changes))
        shared_addition = next(item for item in changes if item["action"] == "set" and item["scope"] == "Shared")
        self.assertIn("XIQ-NL-GCP", main.config_push_change_names(shared_addition))

        def api_response(endpoint, params, ctx):
            if params["type"] == "config":
                return '<response status="success" code="20"><result/></response>'
            if params["type"] == "op":
                return '<response status="success"><result><job>607</job></result></response>'
            self.fail(f"Unexpected PAN-OS request type: {params['type']}")

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post", side_effect=api_response) as api_post, \
             patch("app.main.wait_panos_job", return_value={"status": "FIN", "result": "OK", "details": []}):
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": selected}, follow_redirects=True,
            )

        self.assertIn("naar de candidate geschreven en gevalideerd", response.get_data(as_text=True))
        config_calls = [call.args[1] for call in api_post.call_args_list if call.args[1]["type"] == "config"]
        self.assertEqual(len(config_calls), 2)
        self.assertEqual({call["action"] for call in config_calls}, {"multi-move"})
        self.assertIn("XIQ-NL-GCP", {
            node.text for call in config_calls
            for node in main.ET.fromstring(f"<fragment>{call['element']}</fragment>").findall("./selected-list/source/member")
        })

    def test_native_multi_move_can_add_new_reference_in_another_vsys(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared/><devices><entry name="localhost.localdomain"><vsys>'
            b'<entry name="vsys1"><address><entry name="XIQ-NL-GCP">'
            b'<ip-netmask>198.51.100.45/32</ip-netmask></entry></address>'
            b'<rulebase><security><rules><entry name="Existing XIQ rule">'
            b'<destination><member>XIQ-NL-GCP</member></destination></entry></rules></security></rulebase>'
            b'</entry><entry name="vsys2"><address/><rulebase><security><rules/>'
            b'</security></rulebase></entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        local_collection = desired_root.find("./devices/entry/vsys/entry[@name='vsys1']/address")
        moved_object = local_collection.find("./entry[@name='XIQ-NL-GCP']")
        local_collection.remove(moved_object)
        shared_collection = main.ET.SubElement(desired_root.find("./shared"), "address")
        shared_collection.append(moved_object)
        vsys2_rules = desired_root.find("./devices/entry/vsys/entry[@name='vsys2']/rulebase/security/rules")
        new_rule = main.ET.SubElement(vsys2_rules, "entry", {"name": "Explore-Access Points-to-XIQ-RadSec"})
        main.ET.SubElement(main.ET.SubElement(new_rule, "destination"), "member").text = "XIQ-NL-GCP"
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "move object to Shared and add VSYS2 reference", "candidate.xml", desired, "api",
            baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        selected = list(dict.fromkeys(
            item["selection_key"] for item in main.config_push_delta(base, desired)
        ))

        def api_response(endpoint, params, ctx):
            if params["type"] == "config":
                return '<response status="success" code="20"><result/></response>'
            if params["type"] == "op":
                return '<response status="success"><result><job>609</job></result></response>'
            self.fail(f"Unexpected PAN-OS request type: {params['type']}")

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post", side_effect=api_response) as api_post, \
             patch("app.main.wait_panos_job", return_value={"status": "FIN", "result": "OK", "details": []}):
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": selected}, follow_redirects=True,
            )

        self.assertIn("naar de candidate geschreven en gevalideerd", response.get_data(as_text=True))
        config_calls = [call.args[1] for call in api_post.call_args_list if call.args[1]["type"] == "config"]
        self.assertEqual({call["action"] for call in config_calls}, {"multi-move", "set"})
        move_call = next(call for call in config_calls if call["action"] == "multi-move")
        self.assertIn("XIQ-NL-GCP", [
            node.text for node in main.ET.fromstring(f"<fragment>{move_call['element']}</fragment>").findall("./selected-list/source/member")
        ])

    def create_existing_shared_object_move_workspace(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared><address><entry name="XIQ-NL-GCP"><ip-netmask>198.51.100.44/32</ip-netmask>'
            b'</entry></address></shared><devices><entry name="localhost.localdomain"><vsys>'
            b'<entry name="vsys1"><address/></entry><entry name="vsys2">'
            b'<address><entry name="XIQ-NL-GCP"><ip-netmask>198.51.100.45/32</ip-netmask></entry></address>'
            b'<rulebase><security><rules><entry name="Explore-Access Points-to-XIQ-RadSec">'
            b'<destination><member>XIQ-NL-GCP</member></destination></entry></rules></security></rulebase>'
            b'</entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find("./devices/entry/vsys/entry[@name='vsys2']/address").clear()
        desired_root.find("./shared/address/entry[@name='XIQ-NL-GCP']/ip-netmask").text = "198.51.100.45/32"
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "move existing Shared object", "candidate.xml", desired, "api", baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        changes = main.config_push_delta(base, desired)
        removal = next(item for item in changes if item["action"] == "delete" and item["family"] == "object:address")
        shared_edit = next(item for item in changes if item["action"] == "edit" and item["scope"] == "Shared")
        self.assertEqual(shared_edit["name"], "XIQ-NL-GCP")
        return workspace_id, base, removal, shared_edit

    def test_shared_edit_is_paired_with_vsys_delete_when_only_one_scope_selected(self):
        workspace_id, base, removal, _ = self.create_existing_shared_object_move_workspace()
        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post") as api_post:
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": removal["selection_key"]},
                follow_redirects=True,
            )

        self.assertIn("Verplaatsing van XIQ-NL-GCP vereist zowel de bron- als doelscope", response.get_data(as_text=True))
        api_post.assert_not_called()

    def test_shared_move_with_live_policy_reference_is_blocked_before_any_write(self):
        workspace_id, base, removal, shared_edit = self.create_existing_shared_object_move_workspace()

        def api_response(endpoint, params, ctx):
            if params["type"] == "config":
                return '<response status="success" code="20"><result/></response>'
            if params["type"] == "op":
                return '<response status="success"><result><job>608</job></result></response>'
            self.fail(f"Unexpected PAN-OS request type: {params['type']}")

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post", side_effect=api_response) as api_post, \
             patch("app.main.wait_panos_job", return_value={"status": "FIN", "result": "OK", "details": []}):
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": [removal["selection_key"], shared_edit["selection_key"]]},
                follow_redirects=True,
            )

        message = response.get_data(as_text=True)
        self.assertIn("objecten zijn nog in gebruik", message)
        self.assertIn("Explore-Access Points-to-XIQ-RadSec", message)
        api_post.assert_not_called()

    def test_same_name_shared_merge_rehomes_local_references_before_delete(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared><address><entry name="0_NAC_10_10_130_0_24">'
            b'<ip-netmask>10.10.130.0/24</ip-netmask></entry></address></shared>'
            b'<devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<address><entry name="0_NAC_10_10_130_0_24"><ip-netmask>10.10.130.0/24</ip-netmask>'
            b'</entry></address><rulebase><security><rules><entry name="Migrated sites to Untrust">'
            b'<source><member>0_NAC_10_10_130_0_24</member></source>'
            b'</entry></rules></security></rulebase></entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find("./devices/entry/vsys/entry[@name='vsys1']/address").clear()
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "merge same-name object into Shared", "candidate.xml", desired, "api",
            baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        deletion = next(item for item in main.config_push_delta(base, desired) if item["action"] == "delete")
        requests = []

        def api_response(endpoint, params, ctx):
            requests.append(dict(params))
            if params["type"] == "config":
                if params["action"] == "multi-config":
                    return (
                        '<response status="success" code="20"><result>'
                        '<response status="success" code="20" id="1"/>'
                        '<response status="success" code="20" id="2"/>'
                        '<response status="success" code="20" id="3"/>'
                        '</result></response>'
                    )
                return '<response status="success" code="20"><result/></response>'
            if params["type"] == "op":
                return '<response status="success"><result><job>610</job></result></response>'
            self.fail(f"Unexpected PAN-OS request type: {params['type']}")

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post", side_effect=api_response), \
             patch("app.main.wait_panos_job", return_value={"status": "FIN", "result": "OK", "details": []}):
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": deletion["selection_key"]},
                follow_redirects=True,
            )

        self.assertIn("naar de candidate geschreven en gevalideerd", response.get_data(as_text=True))
        config_calls = [item for item in requests if item["type"] == "config"]
        self.assertEqual(len(config_calls), 1)
        self.assertEqual(config_calls[0]["action"], "multi-config")
        self.assertEqual(config_calls[0]["strict-transactional"], "no")
        transaction = main.ET.fromstring(config_calls[0]["element"])
        self.assertEqual([item.tag for item in transaction], ["rename", "edit", "delete"])
        self.assertTrue(transaction[0].get("newname").startswith("PF_TMP_"))
        self.assertTrue(transaction[0].get("xpath").endswith("/entry[@name='0_NAC_10_10_130_0_24']"))
        self.assertTrue(transaction[1].get("xpath").endswith("/source"))
        self.assertIn("0_NAC_10_10_130_0_24", main.ET.tostring(transaction[1], encoding="unicode"))
        self.assertIn("PF_TMP_", transaction[2].get("xpath"))

    def test_same_name_shared_merge_stops_on_nested_transaction_error(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared><address><entry name="same-object"><ip-netmask>192.0.2.10/32</ip-netmask>'
            b'</entry></address></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<address><entry name="same-object"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address>'
            b'<rulebase><security><rules><entry name="allow"><source><member>same-object</member></source>'
            b'</entry></rules></security></rulebase></entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find("./devices/entry/vsys/entry[@name='vsys1']/address").clear()
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "transaction error rolls back Shared merge", "candidate.xml", desired, "api",
            baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        deletion = next(item for item in main.config_push_delta(base, desired) if item["action"] == "delete")
        requests = []

        def api_response(endpoint, params, ctx):
            requests.append(dict(params))
            return (
                '<response status="success" code="20">'
                '<response status="error" code="10"><msg>Object is still referenced</msg></response>'
                '</response>'
            )

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post", side_effect=api_response), \
             patch("app.main.wait_panos_job") as wait_job:
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": deletion["selection_key"]},
                follow_redirects=True,
            )

        message = response.get_data(as_text=True)
        self.assertIn("Shared object merge", message)
        self.assertIn("kan dit object niet verwijderen zolang er verwijzingen naar bestaan", message)
        self.assertEqual([item.get("action") for item in requests], ["multi-config"])
        wait_job.assert_not_called()

    def test_same_name_shared_merge_supports_panorama_device_group_scope(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared><address><entry name="same-object"><ip-netmask>192.0.2.10/32</ip-netmask>'
            b'</entry></address></shared><devices><entry name="localhost.localdomain"><device-group>'
            b'<entry name="DG-A"><address><entry name="same-object"><ip-netmask>192.0.2.10/32</ip-netmask>'
            b'</entry></address><pre-rulebase><security><rules><entry name="allow"><source>'
            b'<member>same-object</member></source></entry></rules></security></pre-rulebase>'
            b'</entry></device-group></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find("./devices/entry/device-group/entry[@name='DG-A']/address").clear()
        desired = main.normalized_config_xml(desired_root)
        deletion = next(item for item in main.config_push_delta(base, desired) if item["action"] == "delete")

        plan, moved = main.panos_scope_move_plan(
            base, desired, [deletion], {node: kind for kind, node in main.OBJECT_NODES.items()},
        )

        self.assertEqual([item["action"] for item in plan], ["multi-config"])
        self.assertEqual(moved, {("addresses", "same-object")})

    def test_multiple_shared_merges_parse_each_config_once_per_object_type(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared><address>'
            b'<entry name="object-a"><ip-netmask>192.0.2.10/32</ip-netmask></entry>'
            b'<entry name="object-b"><ip-netmask>192.0.2.20/32</ip-netmask></entry>'
            b'</address></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<address><entry name="object-a"><ip-netmask>192.0.2.10/32</ip-netmask></entry>'
            b'<entry name="object-b"><ip-netmask>192.0.2.20/32</ip-netmask></entry></address>'
            b'<rulebase><security><rules><entry name="allow-a"><source><member>object-a</member>'
            b'</source></entry><entry name="allow-b"><source><member>object-b</member></source>'
            b'</entry></rules></security></rulebase></entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        local_addresses = desired_root.find("./devices/entry/vsys/entry/address")
        for local_entry in list(local_addresses):
            local_addresses.remove(local_entry)
        desired = main.normalized_config_xml(desired_root)
        deletions = [
            item for item in main.config_push_delta(base, desired)
            if item["action"] == "delete" and item["family"] == "object:address"
        ]

        with patch("app.main.parse_snapshot", wraps=main.parse_snapshot) as parse_config:
            plan, moved = main.panos_scope_move_plan(
                base, desired, deletions,
                {node: kind for kind, node in main.OBJECT_NODES.items()},
            )

        self.assertEqual([item["action"] for item in plan], ["multi-config"])
        self.assertEqual(moved, {("addresses", "object-a"), ("addresses", "object-b")})
        self.assertEqual(parse_config.call_count, 2)

    def test_same_name_shared_merge_blocks_panorama_parent_scope_shadow(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared><address><entry name="same-object"><ip-netmask>192.0.2.10/32</ip-netmask>'
            b'</entry></address></shared><devices><entry name="localhost.localdomain"><device-group>'
            b'<entry name="DG-P"><address><entry name="same-object"><ip-netmask>198.51.100.10/32</ip-netmask>'
            b'</entry></address></entry><entry name="DG-A"><parent-dg>DG-P</parent-dg><address>'
            b'<entry name="same-object"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address>'
            b'<pre-rulebase><security><rules><entry name="allow"><source><member>same-object</member>'
            b'</source></entry></rules></security></pre-rulebase></entry></device-group></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find("./devices/entry/device-group/entry[@name='DG-A']/address").clear()
        desired = main.normalized_config_xml(desired_root)
        deletion = next(item for item in main.config_push_delta(base, desired) if item["action"] == "delete")

        plan, moved = main.panos_scope_move_plan(
            base, desired, [deletion], {node: kind for kind, node in main.OBJECT_NODES.items()},
        )

        self.assertEqual([item["action"] for item in plan], ["delete"])
        self.assertEqual(moved, set())

    def test_shared_fallback_is_not_accepted_when_its_addition_is_not_selected(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<address><entry name="aaa-first"><ip-netmask>192.0.2.9/32</ip-netmask></entry>'
            b'<entry name="same-name"><ip-netmask>192.0.2.8/32</ip-netmask></entry></address>'
            b'<rulebase><security><rules><entry name="allow"><destination><member>same-name</member>'
            b'</destination></entry></rules></security></rulebase>'
            b'</entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        local_collection = desired_root.find("./devices/entry/vsys/entry/address")
        for local_entry in list(local_collection):
            local_collection.remove(local_entry)
        shared_address = main.ET.SubElement(desired_root.find("./shared"), "address")
        first_entry = main.ET.SubElement(shared_address, "entry", {"name": "aaa-first"})
        main.ET.SubElement(first_entry, "ip-netmask").text = "192.0.2.9/32"
        entry = main.ET.SubElement(shared_address, "entry", {"name": "same-name"})
        main.ET.SubElement(entry, "ip-netmask").text = "192.0.2.8/32"
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "incomplete Shared move", "candidate.xml", desired, "api", baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        removal = next(
            item for item in main.config_push_delta(base, desired)
            if item["action"] == "delete" and item["family"] == "object:address"
        )

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post") as api_post:
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": removal["selection_key"]},
                follow_redirects=True,
            )

        self.assertIn("vereist zowel de bron- als doelscope", response.get_data(as_text=True))
        api_post.assert_not_called()

    def test_shared_fallback_with_different_object_behavior_still_blocks_deletion(self):
        base = main.normalized_config_xml(main.ET.fromstring(
            b'<config><shared><address><entry name="same-name"><ip-netmask>192.0.2.10/32</ip-netmask>'
            b'</entry></address></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
            b'<address><entry name="same-name"><ip-netmask>192.0.2.8/32</ip-netmask></entry></address>'
            b'<rulebase><security><rules><entry name="allow"><source><member>same-name</member>'
            b'</source></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'
        ))
        desired_root = main.ET.fromstring(base)
        desired_root.find("./devices/entry/vsys/entry/address").remove(
            desired_root.find("./devices/entry/vsys/entry/address/entry")
        )
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "unsafe different Shared fallback", "candidate.xml", desired, "api", baseline_xml=base,
        )
        self.extra_workspace_ids.append(workspace_id)
        removal = next(
            item for item in main.config_push_delta(base, desired)
            if item["action"] == "delete" and item["family"] == "object:address"
        )

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), base)), \
             patch("app.main.panos_api_post") as api_post:
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push", base_url="https://forge.test",
                data={"csrf": "incremental-commit-csrf", "family": removal["selection_key"]},
                follow_redirects=True,
            )

        self.assertIn("objecten zijn nog in gebruik", response.get_data(as_text=True))
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
        desired_root = main.ET.fromstring(candidate)
        desired_root.remove(desired_root.find("mgt-config"))
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "protected-only test", "candidate.xml", desired, "test",
            baseline_xml=candidate,
        )
        self.extra_workspace_ids.append(workspace_id)

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), candidate)):
            response = self.client.get(
                f"/config-workspaces/{workspace_id}/push-preview",
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
        desired_root = main.ET.fromstring(candidate)
        desired_root.remove(desired_root.find("mgt-config"))
        desired = main.normalized_config_xml(desired_root)
        workspace_id = main.store_config_workspace(
            self.profile, "protected-only test", "candidate.xml", desired, "test",
            baseline_xml=candidate,
        )
        self.extra_workspace_ids.append(workspace_id)

        with patch("app.main.fetch_panos_candidate_xml", return_value=("https://fw.example.invalid", "test-key", object(), candidate)):
            response = self.client.post(
                f"/config-workspaces/{workspace_id}/push",
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
