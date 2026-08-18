import json
import io
import os
import pathlib
import tempfile
import time
import unittest
import re
from types import SimpleNamespace
from html.parser import HTMLParser
from urllib.parse import urlsplit
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-adapter-test-"))
os.environ.setdefault("PPF_SYSLOG_PORT", "55141")
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "unit-test-bootstrap-password")

from app import main


class NavigationTargets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.actions = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(values["id"])
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
        if tag == "form" and values.get("action"):
            self.actions.append(values["action"])


class TargetAdapterTests(unittest.TestCase):
    def profile(self, target, **settings):
        defaults = {"device_group": "Branches", "rulebase": "pre", "vsys": "vsys2", "endpoint": "https://example.invalid"}
        defaults.update(settings)
        return {"target_type": target, "settings_json": json.dumps(defaults), "secret_blob": b""}

    def test_log_forwarding_payload_has_panos_fields_and_reference_guards(self):
        matches = [{
            "name": "traffic", "action_desc": "All traffic", "log_type": "traffic",
            "filter": "", "send_syslog": ["siem"], "send_email": [],
            "send_snmptrap": [], "send_http": [], "send_to_panorama": True,
            "quarantine": False, "actions": [{
                "name": "tag-source", "type": "tagging", "action": "add-tag",
                "target": "source-address", "registration": "localhost",
                "timeout": "60", "tags": ["investigate"],
            }],
        }]
        payload = main.scm_object_payload("log-forwarding", {
            "name": "forward-all", "description": "SIEM",
            "enhanced_application_logging": "on", "match_list_json": json.dumps(matches),
        }, {})
        self.assertTrue(payload["enhanced_application_logging"])
        self.assertEqual(payload["match_list"][0]["send_syslog"], ["siem"])
        xml = main.object_payload_xml(payload)
        self.assertIn('<entry name="forward-all">', xml)
        self.assertIn('<send-syslog><member>siem</member></send-syslog>', xml)
        self.assertIn('<actions><entry name="tag-source"><type><tagging>', xml)
        catalog = [
            {"name": "siem", "kind": "syslog-server-profiles"},
            {"name": "investigate", "kind": "tags"},
        ]
        main.validate_object_references(payload, "log-forwarding", catalog)
        with self.assertRaisesRegex(ValueError, "niet-bestaande"):
            main.validate_object_references(payload, "log-forwarding", [])

    def test_policy_reference_validation_rejects_unknown_and_multiple_scalar_values(self):
        catalog = [{"name": "forward-all", "kind": "log-forwarding"}]
        policy = {"log_setting": "forward-all"}
        main.validate_policy_references(policy, catalog, {"log_setting"})
        with self.assertRaisesRegex(ValueError, "niet-bestaande"):
            main.validate_policy_references({"log_setting": "missing"}, catalog, {"log_setting"})
        with self.assertRaisesRegex(ValueError, "maximaal één"):
            main.validate_policy_references({"log_setting": "one,two"}, catalog, {"log_setting"})

    def test_nat_and_zone_reference_fields_require_existing_objects(self):
        catalog = [
            {"name": "ethernet1/1", "kind": "interfaces"},
            {"name": "public-nat", "kind": "addresses"},
            {"name": "strict", "kind": "zone-protection-profiles"},
            {"name": "forward-all", "kind": "log-forwarding"},
        ]
        main.validate_policy_references({
            "to_interface": "ethernet1/1", "source_translation_address": "public-nat",
        }, catalog, {"to_interface", "source_translation_address"})
        main.validate_object_references({
            "name": "Internet", "network": {"layer3": ["ethernet1/1"]},
            "zone_protection_profile": "strict", "log_setting": "forward-all",
        }, "zones", catalog)
        with self.assertRaisesRegex(ValueError, "Maak deze eerst aan"):
            main.validate_policy_references(
                {"destination_translation_address": "missing"}, catalog,
                {"destination_translation_address"},
            )
        with self.assertRaisesRegex(ValueError, "Interfaces"):
            main.validate_object_references(
                {"name": "Internet", "network": {"layer3": ["ethernet1/9"]}},
                "zones", catalog,
            )

    def test_panos_interface_reference_catalog_includes_physical_and_subinterfaces(self):
        response = """<response status='success'><result><interface><ethernet>
        <entry name='ethernet1/1'><layer3><units><entry name='ethernet1/1.100'/></units></layer3></entry>
        </ethernet><loopback><units><entry name='loopback.1'/></units></loopback></interface></result></response>"""
        with patch("app.main.panos_object_bases", return_value=["/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys2']"]), patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.policy_api.api_get", return_value=response):
            names = {item["name"] for item in main.fetch_network_reference_catalog(self.profile("panos"), "interfaces")}
        self.assertEqual(names, {"ethernet1/1", "ethernet1/1.100", "loopback.1"})

    def test_policy_and_object_reference_editors_are_picker_backed(self):
        app_template = (pathlib.Path(__file__).parents[1] / "app/templates/app.html").read_text()
        workspace_template = (pathlib.Path(__file__).parents[1] / "app/templates/workspace_editor.html").read_text()
        javascript = (pathlib.Path(__file__).parents[1] / "app/static/app.js").read_text()
        self.assertIn('data-picker-cardinality="one"', app_template)
        self.assertIn('data-log-actions-supported', app_template)
        self.assertIn('data-log-actions-supported', workspace_template)
        self.assertIn('data-object-tag-entry placeholder="Klik om bestaande tags te kiezen"', app_template)
        self.assertIn('data-zone-reference-kind="interfaces"', app_template)
        self.assertIn('data-zone-reference-kind="zone-protection-profiles"', app_template)
        self.assertIn('data-zone-reference-kind="log-forwarding"', app_template)
        self.assertIn('function prepareBulkScalars()', javascript)
        self.assertIn('Geen bestaande compatibele waarde gevonden.', javascript)

    def test_panorama_policy_xpath_uses_device_group_and_pre_rulebase(self):
        xpath = main.panos_policy_xpath(self.profile("panorama"), "nat")
        self.assertIn("device-group/entry[@name='Branches']/pre-rulebase/nat/rules", xpath)

    def test_profile_without_firewall_serial_has_no_flow_identity(self):
        profile = {"serial": "", "settings_json": json.dumps({"passive_serial": ""})}
        self.assertEqual(main.profile_serials(profile), [])

    def test_security_headers_and_cookie_flags_are_present(self):
        response = main.app.test_client().get("/login", base_url="https://forge.test")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Secure", response.headers["Set-Cookie"])
        self.assertIn("HttpOnly", response.headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", response.headers["Set-Cookie"])
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["Strict-Transport-Security"], "max-age=31536000")

    def test_login_rate_limit_blocks_repeated_failures(self):
        client, username = "192.0.2.99", "rate-limit-test"
        main.clear_login_failures(client, username)
        for _ in range(main.LOGIN_MAX_FAILURES - 1):
            self.assertFalse(main.login_rate_limited(client, username, record_failure=True))
        self.assertTrue(main.login_rate_limited(client, username, record_failure=True))
        main.clear_login_failures(client, username)

    def test_login_rate_limit_also_blocks_username_spraying(self):
        client = "192.0.2.100"
        main.clear_login_failures(client, "unused")
        for index in range(main.LOGIN_MAX_FAILURES - 1):
            self.assertFalse(main.login_rate_limited(client, f"user-{index}", record_failure=True))
        self.assertTrue(main.login_rate_limited(client, "last-user", record_failure=True))
        main.clear_login_failures(client, "last-user")

    def test_failed_application_catalog_refresh_has_retry_backoff(self):
        profile = {"id": 987654, "target_type": "panos"}
        cache_path = main.application_cache_path(profile["id"])
        key = (profile["id"], "applications")
        with main._catalog_refresh_lock:
            main._catalog_errors.pop(key, None)
            main._catalog_retry_after.pop(key, None)
            main._catalog_refreshing.discard(key)
        try:
            with patch.object(main, "fetch_application_objects", side_effect=RuntimeError("offline")) as fetch:
                main.refresh_catalog_async(profile, "applications", cache_path)
                for _ in range(100):
                    with main._catalog_refresh_lock:
                        finished = key not in main._catalog_refreshing
                    if finished: break
                    time.sleep(0.01)
                main.refresh_catalog_async(profile, "applications", cache_path)
                time.sleep(0.02)
                self.assertEqual(fetch.call_count, 1)
        finally:
            with main._catalog_refresh_lock:
                main._catalog_errors.pop(key, None)
                main._catalog_retry_after.pop(key, None)
                main._catalog_refreshing.discard(key)
            cache_path.unlink(missing_ok=True)

    def test_panos_endpoint_requires_clean_https_origin(self):
        self.assertEqual(main.validate_panos_endpoint("https://192.0.2.1/"), "https://192.0.2.1")
        for value in ("http://192.0.2.1", "file:///etc/passwd", "https://user:pass@192.0.2.1", "https://192.0.2.1/api", "https://192.0.2.1/?x=1"):
            with self.assertRaises(ValueError): main.validate_panos_endpoint(value)

    def test_profile_security_enums_and_ip_validation(self):
        self.assertEqual(main.optional_ip_address(" 192.0.2.10 "), "192.0.2.10")
        self.assertEqual(main.optional_ip_address("2001:0db8::1"), "2001:db8::1")
        self.assertEqual(main.optional_ip_address(""), "")
        with self.assertRaises(ValueError): main.optional_ip_address("not-an-ip")
        self.assertEqual(main.TARGET_TYPES, {"scm", "panorama", "panos"})

    def test_known_distribution_passwords_are_blocked_on_change(self):
        self.assertTrue(main.password_is_blocked("OCD1234!"))
        self.assertTrue(main.password_is_blocked("admin"))
        self.assertFalse(main.password_is_blocked("a-different-strong-password"))

    def test_trusted_host_rejects_host_header_injection(self):
        previous = main.app.config.get("TRUSTED_HOSTS")
        main.app.config["TRUSTED_HOSTS"] = ["forge.test"]
        try:
            response = main.app.test_client().get("/login", base_url="https://attacker.invalid")
            self.assertEqual(response.status_code, 400)
        finally:
            main.app.config["TRUSTED_HOSTS"] = previous

    def test_missing_csrf_is_rejected(self):
        response = main.app.test_client().post("/login", data={"username": "admin", "password": "not-used"}, base_url="https://forge.test")
        self.assertEqual(response.status_code, 400)

    def test_authenticated_certificate_upload_activates_validated_bundle(self):
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "admin"
            login["csrf"] = "certificate-csrf"
        result = {
            "fqdn": "forge.customer.example",
            "fingerprint": "AA11",
        }
        previous_hosts = main.app.config.get("TRUSTED_HOSTS")
        main.app.config["TRUSTED_HOSTS"] = ["forge.test"]
        try:
            with patch.object(main, "install_certificate", return_value=result) as installer, patch.object(main, "schedule_tls_reload") as reload_tls:
                response = client.post(
                    "/settings/certificate",
                    base_url="https://forge.test",
                    content_type="multipart/form-data",
                    data={
                        "csrf": "certificate-csrf",
                        "fqdn": "forge.customer.example",
                        "certificate": (io.BytesIO(b"certificate-pem"), "fullchain.pem"),
                        "private_key": (io.BytesIO(b"private-key-pem"), "private.key"),
                    },
                )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["Location"], "/#settings")
            self.assertEqual(installer.call_args.args[2:], ("forge.customer.example", b"certificate-pem", b"private-key-pem"))
            reload_tls.assert_called_once_with()
            self.assertIn("forge.customer.example", main.app.config["TRUSTED_HOSTS"])
        finally:
            main.app.config["TRUSTED_HOSTS"] = previous_hosts

    def test_profile_names_are_html_escaped(self):
        payload = '<img src=x onerror="alert(1)">'
        stamp = main.now()
        with main.db() as conn:
            profile_id = int(conn.execute(
                "INSERT INTO profiles(name,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (payload, "scm", "{}", b"", stamp, stamp),
            ).lastrowid)
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "test"
            login["must_change"] = False
        try:
            page = client.get("/", base_url="https://forge.test").get_data(as_text=True)
            self.assertNotIn(payload, page)
            self.assertIn("&lt;img src=x onerror=", page)
        finally:
            with main.db() as conn:
                conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_protected_routes_require_authentication(self):
        client = main.app.test_client()
        for path in ("/", "/runs/1", "/runs/1/csv", "/profiles/1/catalog/applications", "/config-workspaces/1/export/xml", "/config-workspaces/1/push-preview", "/config-workspaces/1/edit"):
            response = client.get(path, base_url="https://forge.test")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["Location"], "/login")

    def test_default_login_is_not_forced_to_change_password(self):
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "admin"
            login["must_change"] = True
        response = client.get("/", base_url="https://forge.test")
        self.assertEqual(response.status_code, 200)

    def test_offline_workspace_templates_compile(self):
        main.app.jinja_env.get_template("app.html")
        main.app.jinja_env.get_template("workspace_push.html")
        main.app.jinja_env.get_template("workspace_object_preview.html")

    def test_internal_xml_fields_are_not_serialized_into_gui_records(self):
        record = {
            "name": "visible", "_xml": "<entry name='secret'/>", "_raw": {"hidden": True},
            "nested": [{"value": "shown", "_transport": "hidden"}],
        }
        public = main.public_ui_record(record)
        self.assertEqual(public, {"name": "visible", "nested": [{"value": "shown"}]})
        workspace_template = (main.BASE / "app" / "templates" / "workspace_editor.html").read_text()
        live_template = (main.BASE / "app" / "templates" / "app.html").read_text()
        self.assertIn("public_ui_record|tojson", workspace_template)
        self.assertIn("public_ui_record|tojson", live_template)

    def test_object_tags_and_members_share_multiselect_picker_controls(self):
        workspace_template = (main.BASE / "app" / "templates" / "workspace_editor.html").read_text()
        live_template = (main.BASE / "app" / "templates" / "app.html").read_text()
        javascript = (main.BASE / "app" / "static" / "app.js").read_text()
        for template in (workspace_template, live_template):
            self.assertIn("data-object-tag-values", template)
            self.assertIn("data-tag-picker-open", template)
            self.assertIn("data-object-picker-selected-count", template)
            self.assertIn("data-object-picker-add-selected", template)
        self.assertIn("objectPickerSelections", javascript)
        self.assertIn('openObjectPicker("tags")', javascript)
        self.assertIn("loadObjectApplications", javascript)
        self.assertIn("function parseTagTokens", javascript)
        self.assertIn("tagQuoteOpen", javascript)
        self.assertIn("objectValueAlreadyAssigned", javascript)
        self.assertIn("activeField._offlineValues.has", javascript)
        self.assertIn("pickerTarget._hasPickerValue", javascript)
        self.assertIn("data-single-tag-values", live_template)
        self.assertIn("data-single-tag-picker", live_template)
        self.assertNotIn('<label>Tags</label><input name="tags"', workspace_template)
        self.assertNotIn('<label>Tags</label><input name="tags"', live_template)
        for template in (workspace_template, live_template):
            self.assertRegex(template, re.compile(r"data-object-picker-add-selected.*data-member-results", re.S))
            self.assertRegex(template, re.compile(r"data-policy-picker-add-selected.*data-policy-picker-results", re.S))
        self.assertIn('row.addEventListener("click", toggleSelection)', javascript)

    def test_multivalue_controls_use_one_integrated_token_input(self):
        workspace_template = (main.BASE / "app" / "templates" / "workspace_editor.html").read_text()
        live_template = (main.BASE / "app" / "templates" / "app.html").read_text()
        javascript = (main.BASE / "app" / "static" / "app.js").read_text()
        css = (main.BASE / "app" / "static" / "app.css").read_text()
        for template in (workspace_template, live_template):
            self.assertIn('class="token-input"', template)
            self.assertIn('class="token-chip-list" data-object-tag-values', template)
            self.assertIn('class="token-chip-list" data-member-values', template)
            self.assertNotIn('class="policy-value-entry"', template)
            self.assertNotIn('class="member-editor"', template)
            self.assertNotIn('class="dynamic-filter-editor"', template)
        self.assertIn('class="token-chip-list" data-bulk-values', workspace_template)
        self.assertIn('class="token-chip-list" data-offline-policy-values', workspace_template)
        self.assertIn('class="token-chip-list" data-bulk-values', live_template)
        self.assertIn('class="token-chip-list" data-single-tag-values', live_template)
        self.assertIn('data-single-token-field="{{field}}"', live_template)
        self.assertIn('class="token-chip-list" data-single-token-values', live_template)
        self.assertIn('entry._addTokenValue = addSingleToken', javascript)
        self.assertIn('tokenInput.className = "token-input"', javascript)
        self.assertIn('.token-input:focus-within', css)

    def test_bulk_and_single_edit_commit_every_pending_multivalue_field(self):
        javascript = (main.BASE / "app" / "static" / "app.js").read_text()
        self.assertIn("fieldNode._addBulkValue = addValue", javascript)
        self.assertIn("if (entry && entry.value.trim()) fieldNode._addBulkValue()", javascript)
        self.assertIn("if (entry && entry.value.trim()) field._offlineAddValue(entry.value)", javascript)

    def test_security_profiles_are_editable_in_xml_workspaces(self):
        profile_types = {
            "hip-profiles", "antivirus", "anti-spyware", "vulnerability-protection",
            "url-filtering", "file-blocking", "wildfire-analysis", "dos-protection",
            "security-profile-groups", "log-forwarding", "authentication",
        }
        self.assertTrue(profile_types.issubset(main.WORKSPACE_EDITABLE_OBJECT_TYPES))
        self.assertEqual(main.WORKSPACE_EDITABLE_OBJECT_TYPES, set(main.OBJECT_NODES))
        template = (main.BASE / "app" / "templates" / "workspace_editor.html").read_text()
        self.assertIn("object.editable and object_type in workspace_editable_object_types", template)
        self.assertIn("data-generic-object-editor", template)

    def test_url_profile_category_move_is_atomic(self):
        fields = [
            {"path": "0", "kind": "members", "label": "Allow", "values": []},
            {"path": "1", "kind": "members", "label": "Block", "values": ["OCD-ALLOW", "malware"]},
            {"path": "2", "kind": "members", "label": "Credential Enforcement / Allow", "values": ["OCD-ALLOW"]},
        ]
        updates = [
            {"path": "0", "kind": "members", "values": ["OCD-ALLOW"]},
            {"path": "1", "kind": "members", "values": ["OCD-ALLOW", "malware"]},
            {"path": "2", "kind": "members", "values": ["OCD-ALLOW"]},
        ]
        normalized = main.normalize_url_profile_updates(fields, updates)
        self.assertEqual(normalized[0]["values"], ["OCD-ALLOW"])
        self.assertEqual(normalized[1]["values"], ["malware"])
        self.assertEqual(normalized[2]["values"], ["OCD-ALLOW"])

    def test_scm_security_profile_endpoints_use_structured_generic_editor(self):
        expected = {
            "url-filtering": "url-access-profiles",
            "anti-spyware": "anti-spyware-profiles",
            "vulnerability-protection": "vulnerability-protection-profiles",
            "file-blocking": "file-blocking-profiles",
            "security-profile-groups": "profile-groups",
        }
        for object_type, endpoint in expected.items():
            metadata = main.SCM_OBJECT_TYPES[object_type]
            self.assertEqual(metadata["service"], "security")
            self.assertEqual(metadata["endpoint"], endpoint)
            self.assertTrue(metadata["generic"])
            self.assertTrue(metadata["editable"])
        javascript = (main.BASE / "app" / "static" / "app.js").read_text()
        self.assertIn('item.generic', javascript)
        self.assertIn('Toestaan en een URL Filtering-log genereren.', javascript)
        self.assertIn('/catalog/url-categories', javascript)
        self.assertNotIn('schemaRequiredTypes', javascript)
        self.assertIn('data-object-create-template', javascript)

    def test_all_presented_generic_object_families_are_creatable(self):
        generic_types = {
            object_type for object_type, metadata in main.SCM_OBJECT_TYPES.items()
            if metadata.get("generic")
        }
        self.assertIn("external-dynamic-lists", generic_types)
        self.assertIn("decryption-profiles", generic_types)
        self.assertIn("dos-protection", generic_types)
        for object_type in sorted(generic_types):
            with self.subTest(object_type=object_type):
                metadata = main.SCM_OBJECT_TYPES[object_type]
                self.assertTrue(metadata.get("creatable"))
                self.assertTrue(metadata.get("editable"))
                record = main.scm_generic_create_record(object_type, {"folder": "Branch"})
                self.assertIsNotNone(record)
                self.assertTrue(record["edit_fields"])
                self.assertEqual(record["_raw"]["folder"], "Branch")

    def test_reference_catalog_keeps_partial_results_when_one_endpoint_is_forbidden(self):
        profile = {"id": 991122, "target_type": "scm"}
        cache_paths = [
            main.OBJECT_CACHE / f"{profile['id']}-{kind}.json"
            for kind in (
                "syslog-server-profiles", "email-server-profiles",
                "snmp-trap-server-profiles", "http-server-profiles", "tags",
            )
        ]
        for path in cache_paths:
            path.unlink(missing_ok=True)

        def fetch(_profile, kind):
            if kind == "email-server-profiles":
                raise RuntimeError("forbidden")
            if kind == "log-forwarding":
                return []
            return [{"name": f"{kind}-ok"}]

        try:
            with patch.object(main, "fetch_scm_objects", side_effect=fetch):
                catalog = main.fetch_object_catalog(profile, "log-forwarding")
            kinds = {item["kind"] for item in catalog}
            self.assertIn("syslog-server-profiles", kinds)
            self.assertIn("snmp-trap-server-profiles", kinds)
            self.assertIn("http-server-profiles", kinds)
            self.assertIn("tags", kinds)
            self.assertNotIn("email-server-profiles", kinds)
        finally:
            for path in cache_paths:
                path.unlink(missing_ok=True)

    def test_workspace_generic_add_uses_server_side_create_schema(self):
        template = (main.BASE / "app" / "templates" / "workspace_editor.html").read_text()
        javascript = (main.BASE / "app" / "static" / "app.js").read_text()
        self.assertIn("data-object-create-template", template)
        self.assertIn('add.textContent = "+ Add"', javascript)
        self.assertIn("genericEditor ? createTemplate : null", javascript)

    def test_scm_url_category_catalog_returns_selectable_custom_categories(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("scm-category-catalog", 1, "", "", "scm", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1; login["username"] = "test"; login["must_change"] = False
        try:
            with patch.object(main, "fetch_scm_objects", return_value=[{"name": "OCD-ALLOW"}, {"name": "OCD-BLOCK"}]):
                response = client.get(f"/profiles/{profile_id}/catalog/url-categories", base_url="https://forge.test")
            self.assertEqual(response.status_code, 200)
            self.assertEqual([item["name"] for item in response.json["items"]], ["OCD-ALLOW", "OCD-BLOCK"])
        finally:
            with main.db() as conn: conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_scm_url_profile_edit_builds_candidate_without_raw_xml(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("scm-profile-edit", 1, "", "", "scm", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
        raw = {"id": "profile-id", "name": "OCD-URL", "allow": [], "alert": [], "block": ["OCD-ALLOW", "malware"], "folder": "Branch"}
        record = {**raw, "edit_fields": main._scm_config_fields(raw), "generic": True, "_raw": raw}
        fields = {field["label"]: field for field in record["edit_fields"]}
        updates = [
            {"path": fields["Allow"]["path"], "kind": "members", "values": ["OCD-ALLOW"]},
            {"path": fields["Block"]["path"], "kind": "members", "values": ["OCD-ALLOW", "malware"]},
        ]
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1; login["username"] = "test"; login["must_change"] = False; login["csrf"] = "profile-csrf"
        draft_path = main.OBJECT_DRAFTS / "generic-profile-draft.json"
        try:
            with patch.object(main, "fetch_scm_objects", return_value=[record]), \
                 patch.object(main, "scm_client", return_value=(SimpleNamespace(scm_folder="Branch", scm_object_folder="Branch", scm_snippet="", scm_device=""), "token", None, {})), \
                 patch.object(main.secrets, "token_urlsafe", return_value="generic-profile-draft"):
                response = client.post(
                    f"/objects/{profile_id}/url-filtering/preview",
                    data={"csrf": "profile-csrf", "object_id": "profile-id", "name": "OCD-URL", "generic_updates": json.dumps(updates)},
                    base_url="https://forge.test",
                )
            self.assertEqual(response.status_code, 200, response.data.decode())
            draft = json.loads(draft_path.read_text())
            self.assertEqual(draft["payload"]["allow"], ["OCD-ALLOW"])
            self.assertEqual(draft["payload"]["block"], ["malware"])
            self.assertNotIn("_raw", response.data.decode())
        finally:
            draft_path.unlink(missing_ok=True)
            with main.db() as conn: conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_scm_external_dynamic_list_can_be_created_without_existing_schema(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("scm-edl-create", 1, "", "", "scm", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
        seed = main.scm_generic_create_record("external-dynamic-lists", {"folder": "Branch"})
        url_field = next(field for field in seed["edit_fields"] if field["label"] == "Type / Ip / Url")
        updates = [{"path": url_field["path"], "kind": "text", "value": "https://example.test/edl.txt"}]
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1; login["username"] = "test"; login["must_change"] = False; login["csrf"] = "edl-csrf"
        draft_path = main.OBJECT_DRAFTS / "generic-edl-draft.json"
        try:
            with patch.object(main, "fetch_scm_objects", return_value=[]), \
                 patch.object(main, "scm_client", return_value=(SimpleNamespace(scm_folder="Branch", scm_object_folder="Branch", scm_snippet="", scm_device=""), "token", None, {})), \
                 patch.object(main.secrets, "token_urlsafe", return_value="generic-edl-draft"):
                response = client.post(
                    f"/objects/{profile_id}/external-dynamic-lists/preview",
                    data={"csrf": "edl-csrf", "name": "OCD-EDL", "generic_updates": json.dumps(updates)},
                    base_url="https://forge.test",
                )
            self.assertEqual(response.status_code, 200, response.data.decode())
            draft = json.loads(draft_path.read_text())
            self.assertEqual(draft["operation"], "create")
            self.assertEqual(draft["payload"]["type"]["ip"]["url"], "https://example.test/edl.txt")
            self.assertEqual(draft["payload"]["folder"], "Branch")
        finally:
            draft_path.unlink(missing_ok=True)
            with main.db() as conn: conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_workspace_actionbar_is_scoped_to_the_right_content_pane(self):
        css = (main.BASE / "app" / "static" / "app.css").read_text()
        self.assertIn(".workspace-editor-content .object-actionbar", css)
        self.assertIn("position: sticky", css)
        self.assertIn("left: auto", css)
        main.app.jinja_env.get_template("workspace_editor.html")
        main.app.jinja_env.get_template("workspace_policy_preview.html")
        main.app.jinja_env.get_template("workspace_policy_bulk_preview.html")

    def test_workspace_policy_editor_is_actionable_and_supports_rename(self):
        template = (main.BASE / "app" / "templates" / "workspace_editor.html").read_text()
        javascript = (main.BASE / "app" / "static" / "app.js").read_text()
        self.assertIn('name="name" value="{{edit_policy.name}}" required', template)
        self.assertIn("data-offline-policy-field", template)
        self.assertIn("data-offline-policy-picker", template)
        self.assertIn("data-offline-policy-kinds", template)
        self.assertIn("function setupOfflinePolicyTabs()", javascript)
        self.assertIn("_offlineAddValue", javascript)
        self.assertIn("data-policy-bulk-form", template)
        self.assertIn("data-open-policy-bulk", template)
        self.assertIn("data-policy-picker-add-selected", template)
        self.assertIn("policy-editor-dialog", template)
        self.assertIn("offlineDialog.showModal()", javascript)
        self.assertIn("pickerSelections", javascript)

    def test_scm_configuration_fields_preserve_types_and_hide_secrets(self):
        raw = {
            "id": "abc", "name": "ethernet1/1", "folder": "Branch",
            "enabled": True, "mtu": 1500, "members": ["one", "two"],
            "nested": {"mode": "auto", "password": "must-not-render"},
            "complex": [{"name": "child", "value": 1}],
        }
        fields = main._scm_config_fields(raw)
        self.assertNotIn("must-not-render", repr(fields))
        kinds = {field["label"]: field["kind"] for field in fields}
        self.assertEqual(kinds["Enabled"], "bool")
        self.assertEqual(kinds["Members"], "members")
        self.assertEqual(kinds["Complex"], "json")
        self.assertEqual(kinds["Nested / Password"], "protected")
        updates = [
            {"path": next(field["path"] for field in fields if field["label"] == "Enabled"), "kind": "bool", "value": "false"},
            {"path": next(field["path"] for field in fields if field["label"] == "Mtu"), "kind": "text", "value": "1400"},
            {"path": next(field["path"] for field in fields if field["label"] == "Members"), "kind": "members", "values": ["three"]},
        ]
        payload = main._scm_config_payload(raw, updates, "ethernet1/2")
        self.assertEqual(payload["name"], "ethernet1/2")
        self.assertIs(payload["enabled"], False)
        self.assertEqual(payload["mtu"], 1400)
        self.assertEqual(payload["members"], ["three"])
        self.assertEqual(payload["nested"]["password"], "must-not-render")

    def test_scm_network_and_device_editor_routes_compile(self):
        template = (main.BASE / "app" / "templates" / "app.html").read_text()
        javascript = (main.BASE / "app" / "static" / "app.js").read_text()
        self.assertIn("scm_configuration_preview", template)
        self.assertIn("scm_configuration_delete_preview", template)
        self.assertIn("policy_view='device'", template)
        self.assertIn("data-config-record-edit", template)
        self.assertIn("setupWorkspaceConfigurationEditor", javascript)
        main.app.jinja_env.get_template("scm_config_preview.html")

    def test_scm_device_lists_do_not_send_network_pagination_parameters(self):
        profile = self.profile("scm", folder="Branch")
        scm = SimpleNamespace(scm_api_base="https://api.strata.paloaltonetworks.com/config/security/v1")
        response = {"data": [{"id": "one", "folder": "Branch", "general": {"timezone": "UTC"}}]}
        with patch.object(main, "scm_client", return_value=(scm, "token", "unused", {"folder": "Branch"})), patch.object(main.policy_api, "scm_http_request", return_value=response) as request_mock, patch.object(main.policy_api, "scm_fetch_all") as paged_mock:
            records = main.fetch_scm_configuration_records(profile, "device", "setup")
        self.assertEqual(len(records), 8)
        self.assertEqual(request_mock.call_count, 8)
        self.assertTrue(all(call.kwargs.get("params") == {"folder": "Branch"} for call in request_mock.call_args_list))
        paged_mock.assert_not_called()

    def test_panos_application_catalog_combines_custom_and_predefined(self):
        profile = self.profile("panorama")
        response = "<response status='success'><result><application><entry name='ssl'/><entry name='web-browsing'/></application></result></response>"
        with patch("app.main.fetch_panos_objects", return_value=[{"id": "custom", "name": "custom"}]), patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.policy_api.api_get", return_value=response) as api_get:
            items = main.fetch_application_objects(profile)
        self.assertEqual({item["name"] for item in items}, {"custom", "ssl", "web-browsing"})
        self.assertEqual(api_get.call_args.args[1]["xpath"], "/config/predefined/application")

    def test_offline_workspace_storage_keeps_full_xml_and_inventory(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("offline-test", 1, "", "", "panos", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        workspace_id = main.store_config_workspace(
            profile, "offline", "config.xml",
            b'<config version="12.1"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>',
            "upload",
        )
        workspace = main.workspace_row(workspace_id)
        try:
            self.assertEqual(json.loads(workspace["metadata_json"])["vsys"], ["vsys1"])
            self.assertTrue(main.workspace_config_path(workspace).read_bytes().startswith(b"<?xml"))
            client = main.app.test_client()
            with client.session_transaction(base_url="https://forge.test") as login:
                login["user_id"] = 1
                login["username"] = "test"
                login["must_change"] = False
            response = client.get(f"/config-workspaces/{workspace_id}/edit", base_url="https://forge.test", follow_redirects=True)
            self.assertEqual(response.status_code, 200, response.data.decode())
            self.assertIn(b"Virtual system", response.data)
        finally:
            main.workspace_config_path(workspace).unlink(missing_ok=True)
            with main.db() as conn:
                conn.execute("DELETE FROM config_workspaces WHERE id=?", (workspace_id,))
                conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_network_configuration_save_directly_creates_workspace_version(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("direct-network-save", 1, "", "", "panos", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><comment>old</comment></entry></ethernet></interface></network><vsys><entry name="vsys1"/></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "direct", "config.xml", xml, "upload")
        _, records = main.scoped_configuration_records(xml, "vsys1", "", "network", "interfaces")
        interface = records[0]
        comment = next(field for field in interface["edit_fields"] if field["label"] == "Comment")
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "test"
            login["must_change"] = False
            login["csrf"] = "direct-save-csrf"
        try:
            response = client.post(
                f"/config-workspaces/{workspace_id}/configuration/preview",
                data={
                    "csrf": "direct-save-csrf", "direct_save": "yes", "scope": "vsys1",
                    "workspace_view": "network", "config_section": "interfaces",
                    "locator": interface["locator"], "operation": "update", "name": interface["name"],
                    "generic_updates": json.dumps([{"path": comment["path"], "kind": "text", "value": "saved"}]),
                },
                base_url="https://forge.test",
            )
            self.assertEqual(response.status_code, 302)
            self.assertNotIn("configuration-drafts", response.headers["Location"])
            with main.db() as conn:
                latest = conn.execute("SELECT * FROM config_workspaces WHERE profile_id=? ORDER BY id DESC LIMIT 1", (profile_id,)).fetchone()
            self.assertNotEqual(latest["id"], workspace_id)
            self.assertIn(b"<comment>saved</comment>", main.workspace_config_path(latest).read_bytes())
        finally:
            with main.db() as conn:
                workspaces = conn.execute("SELECT * FROM config_workspaces WHERE profile_id=?", (profile_id,)).fetchall()
            for item in workspaces:
                main.workspace_config_path(item).unlink(missing_ok=True)
            with main.db() as conn:
                conn.execute("DELETE FROM config_workspaces WHERE profile_id=?", (profile_id,))
                conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_configuration_editors_use_direct_save_without_duplicate_button(self):
        for template_name in ("workspace_editor.html", "app.html"):
            template = (pathlib.Path(main.__file__).parent / "templates" / template_name).read_text()
            self.assertNotIn("Dupliceer als nieuw", template)
            self.assertNotIn("data-config-duplicate", template)
        workspace_template = (pathlib.Path(main.__file__).parent / "templates" / "workspace_editor.html").read_text()
        scm_template = (pathlib.Path(main.__file__).parent / "templates" / "app.html").read_text()
        self.assertIn('name="direct_save" value="yes"', workspace_template)
        self.assertIn('name="direct_save" value="yes"', scm_template)
        self.assertGreaterEqual(workspace_template.count('name="direct_save" value="yes"'), 5)
        self.assertNotIn("Preview wijzigingen", workspace_template)

    def test_scm_direct_save_writer_updates_candidate_after_fingerprint_check(self):
        profile = {"id": 42, "target_type": "scm"}
        draft = {
            "view": "network", "section": "zones", "operation": "update",
            "endpoint": "zones", "before_id": "zone-id", "before_name": "Trust",
            "fingerprint": "same", "payload": {"name": "Trust", "enable_user_identification": True},
        }
        current = [{"endpoint": "zones", "id": "zone-id", "fingerprint": "same"}]
        scm = SimpleNamespace(scm_api_base="https://api.example.invalid")
        with patch.object(main, "fetch_scm_configuration_records", return_value=current), \
             patch.object(main, "scm_client", return_value=(scm, "token", None, {"folder": "Branch"})), \
             patch.object(main.policy_api, "scm_api_root", return_value="https://api.example.invalid"), \
             patch.object(main.policy_api, "scm_http_request") as request_mock:
            main._write_scm_configuration_draft(profile, draft)
        request_mock.assert_called_once_with(
            "PUT", "https://api.example.invalid/config/network/v1/zones/zone-id",
            "token", payload=draft["payload"],
        )

    def test_panorama_policy_management_chooses_config_source_before_live_fetch(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("source-choice-test", 1, "", "", "panorama", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        workspace_id = main.store_config_workspace(
            profile, "API snapshot", "api-candidate.xml",
            b'<config><devices><entry name="localhost.localdomain"><device-group><entry name="Branches"/></device-group></entry></devices></config>',
            "api",
        )
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "test"
            login["must_change"] = False
        try:
            with patch.object(main, "fetch_scm_policy_type") as fetch:
                response = client.get(f"/?policy_profile={profile_id}", base_url="https://forge.test")
            self.assertEqual(response.status_code, 200)
            self.assertIn(b">Ophalen<", response.data)
            self.assertIn(b">Import<", response.data)
            self.assertNotIn(b"Naam workspace", response.data)
            self.assertNotIn(b"Bewaar de volledige candidate", response.data)
            self.assertIn(b"API snapshot", response.data)
            fetch.assert_not_called()
        finally:
            workspace = main.workspace_row(workspace_id)
            main.workspace_config_path(workspace).unlink(missing_ok=True)
            with main.db() as conn:
                conn.execute("DELETE FROM config_workspaces WHERE id=?", (workspace_id,))
                conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_panorama_and_standalone_remember_selected_full_config(self):
        for target, xml in (
            ("panorama", b'<config><devices><entry name="localhost.localdomain"><device-group><entry name="Branches"/></device-group></entry></devices></config>'),
            ("panos", b'<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>'),
        ):
            timestamp = main.now()
            with main.db() as conn:
                cursor = conn.execute(
                    "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (f"remember-{target}", 1, "", "", target, "{}", b"", timestamp, timestamp),
                )
                profile_id = cursor.lastrowid
                profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
            workspace_id = main.store_config_workspace(profile, "remembered", "config.xml", xml, "upload")
            fingerprint_before = main.build_fingerprint(profile, include_flows=False)
            main.set_active_config_workspace(profile_id, workspace_id)
            with main.db() as conn:
                updated_profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
            self.assertEqual(main.active_config_workspace_id(updated_profile), workspace_id)
            self.assertEqual(main.build_fingerprint(updated_profile, include_flows=False), fingerprint_before)
            client = main.app.test_client()
            with client.session_transaction(base_url="https://forge.test") as login:
                login["user_id"] = 1
                login["username"] = "test"
                login["must_change"] = False
            response = client.get(f"/?policy_profile={profile_id}", base_url="https://forge.test")
            self.assertEqual(response.status_code, 302)
            self.assertIn(f"/config-workspaces/{workspace_id}/edit", response.headers["Location"])
            chooser = client.get(f"/?policy_profile={profile_id}&policy_source=choose", base_url="https://forge.test")
            self.assertEqual(chooser.status_code, 200)
            self.assertNotIn(b"Huidige candidate", chooser.data)
            try:
                main.workspace_config_path(main.workspace_row(workspace_id)).unlink(missing_ok=True)
            finally:
                with main.db() as conn:
                    conn.execute("DELETE FROM config_workspaces WHERE id=?", (workspace_id,))
                    conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_rendered_workspace_navigation_has_no_dead_internal_targets(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("link-audit", 1, "", "", "panos", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"/></ethernet></interface></network><vsys><entry name="vsys1"><zone><entry name="Trust"/></zone><address><entry name="host-a"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address><rulebase><security><rules><entry name="allow-a"><from><member>Trust</member></from><to><member>Trust</member></to><source><member>host-a</member></source><destination><member>any</member></destination><application><member>ping</member></application><service><member>application-default</member></service><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "link audit", "config.xml", xml, "upload")
        main.set_active_config_workspace(profile_id, workspace_id)
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "test"
            login["must_change"] = False
        try:
            paths = [
                f"/config-workspaces/{workspace_id}/edit?workspace_view=policies",
                f"/config-workspaces/{workspace_id}/edit?workspace_view=objects",
                f"/config-workspaces/{workspace_id}/edit?workspace_view=network",
                f"/config-workspaces/{workspace_id}/edit?workspace_view=device",
                f"/config-workspaces/{workspace_id}/push-preview",
                f"/?policy_profile={profile_id}&policy_source=choose",
            ]
            parser = NavigationTargets()
            for path in paths:
                response = client.get(path, base_url="https://forge.test")
                self.assertEqual(response.status_code, 200, path)
                parser.feed(response.data.decode())
                self.assertNotIn("#config-workspaces", response.data.decode())
            for href in set(parser.links):
                parsed = urlsplit(href)
                if parsed.scheme or parsed.netloc or parsed.path.startswith("/static/"):
                    continue
                target = parsed.path or "/"
                if parsed.query:
                    target += "?" + parsed.query
                response = client.get(target, base_url="https://forge.test")
                self.assertNotIn(response.status_code, {404, 405, 500}, href)
                if parsed.fragment and response.status_code == 200 and "text/html" in response.content_type:
                    target_parser = NavigationTargets()
                    target_parser.feed(response.data.decode())
                    self.assertIn(parsed.fragment, target_parser.ids, href)
            for action in set(parser.actions):
                parsed = urlsplit(action)
                response = client.open(parsed.path, method="OPTIONS", base_url="https://forge.test")
                self.assertNotIn(response.status_code, {404, 405, 500}, action)
            policy_html = client.get(paths[0], base_url="https://forge.test").data.decode()
            self.assertIn("policy_kind=nat", policy_html)
            self.assertIn("scope=vsys1", policy_html)
            object_html = client.get(paths[1], base_url="https://forge.test").data.decode()
            self.assertIn("data-object-row", object_html)
            self.assertIn("data-object-add", object_html)
            self.assertIn("data-object-edit", object_html)
            index_html = client.get(paths[-1], base_url="https://forge.test").data.decode()
            self.assertIn("data-menu-toggle", index_html)
            self.assertIn("data-config-pull-progress", index_html)
            self.assertIn("app.css?v=", index_html)
            self.assertIn("app.js?v=", index_html)
        finally:
            main.workspace_config_path(main.workspace_row(workspace_id)).unlink(missing_ok=True)
            with main.db() as conn:
                conn.execute("DELETE FROM config_workspaces WHERE id=?", (workspace_id,))
                conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_workspace_remembers_device_group_and_template_when_links_omit_them(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("context-memory", 1, "", "", "panorama", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><device-group><entry name="First"/><entry name="Second"><reference-template>Template-B</reference-template></entry></device-group><template><entry name="Template-A"/><entry name="Template-B"/></template></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "context", "config.xml", xml, "upload")
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "test"
            login["must_change"] = False
        try:
            first = client.get(
                f"/config-workspaces/{workspace_id}/edit?scope=Second&template=Template-B&workspace_view=network",
                base_url="https://forge.test",
            )
            self.assertEqual(first.status_code, 200)
            remembered = client.get(
                f"/config-workspaces/{workspace_id}/edit?workspace_view=policies&rulebase=post",
                base_url="https://forge.test",
            )
            self.assertEqual(remembered.status_code, 200)
            self.assertIn(b'<option value="Second" selected>', remembered.data)
            network = client.get(
                f"/config-workspaces/{workspace_id}/edit?workspace_view=device",
                base_url="https://forge.test",
            )
            self.assertIn(b'<option value="Template-B" selected>', network.data)
        finally:
            main.workspace_config_path(main.workspace_row(workspace_id)).unlink(missing_ok=True)
            with main.db() as conn:
                conn.execute("DELETE FROM config_workspaces WHERE id=?", (workspace_id,))
                conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_workspace_xml_is_parsed_once_and_reused_across_navigation(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("cache-test", 1, "", "", "panos", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="host"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address><rulebase><security><rules><entry name="allow"/></rules></security></rulebase></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "cache", "config.xml", xml, "upload")
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "test"
            login["must_change"] = False
        main.cached_workspace_config.cache_clear()
        try:
            with patch.object(main, "parse_snapshot", wraps=main.parse_snapshot) as parser:
                policy = client.get(f"/config-workspaces/{workspace_id}/edit?workspace_view=policies", base_url="https://forge.test")
                objects = client.get(f"/config-workspaces/{workspace_id}/edit?workspace_view=objects", base_url="https://forge.test")
                self.assertEqual(policy.status_code, 200)
                self.assertEqual(objects.status_code, 200)
                self.assertEqual(parser.call_count, 1)
        finally:
            main.cached_workspace_config.cache_clear()
            main.workspace_config_path(main.workspace_row(workspace_id)).unlink(missing_ok=True)
            with main.db() as conn:
                conn.execute("DELETE FROM config_workspaces WHERE id=?", (workspace_id,))
                conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_offline_object_create_preview_and_apply_creates_new_workspace(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("offline-object", 1, "", "", "panos", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="existing"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "objects", "config.xml", xml, "upload")
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "test"
            login["must_change"] = False
            login["csrf"] = "object-csrf"
        try:
            preview = client.post(
                f"/config-workspaces/{workspace_id}/objects/preview",
                data={"csrf": "object-csrf", "scope": "vsys1", "object_type": "addresses", "name": "added", "value_type": "ip_netmask", "value": "192.0.2.2/32", "description": "new object"},
                base_url="https://forge.test",
            )
            self.assertEqual(preview.status_code, 200)
            parser = NavigationTargets(); parser.feed(preview.data.decode())
            action = next(item for item in parser.actions if "/config-workspaces/object-drafts/" in item)
            applied = client.post(action, data={"csrf": "object-csrf"}, base_url="https://forge.test")
            self.assertEqual(applied.status_code, 302)
            with main.db() as conn:
                latest = conn.execute("SELECT * FROM config_workspaces WHERE profile_id=? ORDER BY id DESC LIMIT 1", (profile_id,)).fetchone()
            self.assertNotEqual(latest["id"], workspace_id)
            _, objects = main.scoped_objects(main.workspace_config_path(latest).read_bytes(), "vsys1", "addresses")
            self.assertEqual([item["name"] for item in objects], ["existing", "added"])
            direct = client.post(
                f"/config-workspaces/{latest['id']}/objects/preview",
                data={"csrf": "object-csrf", "direct_save": "yes", "scope": "vsys1", "object_type": "addresses", "name": "direct-added", "value_type": "ip_netmask", "value": "192.0.2.3/32", "description": "direct object"},
                base_url="https://forge.test",
            )
            self.assertEqual(direct.status_code, 302)
            with main.db() as conn:
                direct_latest = conn.execute("SELECT * FROM config_workspaces WHERE profile_id=? ORDER BY id DESC LIMIT 1", (profile_id,)).fetchone()
            self.assertNotEqual(direct_latest["id"], latest["id"])
            _, direct_objects = main.scoped_objects(main.workspace_config_path(direct_latest).read_bytes(), "vsys1", "addresses")
            self.assertEqual([item["name"] for item in direct_objects], ["existing", "added", "direct-added"])
        finally:
            with main.db() as conn:
                workspaces = conn.execute("SELECT * FROM config_workspaces WHERE profile_id=?", (profile_id,)).fetchall()
            for item in workspaces:
                main.workspace_config_path(item).unlink(missing_ok=True)
            with main.db() as conn:
                conn.execute("DELETE FROM config_workspaces WHERE profile_id=?", (profile_id,))
                conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_offline_policy_rename_and_fields_are_applied_to_a_new_workspace(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("offline-policy", 1, "", "", "panos", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><tag><entry name="edited"/></tag><rulebase><security><rules><entry name="old-name"><from><member>Trust</member></from><to><member>Internet</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>web-browsing</member></application><service><member>application-default</member></service><action>allow</action><unknown>keep</unknown></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "policy", "config.xml", xml, "upload")
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1
            login["username"] = "test"
            login["must_change"] = False
            login["csrf"] = "policy-csrf"
        try:
            editor = client.get(
                f"/config-workspaces/{workspace_id}/edit?workspace_view=policies&scope=vsys1&policy_kind=security&rulebase=pre&edit_policy=old-name",
                base_url="https://forge.test",
            )
            self.assertEqual(editor.status_code, 200)
            self.assertIn(b'name="name" value="old-name" required', editor.data)
            preview = client.post(
                f"/config-workspaces/{workspace_id}/policies/preview",
                data={"csrf": "policy-csrf", "scope": "vsys1", "policy_kind": "security", "rulebase": "pre", "policy_name": "old-name", "name": "renamed-policy", "from": "Trust", "to": "Internet", "source": "any", "destination": "any", "source_user": "any", "destination_user": "any", "source_hip": "any", "destination_hip": "any", "category": "any", "application": "ssl", "service": "application-default", "tag": "edited", "action": "allow", "description": "renamed"},
                base_url="https://forge.test",
            )
            with client.session_transaction(base_url="https://forge.test") as current_session:
                preview_flashes = list(current_session.get("_flashes", []))
            self.assertEqual(preview.status_code, 200, preview_flashes)
            parser = NavigationTargets(); parser.feed(preview.data.decode())
            action = next(item for item in parser.actions if "/config-workspaces/policy-drafts/" in item)
            applied = client.post(action, data={"csrf": "policy-csrf"}, base_url="https://forge.test")
            self.assertEqual(applied.status_code, 302)
            with main.db() as conn:
                latest = conn.execute("SELECT * FROM config_workspaces WHERE profile_id=? ORDER BY id DESC LIMIT 1", (profile_id,)).fetchone()
            self.assertNotEqual(latest["id"], workspace_id)
            result = main.workspace_config_path(latest).read_bytes()
            self.assertIn(b'<entry name="renamed-policy">', result)
            self.assertNotIn(b'<entry name="old-name">', result)
            self.assertIn(b'<member>ssl</member>', result)
            self.assertIn(b'<unknown>keep</unknown>', result)
        finally:
            with main.db() as conn:
                workspaces = conn.execute("SELECT * FROM config_workspaces WHERE profile_id=?", (profile_id,)).fetchall()
            for item in workspaces:
                main.workspace_config_path(item).unlink(missing_ok=True)
            with main.db() as conn:
                conn.execute("DELETE FROM config_workspaces WHERE profile_id=?", (profile_id,))
                conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_offline_policy_bulk_edit_applies_multiple_rules_atomically(self):
        timestamp = main.now()
        with main.db() as conn:
            cursor = conn.execute(
                "INSERT INTO profiles(name,enabled,serial,source_ip,target_type,settings_json,secret_blob,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("offline-bulk", 1, "", "", "panos", "{}", b"", timestamp, timestamp),
            )
            profile_id = cursor.lastrowid
            profile = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><tag><entry name="bulk-edited"/></tag><application><entry name="dns"/></application><rulebase><security><rules><entry name="one"><from><member>Trust</member></from><source><member>any</member></source><destination><member>any</member></destination><application><member>ssl</member></application><service><member>application-default</member></service><action>allow</action></entry><entry name="two"><from><member>Trust</member></from><source><member>any</member></source><destination><member>any</member></destination><application><member>web-browsing</member></application><service><member>application-default</member></service><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''
        workspace_id = main.store_config_workspace(profile, "bulk", "config.xml", xml, "upload")
        client = main.app.test_client()
        with client.session_transaction(base_url="https://forge.test") as login:
            login["user_id"] = 1; login["username"] = "test"; login["must_change"] = False; login["csrf"] = "bulk-csrf"
        try:
            preview = client.post(
                f"/config-workspaces/{workspace_id}/policies/bulk-preview",
                data={"csrf": "bulk-csrf", "scope": "vsys1", "policy_kind": "security", "rulebase": "standard", "policy_name": ["one", "two"], "tag_add": "bulk-edited", "application_add": "dns", "action": "deny"},
                base_url="https://forge.test",
            )
            self.assertEqual(preview.status_code, 200)
            parser = NavigationTargets(); parser.feed(preview.data.decode())
            action = next(item for item in parser.actions if "/config-workspaces/policy-bulk-drafts/" in item)
            applied = client.post(action, data={"csrf": "bulk-csrf"}, base_url="https://forge.test")
            self.assertEqual(applied.status_code, 302)
            with main.db() as conn:
                latest = conn.execute("SELECT * FROM config_workspaces WHERE profile_id=? ORDER BY id DESC LIMIT 1", (profile_id,)).fetchone()
            _, policies = main.scoped_policies(main.workspace_config_path(latest).read_bytes(), "vsys1", "security", "standard")
            self.assertEqual(len(policies), 2)
            self.assertTrue(all(item["action"] == "deny" for item in policies))
            self.assertTrue(all("dns" in item["application"] and "bulk-edited" in item["tag"] for item in policies))
        finally:
            with main.db() as conn: workspaces = conn.execute("SELECT * FROM config_workspaces WHERE profile_id=?", (profile_id,)).fetchall()
            for item in workspaces: main.workspace_config_path(item).unlink(missing_ok=True)
            with main.db() as conn:
                conn.execute("DELETE FROM config_workspaces WHERE profile_id=?", (profile_id,)); conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def test_oversized_form_is_rejected(self):
        client = main.app.test_client()
        response = client.post(
            "/login",
            data={"csrf": "x", "username": "u", "password": "x" * (main.app.config["MAX_CONTENT_LENGTH"] + 1)},
            base_url="https://forge.test",
        )
        self.assertEqual(response.status_code, 413)

    def test_spreadsheet_formula_values_are_neutralized(self):
        for value in ("=cmd()", "+SUM(1,1)", "-1+2", "@payload", "\tformula", "  =formula"):
            self.assertTrue(main.spreadsheet_safe(value).startswith("'"))
        self.assertEqual(main.spreadsheet_safe("10.0.0.1"), "10.0.0.1")

    def test_configured_syslog_serial_rejects_wrong_source(self):
        with main._syslog_source_policy_lock:
            original = dict(main._syslog_source_policy)
            main._syslog_source_policy.clear()
            main._syslog_source_policy["SERIAL-1"] = {"192.0.2.10", "192.0.2.11"}
        try:
            self.assertTrue(main.syslog_source_allowed("SERIAL-1", "192.0.2.10"))
            self.assertFalse(main.syslog_source_allowed("SERIAL-1", "192.0.2.200"))
            self.assertTrue(main.syslog_source_allowed("UNCONFIGURED", "192.0.2.200"))
        finally:
            with main._syslog_source_policy_lock:
                main._syslog_source_policy.clear(); main._syslog_source_policy.update(original)

    def test_blank_duplicate_profile_does_not_relax_explicit_syslog_source(self):
        with main._syslog_source_policy_lock: original = dict(main._syslog_source_policy)
        profiles = [
            {"serial": "SERIAL-1", "source_ip": "", "settings_json": "{}"},
            {"serial": "SERIAL-1", "source_ip": "192.0.2.10", "settings_json": "{}"},
        ]
        class FakeConnection:
            def execute(self, _query): return self
            def fetchall(self): return profiles
            def __enter__(self): return self
            def __exit__(self, *_args): return False
        try:
            with patch("app.main.db", return_value=FakeConnection()): main.refresh_syslog_source_policy()
            self.assertTrue(main.syslog_source_allowed("SERIAL-1", "192.0.2.10"))
            self.assertFalse(main.syslog_source_allowed("SERIAL-1", "192.0.2.11"))
        finally:
            with main._syslog_source_policy_lock:
                main._syslog_source_policy.clear(); main._syslog_source_policy.update(original)

    def test_standalone_policy_xpath_uses_vsys_rulebase(self):
        xpath = main.panos_policy_xpath(self.profile("panos"), "decryption")
        self.assertIn("vsys/entry[@name='vsys2']/rulebase/decryption/rules", xpath)

    def test_xml_policy_update_preserves_nat_translation(self):
        policy = main.xml_entry_to_policy(main.ET.fromstring("<entry name='NAT-1'><from><member>Trust</member></from><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation><disabled>no</disabled></entry>"), "nat")
        policy["from"] = ["Clients"]
        result = main.ET.fromstring(main.update_xml_policy(policy))
        self.assertEqual(result.findtext("./from/member"), "Clients")
        self.assertEqual(result.findtext("./source-translation/dynamic-ip-and-port/interface-address/interface"), "ethernet1/1")

    def test_panorama_write_is_candidate_edit_only(self):
        profile = self.profile("panorama")
        policy = main.xml_entry_to_policy(main.ET.fromstring("<entry name='NAT-1'><from><member>Trust</member></from></entry>"), "nat")
        with patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.panos_api_post", return_value="<response status='success'><result/></response>") as request, patch("app.main.policy_api.require_success"):
            main.write_target_policy(profile, "nat", policy)
        params = request.call_args.args[1]
        self.assertEqual(params["type"], "config")
        self.assertEqual(params["action"], "edit")
        self.assertNotIn("commit", params.values())

    def test_panos_policy_rename_edits_then_renames_the_existing_entry(self):
        profile = self.profile("panos")
        policy = main.xml_entry_to_policy(main.ET.fromstring("<entry name='old-name'><from><member>Trust</member></from></entry>"), "security")
        policy["name"] = "new-name"
        with patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.panos_api_post", return_value="<response status='success'><result/></response>") as request, patch("app.main.policy_api.require_success"):
            main.write_target_policy(profile, "security", policy, "old-name")
        self.assertEqual([call.args[1]["action"] for call in request.call_args_list], ["edit", "rename"])
        self.assertIn("old-name", request.call_args_list[0].args[1]["xpath"])
        self.assertIn('name="old-name"', request.call_args_list[0].args[1]["element"])
        self.assertEqual(request.call_args_list[1].args[1]["newname"], "new-name")

    def test_panorama_new_objects_default_to_shared(self):
        profile = self.profile("panorama")
        draft = {"object_type": "addresses", "operation": "create", "payload": {"name": "Web", "ip_netmask": "192.0.2.10/32"}}
        with patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.panos_api_post", return_value="<response status='success'><result/></response>") as request, patch("app.main.policy_api.require_success"):
            main.write_panos_object_draft(profile, draft)
        self.assertEqual(request.call_args.args[1]["xpath"], "/config/shared/address")

    def test_scm_nat_payload_preserves_translation(self):
        raw = {"id": "n1", "name": "NAT-1", "from": ["Trust"], "source_translation": {"dynamic_ip_and_port": {"interface_address": {"interface": "ethernet1/1"}}}}
        policy = main.normalize_policy(raw, "nat")
        policy["from"] = ["Clients"]
        payload = main.target_policy_payload(policy, {"folder": "Branch"}, "nat")
        self.assertEqual(payload["from"], ["Clients"])
        self.assertEqual(payload["source_translation"], raw["source_translation"])
        self.assertEqual(payload["folder"], "Branch")

    def test_standalone_zone_scope_uses_vsys(self):
        base = main.panos_object_bases(self.profile("panos"), "zones")[0]
        self.assertIn("vsys/entry[@name='vsys2']", base)

    def test_panos_api_key_is_reused_for_unchanged_profile(self):
        profile = {**self.profile("panos"), "id": 42, "updated_at": "2026-08-06 12:00:00"}
        profile["secret_blob"] = main.fernet.encrypt(json.dumps({"username": "user", "password": "password"}).encode())
        response = "<response status='success'><result><key>cached-key</key></result></response>"
        main.invalidate_profile_caches(42)
        with patch("app.main.panos_api_post", return_value=response) as request:
            self.assertEqual(main.panos_profile_context(profile)[2], "cached-key")
            self.assertEqual(main.panos_profile_context(profile)[2], "cached-key")
        self.assertEqual(request.call_count, 1)
        main.invalidate_profile_caches(42)

    def test_profile_cache_invalidation_removes_catalog_and_api_key(self):
        profile_id = 4242
        cache_path = main.OBJECT_CACHE / f"{profile_id}-applications.json"
        cache_path.write_text("[]")
        main._panos_key_cache[profile_id] = ("version", "endpoint", "key", main.time.time() + 60)
        main._catalog_errors[(profile_id, "applications")] = "failure"
        main.invalidate_profile_caches(profile_id)
        self.assertFalse(cache_path.exists())
        self.assertNotIn(profile_id, main._panos_key_cache)
        self.assertNotIn((profile_id, "applications"), main._catalog_errors)

    def test_panorama_zone_scope_uses_device_group_reference_template(self):
        responses = ["<response status='success'><result><entry name='Branches'><reference-templates><member>Branch-Template</member></reference-templates></entry></result></response>", "<response status='success'><result/></response>"]
        with patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.policy_api.api_get", side_effect=responses):
            base = main.panos_object_bases(self.profile("panorama"), "zones")[0]
        self.assertIn("template/entry[@name='Branch-Template']", base)
        self.assertIn("vsys/entry[@name='vsys2']", base)

    def test_panorama_without_reference_template_keeps_zones_freeform(self):
        response = "<response status='success'><result><entry name='Branches'/></result></response>"
        with patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.policy_api.api_get", return_value=response):
            self.assertEqual(main.panos_object_bases(self.profile("panorama"), "zones"), [])

    def test_zone_xml_preserves_type_interfaces_and_profiles(self):
        xml = main.ET.fromstring(main.object_payload_xml({"name": "Clients", "network": {"layer3": ["ethernet1/1"]}, "enable_user_identification": True, "zone_protection_profile": "strict"}))
        self.assertEqual(xml.findtext("./network/layer3/member"), "ethernet1/1")
        self.assertEqual(xml.findtext("./enable-user-identification"), "yes")
        self.assertEqual(xml.findtext("./zone-protection-profile"), "strict")

    def test_panorama_zone_create_uses_template_candidate(self):
        profile = self.profile("panorama")
        draft = {"object_type": "zones", "operation": "create", "payload": {"name": "Clients", "network": {"layer3": []}}}
        with patch("app.main.panos_object_bases", return_value=["/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='Branch-Template']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys2']"]), patch("app.main.panos_profile_context", return_value=({}, "https://example.invalid", "key", object())), patch("app.main.panos_api_post", return_value="<response status='success'><result/></response>") as request, patch("app.main.policy_api.require_success"):
            main.write_panos_object_draft(profile, draft)
        params = request.call_args.args[1]
        self.assertIn("template/entry[@name='Branch-Template']", params["xpath"])
        self.assertEqual(params["action"], "set")

    def test_scm_scope_envelopes_are_not_treated_as_rules(self):
        self.assertFalse(main.is_complete_scm_policy({"id": "1", "name": "default", "folder": "PA-BPA"}))
        self.assertFalse(main.is_complete_scm_policy({"id": "2", "name": "default", "folder": "PA-BPA", "policy_type": "Security"}))
        self.assertTrue(main.is_complete_scm_policy({"id": "3", "name": "nat", "folder": "PA-BPA", "from": ["Trust"]}))
        self.assertFalse(main.is_scm_policy_for_kind({"id": "3", "name": "nat", "folder": "PA-BPA", "from": ["Trust"]}, "nat"))
        self.assertTrue(main.is_scm_policy_for_kind({"id": "4", "name": "nat", "folder": "PA-BPA", "from": ["Trust"], "to": ["Untrust"], "source": ["any"], "destination": ["any"], "service": "any"}, "nat"))

    def test_nat_normalization_exposes_panos_translation_fields(self):
        normalized = main.normalize_policy({
            "id": "n1", "name": "NAT-1", "from": ["Trust"], "to": ["Untrust"],
            "source": ["any"], "destination": ["server-public"], "service": "tcp-443",
            "source_translation": {"dynamic_ip": {"translated_address": ["192.0.2.10"]}},
            "destination_translation": {"translated_address": "server-private", "translated_port": 8443},
        }, "nat")
        self.assertEqual(normalized["service"], ["tcp-443"])
        self.assertEqual(normalized["source_translation_mode"], "dynamic_ip")
        self.assertEqual(normalized["source_translation_address"], "192.0.2.10")
        self.assertEqual(normalized["destination_translation_address"], "server-private")
        self.assertEqual(normalized["destination_translation_port"], "8443")

    def test_nat_translation_form_builds_api_payload_shape(self):
        replacements = main.nat_translation_replacements({
            "nat_type": "ipv4", "to_interface": "ethernet1/1",
            "source_translation_mode": "dynamic_ip", "source_translation_address": "192.0.2.10,192.0.2.11",
            "destination_translation_address": "server-private", "destination_translation_port": "8443",
        })
        self.assertEqual(replacements["source_translation"], {"dynamic_ip": {"translated_address": ["192.0.2.10", "192.0.2.11"]}})
        self.assertEqual(replacements["destination_translation"], {"translated_address": "server-private", "translated_port": 8443})

    def test_nat_xml_editor_uses_scalar_service_and_translation_nodes(self):
        policy = main.xml_entry_to_policy(main.ET.fromstring(
            "<entry name='NAT-1'><from><member>Trust</member></from><to><member>Untrust</member></to>"
            "<source><member>any</member></source><destination><member>public</member></destination><service>tcp-443</service>"
            "<source-translation><dynamic-ip><translated-address><member>192.0.2.10</member></translated-address></dynamic-ip></source-translation>"
            "</entry>"
        ), "nat")
        self.assertEqual(policy["service"], ["tcp-443"])
        self.assertEqual(policy["source_translation_address"], "192.0.2.10")
        policy["destination_translation"] = {"translated_address": "private", "translated_port": 8443}
        xml = main.ET.fromstring(main.update_xml_policy(policy))
        self.assertEqual(xml.findtext("./service"), "tcp-443")
        self.assertEqual(xml.findtext("./destination-translation/translated-address"), "private")
        self.assertEqual(xml.findtext("./destination-translation/translated-port"), "8443")

    def test_offline_nat_editor_exposes_original_and_translated_packets(self):
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><nat><rules><entry name="NAT-1"><from><member>Trust</member></from><to><member>Untrust</member></to><source><member>any</member></source><destination><member>public</member></destination><service>tcp-443</service><nat-type>ipv4</nat-type><to-interface>ethernet1/1</to-interface><source-translation><dynamic-ip><translated-address><member>192.0.2.10</member></translated-address></dynamic-ip></source-translation><destination-translation><translated-address>private</translated-address><translated-port>8443</translated-port></destination-translation></entry></rules></nat></rulebase></entry></vsys></entry></devices></config>'''
        _, policies = main.scoped_policies(xml, "vsys1", "nat", "standard")
        policy = policies[0]
        self.assertEqual(policy["service"], ["tcp-443"])
        self.assertEqual(policy["to_interface"], "ethernet1/1")
        self.assertEqual(policy["source_translation_mode"], "dynamic_ip")
        self.assertEqual(policy["source_translation_address"], "192.0.2.10")
        self.assertEqual(policy["destination_translation_address"], "private")
        self.assertEqual(policy["destination_translation_port"], "8443")
        no_translation_xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><nat><rules><entry name="NAT-empty"><from><member>Trust</member></from><to><member>Untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><service>any</service></entry></rules></nat></rulebase></entry></vsys></entry></devices></config>'''
        _, no_translation = main.scoped_policies(no_translation_xml, "vsys1", "nat", "standard")
        self.assertEqual(no_translation[0]["source_translation_summary"], "—")
        self.assertEqual(no_translation[0]["destination_translation_summary"], "—")
        policy.update(main.nat_translation_replacements({
            "nat_type": "ipv4", "to_interface": "ethernet1/2",
            "source_translation_mode": "none", "source_translation_address": "",
            "source_translation_interface": "", "destination_translation_address": "private",
            "destination_translation_port": "9443",
        }))
        updated = main.ET.fromstring(main.update_xml_policy(policy))
        self.assertEqual(updated.findtext("./service"), "tcp-443")
        self.assertIsNone(updated.find("./service/member"))
        self.assertEqual(updated.findtext("./to-interface"), "ethernet1/2")
        self.assertEqual(updated.findtext("./destination-translation/translated-port"), "9443")
        template = (pathlib.Path(main.__file__).parent / "templates" / "workspace_editor.html").read_text()
        self.assertIn("Original Packet", template)
        self.assertIn("Translated Packet", template)
        self.assertIn('name="nat_translation_editor" value="yes"', template)


if __name__ == "__main__":
    unittest.main()
