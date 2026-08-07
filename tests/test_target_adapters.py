import json
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("PPF_DATA_DIR", tempfile.mkdtemp(prefix="forge-adapter-test-"))
os.environ.setdefault("PPF_SYSLOG_PORT", "55141")
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "unit-test-bootstrap-password")

from app import main


class TargetAdapterTests(unittest.TestCase):
    def profile(self, target, **settings):
        defaults = {"device_group": "Branches", "rulebase": "pre", "vsys": "vsys2", "endpoint": "https://example.invalid"}
        defaults.update(settings)
        return {"target_type": target, "settings_json": json.dumps(defaults), "secret_blob": b""}

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

    def test_protected_routes_require_authentication(self):
        client = main.app.test_client()
        for path in ("/", "/runs/1", "/runs/1/csv", "/profiles/1/catalog/applications", "/config-workspaces/1/export/xml", "/config-workspaces/1/push-preview", "/config-workspaces/1/edit"):
            response = client.get(path, base_url="https://forge.test")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["Location"], "/login")

    def test_offline_workspace_templates_compile(self):
        main.app.jinja_env.get_template("app.html")
        main.app.jinja_env.get_template("workspace_push.html")
        main.app.jinja_env.get_template("workspace_editor.html")
        main.app.jinja_env.get_template("workspace_policy_preview.html")

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


if __name__ == "__main__":
    unittest.main()
