import json
import os
import tempfile
import unittest
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

    def test_workspace_actionbar_is_scoped_to_the_right_content_pane(self):
        css = (main.BASE / "app" / "static" / "app.css").read_text()
        self.assertIn(".workspace-editor-content .object-actionbar", css)
        self.assertIn("position: sticky", css)
        self.assertIn("left: auto", css)
        main.app.jinja_env.get_template("workspace_editor.html")
        main.app.jinja_env.get_template("workspace_policy_preview.html")

    def test_workspace_policy_editor_is_actionable_and_supports_rename(self):
        template = (main.BASE / "app" / "templates" / "workspace_editor.html").read_text()
        javascript = (main.BASE / "app" / "static" / "app.js").read_text()
        self.assertIn('name="name" value="{{edit_policy.name}}" required', template)
        self.assertIn("data-offline-policy-field", template)
        self.assertIn("data-offline-policy-picker", template)
        self.assertIn("data-offline-policy-kinds", template)
        self.assertIn("function setupOfflinePolicyTabs()", javascript)
        self.assertIn("_offlineAddValue", javascript)

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
        xml = b'''<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules><entry name="old-name"><from><member>Trust</member></from><to><member>Internet</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>web-browsing</member></application><service><member>application-default</member></service><action>allow</action><unknown>keep</unknown></entry></rules></security></rulebase></entry></vsys></entry></devices></config>'''
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


if __name__ == "__main__":
    unittest.main()
