import pathlib
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

from vendor.paloalto_light_syslog import Flow, FlowStore, parse_panos_syslog
from vendor.bdnd_bpa_policy_builder import aggregate_flows
from vendor.bdnd_panos_policy_builder import (
    DeploymentConfig,
    ExistingConfigInventory,
    ZoneRoleConfig,
    apply_existing_inventory,
    deploy_scm_candidate,
    merge_candidates,
    movable_anchor_map,
    rule_move_destination,
)

class SafetyTests(unittest.TestCase):
    def test_scm_deploy_is_explicitly_device_scoped(self):
        text=(ROOT/"vendor/bdnd_panos_policy_builder.py").read_text()
        self.assertIn('config-versions/candidate:push', text)
        self.assertIn('payload={"devices": targets}', text)
        self.assertNotIn('payload={"folder":', text)

    def test_scm_deploy_devices_are_runtime_only(self):
        app_text=(ROOT/"app/main.py").read_text()
        self.assertIn('"PPF_SCM_DEPLOY_DEVICES": ",".join(profile_serials(profile))', app_text)
        config_block = app_text[app_text.index("def write_config"):app_text.index("def export_profile_flows")]
        self.assertNotIn("PPF_SCM_DEPLOY_DEVICES", config_block)

    def test_run_history_is_profile_scoped_and_success_limited(self):
        app_text=(ROOT/"app/main.py").read_text()
        template=(ROOT/"app/templates/app.html").read_text()
        self.assertIn('request.args.get("run_profile", type=int)', app_text)
        self.assertIn("status='complete' ORDER BY id DESC LIMIT 5", app_text)
        self.assertIn("status='complete' \"\n            \"ORDER BY id DESC LIMIT -1 OFFSET ?", app_text)
        self.assertIn("run_profile=p.id", template)
        self.assertIn("selected_run_profile", template)

    @patch("vendor.bdnd_panos_policy_builder.get_scm_token", return_value="test-token")
    @patch("vendor.bdnd_panos_policy_builder.scm_http_request")
    def test_scm_deploy_waits_for_both_device_jobs(self, request, _token):
        request.side_effect = [
            {"data": [{"id": "100"}]},
            {"data": [{"id": "100", "status_str": "FIN", "result_str": "OK"}]},
            {"data": [
                {"id": "101", "parent_id": "100", "device_name": "active", "status_str": "FIN", "result_str": "OK"},
                {"id": "102", "parent_id": "100", "device_name": "passive", "status_str": "FIN", "result_str": "OK"},
            ]},
        ]
        scm = SimpleNamespace(scm_api_base="https://api.strata.paloaltonetworks.com/config/security/v1")
        self.assertEqual(deploy_scm_candidate(scm, ["active", "passive"]), "100")
        self.assertEqual(request.call_args_list[0].kwargs["payload"], {"devices": ["active", "passive"]})

    def test_no_http_port_exposed(self):
        text=(ROOT/"docker-compose.yml").read_text()
        self.assertNotIn('"80:', text)

    def test_distribution_uses_documented_forced_change_bootstrap_login(self):
        compose=(ROOT/"docker-compose.yml").read_text()
        installer=(ROOT/"install.sh").read_text()
        self.assertNotIn("OCD1234!", compose)
        self.assertIn("${PPF_BOOTSTRAP_PASSWORD:-admin}", compose)
        self.assertIn("PPF_BOOTSTRAP_PASSWORD=admin", installer)
        self.assertIn("Initial login: admin / admin", installer)

    def test_untrusted_api_xml_uses_defusedxml(self):
        text=(ROOT/"vendor/bdnd_panos_policy_builder.py").read_text()
        self.assertIn("SafeET.fromstring(xml_text)", text)

    def test_panos_keygen_credentials_are_never_sent_in_url(self):
        app_text=(ROOT/"app/main.py").read_text()
        builder_text=(ROOT/"vendor/bdnd_panos_policy_builder.py").read_text()
        self.assertIn("panos_api_post(endpoint, {\"type\": \"keygen\"", app_text)
        self.assertIn("api_post_form(deployment.panos_endpoint, {\"type\": \"keygen\"", builder_text)
        self.assertNotIn("api_get(deployment.panos_endpoint, {\"type\": \"keygen\"", builder_text)

    def test_panos_api_keys_use_header_not_query_string(self):
        app_text=(ROOT/"app/main.py").read_text()
        builder_text=(ROOT/"vendor/bdnd_panos_policy_builder.py").read_text()
        self.assertIn('headers["X-PAN-KEY"] = api_key', app_text)
        self.assertIn('{"X-PAN-KEY": api_key}', builder_text)
        self.assertIn('request_params.pop("key", "")', builder_text)

    def test_sha1_is_explicitly_non_security_naming_only(self):
        text=(ROOT/"vendor/bdnd_panos_policy_builder.py").read_text()
        for line in text.splitlines():
            if "hashlib.sha1(" in line: self.assertIn("usedforsecurity=False", line)

    def test_runtime_secrets_ignored(self):
        text=(ROOT/".gitignore").read_text()
        self.assertIn("*.key",text)
        self.assertIn("*.sqlite3",text)

    def test_distribution_has_no_bdnd_certificate_name(self):
        dockerfile=(ROOT/"Dockerfile").read_text()
        installer=(ROOT/"install.sh").read_text()
        template=(ROOT/"app/templates/app.html").read_text()
        self.assertNotIn("pa-policy-forge.bdnd.be", dockerfile + installer + template)
        self.assertIn("/certs/tls.crt", dockerfile)
        self.assertIn("/certs/tls.key", dockerfile)

    def test_builder_credentials_are_environment_only(self):
        text=(ROOT/"app/main.py").read_text()
        self.assertIn('panos_password = ""', text)
        self.assertIn('scm_client_secret = ""', text)
        self.assertIn('PPF_SCM_CLIENT_SECRET', text)

    def test_policy_picker_is_moved_into_active_dialog(self):
        script = (ROOT / "app/static/app.js").read_text()
        self.assertIn('activeDialog.appendChild(valuePicker)', script)

    def test_panos_12_versioned_traffic_log_is_parsed(self):
        line = (
            '<14>Aug  5 12:49:02 PA-VM '
            '1,2026/08/05 12:48:58,007954000875040,TRAFFIC,end,3073,'
            '2026/08/05 12:48:58,10.74.80.39,10.74.80.33,0.0.0.0,0.0.0.0,'
            'Allow_All_From_LAB,,,snmpv2-get-request,vsys1,Servers-2180,Servers-2180,'
            'ethernet1/2,ethernet1/2,PA-Policy-Forge-Log-Forwarding,'
            '2026/08/05 12:49:02,8375,1,37255,161,0,0,0x19,udp,allow,211'
        )
        flow = parse_panos_syslog(line)
        self.assertIsNotNone(flow)
        self.assertEqual(flow.serial, '007954000875040')
        self.assertEqual(flow.rule, 'Allow_All_From_LAB')
        self.assertEqual(flow.action, 'allow')
        self.assertEqual(flow.repeat, 1)

    def test_purge_removes_both_cluster_nodes_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FlowStore(pathlib.Path(tmp) / "flows.sqlite3", retention_days=0)
            base = dict(receive_time="2026-08-05 12:00:00", src="10.0.0.1", dst="10.0.0.2", src_zone="a", dst_zone="b", src_user="", app="ssl", proto="tcp", dport="443", action="allow", rule="discovery", url_category="", repeat=1, bytes_total=1)
            store.add_flow(Flow(serial="SERIAL-A", **base))
            store.add_flow(Flow(serial="SERIAL-B", **base))
            store.add_flow(Flow(serial="SERIAL-C", **base))
            self.assertEqual(store.purge_serials(["SERIAL-A", "SERIAL-B"]), 2)
            with store._connect() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM flows WHERE serial='SERIAL-A'").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM flows WHERE serial='SERIAL-B'").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM flows WHERE serial='SERIAL-C'").fetchone()[0], 1)

    def test_existing_objects_and_exact_groups_are_reused(self):
        root = ET.fromstring("""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address><entry name="new-a"><ip-netmask>10.0.0.1/32</ip-netmask></entry><entry name="new-b"><ip-netmask>10.0.0.2/32</ip-netmask></entry></address><address-group/><service><entry name="new-https"><protocol><tcp><port>443</port></tcp></protocol></entry></service><service-group/><rulebase><security><rules><entry name="rule-1"><source><member>new-a</member><member>new-b</member></source><destination><member>any</member></destination><application><member>ssl</member></application><service><member>new-https</member></service></entry></rules></security></rulebase></entry></vsys></entry></devices></config>""")
        deployment = DeploymentConfig(False, False, "", "pre", "", "vsys1", "", "", "", "", False)
        inventory = ExistingConfigInventory(
            addresses={("ip-netmask", "10.0.0.1/32"): "HOST-A", ("ip-netmask", "10.0.0.2/32"): "HOST-B"},
            address_groups={frozenset({"HOST-A", "HOST-B"}): "HOSTS-AB"},
            services={("tcp", "443"): "HTTPS"},
            service_groups={},
            application_groups={frozenset({"ssl"}): "APP-SSL"},
            address_names={"HOST-A", "HOST-B"}, address_group_names={"HOSTS-AB"}, service_names={"HTTPS"}, service_group_names=set(),
        )
        rows = [{"name": "rule-1"}]
        reused = apply_existing_inventory(ET.ElementTree(root), rows, deployment, inventory)
        rule = root.find(".//rules/entry")
        self.assertEqual([x.text for x in rule.findall("./source/member")], ["HOSTS-AB"])
        self.assertEqual([x.text for x in rule.findall("./service/member")], ["HTTPS"])
        self.assertEqual([x.text for x in rule.findall("./application/member")], ["APP-SSL"])
        self.assertEqual(len(root.findall(".//address/entry")), 0)
        self.assertEqual(reused["addresses"], 2)

    def test_syslog_source_rule_is_preserved_as_position_anchor(self):
        base = {
            "src": "10.0.0.1", "dst": "10.0.0.2", "src_zone": "trust", "dst_zone": "dmz",
            "app": "ssl", "proto": "tcp", "dport": "443", "action": "allow", "repeat": "3", "bytes": "100",
        }
        aggregates = aggregate_flows([{**base, "rule": "Discovery-A"}, {**base, "rule": "Discovery-B"}], {"allow"})
        candidates = merge_candidates(aggregates, 1, 0, ZoneRoleConfig({"trust": "client", "dmz": "server"}))
        self.assertEqual({candidate.anchor_rule for candidate in candidates}, {"Discovery-A", "Discovery-B"})

    def test_only_web_ports_are_generalized_for_client_to_internet(self):
        base = {
            "src": "10.0.0.1", "dst": "198.51.100.1", "src_zone": "trust",
            "dst_zone": "internet", "action": "allow", "repeat": "3", "bytes": "100",
            "rule": "Discovery",
        }
        aggregates = aggregate_flows([
            {**base, "app": "ssl", "proto": "tcp", "dport": "443"},
            {**base, "app": "web-browsing", "proto": "tcp", "dport": "80", "dst": "198.51.100.2"},
            {**base, "app": "ntp-base", "proto": "udp", "dport": "123", "dst": "198.51.100.3"},
            {**base, "app": "ssl", "proto": "tcp", "dport": "9440", "dst": "198.51.100.4"},
        ], {"allow"})
        candidates = merge_candidates(
            aggregates, 1, 0, ZoneRoleConfig({"trust": "client", "internet": "internet"})
        )
        observed = {(candidate.app, candidate.service_members) for candidate in candidates}
        self.assertEqual(observed, {
            ("any", ("service-http",)),
            ("any", ("service-https",)),
            ("ntp-base", ("application-default",)),
            ("ssl", ("9440_TCP",)),
        })

    def test_source_rule_is_kept_for_positioning(self):
        rows = [{"name": "generated", "anchor_rule": "Discovery", "preflight_status": "new"}]
        self.assertEqual(movable_anchor_map(rows), {"generated": "Discovery"})
        self.assertEqual(rule_move_destination("Discovery", {"Discovery"}), ("before", "Discovery"))
        self.assertEqual(rule_move_destination("Missing", {"Discovery"}), ("bottom", ""))

if __name__ == "__main__": unittest.main()
