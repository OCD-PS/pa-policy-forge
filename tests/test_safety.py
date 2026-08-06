import pathlib
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

from vendor.paloalto_light_syslog import Flow, FlowStore, parse_panos_syslog
from vendor.bdnd_panos_policy_builder import DeploymentConfig, ExistingConfigInventory, apply_existing_inventory

class SafetyTests(unittest.TestCase):
    def test_scm_never_calls_candidate_push(self):
        text=(ROOT/"vendor/bdnd_panos_policy_builder.py").read_text()
        self.assertNotIn('config-versions/candidate:push', text)

    def test_no_http_port_exposed(self):
        text=(ROOT/"docker-compose.yml").read_text()
        self.assertNotIn('"80:', text)

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

    def test_purge_only_removes_selected_firewall(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FlowStore(pathlib.Path(tmp) / "flows.sqlite3", retention_days=0)
            base = dict(receive_time="2026-08-05 12:00:00", src="10.0.0.1", dst="10.0.0.2", src_zone="a", dst_zone="b", src_user="", app="ssl", proto="tcp", dport="443", action="allow", rule="discovery", url_category="", repeat=1, bytes_total=1)
            store.add_flow(Flow(serial="SERIAL-A", **base))
            store.add_flow(Flow(serial="SERIAL-B", **base))
            self.assertEqual(store.purge("SERIAL-A"), 1)
            with store._connect() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM flows WHERE serial='SERIAL-A'").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM flows WHERE serial='SERIAL-B'").fetchone()[0], 1)

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

if __name__ == "__main__": unittest.main()
