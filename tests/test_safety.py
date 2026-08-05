import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

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

if __name__ == "__main__": unittest.main()
