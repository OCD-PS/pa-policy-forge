from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import http.server
import os
from pathlib import Path
import ssl
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))
os.environ.setdefault("PPF_BOOTSTRAP_PASSWORD", "isolated-security-bootstrap-value")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import main
from vendor import bdnd_panos_policy_builder as policy_api
from vendor.panos_tls import create_panos_ssl_context, inspect_panos_certificate


class SecurityHardeningTests(unittest.TestCase):
    def with_database(self, operation):
        with tempfile.TemporaryDirectory() as temporary:
            original_db = main.APP_DB
            main.APP_DB = Path(temporary) / "forge.sqlite3"
            try:
                operation(main.APP_DB)
            finally:
                main.APP_DB = original_db

    def test_fresh_database_requires_explicit_bootstrap_and_forces_password_change(self):
        def check(path):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("PPF_BOOTSTRAP_PASSWORD", None)
                with self.assertRaisesRegex(RuntimeError, "requires PPF_BOOTSTRAP_PASSWORD"):
                    main.init_db()
                with main.db() as conn:
                    self.assertIsNone(conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone())

                os.environ["PPF_BOOTSTRAP_PASSWORD"] = "unique-bootstrap-password-for-test"
                main.init_db()
                with main.db() as conn:
                    admin = conn.execute(
                        "SELECT password_hash,must_change FROM users WHERE username='admin'"
                    ).fetchone()
                self.assertEqual(admin["must_change"], 1)
                self.assertTrue(main.password_ok("unique-bootstrap-password-for-test", admin["password_hash"]))
        self.with_database(check)

    def test_upgrade_preserves_existing_account_state_and_password(self):
        def check(path):
            import sqlite3

            original_hash = main.password_hash("existing-account-password")
            conn = sqlite3.connect(path)
            with conn:
                conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 1)")
                conn.execute("INSERT INTO users(username,password_hash,must_change) VALUES('admin',?,0)", (original_hash,))
            conn.close()
            with patch.dict(os.environ, {"PPF_BOOTSTRAP_PASSWORD": "new-bootstrap-value-that-must-not-reset"}):
                main.init_db()
            with main.db() as conn:
                admin = conn.execute("SELECT password_hash,must_change FROM users WHERE username='admin'").fetchone()
            self.assertEqual(admin["password_hash"], original_hash)
            self.assertEqual(admin["must_change"], 0)
            self.assertTrue(main.password_ok("existing-account-password", admin["password_hash"]))
        self.with_database(check)

    def test_panos_tls_verifies_certificate_and_hostname_with_optional_ca(self):
        with tempfile.TemporaryDirectory() as temporary:
            ca_file = Path(temporary) / "device-ca.pem"
            key_file = Path(temporary) / "server-key.pem"
            now = datetime.now(timezone.utc)
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Policy Forge test CA")])
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
            ca_certificate = (
                x509.CertificateBuilder()
                .subject_name(issuer)
                .issuer_name(issuer)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=None, decipher_only=None,
                ), critical=True)
                .sign(ca_key, hashes.SHA256())
            )
            certificate = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(server_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .sign(ca_key, hashes.SHA256())
            )
            ca_file.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
            cert_file = Path(temporary) / "server-cert.pem"
            cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_file.write_bytes(server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))

            class HealthHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

                def log_message(self, *_args):
                    pass

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(str(cert_file), str(key_file))
            server.socket = server_context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"https://127.0.0.1:{server.server_port}/"
            try:
                with self.assertRaises(urllib.error.URLError):
                    urllib.request.urlopen(url, context=create_panos_ssl_context(), timeout=3)
                trusted = create_panos_ssl_context(str(ca_file))
                self.assertEqual(trusted.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(trusted.check_hostname)
                self.assertIn(
                    ca_certificate.public_bytes(serialization.Encoding.DER),
                    trusted.get_ca_certs(binary_form=True),
                )
                with urllib.request.urlopen(url, context=trusted, timeout=3) as response:
                    self.assertEqual(response.read(), b"ok")
                pinned = create_panos_ssl_context(pinned_certificate=cert_file.read_text(encoding="ascii"))
                self.assertEqual(pinned.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(pinned.check_hostname)
                self.assertNotIn(
                    ca_certificate.public_bytes(serialization.Encoding.DER),
                    pinned.get_ca_certs(binary_form=True),
                )
                with urllib.request.urlopen(url, context=pinned, timeout=3) as response:
                    self.assertEqual(response.read(), b"ok")
                with self.assertRaises(urllib.error.URLError):
                    urllib.request.urlopen(
                        url.replace("127.0.0.1", "localhost"), context=pinned, timeout=3
                    )
                inspected = inspect_panos_certificate(
                    url.rstrip("/"), context=create_panos_ssl_context()
                )
                self.assertFalse(inspected["verified_by_current_policy"])
                self.assertTrue(inspected["hostname_matches"])
                self.assertEqual(inspected["fingerprint"], certificate.fingerprint(hashes.SHA256()).hex().upper())
                trusted_inspection = inspect_panos_certificate(url.rstrip("/"), context=trusted)
                self.assertTrue(trusted_inspection["verified_by_current_policy"])
                with self.assertRaises(urllib.error.URLError):
                    urllib.request.urlopen(
                        url.replace("127.0.0.1", "localhost"),
                        context=create_panos_ssl_context(str(ca_file)),
                        timeout=3,
                    )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_panorama_uses_verified_context_and_scm_keeps_default_tls(self):
        profile_secret = main.fernet.encrypt(b'{"username":"api-user","password":"api-password"}')
        for target_type in ("panos", "panorama"):
            with self.subTest(target_type=target_type):
                profile = {
                    "id": 81001 if target_type == "panos" else 81002,
                    "updated_at": "version-1",
                    "target_type": target_type,
                    "settings_json": '{"endpoint":"https://fw.example"}',
                    "secret_blob": profile_secret,
                }
                response = ET.Element("response")
                key_node = ET.SubElement(response, "key")
                key_node.text = "test-api-key"
                main._panos_key_cache.pop(profile["id"], None)
                with patch.object(main, "panos_api_post", return_value="<response><result><key>test-api-key</key></result></response>") as post, \
                        patch.object(main.policy_api, "require_success", return_value=response), \
                        patch.dict(os.environ, {"PPF_PANOS_CA_BUNDLE": ""}):
                    main.panos_profile_context(profile)
                    context = post.call_args.args[2]
                    self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                    self.assertTrue(context.check_hostname)

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b'{"items":[]}'

        with patch.object(policy_api, "credential_urlopen", return_value=Response()) as open_request:
            policy_api.scm_http_request("GET", "https://scm.example/api", "token")
        self.assertNotIn("context", open_request.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
