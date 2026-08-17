from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.certificates import (
    CertificateError,
    certificate_summary,
    install_certificate,
    normalize_fqdn,
    validate_certificate_bundle,
)
from app.http_redirect import redirect_location


def certificate_bundle(fqdn: str, key=None, *, days: int = 30) -> tuple[bytes, bytes]:
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)])
    current = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=5))
        .not_valid_after(current + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(fqdn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


class CertificateTests(unittest.TestCase):
    def test_fqdn_normalization_rejects_urls_ips_and_partial_names(self):
        self.assertEqual(normalize_fqdn("Forge.Customer.Example."), "forge.customer.example")
        for value in ("https://forge.example", "192.0.2.1", "localhost", "bad_name.example", "forge.example/path"):
            with self.assertRaises(CertificateError):
                normalize_fqdn(value)

    def test_bundle_validation_checks_dns_name_and_matching_key(self):
        certificate, private_key = certificate_bundle("forge.customer.example")
        summary = validate_certificate_bundle(certificate, private_key, "forge.customer.example")
        self.assertEqual(summary["fqdn"], "forge.customer.example")
        self.assertTrue(summary["self_signed"])
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with self.assertRaisesRegex(CertificateError, "horen niet bij elkaar"):
            validate_certificate_bundle(certificate, other_pem, "forge.customer.example")
        with self.assertRaisesRegex(CertificateError, "niet geldig"):
            validate_certificate_bundle(certificate, private_key, "other.customer.example")

    def test_certificate_install_is_atomic_and_preserves_previous_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert_dir = root / "certs"
            config = root / "data" / "appliance.json"
            first_cert, first_key = certificate_bundle("old.customer.example")
            install_certificate(cert_dir, config, "old.customer.example", first_cert, first_key)
            new_cert, new_key = certificate_bundle("new.customer.example")
            install_certificate(cert_dir, config, "new.customer.example", new_cert, new_key)
            self.assertEqual((cert_dir / "tls.crt").read_bytes(), new_cert)
            self.assertEqual((cert_dir / "tls.key").read_bytes(), new_key)
            self.assertEqual((cert_dir / "tls.crt.previous").read_bytes(), first_cert)
            self.assertEqual((cert_dir / "tls.key.previous").read_bytes(), first_key)
            self.assertEqual(json.loads(config.read_text())["fqdn"], "new.customer.example")
            summary = certificate_summary(cert_dir / "tls.crt", config)
            self.assertTrue(summary["available"])
            self.assertEqual(summary["fqdn"], "new.customer.example")

    def test_http_redirect_prefers_configured_fqdn_and_rejects_host_injection(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "appliance.json"
            config.write_text('{"fqdn":"forge.customer.example"}', encoding="utf-8")
            self.assertEqual(
                redirect_location("/settings?tab=tls", "attacker.invalid", config),
                "https://forge.customer.example/settings?tab=tls",
            )
            config.write_text("{}", encoding="utf-8")
            self.assertEqual(
                redirect_location("/", "192.0.2.10:80", config),
                "https://192.0.2.10/",
            )
            with self.assertRaises(CertificateError):
                redirect_location("/", "attacker.invalid", config)
            with patch.dict(os.environ, {"PPF_REDIRECT_ALLOWED_HOSTS": "forge.customer.example"}):
                self.assertEqual(
                    redirect_location("/", "forge.customer.example:80", config),
                    "https://forge.customer.example/",
                )


if __name__ == "__main__":
    unittest.main()
