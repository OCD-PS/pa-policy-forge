from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import threading
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID


CERTIFICATE_MAX_BYTES = 256 * 1024
PRIVATE_KEY_MAX_BYTES = 64 * 1024
_CERTIFICATE_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.+?-----END CERTIFICATE-----",
    re.DOTALL,
)
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_INSTALL_LOCK = threading.Lock()


class CertificateError(ValueError):
    pass


def normalize_fqdn(value: str) -> str:
    candidate = str(value or "").strip().rstrip(".")
    if not candidate or "://" in candidate or any(char in candidate for char in "/?#@"):
        raise CertificateError("Geef alleen een geldige FQDN op, zonder protocol of pad")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise CertificateError("Gebruik voor een FQDN-certificaat een DNS-naam, geen IP-adres")
    try:
        ascii_name = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise CertificateError("De FQDN bevat ongeldige tekens") from exc
    if len(ascii_name) > 253 or "." not in ascii_name:
        raise CertificateError("De FQDN moet een volledige DNS-naam zijn")
    if any(not _DNS_LABEL.fullmatch(label) for label in ascii_name.split(".")):
        raise CertificateError("De FQDN bevat een ongeldig DNS-label")
    return ascii_name


def load_appliance_config(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def configured_fqdn(path: Path) -> str:
    value = str(load_appliance_config(path).get("fqdn") or "")
    try:
        return normalize_fqdn(value) if value else ""
    except CertificateError:
        return ""


def read_upload(uploaded, limit: int, label: str) -> bytes:
    if not uploaded or not getattr(uploaded, "filename", ""):
        raise CertificateError(f"Kies een bestand voor {label}")
    content = uploaded.stream.read(limit + 1)
    if not content:
        raise CertificateError(f"{label} is leeg")
    if len(content) > limit:
        raise CertificateError(f"{label} is te groot")
    return content


def _certificate_chain(pem_bytes: bytes) -> list[x509.Certificate]:
    blocks = _CERTIFICATE_BLOCK.findall(pem_bytes)
    if not blocks or _CERTIFICATE_BLOCK.sub(b"", pem_bytes).strip():
        raise CertificateError("Het certificaatbestand moet een geldige PEM-chain bevatten")
    try:
        return [x509.load_pem_x509_certificate(block) for block in blocks]
    except ValueError as exc:
        raise CertificateError("De PEM certificate chain kan niet worden gelezen") from exc


def _dns_pattern_matches(pattern: str, fqdn: str) -> bool:
    pattern = pattern.rstrip(".").lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return fqdn.endswith("." + suffix) and fqdn.count(".") == suffix.count(".") + 1
    return pattern == fqdn


def _public_key_bytes(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _name_common_name(name: x509.Name) -> str:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else name.rfc4514_string()


def validate_certificate_bundle(certificate_pem: bytes, private_key_pem: bytes, fqdn: str) -> dict[str, object]:
    fqdn = normalize_fqdn(fqdn)
    certificates = _certificate_chain(certificate_pem)
    leaf = certificates[0]
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise CertificateError("De private key moet een geldige, niet-versleutelde PEM-key zijn") from exc
    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        raise CertificateError("Dit private-keytype wordt niet ondersteund")
    if isinstance(private_key, rsa.RSAPrivateKey) and private_key.key_size < 2048:
        raise CertificateError("Gebruik een RSA-key van minimaal 2048 bits")
    if isinstance(private_key, ec.EllipticCurvePrivateKey) and private_key.key_size < 256:
        raise CertificateError("Gebruik een elliptic-curve key van minimaal 256 bits")
    if _public_key_bytes(private_key.public_key()) != _public_key_bytes(leaf.public_key()):
        raise CertificateError("Het certificaat en de private key horen niet bij elkaar")
    try:
        dns_names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound as exc:
        raise CertificateError("Het certificaat bevat geen DNS Subject Alternative Name") from exc
    if not any(_dns_pattern_matches(pattern, fqdn) for pattern in dns_names):
        raise CertificateError(f"Het certificaat is niet geldig voor {fqdn}")
    current = datetime.now(timezone.utc)
    if leaf.not_valid_before_utc > current:
        raise CertificateError("Het certificaat is nog niet geldig")
    if leaf.not_valid_after_utc <= current:
        raise CertificateError("Het certificaat is verlopen")
    with tempfile.TemporaryDirectory(prefix="ppf-certificate-") as temporary:
        cert_path = Path(temporary) / "tls.crt"
        key_path = Path(temporary) / "tls.key"
        cert_path.write_bytes(certificate_pem)
        key_path.write_bytes(private_key_pem)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert_path, key_path)
        except (OSError, ssl.SSLError) as exc:
            raise CertificateError("OpenSSL kan deze certificate chain en private key niet laden") from exc
    return {
        "fqdn": fqdn,
        "subject": _name_common_name(leaf.subject),
        "issuer": _name_common_name(leaf.issuer),
        "dns_names": list(dns_names),
        "valid_from": leaf.not_valid_before_utc.date().isoformat(),
        "valid_until": leaf.not_valid_after_utc.date().isoformat(),
        "fingerprint": leaf.fingerprint(hashes.SHA256()).hex().upper(),
        "self_signed": leaf.subject == leaf.issuer,
    }


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
    finally:
        temporary.unlink(missing_ok=True)


def _restore(path: Path, previous: bytes | None, mode: int) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
    else:
        _atomic_write(path, previous, mode)


def _install_certificate(cert_dir: Path, config_path: Path, fqdn: str, certificate_pem: bytes, private_key_pem: bytes) -> dict[str, object]:
    summary = validate_certificate_bundle(certificate_pem, private_key_pem, fqdn)
    cert_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert_path = cert_dir / "tls.crt"
    key_path = cert_dir / "tls.key"
    previous_cert = cert_path.read_bytes() if cert_path.is_file() else None
    previous_key = key_path.read_bytes() if key_path.is_file() else None
    previous_config = config_path.read_bytes() if config_path.is_file() else None
    try:
        if previous_cert is not None:
            _atomic_write(cert_dir / "tls.crt.previous", previous_cert, 0o644)
        if previous_key is not None:
            _atomic_write(cert_dir / "tls.key.previous", previous_key, 0o600)
        _atomic_write(cert_path, certificate_pem, 0o644)
        _atomic_write(key_path, private_key_pem, 0o600)
        validate_certificate_bundle(cert_path.read_bytes(), key_path.read_bytes(), str(summary["fqdn"]))
        config = load_appliance_config(config_path)
        config["fqdn"] = summary["fqdn"]
        config_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(
            config_path,
            (json.dumps(config, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            0o600,
        )
    except Exception:
        _restore(cert_path, previous_cert, 0o644)
        _restore(key_path, previous_key, 0o600)
        _restore(config_path, previous_config, 0o600)
        raise
    return summary


def install_certificate(cert_dir: Path, config_path: Path, fqdn: str, certificate_pem: bytes, private_key_pem: bytes) -> dict[str, object]:
    with _INSTALL_LOCK:
        return _install_certificate(cert_dir, config_path, fqdn, certificate_pem, private_key_pem)


def certificate_summary(cert_path: Path, config_path: Path) -> dict[str, object]:
    fqdn = configured_fqdn(config_path)
    result: dict[str, object] = {"available": False, "fqdn": fqdn}
    try:
        certificates = _certificate_chain(cert_path.read_bytes())
        leaf = certificates[0]
        try:
            dns_names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            dns_names = []
        result.update(
            available=True,
            subject=_name_common_name(leaf.subject),
            issuer=_name_common_name(leaf.issuer),
            dns_names=list(dns_names),
            valid_from=leaf.not_valid_before_utc.date().isoformat(),
            valid_until=leaf.not_valid_after_utc.date().isoformat(),
            fingerprint=leaf.fingerprint(hashes.SHA256()).hex().upper(),
            self_signed=leaf.subject == leaf.issuer,
        )
    except (OSError, CertificateError, ValueError) as exc:
        result["error"] = str(exc)
    return result
