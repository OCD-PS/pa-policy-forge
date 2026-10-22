"""TLS configuration shared by PAN-OS and Panorama API clients."""

from __future__ import annotations

import os
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


def create_panos_ssl_context(
    ca_bundle: str | None = None,
    pinned_certificate: str | None = None,
    allow_pinned_hostname_mismatch: bool = False,
) -> ssl.SSLContext:
    """Verify PAN-OS identity using system/admin roots and an optional confirmed leaf pin."""
    bundle = (ca_bundle if ca_bundle is not None else os.getenv("PPF_PANOS_CA_BUNDLE", "")).strip()
    if pinned_certificate:
        # Once an endpoint pin exists, trust only that certificate. This ensures
        # certificate rotation fails closed even if the replacement chains to a
        # public/system CA. Partial-chain validation permits a non-CA server leaf
        # to serve as the explicitly confirmed trust anchor.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(cadata=pinned_certificate)
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        if allow_pinned_hostname_mismatch:
            # Only an explicitly confirmed endpoint certificate may replace
            # hostname matching; chain and validity checks remain enabled.
            context.check_hostname = False
        return context

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if bundle:
        # Add device trust to the system roots so public and private PKI targets both work.
        context.load_verify_locations(cafile=bundle)
    return context


def inspect_panos_certificate(endpoint: str, *, context: ssl.SSLContext | None = None) -> dict:
    """Read a TLS peer certificate without sending HTTP data or API credentials.

    First try the currently configured trust policy. If verification fails, repeat
    only the TLS handshake without verification so an administrator can inspect the
    presented certificate before explicitly pinning it.
    """
    parsed = urlsplit(endpoint)
    host = parsed.hostname
    if parsed.scheme != "https" or not host:
        raise ValueError("Een HTTPS-endpoint is vereist")
    port = parsed.port or 443

    def fetch(context_to_use: ssl.SSLContext) -> bytes:
        with socket.create_connection((host, port), timeout=8) as raw_socket:
            with context_to_use.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert(binary_form=True)
        if not certificate:
            raise ValueError("De endpoint stuurde geen TLS-certificaat")
        return certificate

    verified = False
    try:
        der_certificate = fetch(context or ssl.create_default_context(ssl.Purpose.SERVER_AUTH))
        verified = True
    except ssl.SSLCertVerificationError:
        unverified_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified_context.check_hostname = False
        unverified_context.verify_mode = ssl.CERT_NONE
        der_certificate = fetch(unverified_context)

    certificate = x509.load_der_x509_certificate(der_certificate)
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_names = [str(value) for value in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns_names, ip_names = [], []

    try:
        import ipaddress
        endpoint_ip = str(ipaddress.ip_address(host))
    except ValueError:
        endpoint_ip = None
    if endpoint_ip:
        hostname_matches = endpoint_ip in ip_names
    else:
        normalized_host = host.rstrip(".").casefold()
        hostname_matches = any(
            normalized_host == name.rstrip(".").casefold()
            or (
                name.startswith("*.")
                and normalized_host.endswith(name[1:].rstrip(".").casefold())
                and normalized_host.count(".") == name.count(".")
            )
            for name in dns_names
        )

    now = datetime.now(timezone.utc)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    try:
        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca_certificate = basic_constraints.ca
    except x509.ExtensionNotFound:
        is_ca_certificate = False
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
    return {
        "pem": certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "fingerprint": fingerprint,
        "subject": certificate.subject.rfc4514_string() or "(leeg subject)",
        "issuer": certificate.issuer.rfc4514_string() or "(leeg issuer)",
        "common_name": next(
            (attribute.value for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)),
            "",
        ),
        "dns_names": dns_names,
        "ip_names": ip_names,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "valid_now": not_before <= now <= not_after,
        "hostname_matches": hostname_matches,
        "is_ca_certificate": is_ca_certificate,
        "verified_by_current_policy": verified,
    }
