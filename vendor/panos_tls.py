"""TLS configuration shared by PAN-OS and Panorama API clients."""

from __future__ import annotations

import os
import ssl


def create_panos_ssl_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    """Verify PAN-OS server identity, optionally adding an administrator CA bundle."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    bundle = (ca_bundle if ca_bundle is not None else os.getenv("PPF_PANOS_CA_BUNDLE", "")).strip()
    if bundle:
        # Add device trust to the system roots so public and private PKI targets both work.
        context.load_verify_locations(cafile=bundle)
    return context
