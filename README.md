# PA Policy Forge

Self-hosted Palo Alto traffic-flow policy builder with an HTTPS web interface, UDP syslog collection, encrypted target credentials, policy review, and candidate-only writes to SCM, Panorama, or standalone PAN-OS.

## Safety guarantees

- Stores only aggregated `TRAFFIC` flows where `action=allow`; raw syslog is discarded.
- Separates flows per firewall serial before policy generation.
- Encrypts target credentials with a local key stored outside the application database.
- SCM writes objects/rules but never calls `candidate:push`.
- Panorama and standalone use import/partial-load only and never commit.
- HTTP is not exposed; the appliance serves HTTPS only.
- Runtime databases, credentials, keys, certificates, logs, and generated artifacts stay outside Git.

## Install on Ubuntu Server

```bash
sudo ./install.sh
```

Ports:

- `443/tcp`: HTTPS GUI
- `514/udp`: PAN-OS syslog

Initial local login is `admin` / `OCD1234!`; PA Policy Forge forces a password change before any other page is accessible.

The installer creates a self-signed certificate for the server IP and exposes no HTTP listener. To use a trusted certificate, replace `/opt/pa-policy-forge/certs/tls.crt` and `/opt/pa-policy-forge/certs/tls.key` with your certificate and private key, then run `docker compose restart` from `/opt/pa-policy-forge`.

For offline customers, transfer the repository plus a saved container image bundle, load it with `docker load`, and run the same Compose stack. SCM functionality naturally requires connectivity to Palo Alto cloud endpoints.

## First workflow

1. Log in and change the bootstrap password.
2. Configure one or more PAN-OS firewalls to forward TRAFFIC logs to UDP 514.
3. Confirm each serial appears under discovered firewalls.
4. Create a profile, map zones to roles, and enter the target credentials.
5. Generate a preview and inspect/download the review CSV and XML.
6. Use **Naar candidate schrijven** only after review. Commit/deploy separately in SCM, Panorama, or PAN-OS.
