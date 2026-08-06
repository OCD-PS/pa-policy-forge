# PA Policy Forge

Self-hosted Palo Alto traffic-flow policy builder with an HTTPS web interface, UDP syslog collection, encrypted target credentials, policy review, and candidate-only writes to SCM, Panorama, or standalone PAN-OS.

## Safety guarantees

- Stores only aggregated `TRAFFIC` flows where `action=allow`; raw syslog is discarded.
- Separates flows per firewall serial before policy generation.
- Supports an active and optional passive serial in one logical firewall profile;
  failover logs are shown, exported, analyzed, and purged together.
- Stores a separate optional recognition/source IP for each HA node, covering
  deployments where syslog uses distinct management or service-route addresses.
- Fetches a fresh target inventory for every preview and candidate write.
- Prepares a non-pushing policy run for each active profile every 30 minutes. A
  candidate write reuses the latest flow snapshot only while the profile,
  credentials, and builder version still match and the snapshot is at most one
  preparation interval old. Target inventory and duplicate checks are refreshed
  immediately before writing the candidate.
- Reuses exact existing address/service objects and exact matching address,
  service, and application groups; same-name semantic conflicts are never overwritten.
- Encrypts target credentials with a local key stored outside the application database.
- Existing profiles can be edited without exposing stored credentials. Blank credential
  fields preserve the existing encrypted value; only explicitly entered replacements are saved.
- SCM writes objects/rules but never calls `candidate:push`.
- Panorama and standalone use import/partial-load only and never commit.
- The source security-policy name from each syslog flow is retained as its
  positioning anchor. Candidate rules are moved directly before that source
  policy in SCM, Panorama, or standalone PAN-OS. If the anchor is not present
  in the selected target scope/rulebase, the generated rule is moved to the
  bottom instead.
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
   For HA pairs, configure both the active and passive firewall serial.
5. Generate a preview and inspect/download the review CSV and XML.
6. Use **Naar candidate schrijven** only after review. Commit/deploy separately in SCM, Panorama, or PAN-OS.
7. After the accepted rules are manually positioned and deployed, use **Flows purgen** on the profile to start a clean observation cycle. Profiles and run history are retained.

Policy runs can be removed individually from the run history. Deletion removes
the database record plus its review/XML artifacts, after verifying that the
artifact directory is inside the configured runs root. Active runs cannot be deleted.

The Flows page always starts with a device/firewall-group chooser. Flow details
open only after selecting a logical firewall or HA pair.

## Policy management

The **Policybeheer** page uses an Expedition-inspired filter, selection, and
bulk-change workflow. SCM security rules are loaded in rulebase order. A single
PAN-OS-style expression bar supports security-rule fields, `and`, `or`, `not`,
and nested parentheses. Click a row and Ctrl- or Shift-click another row to
select the continuous range. The selected-rule count and **Bulk edit** action
remain available in the fixed bottom action bar. Bulk list changes are explicit
add/remove operations:

The workspace has separate **Policies** and **Objects** navigation. SCM object
inventory is read from the configured object scope. Addresses, address groups,
application groups, services, service groups, and tags can be prepared through
a preview and then written to SCM candidate. Existing objects open in a
PAN-OS-style editor; multi-select delete is available from the fixed bottom
action bar. Addresses support all four PAN-OS address types and tags. Address
groups support static members and dynamic filters. Address, service, and
application groups use searchable member pickers and removable member chips.
Installed applications open as read-only details and their target-specific SCM
catalog is cached for 30 minutes, with background refresh to keep pages responsive.
Services support TCP/UDP,
destination/source ports, and optional timeout overrides. Creation is stopped
when the name or equivalent object already exists, and stale edit/delete drafts
are rejected. Object changes never commit or push the SCM candidate
configuration automatically.
SCM policy inventory includes Security, NAT, QoS, Policy Based Forwarding,
Decryption, Application Override, and Authentication. Unsupported or unavailable
tenant categories are shown explicitly instead of blocking the workspace.
Removing one zone or object never removes the other existing members. A preview
shows every changed value before a separate candidate write. The candidate
write re-fetches the live rules and stops on concurrent changes. SCM is the
first enabled connector; Panorama and standalone use the same UI but are not
enabled for bulk writes yet.

Flow aggregation happens continuously while syslog arrives. CPU-parallel builder work
defaults to `max(1, detected CPUs - 2)`, reserving two logical CPUs for the web UI,
syslog receiver, and operating system.

The preparation cadence can be changed with `PPF_PREPARE_INTERVAL` (seconds,
minimum 300). Automatic preparation never writes or deploys candidate configuration.
