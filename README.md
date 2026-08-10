# PA Policy Forge

Self-hosted Palo Alto traffic-flow policy builder with an HTTPS web interface, UDP syslog collection, encrypted target credentials, policy review, and target-aware pushes to SCM, Panorama, or standalone PAN-OS.

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
- SCM generated-policy pushes write objects/rules to the configured folder, then deploy
  the candidate to the active and optional passive serial from the firewall profile.
  Device serials are used only by the deployment operation and never added to policy payloads.
- SCM deployment success requires both the parent job and every targeted firewall child job
  to finish with `FIN/OK`.
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

The default login is `admin` / `admin`. For the current lab workflow PA Policy
Forge does not force a password change. Direct Docker Compose deployments may
override the initial password through `PPF_BOOTSTRAP_PASSWORD`. Change this
behavior before using the application in a customer or otherwise untrusted
environment.

The installer also pins the published container ports to the appliance's
primary address through `PPF_BIND_ADDRESS`. Override `PPF_BIND_ADDRESS` and
`PPF_TRUSTED_HOSTS` in `/opt/pa-policy-forge/.env` when the appliance uses a
different management address or additional DNS aliases.

The installer creates a self-signed certificate for the server IP and exposes no HTTP listener. To use a trusted certificate, replace `/opt/pa-policy-forge/certs/tls.crt` and `/opt/pa-policy-forge/certs/tls.key` with your certificate and private key, then run `docker compose restart` from `/opt/pa-policy-forge`.

For offline customers, transfer the repository plus a saved container image bundle, load it with `docker load`, and run the same Compose stack. SCM functionality naturally requires connectivity to Palo Alto cloud endpoints.

## First workflow

1. Log in with the configured bootstrap account.
2. Configure one or more PAN-OS firewalls to forward TRAFFIC logs to UDP 514.
3. Confirm each serial appears under discovered firewalls.
4. Create a profile, map zones to roles, and enter the target credentials.
   For HA pairs, configure both the active and passive firewall serial.
5. Generate a preview and inspect/download the review CSV and XML.
6. Use **Push** only after review. SCM-generated policies are written to the configured
   folder and deployed to the profile's HA targets. Panorama and standalone writes remain
   candidate-only and require their normal commit workflow.
7. After the accepted rules are manually positioned and deployed, use **Flows purgen** on the profile to start a clean observation cycle. Profiles and run history are retained.

Policy runs can be removed individually from the run history. Deletion removes
the database record plus its review/XML artifacts, after verifying that the
artifact directory is inside the configured runs root. Active runs cannot be deleted.

The Flows page always starts with a device/firewall-group chooser. Flow details
open only after selecting a logical firewall or HA pair.

## Offline configuration workspaces

Panorama and standalone profiles support complete offline configuration snapshots.
A workspace is selected from **Policybeheer** rather than from a separate product
area. On first use, a Panorama or standalone profile chooses a complete API pull
into XML, an XML import, or an existing complete XML workspace. The selected
workspace is remembered per profile and opens automatically on later visits. A
visible source-change action allows a fresh pull, a new import, or selection of an
older workspace. SCM continues directly with its live API workflow. The editor
displays the acquisition source and uses the complete XML as its backing document.
A snapshot can be uploaded as PAN-OS XML or pulled from the target's complete
candidate configuration through the XML API. PA Policy Forge validates the XML
with a hardened parser, verifies that its flavor matches the selected profile,
stores the complete normalized XML with a SHA-256 fingerprint, and inventories:

- Panorama device groups, parent relationships, reference templates, templates,
  template stacks, pre/post policies, and object counts;
- standalone virtual systems, interfaces, zones, policies, and objects;
- the PAN-OS version and the full configurable Policies, Objects, Network, and
  Device navigation tree.

The workspace navigation is vertical and independently collapsible. Complete XML
and best-effort set-command exports are available. A complete snapshot can also be
uploaded through the target XML API and loaded as the new candidate configuration.
Supported entries in the vertical tree link directly to their policy, object,
Network, or Device view. Network and Device records open in an orange PAN-OS-style
editor with grouped tabs, typed booleans, multi-value chips, rename, duplicate,
delete, and a mandatory preview. Internal navigation and form targets are covered
by authenticated route-and-fragment regression tests.
This high-impact action requires typing the workspace name and never commits the
candidate automatically. Device groups, templates, VSYS selections, and unknown
XML nodes remain preserved so later graphical editors can operate as scoped diffs
without reconstructing or dropping unsupported configuration.

The offline editor resolves Panorama policy and object inheritance from Shared
through parent device groups to the selected device group. Inherited entries are
visible but read-only. Standalone workspaces use the selected VSYS while retaining
device-level Network configuration. A local policy edit has a before/after preview
and creates a new immutable workspace version: only the exact selected rule node is
replaced, unknown XML is preserved, and a fingerprint prevents applying a draft to
a changed source snapshot. Network and Device edits use the same immutable
workspace flow. Panorama records retain their concrete owner template, including
records shown through a template stack; standalone zones remain VSYS-scoped while
interfaces and routing remain device-scoped. Passwords, private keys, hashes, and
large certificate blobs are not exposed to the browser and remain untouched.

SCM exposes matching Network and Device navigation through its native
`/config/network/v1` and `/config/device/v1` resources. Edits are previewed and
written to the selected folder, snippet, or device candidate; the existing profile
**Push** operation remains the explicit deployment step. The SCM service account
must have access to the corresponding Network or Device API family; an HTTP status
is shown when that tenant role does not permit the requested configuration family.

## Policy management

The **Policybeheer** page uses an Expedition-inspired filter, selection, and
bulk-change workflow. SCM security rules are loaded in rulebase order. A single
PAN-OS-style expression bar supports security-rule fields, `and`, `or`, `not`,
and nested parentheses. Click a row and Ctrl- or Shift-click another row to
select the continuous range. The selected-rule count and **Bulk edit** action
remain available in the fixed bottom action bar. Bulk list changes are explicit
add/remove operations:

The workspace has separate **Policies** and **Objects** navigation. Object
inventory is read from the configured SCM scope, Panorama shared/device-group
scope, or standalone vsys. Addresses, address groups,
application groups, services, service groups, and tags can be prepared through
a preview and then written to the selected target candidate. Existing objects open in a
PAN-OS-style editor; multi-select delete is available from the fixed bottom
action bar. Addresses support all four PAN-OS address types and tags. Address
groups support static members and dynamic filters. Address, service, and
application groups use searchable member pickers and removable member chips.
Installed applications open as read-only details and their target-specific
catalog is cached for 30 minutes, with background refresh to keep pages responsive.
Services support TCP/UDP,
destination/source ports, and optional timeout overrides. Creation is stopped
when the name or equivalent object already exists, and stale edit/delete drafts
are rejected. Object changes never commit or deploy the target candidate
configuration automatically.
Policy inventory and candidate edits use one shared UI for SCM, Panorama, and
standalone PAN-OS. The selected firewall profile automatically chooses SCM REST,
Panorama XML API with device-group/pre-post rulebase, or standalone XML API with
the configured vsys. Security, NAT, QoS, Policy Based Forwarding, Decryption,
Application Override, and Authentication use the same filter, multi-select,
bulk-preview, stale-check, and candidate-write workflow. Target-specific nested
settings that are not changed are preserved as complete XML subtrees or nested
objects in SCM payloads. Unsupported or unavailable tenant
categories are shown explicitly instead of blocking the workspace.
Removing one zone or object never removes the other existing members. A preview
shows every changed value before a separate candidate write. The candidate
write re-fetches the live rules and stops on concurrent changes. No connector
automatically commits or deploys the candidate configuration.

Flow aggregation happens continuously while syslog arrives. CPU-parallel builder work
defaults to `max(1, detected CPUs - 2)`, reserving two logical CPUs for the web UI,
syslog receiver, and operating system.

The preparation cadence can be changed with `PPF_PREPARE_INTERVAL` (seconds,
minimum 300). Automatic preparation never writes or deploys candidate configuration.
