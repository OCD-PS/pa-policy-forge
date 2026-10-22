# PA Policy Forge

Self-hosted Palo Alto traffic-flow policy builder with an HTTPS web interface, UDP and TCP syslog collection, encrypted target credentials, policy review, and target-aware pushes to SCM, Panorama, or standalone PAN-OS.

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
  exactly once in the selected target scope/rulebase, the candidate push is
  blocked. SCM deployment starts only after the final rule order is verified.
- HTTP serves redirects only; every request on port 80 receives a permanent redirect to HTTPS.
- Runtime databases, credentials, keys, certificates, logs, and generated artifacts stay outside Git.

## Install on Ubuntu Server

```bash
sudo ./install.sh
```

Ports:

- `80/tcp`: HTTP to HTTPS redirect only
- `443/tcp`: HTTPS GUI
- `514/udp`: PAN-OS syslog
- `514/tcp`: PAN-OS syslog using RFC 6587 octet-counting or newline framing

On a fresh install, configure a unique `PPF_BOOTSTRAP_PASSWORD` of at least 12
characters before starting Compose or running the installer. The application
fails closed if no valid bootstrap password is configured, and the `admin`
account must change that password at first login. Existing databases are left
untouched: changing or removing the bootstrap environment variable never resets
an existing account. Store the value in the root-owned, mode-0600
`/opt/pa-policy-forge/.env`; do not commit it. Values containing `$` must be
single-quoted in `.env` so Compose treats them as literal characters rather
than variable interpolation. For example: `PPF_BOOTSTRAP_PASSWORD='pa$word-long'`.

PAN-OS and Panorama API calls verify the server certificate chain and hostname.
The system trust store is used by default. To trust a private or self-signed
device CA, place its PEM certificate under `/opt/pa-policy-forge/trust/` and set
`PPF_PANOS_CA_BUNDLE` in `.env` to its container path, for example
`/etc/pa-policy-forge/trust/firewall-ca.pem`. The mounted trust directory is
read-only in the app container. SCM continues using the normal system CA trust
and does not use this PAN-OS-specific bundle.

For a PAN-OS/Panorama endpoint certificate that is not issued by a trusted CA,
open the device profile and choose **Controleer certificaat**. Policy Forge only
reads the TLS certificate at this stage; it does not send API credentials. Review
the SHA-256 fingerprint and verify it with an independent trusted source before
explicitly accepting it. The accepted leaf certificate is pinned to that exact
profile endpoint. Certificate validity is still checked. A changed certificate
blocks API calls until its new fingerprint is reviewed and explicitly accepted;
the page shows the previous and current fingerprints. A certificate without a
matching endpoint SAN requires a separate, clearly labelled confirmation and
uses the exact pinned certificate as endpoint identity. Expired certificates
and CA certificates cannot be pinned. Changing the profile endpoint clears the
pin. This exception applies only to the selected PAN-OS/Panorama profile; it
does not alter TLS verification for SCM, GitHub, or other services.

Runtime direct dependency versions are maintained in `requirements.in`; the
hash-locked `requirements.txt` is generated with pip-tools and installed with
`--require-hashes`. After changing direct dependencies, regenerate the lock
with the separately hash-locked toolchain (`requirements-lock-tools.txt`):

```bash
python -m pip install --require-hashes -r requirements-lock-tools.txt
python -m piptools compile --resolver=backtracking --generate-hashes --strip-extras --output-file=requirements.txt requirements.in
python -m piptools compile --resolver=backtracking --generate-hashes --strip-extras --output-file=requirements-dev.txt requirements-dev.in
python -m piptools compile --resolver=backtracking --generate-hashes --allow-unsafe --strip-extras --output-file=requirements-lock-tools.txt requirements-lock-tools.in
```

CI installs the hash-locked runtime and test dependency files. The lock-generation
toolchain is kept separate and is not installed by CI.

The Dockerfile also pins the official Python 3.14 slim multi-platform image by
manifest digest.

The installer also pins the published container ports to the appliance's
primary address through `PPF_BIND_ADDRESS`. Override `PPF_BIND_ADDRESS` and
`PPF_TRUSTED_HOSTS` in `/opt/pa-policy-forge/.env` when the appliance uses a
different management address or additional DNS aliases.

The installer creates a self-signed certificate for the server IP and starts a dedicated,
unprivileged HTTP redirect container. If the final FQDN is already known, provide it during
installation:

```bash
sudo env PPF_FQDN=policy-forge.example.com ./install.sh
```

After login, open **Instellingen** to activate the end-user certificate. Enter the FQDN and
upload a PEM certificate chain plus its matching unencrypted PEM private key. PA Policy Forge
checks the DNS SAN, validity period, key strength, certificate/key match, and OpenSSL loadability
before atomically replacing the active files. The previous pair is retained as
`tls.crt.previous` and `tls.key.previous`, the new FQDN is accepted as a trusted host, the HTTP
redirect target changes immediately, and Gunicorn reloads the certificate without requiring
Docker access from the application.

Certificate files remain outside Git under `/opt/pa-policy-forge/certs`. The private key and
appliance configuration are mode `0600`; the certificate directory is writable only by the
non-root container user so certificate activation does not require mounting the Docker socket.

For offline customers, transfer the repository plus a saved container image bundle, load it with `docker load`, and run the same Compose stack. SCM functionality naturally requires connectivity to Palo Alto cloud endpoints.

## First workflow

1. Log in as `admin` with the configured bootstrap password and choose a new
   password when prompted.
2. Configure one or more PAN-OS firewalls to forward TRAFFIC logs to UDP or TCP 514.
3. Confirm each serial appears under discovered firewalls.
4. Add a firewall profile with its active and optional passive serial/source IP.
5. Open the device card, choose whether it is managed by SCM, Panorama, or standalone
   PAN-OS, and save the connection. Policy Forge then reads the current target zones.
6. Assign each current zone a client, server, internet, or other role in the device
   workspace. Preview, policy management, run history, and push stay unavailable until
   both the management target and zone roles are configured.
7. Generate a preview from the same device workspace or **Policy runs**, then inspect/download the review CSV and XML.
8. Open that completed preview and use its API-push action only after review. The exact
   preview artifacts and unchanged target settings are verified before writing. SCM-generated policies are written to the configured
   folder and deployed to the profile's HA targets. Panorama and standalone writes remain
   candidate-only and require their normal commit workflow.
9. After the accepted rules are manually positioned and deployed, use **Flows purgen** on the profile to start a clean observation cycle. Profiles and run history are retained.

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
and best-effort set-command exports are available. A complete snapshot can be
compared with the live candidate and selectively written by configuration
location and family. Standalone PAN-OS policy and object views offer Shared plus
each discovered VSYS; Shared entries appear as inherited, read-only records while
editing a VSYS. Shared and VSYS-local rules or objects can be edited in their own
location. Panorama keeps Shared/device-group inheritance and template ownership.
Supported entries in the vertical tree link directly to their policy, object,
Network, or Device view. Network and Device records open in an orange PAN-OS-style
editor with grouped tabs, typed booleans, multi-value chips, rename, duplicate,
delete, and a mandatory preview. Internal navigation and form targets are covered
by authenticated route-and-fragment regression tests.
The incremental push preview lists candidate differences by location and
configuration family. Shared, each VSYS, Panorama device groups, and templates
remain separate selections, even when a family name is the same. Only checked
location/family combinations are written through exact PAN-OS XML API `set`,
`edit`, and `delete` operations; it does not load or replace the full `/config`.
The preview is tied to the candidate fingerprint and stops if the target candidate
changes before apply. Objects and network prerequisites are written before policy
families, so selecting a Shared object and a VSYS policy writes the object first;
deletions run in reverse dependency order. PAN-OS full validation runs after the writes;
the app never commits or deploys. Protected management identity and administrator
settings cannot be replaced from a workspace. Panorama and standalone use the
same incremental flow while their XML paths retain the selected device-group,
template, or VSYS ownership.

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
SCM Device list calls use only the documented location attribution and do not add
the pagination parameters used by Network and Object list APIs.

## Migration workspace

The separate **Migratie** workspace keeps the existing Policybeheer workflow intact while
adding an Expedition-inspired source/base/merge flow. Supported first-wave adapters are
Cisco ASA, Cisco IOS/ACL, Check Point JSON/XML, Fortinet FortiGate, Juniper SRX, and a
conservative generic JSON/XML adapter.

Every import is normalized before target mapping. SCM uses its native REST object and
policy endpoints; Panorama and standalone PAN-OS merge into a new full XML workspace.
Equivalent addresses and services are reused and policy references are rewritten. A name
collision with different content stops the merge for review. Nothing commits or deploys
automatically.

The migration workspace also preserves extended PAN-OS families instead of flattening
them: applications, tags, schedules, EDLs, security profiles and groups, all PAN-OS
policy rulebases, VLANs, virtual/logical routers, virtual wires, IKE/IPsec, GlobalProtect,
network profiles, and device configuration. Global Search & Merge supports selection,
name, value, and name-plus-value matching with an explicit master, reference rewrites,
rename/delete/enable/disable transformations, duplicate and unresolved-reference analysis,
live profile pulls, portable project bundles, full XML export, and set-command export.
SCM mappings are preflighted before candidate writes so an unsupported selected family
cannot result in a silent partial migration.
SCM candidate writes remain native per-object/per-policy API calls; the migration
family mapping controls which families are created, mapped, or ignored. Tags,
objects, security profiles, and network prerequisites are written before policy
families. The subsequent SCM deployment remains a separate explicit action.

The Migration Control Center adds an explicit source-family decision (`map`, `create`,
`ignore`, or `review`), mandatory per-item topology mapping, saved AND/OR filters, bulk
rename refactors, project-health and best-practice checks, offline discovery, cached
application/URL/region catalogs, reusable migration snippets, project roles, and a
project-scoped audit trail. A staged API plan can be downloaded for review but performs no
write. Preview drafts are bound to the exact project, profile, and base configuration;
unresolved topology, merge conflicts, stale previews, and zero-delta candidates are blocked.

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
