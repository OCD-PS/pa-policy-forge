# Security audit — 2026-09-07

Scope: PA Policy Forge application and bundled builders at `2574631`, followed by
isolated regression testing of the fixes. All proof cases use synthetic data and
in-process HTTP handlers. No password brute force, live denial-of-service tests,
firewall changes, gateway changes, or credential resets were performed. The known
lab bootstrap login is an explicitly accepted test exception.

## Findings and fixes

| Severity | Finding | Fix and evidence |
| --- | --- | --- |
| High | Project role checks could be bypassed using direct workspace IDs. An unrelated logged-in account could export project XML or attach it to its own project; viewers could submit editor drafts. Old immutable versions were also unprotected. | Central workspace authorization applies to editor, export, selection, delete, push, catalogs, and draft application. Durable workspace/project links follow immutable versions, remain restrictive after project deletion, and are checked when choosing a base. Five security regressions failed against the original version and pass with the fix. |
| Medium | Default urllib redirects could forward `Authorization` or `X-PAN-KEY` headers to another origin or downgrade HTTPS requests. | One shared HTTPS-only, no-redirect transport is used by PAN-OS, Panorama, SCM and the legacy bundled sender. The canonical PAN-OS `/api/` path avoids slash redirects. Tests cover 301/302/303/307/308 without opening sockets. |
| Medium | Check Point archive limits were enforced after `getmembers()` had traversed the entire archive. Ignored files did not count against the decompressed-byte budget. | Iterate members and check limits before reading/advancing; count all regular payloads. Header-only and 1001-empty-member fixtures verify rejection without allocating a large payload. |
| Low | OAuth token endpoint errors could reflect submitted client secrets into displayed/logged exception text. | Token errors expose the HTTP status but not the remote response body. A synthetic reflected-secret test verifies redaction. |

The workspace ACL backfill is deliberately conservative. Releases before this
fix did not store version parent IDs, so historical migration/edit snapshots are
matched by profile and original filename. If several projects match, permissions
to all are required. Normal unattached policy-builder workspaces retain their
existing shared-access model. Project roles are not a new global application RBAC
system: authenticated users still share global device profiles and settings.

## Verification

- Original build: 5 failures out of 8 initial authorization regression cases.
- Fixed build: 16 new bounded security tests passed.
- Complete isolated suite: 254 tests passed; no firewall API calls were needed.
- `pip-audit -r requirements.txt`: no known vulnerabilities in the resolved pinned
  dependency set at the time of the audit. This is not a future guarantee.
- Bandit reviewed 15,837 Python source lines. Its initial 28 medium / 21 low
  findings were triaged; parameterized SQL construction, intentional container
  bind addresses, generated local XML and explicitly accepted PAN-OS lab TLS
  behavior account for many automated flags. Static findings are not all proven
  vulnerabilities, nor is a low scanner count proof of security.
- Read-only production checks: health returned 200; unauthenticated migration and
  workspace export requests returned 302 to login.
- Existing regression coverage was rerun for CSRF, login requirements, cookie and
  security headers, HTML escaping, upload path traversal, XML entity safety,
  protected secret fields, and spreadsheet formula escaping.

Use `PPF_BACKGROUND_WORKERS=0` when importing the app in isolated tests. It
suppresses startup syslog listeners and scheduled workers; production defaults
remain unchanged.

The independent second pass also reproduced numeric project-ID reuse after
deletion: a newly created project could otherwise inherit a tombstoned ACL.
Workspace grants now bind to a durable random project identity as well as its
integer ID. The delete/recreate regression failed before that follow-up fix and
passes afterward.

## Remaining limits / accepted risks

- PAN-OS/Panorama certificate verification remains disabled as explicitly
  requested for the lab. No-redirect transport does not prevent an on-path attacker
  impersonating that endpoint. Customer deployments should trust the relevant CA
  and enable verified device transport in a separate deliberate change.
- The known bootstrap password, optional outer gateway and current authentication
  model were not changed. These test choices need customer-specific hardening.
- Syslog UDP/TCP requires a trusted management network and configured source
  recognition. This audit did not perform sustained load/flood testing or claim
  cryptographic sender authentication for plaintext syslog.
- This is a scoped engineering security assessment, not a certification or proof
  that every possible vulnerability has been eliminated.
