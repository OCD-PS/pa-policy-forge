# PA Policy Forge source instructions

## Product coverage

- Shared behavior must be checked across standalone PAN-OS (including multi-VSYS and Shared), Panorama, and Strata Cloud Manager (SCM).
- Preserve target-specific ownership and API semantics. Call out any flavour where behavior is unsupported or differs.
- Keep runtime configuration, credentials, certificates, databases, logs, and generated output outside Git.

## Changes and safety

- Inspect the full diff, call sites, tests, and existing conventions before editing.
- Prefer focused changes and the fastest meaningful checks; run the relevant suite for affected code.
- Review authorization, validation, secret handling, injection/SSRF, error handling, logging, and performance where relevant.
- For every implementation change and scheduled code review, assign a separate read-only Vulnerability Reviewer using `.agents/skills/pa-policy-forge-vulnerability-review/SKILL.md`. Review source dependencies, lockfiles, container base/runtime images, and host/runtime packages when reachable; check current vendor advisories and CVEs, and verify exact affected/fixed versions and exposure. Include PAN-OS single/multi-VSYS and Shared, Panorama, and SCM when application behavior is affected.
- The Vulnerability Reviewer reports findings with evidence and recommended fixes; the implementation agent owns remediation. Do not claim a live host or image is clean when access is unavailable, and distinguish confirmed matches from provisional reports or unverified assets.
- Do not exercise login flows unless specifically requested.
- Tests and previews must not contact or modify a live firewall unless the user explicitly requests an E2E run and its target/scope are verified.
- Never commit, push, deploy, or commit firewall candidate configuration unless the user explicitly asks for that action.
- Never print or commit secrets, passwords, tokens, private keys, session cookies, or MFA codes.

## Checks

- Python: `python -m pytest -q`
- Front end: `npm ci --ignore-scripts` then `npm test`
- Use the narrowest relevant check first, then run both suites for cross-cutting changes.
