---
name: pa-policy-forge-review
description: Review PA Policy Forge code changes for concrete regressions, performance, and security across standalone PAN-OS (including multi-VSYS and Shared), Panorama, and Strata Cloud Manager. Use when asked to review code, inspect a change, or run the scheduled project review. Do not use for implementation-only tasks.
---

# PA Policy Forge Code Review

Perform a read-only review. Do not edit files, commit, push, deploy, or contact a live firewall.

## Review procedure

1. Read the project and repository `AGENTS.md` files. Inspect `git status`, the complete change, relevant callers, and tests. Include uncommitted changes when the task asks for a working-tree review.
2. Trace the changed behavior through the relevant adapter and data model. For shared code, check standalone PAN-OS, multi-VSYS/Shared scope, Panorama, and SCM; state which variants the evidence covers.
3. Look for introduced defects in correctness, authorization boundaries, validation, secret handling, XML/API payloads, error handling, and practical performance. Focus security review on changed paths; do not broaden into login-flow testing unless requested.
4. Run only existing, relevant checks when the user asks for verification or when the review task explicitly includes them. Never treat a passing test suite as proof of live firewall behavior.
5. Report findings first. Include severity, file and line, a concrete triggering scenario, impact, affected flavour(s), and a specific fix. Report only actionable issues supported by code or test evidence; separate unresolved hypotheses from confirmed findings.
6. If no concrete issue is found, say so briefly and list the checks performed. If there is no new/reviewable change, say that instead of repeating old findings.

## Boundaries

- Never print or reproduce credentials, tokens, private keys, session cookies, MFA codes, or decrypted secrets.
- Treat firewall writes, commits, deployments, and external GitHub changes as out of scope for review.
- Do not add speculative style comments or findings that cannot be tied to an execution path.
