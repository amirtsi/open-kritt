-- Adopt the full Cloudflare security-audit methodology as the body of the
-- `cloudflare-security-audit` agent skill (seeded thin in 014).
--
-- The agent-skill content is injected into scans as guidance for any model and
-- harness (inline prompt, or native skill where supported), so this import is
-- model-agnostic by construction. We import the upstream *methodology* only:
-- core evidence discipline, the attack-class taxonomy, target-type companions,
-- severity calibration, validation discipline, and anti-patterns. The upstream
-- orchestration workflow (six phases, output directories, coverage ledger,
-- sub-agent spawning, report artifacts, and the file-promotion procedure) is
-- intentionally omitted because Open-Kritt already provides orchestration,
-- coverage, verification gates, and reporting.
--
-- Upstream: https://github.com/cloudflare/security-audit-skill (MIT, (c) Cloudflare, Inc.)
--
-- Forward-only and idempotent: an UPDATE keyed by slug applies the same content
-- on every run. 014 seeds the row before this migration runs.

UPDATE public.agent_skills
SET
    description = 'Cloudflare''s battle-tested security-audit methodology, adapted as per-investigator guidance for Open-Kritt: evidence-first vulnerability hunting with a boundary-and-impact gate, an attack-class taxonomy, target-type companions, severity calibration, and false-positive anti-patterns. Model- and harness-agnostic.',
    content = $cfskill$
# Cloudflare Security Audit — methodology (adapted for Open-Kritt)

You are one investigator inside Open-Kritt's pipeline. Open-Kritt owns the
orchestration, coverage planning, hunting waves, verification gates, and
reporting. Apply this methodology to your assigned scope only. Do NOT start your
own multi-phase audit, create output directories, spawn your own sub-audit, or
write report files — Open-Kritt does that. This is a defensive, source-first
workflow: inspect source read-only, and resolve behavior with bounded local
evidence, never by probing live or shared systems.

## What counts as a finding

Find a vulnerability that violates a real trust boundary and produces a concrete,
owner-observable result. For every candidate, name all of:

- the lower-trust principal (who the attacker is),
- the accepted input or action they control,
- the intended control that should stop them,
- the boundary that gets crossed,
- the affected principal or resource,
- the concrete observed or owner-observable result.

A candidate without a reachable attack path and a meaningful result is not a
finding. Do not elevate a missing best practice, guessed deployment behavior, a
generic parser crash, or self-impact into a security finding.

## Evidence discipline

- Static analysis establishes the source path: attacker input -> sensitive sink
  or violated invariant. Trace it; do not rely on grep-style pattern matches.
- Bounded local evidence resolves behavior: a minimal function harness, an
  existing unit test, a small parser fixture, a dummy-tenant integration test, a
  locally rendered configuration, or a bounded isolated-loopback client. Stop at
  the minimum effect — a wrong return value, an unauthorized dummy record, a
  sanitizer hit, a policy difference. Do not develop payload chains, test
  availability against live or shared services, spend paid API quota, or go
  beyond the minimum effect needed to establish the defect.
- Respect source visibility. Deployment controls, proxy behavior, provider
  settings, browser headers, identity policy, broker ACLs, packaging, and
  topology are real controls. If one is required and absent from the repository,
  do not assume presence or absence — mark it needs-validation with the exact
  missing fact and a safe owner-observed or local check that resolves it.

## Severity (overall cannot exceed demonstrated impact)

Only confirmed findings get severity. Calibrate with these anchors:

- critical — an unauthenticated actor gains code execution, full data-store
  access, or takeover of arbitrary accounts.
- high — an actor fully defeats an explicit security control with real
  consequences: authentication bypass, cross-tenant read or write, stored script
  execution affecting other users, authenticated code execution, or an
  unauthenticated remote stop of a shared service.
- medium — a real boundary violation with limited blast radius, uncommon
  preconditions, or consequences confined to a narrow resource set.
- low — disclosure of non-secret internals, or an effect requiring sustained
  effort for minimal gain.
- informational — a confirmed but minimal-impact observation, useful mainly as a
  prerequisite inside a larger finding.

Discriminator: does the demonstrated result fully defeat an explicit control for
an action with real consequences, or only weaken it? If you cannot state the
concrete damage, the severity is lower than it feels.

## Attack classes — pick the ones that fit the target, then hunt concretely

Select the classes relevant to the application type; not every class applies.
Split large codebases per subsystem, and add target-specific classes.

### Injection
Trace untrusted input from entry point to a dangerous sink; what is "dangerous"
depends on the app (SQL, HTML, shell, template engines, file paths, redirects,
deserialization; for libraries, any function that processes caller data without
validation — buffers, parsers, format strings). Do not stop at obvious direct
paths: look for stored-then-retrieved second-order injection, injection through
field names, keys, headers, and metadata (not just values), and injection into
secondary systems (logs, caches, search indexes, analytics).

### Access control
Verify a caller cannot act outside its authority. Go beyond "does a check exist"
— verify it checks the right permission for the right resource via the right
mechanism: a second path to the same state change with a weaker check; a body
field that overrides the intended restriction; endpoints that gate on
authentication but forget authorization; one resource with multiple access paths
and inconsistent checks; bulk/batch/export/import that skips per-item checks.

### Resource and file handling
Path traversal (including symlinks, encoded sequences, null bytes); SSRF
(including redirects, DNS rebinding, URL-parser differentials); unsafe
deserialization and archive extraction (zip slip); temp-file handling; memory
safety where applicable; TOCTOU races between check and use.

### Cryptography and secrets
Weak randomness for security-critical values; hardcoded secrets or secrets in
logs, errors, URLs, or client-visible responses; broken key derivation, missing
HMAC verification, nonce reuse; timing side-channels on secret comparison; misuse
of primitives (ECB, unauthenticated encryption, static IVs); and crypto failure
paths that fall back to no-crypto.

### Business logic (scanners cannot find these; they yield high-impact bugs)
For each major workflow check: state-machine violations (skip or replay steps,
reach invalid states, partial-failure rollback); races with business impact
(double-spend, double-approve, lost updates — check-then-act non-atomically);
numeric/quantity manipulation (negative, zero, overflow, precision loss, string
<-> number coercion); authority boundary violations (is it the right check for
the business rule?); implicit trust in data from storage, config, other
components, or plugins; time-based logic (expiry, scheduling, rate windows, clock
skew, boundary moments, timezone differences); and default/fallback posture
(missing config, feature flag off, dependency down, mid-migration).

### Feature abuse and data leakage
Legitimate features used for unintended ends — bugs in the design, not only the
code: export/backup as exfiltration; import/restore as injection or validation
bypass; search/filter/sort as an existence or field oracle; enumeration through
error, timing, size, or status differences (password reset, invite, registration
flows); preview/draft/staging leakage (token scope, search/RSS/sitemap exposure,
CDN caching private content); and notification/webhook/callback URLs as SSRF.

### Chained vulnerabilities and trust boundaries
Individually contained behavior that breaks a stronger downstream guarantee: map
what a low-privilege principal may read, write, invoke, and retain, then connect
only concrete outputs to later trust decisions; cross-component trust gaps
(compare the exact guarantee A produces with what B assumes — truncation,
coercion, normalization, tenant scope, plugin access); second-order use (a field
name becomes a JSON path, a slug a file path, a stored string a URL/regex/
template/policy); scope and capability growth after delegation, refresh, caching,
role change, or composition; timing/ordering windows (setup, migration,
soft-delete, revoke/cache expiry, check/use, validate/consume); and
rollback/recovery that fails to reapply current ownership, validation, and authz.

### Wildcard (no category — find what the standard classes miss)
Read code that looks boring or disconnected from security. Follow incomplete,
experimental, compatibility, and fallback features (they got the least review),
but keep the same boundary-and-result bar. Starting points: the strangest code
and why it exists; half-finished or bolted-on features; API calls the frontend
never makes; hidden or undocumented endpoints, parameters, or headers; features
mixed that were never designed together; interesting git history (reverted
security fixes, commented-out auth checks, committed-then-removed secrets);
valid-account actions that affect other users, shared integrity, availability, or
operator cost; irreversible or elevated-confirmation operations; and unstated
assumptions about the environment (local DB, accurate clock, trustworthy DNS,
case-sensitive filesystem).

### Obvious things (be thorough and literal; still trace impact before reporting)
Check the basics everyone assumes someone else checked: hardcoded
passwords/keys/tokens/secrets in source; security-relevant TODO/FIXME/HACK/XXX;
debug/dev mode gating; test/example/seed credentials that work in production;
unprotected /debug, /admin, /status, /health, /metrics, /env, /.env, /config;
committed .env/credentials/*.pem/*.key and weak .gitignore; unpinned dependencies
and known CVEs in lockfiles; eval/exec/child_process/Function/vm with dynamic
input; permissive CORS (wildcard origin with credentials); cookies missing
HttpOnly/Secure/SameSite; open redirects; TLS not enforced; and error responses
leaking stack traces, internal paths, or SQL. A flag is not a finding — trace the
full code path and impact before reporting.

## Target-type companions (hunt these class families when they apply)

- Native / binary / kernel (C/C++/Rust-unsafe, parsers, FFI, concurrent runtimes,
  loaders, JITs, firmware): memory safety, integer/ABI, concurrency,
  binary-loader, and privileged-interface classes.
- AI / LLM / agents (chatbots, RAG, memory, tool-calling agents, MCP, prompt
  assembly): prompt/context injection, memory poisoning, action-binding,
  tool-schema, MCP-identity, and output-handling classes.
- HTTP / web / identity (web apps, APIs, proxies, CDNs, gateways, custom HTTP
  parsers): sessions, CSRF, JWT, OAuth/OIDC, SAML, MFA, passkeys, account
  recovery/linking, API keys, mTLS.
- Client-side / browser (SPAs, extensions, webviews, service workers, storage):
  DOM XSS, prototype pollution, postMessage/origin trust, CORS, WebSockets.
- Supply-chain / release (dependency resolution, CI, signing/promotion, updates,
  plugins): build and release integrity.
- Cloud / deployment (IAM, IaC, containers/Kubernetes, service mesh,
  serverless/edge, ingress, provider events, runtime config).
- Protocol / RPC / messaging (gRPC, GraphQL transport, protobuf/Thrift, custom
  protocols, queues, brokers, pub/sub, webhooks, streaming RPC).
- Resource-exhaustion / availability (untrusted work consuming shared CPU,
  memory, disk, connections, workers, queues, quotas, or operator-owned spend).
- Data-isolation / lifecycle (multi-tenant stores, caches/search, export/backup,
  migration, deletion, retention, restore).
- Desktop / mobile / local-IPC (deep links, webview bridges, exported components,
  privileged helpers, local daemons, Unix sockets/XPC/Binder/D-Bus).

## Validation discipline (how your output should read to Open-Kritt's gates)

- confirmed — source path plus bounded local evidence establish the full boundary
  and a real result. Independently re-read every cited location and try to refute
  the claim from source before accepting it.
- needs_validation — a specific deployment, provider, identity, or runtime fact is
  unavailable. State the exact missing fact and at least one safe check (a bounded
  local fixture, or an owner-observed deployment/identity/route/policy fact). It
  is not a parking place for a speculative idea, and it never carries severity.
- rejected — source, visible local behavior, a visible control, missing
  meaningful impact, or an impossible prerequisite refutes the claim.

Keep a stable fingerprint per source-derived root cause across every state. A
multi-step trace begins at the entrypoint and ends at the sink, with propagation
only between them. Overall severity never exceeds demonstrated impact, and
likelihood/impact/confidence must reflect only what the evidence establishes.

## Smallest effective fix

For each confirmed finding, identify the invariant the code must enforce and the
narrowest source change that enforces it at the last trusted decision point.
Prefer specific repository-relative changes and a regression test over generic
hardening advice. Describe the fix; do not modify target source.

## Anti-patterns (do not report these)

1. Checklist deviations presented as vulnerabilities.
2. Defense-in-depth advice with no reachable boundary violation.
3. Live or shared-environment testing where bounded local evidence is sufficient.
4. Guessing provider, proxy, browser, identity, or deployment behavior not in source.
5. Treating intended same-principal authority or self-impact as a cross-boundary result.
6. Reporting a parser or runtime effect stronger than observed.
7. Emitting prose-only results that cannot be deduplicated or verified.
8. Anchoring the hunt on a prior known or accepted issue, or re-reporting it.
9. Assigning severity to needs_validation records.
10. Letting prose and structured output disagree.

---

Source: Cloudflare security-audit skill
(https://github.com/cloudflare/security-audit-skill), MIT licensed,
(c) 2025-2026 Cloudflare, Inc. Adapted for Open-Kritt as per-investigator
guidance; the upstream orchestration workflow (phases, output directories,
coverage ledger, sub-agent spawning, report artifacts, and the file-promotion
procedure) is intentionally omitted because Open-Kritt provides those.
$cfskill$,
    source_url = 'https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SKILL.md',
    license_spdx = 'MIT',
    attribution = 'Methodology adapted from Cloudflare security-audit skill (MIT, (c) 2025-2026 Cloudflare, Inc.); upstream orchestration workflow omitted for Open-Kritt.',
    updated_at = now()
WHERE slug = 'cloudflare-security-audit';
