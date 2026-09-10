# Bot Detection Policy — MVP Design

_Date: 2026-09-10_
_Status: Approved for implementation planning_
_Delivers P4A Policy Idea: "Bot Detection Policy (scripted-client & non-human traffic)" (`974ac3da-b883-4ad6-9ea7-ce3459f0de12`, currently `under_review`)_

## Summary

An **inbound PDK policy** (Rust → WebAssembly, for MuleSoft Omni / Flex Gateway)
that classifies each incoming request as **scripted-bot** or **human-like** using
**Layer-7 header heuristics only**, then either **audits** (observes and emits
evidence) or **blocks** it. It gives the gateway a native way to flag or block
automated clients — something IP allow/blocklists (network-level), rate
limiting / spike control (volume-only), and client-id enforcement (identity-only)
do not address.

The policy runs in the **request-headers phase**. It does not buffer the request
body. It complements, and does not replace, IP filtering and rate-limiting
policies.

## Goals (MVP)

- Detect scripted clients from HTTP request headers:
  - `User-Agent` denylist / allowlist matching.
  - Browser-typical header-signature check (absence of headers a real browser
    normally sends).
- Two enforcement modes: `audit` (default) and `block`.
- Emit evidence on every detection: an Anypoint Monitoring **policy violation**
  plus a **structured log** line carrying the matched reasons.
- **Fail-open by default** (configurable) so the gateway degrades safely.
- All detection logic isolated in a pure, unit-testable function.

## Non-Goals (explicitly deferred / out of scope)

- **Behavioral / frequency analysis** (per-client request velocity, inter-arrival
  cadence, burstiness; in-memory or Redis-backed sliding windows) — follow-up
  phase, not MVP.
- **External bot-reputation HTTP delegation** — follow-up phase, not MVP.
- **JA3 / JA4 TLS fingerprinting** — impossible in the proxy-wasm sandbox (no TLS
  handshake access); permanently out of scope.
- Request-body inspection — not needed for the MVP heuristics.

## Architecture

Single inbound PDK filter registered on the request-headers phase.

```
request headers ──▶ read UA + configured headers
                       │
                       ▼
                 classify(headers, config) ─────▶ Verdict { is_bot, reasons }
                       │
        ┌──────────────┴───────────────┐
     Human                            Bot
        │                              │
     continue                emit policy violation + structured log
                                       │
                          ┌────────────┴────────────┐
                       audit                       block
                          │                          │
             inject x-p4a-bot-detection:      stop with blockStatusCode
             flagged header, continue         + blockBody
```

**Error handling:** any internal error (e.g. header read failure) is resolved by
the `failOpen` setting — `true` (default) → continue; `false` → treat as a block.

### Components

| Unit | Responsibility | Depends on |
| --- | --- | --- |
| `src/classifier.rs` | Pure `classify(headers, config) -> Verdict`. No gateway/IO. All heuristics live here. | config types only |
| `src/lib.rs` | PDK glue: read headers, call `classify`, emit evidence, enforce mode, fail-open. | pdk, classifier, config |
| `src/generated/config.rs` | Generated from `gcl.yaml` (`cargo anypoint config-gen`). | gcl.yaml |
| `definition/gcl.yaml` | Config schema surfaced in the Anypoint config UI. | — |

Keeping `classify` pure and free of PDK types is the key isolation boundary: the
entire decision surface is testable in-process without a gateway.

## Classification logic

`classify(headers, config) -> Verdict`:

1. **Allowlist short-circuit.** If `User-Agent` matches any `userAgentAllowlist`
   pattern → `Human`, pass through, no evidence emitted.
2. Otherwise gather signals:
   - `ua_missing` — `User-Agent` header absent or empty.
   - `ua_denylisted` — `User-Agent` matches any `userAgentDenylist` pattern.
   - `missing_browser_headers` — count of `requiredBrowserHeaders` that are
     absent from the request.
3. **Verdict.** `is_bot = ua_missing || ua_denylisted ||
   (missing_browser_headers >= headerSignatureThreshold)`. Otherwise `Human`.
   A `Bot` verdict carries the list of matched reasons (e.g.
   `["ua_denylisted:python-requests", "missing_headers:2"]`) for evidence.

Pattern matching is case-insensitive substring/regex against the header value;
the exact matcher (glob vs. regex) is an implementation-plan decision, defaulting
to case-insensitive substring for the shipped defaults to keep it cheap and
predictable.

## Configuration schema (`definition/gcl.yaml`)

All property names avoid Rust reserved keywords (no `type`, `match`, `move`,
`ref`, …). Every property carries a `description` for the Anypoint config UI.

| Property | Type | Default | Notes |
| --- | --- | --- | --- |
| `mode` | enum `audit` \| `block` | `audit` | Enforcement behavior on a Bot verdict. |
| `userAgentAllowlist` | list of string patterns | `[]` | Match → immediate Human pass, short-circuits all other checks. |
| `userAgentDenylist` | list of string patterns | `["curl", "wget", "python-requests", "Go-http-client", "PostmanRuntime", "java", "libwww-perl", "okhttp", "aiohttp", "node-fetch"]` | Case-insensitive. |
| `requiredBrowserHeaders` | list of string | `["Accept", "Accept-Language", "Sec-Fetch-Mode", "sec-ch-ua"]` | Headers a real browser normally sends. |
| `headerSignatureThreshold` | integer | `2` | Missing-required-header count at/above which the request is flagged. |
| `failOpen` | boolean | `true` | On internal error: `true` → continue; `false` → block. |
| `blockStatusCode` | integer | `403` | Response status in `block` mode. |
| `blockBody` | string | `"Request blocked: automated client detected."` | Response body in `block` mode. |

`treatMissingUserAgentAsBot` is intentionally omitted — a missing UA is always a
signal (`ua_missing`); admins who want to allow it can add a matching allowlist
entry.

## Request flow (in `src/lib.rs`)

1. Read `User-Agent` and each `requiredBrowserHeaders` value.
2. `verdict = classify(headers, config)`.
3. `Human` → `Flow::Continue`.
4. `Bot`:
   a. Emit a policy violation (Anypoint Monitoring) with the reasons.
   b. Emit a structured log line (level `warn`) with the reasons + mode.
   c. `block` → stop the request with `blockStatusCode` + `blockBody`.
   d. `audit` → inject request header `x-p4a-bot-detection: flagged` and continue,
      so downstream policies / upstream services can observe the classification.
5. On any internal error, resolve via `failOpen`.

## Repo layout (unified model)

```
bot-detection/
├── Cargo.toml                 # pdk inline dependency, version >= 1.8
├── Makefile                   # build / test / publish
├── src/
│   ├── lib.rs                 # PDK glue + request handler
│   ├── classifier.rs          # pure classification logic
│   └── generated/config.rs    # generated from gcl.yaml
├── definition/
│   └── gcl.yaml               # config schema
├── tests/                     # PDK integration tests
├── docs/
│   ├── how-to.md              # consumer-facing usage doc
│   └── superpowers/specs/     # this design doc
├── README.md
└── icon.svg                   # optional catalog icon
```

## Testing strategy (TDD)

**Unit tests (`classifier.rs`)** — exercised without the gateway:
- Allowlist match wins even when UA is denylisted / headers missing.
- Denylisted UA → Bot, with the matching reason.
- Missing / empty UA → Bot (`ua_missing`).
- `missing_browser_headers` exactly at threshold → Bot; one below → Human.
- Clean browser-like request (good UA, all required headers) → Human.
- Case-insensitivity of UA matching.

**Integration tests (PDK)**:
- `audit` mode: flagged request passes through, `x-p4a-bot-detection: flagged`
  injected, violation + log emitted.
- `block` mode: flagged request returns `blockStatusCode` with `blockBody`.
- Human request: passes untouched in both modes.
- Fail-open path: forced internal error continues when `failOpen=true`.

## Documentation & submission (later)

- `docs/how-to.md`: what the policy does, config params + defaults, a minimal
  apply example, caveats (L7-only, complements rate limiting/IP filtering).
- The P4A submission `description` (submit-time metadata) mirrors the how-to
  body; `category = Security`. Handled at submission time via the
  `p4a-verify-requirements` + `p4a-mcp-usage` skills — not part of the build.

## Risks / open considerations

- **False positives** on legitimate non-browser clients (mobile SDKs, server-side
  integrations). Mitigated by: `audit` default, allowlist, and configurable
  threshold. Rollout guidance goes in the how-to.
- **Regex cost** if admins supply pathological patterns. Default matcher is
  case-insensitive substring; if regex is offered, document the ReDoS caveat.
- **Config property naming** must stay clear of Rust keywords through any future
  additions (build-pipeline codegen constraint).
