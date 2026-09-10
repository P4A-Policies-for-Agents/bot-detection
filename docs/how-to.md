# Bot Detection — How To

## What it does

`bot-detection` is an **inbound** Flex Gateway policy that flags scripted
(non-human) HTTP clients using **Layer-7 header heuristics** — no TLS
fingerprinting, no request body inspection. On every request it:

1. Checks the `User-Agent` header against a configurable **allowlist**
   (short-circuits to Human, no evidence emitted) and **denylist**
   (case-insensitive substring match against known script/HTTP-library
   user agents such as `curl`, `python-requests`, `okhttp`, …).
2. Counts how many of a configurable set of **browser-typical headers**
   (`Accept`, `Accept-Language`, `Sec-Fetch-Mode`, `sec-ch-ua` by default)
   are missing from the request. If the missing count reaches a configurable
   threshold, the request is flagged.
3. On a **Bot** verdict, emits an Anypoint Monitoring policy violation and a
   structured log line carrying the matched reasons, then either **audits**
   (lets the request through, injecting the `x-p4a-bot-detection: flagged`
   request header) or **blocks** it (returns a configured status code and
   body), per the `mode` setting.

A missing/empty `User-Agent` is always treated as a bot signal; there is no
separate toggle for it — allowlist a specific pattern if you need to admit a
UA-less client.

## Configuration reference

All properties are defined in [`definition/gcl.yaml`](../definition/gcl.yaml).

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `mode` | enum: `audit` \| `block` | `audit` | Enforcement behavior on a Bot verdict. `audit` lets the request through and injects the `x-p4a-bot-detection: flagged` marker header; `block` returns `blockStatusCode` + `blockBody`. |
| `userAgentAllowlist` | array of string | `[]` | Case-insensitive substrings. A match short-circuits classification to Human — the request passes through with no evidence emitted, regardless of other signals. |
| `userAgentDenylist` | array of string | `["curl", "wget", "python-requests", "Go-http-client", "PostmanRuntime", "java", "libwww-perl", "okhttp", "aiohttp", "node-fetch"]` | Case-insensitive substrings. A `User-Agent` matching any entry is flagged as a scripted client. |
| `requiredBrowserHeaders` | array of string | `["Accept", "Accept-Language", "Sec-Fetch-Mode", "sec-ch-ua"]` | Headers a real browser normally sends. The count of these absent from the request feeds the header-signature check. |
| `headerSignatureThreshold` | integer (min `0`) | `2` | Number of missing required browser headers at or above which the request is flagged as a bot. A value of `0` disables the header-signature check. |
| `failOpen` | boolean | `true` | On an internal enforcement error: `true` continues the request; `false` rejects it with `500`. |
| `blockStatusCode` | integer (min `100`, max `599`) | `403` | HTTP status returned in `block` mode when a request is classified as a bot. |
| `blockBody` | string | `"Request blocked: automated client detected."` | Response body returned in `block` mode. |

## Minimal apply example

Start in `audit` mode with the shipped defaults — this observes traffic and
tags flagged requests without rejecting anything:

```yaml
policies:
  - policyRef:
      name: bot-detection-flex-v1-0
    config:
      mode: audit
```

Once you've reviewed the audit evidence (see Rollout below) and are ready to
enforce, switch to `block`:

```yaml
policies:
  - policyRef:
      name: bot-detection-flex-v1-0
    config:
      mode: block
      blockStatusCode: 403
      blockBody: "Request blocked: automated client detected."
```

## Rollout guidance

1. **Deploy in `audit` mode first** (the default). Nothing gets rejected;
   every flagged request still reaches the upstream but carries the
   `x-p4a-bot-detection: flagged` request header, and each flag emits an
   Anypoint Monitoring policy violation plus a structured `warn` log line
   with the matched reasons (e.g. `ua_denylisted:python-requests`,
   `missing_headers:2`).
2. **Watch the policy violations and the marker header** for a representative
   traffic window. Look specifically for legitimate non-browser clients being
   flagged — mobile SDKs, server-to-server integrations, internal health
   checks, etc.
3. **Tune before enforcing:**
   - Add known-good non-browser clients to `userAgentAllowlist` so they
     short-circuit to Human.
   - Raise `headerSignatureThreshold` if legitimate clients routinely omit
     one or more of the `requiredBrowserHeaders` (or trim
     `requiredBrowserHeaders` itself to headers your traffic actually sends).
4. **Switch to `mode: block`** once the audit signal is clean, choosing
   `blockStatusCode` / `blockBody` to match your API's error conventions.
   Keep `failOpen: true` (the default) unless you have a specific reason to
   fail closed on internal policy errors.

## Caveats

- **Layer-7 only.** Detection is based entirely on request headers
  (`User-Agent` and header-signature). It does not inspect the request body,
  TLS handshake, or connection-level behavior.
- **Complements, does not replace, IP filtering and rate limiting.** This
  policy does not do network-level allow/blocklisting or traffic-volume
  control — pair it with an IP filtering policy and rate limiting / spike
  control for those concerns.
- **JA3/JA4 TLS fingerprinting is out of scope**, permanently — the
  proxy-wasm sandbox this policy runs in has no access to the TLS handshake.
- **Behavioral/velocity analysis and external bot-reputation lookups are
  deferred follow-ups**, not part of this policy today. There is no
  per-client request-rate or inter-arrival tracking, and no outbound call to
  a third-party bot-reputation service.
