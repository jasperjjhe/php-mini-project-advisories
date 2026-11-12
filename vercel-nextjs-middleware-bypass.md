# Vercel Next.js - Draft-mode secret reuse allows middleware authorization bypass (x-prerender-revalidate)

## One-line summary

The value of the `x-prerender-revalidate` header that makes Next.js skip middleware is the same secret handed to draft-mode users as the `__prerender_bypass` cookie, so any holder of a valid draft-mode cookie can bypass authentication middleware on arbitrary requests, including POSTs and Server Actions, on self-hosted deployments. The affected version range is every release line that carries the skip block: verified on 15.5.29 (LTS backport), 16.4.6 (latest stable), and 16.5.0-canary.46 (canary, audited commit); earlier lines that include the same code are likely affected but were not tested. Vercel's own platform edge-executed middleware (deployments hosted on vercel.com/vercel.app) is a different execution environment and was not tested; this finding is specific to self-hosted Node.js server deployments.

## Severity

High - CVSS 3.1: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.1)

PR:L is claimed because exploitation requires possession of a valid draft-mode bypass cookie; such cookies are routinely distributed to non-admin users (content editors, preview reviewers) by the draft-mode feature itself, and the same secret value protects every middleware-gated route on the deployment.

A:N, not A:L: no availability impact was demonstrated and none is plausible from this primitive (the bypass exposes existing routes; it does not exhaust or degrade anything). The vector is byte-identical to the vendor's own scoring vector for CVE-2026-44574 (GHSA-492v-c6pp-mqqv, 8.1), a middleware-authorization bypass whose precondition is strictly weaker because no secret is required; CVSS quantization makes the two scores equal even though this finding's precondition is stronger.

## Affected component

- `packages/next/src/server/next-server.ts`, `runMiddleware`: middleware execution is skipped when the request header `x-prerender-revalidate` equals `previewProps.previewModeId`. The skip block sits at lines 1695-1705 at canary commit `0d6361d3d913bd86e84a7f0a1fc3a0541ad2cc7e` (tag `v16.5.0-canary.46`), at lines 1771-1781 in 16.4.6 (commit `54b876b6b161b0ecda19562eb264bec637e60d6d`), and at lines 1625-1633 in 15.5.29 (commit `17014e9cf7891cc353ebfd8fb4a407f9e4cbbf47`). On a match the method returns a synthetic `x-middleware-next: '1'` response and no user middleware runs for the request.
- `packages/next/src/server/api-utils/index.ts` (`checkIsOnDemandRevalidate`, lines 89-102 at the canary commit): the comparison is a plain `===` between the raw header value and `previewModeId`.
- `packages/next/src/server/async-storage/draft-mode-provider.ts:67-68` and `packages/next/src/server/api-utils/node/api-resolver.ts:154,219`: the same `previewModeId` is the secret value set as the `__prerender_bypass` cookie for draft-mode sessions.
- Version mapping: the npm build tested for the canary row is 16.5.0-canary.46 (tag `v16.5.0-canary.46` = commit `0d6361d3d913bd86e84a7f0a1fc3a0541ad2cc7e`); the source checkout used for the static audit is commit `2e97a394837c5fb6aa11b810106fcd3fc7d64370`. These are different commits, and the skip block is byte-identical in both, so the audited code and the tested build carry the same defect.

## Steps to reproduce

1. Enable draft mode in a self-hosted Next.js application whose middleware protects routes (the standard auth-middleware pattern: redirect to login unless a session cookie exists).
2. Visit any draft-mode-enabled route as a preview user and capture the `__prerender_bypass` cookie value.
3. Send an arbitrary request to any middleware-protected route with the captured cookie and the header `x-prerender-revalidate` set to the same value.
4. Observe that middleware does not execute: the protected route is served (and Server Actions run) without the session the middleware would require.

The header alone works because `runMiddleware` compares the raw header against `previewModeId` before any authorization logic in user middleware runs.

## Validation

Runtime validation was performed on 2026-11-10 against a minimal app-router application (source and Dockerfile available on request): a middleware auth gate on `/admin/*` (session cookie check, 307 to /login on failure), an official `draftMode().enable()` endpoint, a gated JSON route handler, a gated state-changing POST handler, and a gated server action reached through its no-JS multipart form path. The app ran as a Node server (`next build` + `next start`) inside a Docker container published on `127.0.0.1` loopback only, telemetry disabled, no outbound connections at runtime; npm packages were installed from registry.npmjs.org during the image build.

Results by release line (every exchange captured as a raw `curl --trace-ascii` wire trace; every transcript carries the server boot banner naming the exact version):

| next version | channel | gate blocks (C2/C3) | GET bypass (C4) | header-only bypass (C5) | POST bypass (C6b) | server action (C7c) | identity match (C8) | wrong-value control (C11) |
|---|---|---|---|---|---|---|---|---|
| 16.5.0-canary.46 | canary | yes (307) | yes (200) | yes (200) | yes (200) | yes (303) | yes | yes (307) |
| 16.4.6 | latest stable | yes (307) | yes (200) | yes (200) | yes (200) | yes (303) | yes | not captured |
| 15.5.29 | LTS backport line | yes (307) | yes (200) | yes (200) | yes (200) | yes (303) | yes | not captured |

Capture matrix:

| Step | Request | Result | Proves |
|---|---|---|---|
| C1 | `GET /draft` | 200 + `Set-Cookie: __prerender_bypass=<32 hex>` | the official API hands the bypass secret to the client |
| C2 | `GET /admin/secret`, no credentials | 307 to /login | the middleware gate blocks unauthenticated reads |
| C3 | `GET /admin/secret` + draft cookie only | 307 to /login | the cookie alone does not pass the gate |
| C4 | `GET /admin/secret` + cookie + `x-prerender-revalidate: <same value>` | 200, marker `ADMIN-SECRET-OK` | the cookie's value replayed as a header skips middleware |
| C5 | `GET /admin/secret` + header only, no cookie | 200, marker | the skip is driven by the header alone |
| C6a/C6b | `POST /admin/write` without / with credentials | 307 / 200 `ADMIN-WRITE-OK` | state-changing requests behind the gate are reachable |
| C7a | `GET /admin` with bypass | 200 page with the no-JS action form | the skipped render exposes the server action id |
| C7b/C7c | multipart `POST /admin` with the `$ACTION_ID_*` field, without / with bypass | 307 / 303 to `/done?ran=1` | the server action executes with no valid session |
| C8 | read `.next/prerender-manifest.json` in the container | `preview.previewModeId` equals the C1 cookie value | one secret, three identities: build token, cookie value, accepted header |
| C9 | read `/tmp/v1-write-marker.txt` and `/tmp/v1-action.log` in the container | both written, UTC timestamps match the wire responses | server-side corroboration that the bypassed handlers ran |
| C10 | server log tail | boot banner + the actions origin warning | server-side context, see caveats below |
| C11 | `GET /admin/secret` + cookie + `x-prerender-revalidate: <wrong value>` | 307 to /login | a wrong header value does not skip; value-match is the discriminator |

The wrong-value control (C11, captured on the canary build in a follow-up session from the same image): the request is identical to C4 except the header carries a fresh random 32-hex value instead of the cookie's value. Middleware ran and blocked (307 to `/login?blocked=1`). Together with C3 (cookie only, 307) and C4 (same cookie, correct value, 200) this isolates value-matching as the discriminator: neither "any value in that header skips middleware" nor "the original capture was lucky" survives.

Evidence properties:

- Responses on the bypassed requests are live-rendered, not cache replays: the protected routes are `export const dynamic = 'force-dynamic'` and every 200 carries a fresh per-request `now` timestamp (canary: C4 at 22:38:06.521Z, the next request at 22:38:06.941Z; the stable and v15 transcripts show the same pattern).
- Empirical non-duplicate control: 15.5.29 and 16.4.6 postdate the fixes for CVE-2025-29927 (fixed 15.2.3) and CVE-2026-44574/44575 (fixed 15.5.16/16.2.5), and the full chain still reproduces on them.
- When cookie and header are both present with the same value, the request is treated as an on-demand revalidate and draft rendering is disabled (`draftMode` reads `false` in C4 responses). The protected content is still served; an attacker who wants normal-mode rendering sends the header without the cookie (C5).
- Server Actions carry their own Origin/Host check, visible as the "Missing origin header" warning in the server logs. The bypass defeats the middleware authorization layer, not that check; a cross-site form POST from an attacker page would be refused by the action layer itself. The bypass matters where the attacker can present the stolen cookie value from a context that passes the action-layer check (same-site paths, replay tooling), and for route handlers, pages, and every non-action middleware-gated resource, where no second check exists.
- The published cookie flags (Secure, SameSite=none) govern browser storage semantics; replay with curl or any HTTP client is unaffected.

Reproduce commands:

```
docker build --build-arg NEXT_VERSION=16.5.0-canary.46 -t nextjs-v1-poc:canary .
docker run --rm -d --name nextjs-v1-canary -p 127.0.0.1:3111:3000 -e NEXT_TELEMETRY_DISABLED=1 nextjs-v1-poc:canary
node capture.mjs 3111 canary-16.5.0-canary.46 nextjs-v1-canary
```

Swap `NEXT_VERSION` for `16.4.6` or `15.5.29` for the other rows. `react`/`react-dom` install at major-19 ranges and no lockfile ships with the PoC; immaterial here because the defect lives in the `next` package, noted for reproducibility.

## Evidence

Transcripts and captures (paths relative to the PoC directory; available as attachments):

- `evidence/canary-16.5.0-canary.46-transcript.txt` (C1-C10), `evidence/stable-16.4.6-transcript.txt` (C1-C10), `evidence/v15-15.5.29-transcript.txt` (C1-C10), `evidence/c11-wrong-value-control-transcript.txt` (C11)
- `_trace-*.txt`: standalone raw wire traces from the capture runs (every transcript also inlines its own traces)
- `evidence/*-admin-page.html`: captured server-action pages per version
- app source: `middleware.js`, `app/` (draft endpoint, gated routes, server action), `Dockerfile`, `capture.mjs`, `capture-c11.mjs`, `next.config.mjs` (empty config; no revalidation secret or preview-mode override was set by the app)

## Impact

On self-hosted Next.js deployments, middleware is the standard place applications implement authentication and authorization. Anyone legitimately holding a draft-mode bypass cookie - content editors, preview reviewers, CMS integrations - can silently disable that layer for any request, reaching admin APIs, mutating Server Actions, or internal endpoints the middleware was meant to protect. The same secret doubling as both a draft-mode capability and a middleware-skip capability means the blast radius of a leaked draft cookie is the whole application, not draft previews.

## Design context

`x-prerender-revalidate` is by design an ops-facing secret: vercel/next.js#72082 states that "in order for an external system to trigger these revalidation, you'll need to send a request with the `x-prerender-revalidate` header". The reported defect is not the existence of the skip but the identity of the skip token with the browser-distributed draft-mode cookie: a value meant for deployment infrastructure is handed to non-admin human users by `draftMode().enable()`. The skip branch also has no scope restriction - it checks only the value match (`isOnDemandRevalidate`) and ignores `revalidateOnlyGenerated` - so any request presenting the value skips middleware for any route.

## Why this is distinct from prior advisories

- CVE-2025-29927 (GHSA-f82v-jwr5-mffw): header-stacking of `x-middleware-subrequest` to defeat subrequest detection - different mechanism; that mechanism has since been removed entirely, and all three versions tested here are patched for it, yet the bypass reproduces.
- CVE-2026-44574 / CVE-2026-44575 / CVE-2026-45109 (segment-prefetch bypasses): different bypass routes via prefetch routes and route-parameter injection; the tested stable versions are patched for these as well (fixed 15.5.16/16.2.5).
- GHSA-3w37-wq28-93x7: draft-mode content leaking through pending `use cache` - related feature surface, different primitive and impact.
- No published advisory (checked the full 79-advisory archive of this repository, 2020-2026) mentions `x-prerender-revalidate`, `previewModeId` reuse, or the draft cookie acting as a middleware-skip token. NVD keyword search confirms zero hits. GitHub issue search shows no public report of this combination.

## Suggested fix

Decouple the two secrets: derive the middleware-skip token from a deployment-scoped value that is never delivered to browsers (for example, an internal-only revalidate secret distinct from `previewModeId`), and/or validate the `x-prerender-revalidate` header only for trusted internal callers rather than any request presenting the value. Alternatively, refuse the skip when the request also carries a `__prerender_bypass` cookie without an explicit opt-in, so draft-mode users cannot double as middleware skippers.

## Credits

Reporter: Jasper He (jasperjjh on HackerOne)
