# agent-discovery-crawler

Measurement crawler for the agent-discovery layer (paper §4: *Nobody's Home at
`/.well-known`*), v0.5.0 (adds the MCP `initialize` handshake probe (§4.6e)
behind an ethics gate, the coordinated-disclosure tooling, and two reporting
fixes; see "Changes in 0.5.0" at the end).
For each host it fetches the
fourteen canonical discovery paths in random order plus two random nonexistent
paths (SimHash soft-404 baseline), validates each artifact,
fingerprints the hosting platform from the homepage, and runs endpoint/OAuth
hygiene checks on any valid MCP/A2A card or protected-resource document.

## Data

Crawl results are published as gzipped JSONL with a datasheet and SHA-256 manifest in this Google Drive folder:

https://drive.google.com/drive/folders/1jLDzuVje_Y-iQqP0YApaoULo0-PfpmhL

Current release: `release-2026-10-07 (v0.6.0)` — Tranco list 647LX top 100K (three bands), the 5,000-host WebMCP subsample, the commerce (7,810 hosts) and fintech (4,050) vertical corpora, and the MCP-registry corpus (17,238 hosts), each crawled from one local vantage between 5 and 7 October 2026. Per-host security findings (`hygiene`) are withheld until coordinated disclosure completes (window closes 4 January 2027); see `release/DATASHEET.md`. A Zenodo DOI will replace the Drive link at publication.

Node.js >= 20, TypeScript. Dependencies: `undici` (HTTP + proxy agent), `ajv`
(JSON structural checks), `yaml` (OpenAPI YAML), `p-limit` (host concurrency),
`tldts` (registrable domain), and since 0.4.0 `playwright-core` (headless
Chromium driver for the WebMCP module; `playwright-core`, not `playwright`, so
`npm install` does not download a browser — see "WebMCP module" for the one-time
Chromium install).

## Install / run

```sh
npm install                    # no new dependency in 0.5.0; needed once after 0.4.0 (playwright-core)
npx playwright-core install chromium   # one-time, ~150 MB, only needed for the WebMCP module (or set CRAWLER_CHROMIUM_PATH to any Chromium/Chrome binary)
npm test                       # self-test: validators, soft-404 rules, fingerprints, blocked rule, summarizer, Tranco loader, HTTP layer on a loopback server, robots/links/origin-trial helpers, subsample, the handshake probe + disclosure builder against the in-process fixture server, and the WebMCP shim in headless Chromium (88 checks, no external network; the 6 browser checks are skipped with a notice when no Chromium is installed)
export CRAWLER_CONTACT_URL=https://your-lab.example/crawler   # required for any non-fixture corpus
export CRAWLER_CONTACT_EMAIL=crawler-optout@your-lab.example  # required for any non-fixture corpus
npm run crawl -- --hosts hosts/smoke.txt --out out/smoke-us.jsonl --vantage us --concurrency 20 --rps-per-host 1
npm run summarize -- out/smoke-us.jsonl [--platform-table]
npm run crawl:local            # same smoke corpus from a developer laptop (no egress proxy); see hosts/README.md
npm run corpus:tranco          # download the current Tranco list and write hosts/tranco-<id>-{1-1k,1k-10k,10k-100k}.txt (+ tranco-latest-*.txt copies)
npm run crawl:tranco1k         # crawl hosts/tranco-latest-1-1k.txt -> out/tranco-1-1k-local.jsonl, 20 in flight, 1 rps/host, --progress
npm run crawl:tranco10k        # 1K-10K band -> out/tranco-1k-10k-local.jsonl
npm run crawl:tranco100k       # 10K-100K band -> out/tranco-10k-100k-local.jsonl, 40 in flight (split it with --shard, see "Sharding a band")
npm run corpus:webmcp-sample   # 5,000-host WebMCP subsample from the results files -> hosts/webmcp-sample.txt (+ .meta.json)
npm run webmcp -- --hosts hosts/webmcp-sample.txt --out out/webmcp-sample.jsonl --concurrency 4 --pages 4   # headless WebMCP module
npm run handshake -- --in out/tranco-1-1k-local.jsonl --dry-run                                   # list the MCP endpoints the probe WOULD contact (contacts nothing)
npm run handshake -- --in out/tranco-*-local.jsonl --out out/handshake.jsonl --rps 1 --i-have-read-the-ethics-section   # one initialize per endpoint (see "Handshake probe")
npm run disclosure -- --in out/handshake.jsonl --results out/tranco-*-local.jsonl --out release/disclosure/   # findings.csv, email-template.md, summary.md
```

Every `crawl` prints a start banner (version, host counts, vantage,
concurrency, rps, timeout, the User-Agent, and an estimated duration =
`ceil(hosts / concurrency) x 16 requests / rps`, hygiene follow-ups not
included) before the first request.

**Identity (§4.9).** The User-Agent is
`AgentDiscoveryCrawler/0.6 (+$CRAWLER_CONTACT_URL; research; opt-out: mailto:$CRAWLER_CONTACT_EMAIL)`.
Both variables must be set; the CLI refuses to start against any host list
that is not entirely `*.fixture` hosts when either is missing (exit 2). The
`crawl` and `crawl:*` scripts set `UV_THREADPOOL_SIZE=64` so DNS lookups and
zlib work for 20 concurrent hosts do not queue behind libuv's default 4
threads; set it yourself if you invoke `tsx src/run.ts` directly.

`crawl` flags: `--hosts FILE` (one host per line; `#` comments, `rank,domain`
CSV rows and URLs are accepted), `--out FILE.jsonl`, `--vantage LABEL`
(default `local`), `--concurrency N` (hosts in flight, default 20),
`--rps-per-host R` (default 1, paper §4.9), `--timeout-ms` (default 10000),
`--limit N`, `--no-hygiene`, `--store-bodies` (archive valid 200 bodies gzip'd
under `out/bodies/<host>/`, for the consistency module; default off),
`--progress` (one status line to stderr every 60 s: `done/total`, reachable,
blocked, elapsed, ETA, so a long run can be followed with `tail -f` on its
log), `--shard i/n` (take every n-th host of the file starting at i, 0-based;
see "Sharding a band"), `--scheme http` (fixtures only).

The run is **idempotent**: hosts already present in `--out` are skipped, so a
crashed run is resumed by re-running the same command. `SIGTERM` / `SIGINT`
stop it gracefully: no new hosts are started, in-flight hosts finish (at most
a few tens of seconds), the JSONL is flushed and the process exits 0 with a
`stopped: N hosts ..., M left for resume` line; a second signal exits
immediately (in-flight hosts are simply re-crawled on resume). Send the signal
to the node process (`pkill -TERM -f 'src/run.ts'`), not to the `npm` wrapper.

### Long runs

```sh
nohup npm run crawl:tranco1k > out/tranco-1-1k.log 2>&1 &
tail -f out/tranco-1-1k.log          # per-host lines plus a `progress:` line every minute
pkill -TERM -f 'src/run.ts'          # graceful stop; re-run the same command to resume
```

### Egress proxy

All HTTPS goes through whatever `HTTPS_PROXY` points at, via undici's
`EnvHttpProxyAgent` (Node's built-in `fetch` ignores `HTTPS_PROXY` unless
`NODE_USE_ENV_PROXY=1` on Node >= 22.21, so we do not rely on it). TLS
verification is never disabled; the proxy's CA is picked up from
`NODE_EXTRA_CA_CERTS`. When the proxy refuses a tunnel (403/407 on CONNECT) or
answers the request itself with a policy interstitial, the probe is recorded
with `error: "proxy_denied"` and the host with
`blocked.reason = "proxy_denied (crawler egress policy, not target) ..."`. This
is kept distinct from target-side blocking so it is never counted as a site's
bot defense; `summarize` reports it in its own column and excludes those hosts
from the reachable denominator.

### Local end-to-end fixtures

```sh
npm run fixtures &             # http://127.0.0.1:8787, thirteen virtual hosts (seven HTTP-crawl ones, four handshake ones, two WebMCP ones)
npm run crawl:fixtures         # = CRAWLER_FIXTURE_PORT=8787 tsx src/run.ts --hosts hosts/fixtures.txt --out out/fixtures.jsonl --scheme http --rps-per-host 50 --vantage local
npm run summarize -- out/fixtures.jsonl
```

`good.fixture` publishes the full stack (all 14 valid; `llms.txt` is served
gzip, `llms-full.txt` deflate, the MCP card and `openapi.json` brotli, so the
run proves content decoding end to end), `spa.fixture` returns the same 200
HTML for every path (soft-404s), `broken.fixture` has invalid and insecure
artifacts (PRM `resource` mismatch, AS metadata without
`response_types_supported`, a gzip'd OIDC document advertising PKCE `plain`
only, an llms-full.txt whose H1 is not the first line), `blocked.fixture` is a
Cloudflare-style challenge wall, `empty.fixture` 404s, `redirect.fixture`
301s every path to another domain (`redirect_only`), `apex.fixture` 301s
every path to `www.apex.fixture`, which serves a valid `llms.txt` and
`security.txt` (`www_redirect: true`, not `cross_origin_hit`);
`mcp-public.fixture`, `mcp-sse.fixture`, `mcp-protected.fixture` and
`mcp-html.fixture` each publish a card whose endpoint answers `initialize`
differently (see "Handshake probe"; `npm run handshake:fixtures`); `webmcp.fixture`
and `webmcp-none.fixture` belong to the WebMCP module (`hosts/webmcp-fixtures.txt`,
`npm run webmcp:fixtures`; see below). Hosts ending in
`.fixture` are routed to `127.0.0.1:$CRAWLER_FIXTURE_PORT` with the original
`Host` header; this hook is inert unless the env var is set, and the contact
preflight is waived for an all-fixture host list. Fixtures are plain HTTP, so
hygiene correctly reports `*_not_https` for them.

## What is probed (paper §4.2, post-review: 14 paths)

| path | artifact | validity rule |
|---|---|---|
| `/llms.txt`, `/llms-full.txt` | llms.txt | not HTML; Markdown with >= 1 ATX/setext heading (front-matter tolerated); H1 not on the first non-blank line -> `note:h1_not_first` (not fatal) |
| `/.well-known/mcp-server-card` | MCP server card (SEP-2127, current) | JSON object with `name` and `remotes[]` (SEP-2127) **or** `url`/`transport`/`tools` (SEP-1649 draft); `card_spec` records which (`sep-2127` / `sep-1649` / `unknown`); notes for non-reverse-DNS names |
| `/.well-known/mcp/server-card.json` | MCP server card (legacy path) | same rule; tagged `legacy` |
| `/.well-known/oauth-protected-resource` | RFC 9728 | object with `resource` (string) whose value identifies the resource the URL was derived from (§3.3: root doc -> `https://host/`; `.../oauth-protected-resource/<p>` -> `https://host/<p>`), else `prm_resource_mismatch` (invalid). `authorization_servers` is OPTIONAL: absence is `note:prm_no_authorization_servers`, not invalid |
| `/.well-known/oauth-authorization-server` | RFC 8414 | object with `issuer` and non-empty `response_types_supported` (both REQUIRED by §2) |
| `/.well-known/openid-configuration` | OIDC discovery | object with `issuer` and non-empty `response_types_supported` |
| `/.well-known/agent-card.json`, `/.well-known/agent.json` | A2A agent card | object with `name` and one of `url` (legacy) / `supportedInterfaces` (v1.0) / `skills` |
| `/openapi.json`, `/openapi.yaml` | OpenAPI | parses as JSON or YAML; `openapi` string starting `3.` (Swagger 2 recorded as invalid with reason) |
| `/.well-known/ai-catalog.json` | AI Card catalog | any JSON object |
| `/.well-known/security.txt` | RFC 9116 | non-HTML text with a `Contact:` field (missing `Expires:` noted, not fatal) |
| `/ai.txt` | ai.txt | any non-empty non-HTML text |

`/.well-known/mcp.json` was dropped (no spec). `mcp_card_path` on each host
record says which MCP card path answered with a valid card (current path
preferred).

All of these are **lightweight** structural checks (presence and type of the
fields a client needs to proceed), not conformance tests: no JSON Schema for
the full documents, no URL reachability inside the validator, no signature
or TLS-chain verification of issuers, no OpenAPI dereferencing. `valid` means
"a client could start using this"; `reasons[]` records what was looked at so
stricter rules can be re-scored offline from the stored fields.

Request details: `GET`, `https://`, up to 3 redirects **within the same
registrable domain** (tldts, PSL private section enabled, so `a.github.io` and
`b.github.io` are different sites; IP-literal hosts share a "domain" only when
they are the same address, never by last-two-labels fallback). A redirect between
`example.com` and `www.example.com` (either direction, scheme upgrade allowed)
is **same-site**: it is followed, the probe gets `www_redirect: true` with
`final_url`, and `cross_origin_hit` stays `false`. A redirect that lands on
any other origin inside the domain (e.g. `example.com` -> `docs.example.com`)
is followed and the probe gets `cross_origin_hit: true` with `final_url`; a
redirect that leaves the domain is not followed (`error:
cross_domain_redirect`, target kept in `final_url`); a `303` always continues
with `GET`. A host whose every request (14 probes + 2 baselines) is a
`cross_domain_redirect` gets `redirect_only: true` and is excluded from the
reachable denominator. `--timeout-ms` (default 10 s) is applied to connect,
headers and body via a per-timeout undici dispatcher, 2 MiB body cap, probe
order randomized per host (recorded in `probe_order`), User-Agent as above.

**Content decoding.** `accept-encoding: gzip, br, deflate` is sent (CDNs
compress JSON/text by default) and, because `undici.request()` does not
decode, the body is decoded per `content-encoding` with zlib before anything
looks at it: `sha256`, `bytes`, SimHash, validation and the fingerprint all
see the decoded bytes. The cap applies to both encoded and decoded size; a
body that will not decode gets `error: decode_error`.

**Rate limiting.** One global limiter per target hostname, `--rps-per-host`
(default 1) requests per second, inside `fetchUrl` itself, so probes, the
homepage fetch, and every hygiene follow-up to third-party IdPs and endpoints
share it. Twenty hosts in flight means 20 different hostnames at 1 rps each; a
popular IdP referenced by many cards is still hit at 1 rps in total.

**Soft-404**: two random `/__nx_<hex>` paths are fetched first. Each body gets a
64-bit SimHash (3-token shingles over lowercased alphanumeric tokens with
HTML tags and nonce-like tokens stripped; FNV-1a features). A 200 probe is a
soft-404 if (a) its SimHash similarity (`1 - hamming/64`) to either baseline
that itself returned 200 is >= 0.9, or the sha256 matches exactly, reason
`soft404:hash_near_dup`; or (b) its `Content-Type` is `text/html` (or there is
no content-type and the body looks like HTML) for a JSON/Markdown/OpenAPI
path, reason `soft404:html_content_type`. The two reasons are kept distinct
and `nx_similarity` is stored per probe so the threshold can be re-scored
offline. Rule (b) also rejects a correct JSON body mis-served as `text/html`.

**Blocked** (paper §4.3): more than half of the 16 requests (14 probes + 2 nx
baselines) returned 403, 429, a recognized bot challenge (Cloudflare
`cf-mitigated: challenge`, Vercel, DataDome/PerimeterX cookies, Akamai denial
page) or a connection reset. **Only those count.** A host where more than half
failed with DNS/timeout/refused/TLS is `blocked: false` with `reason:
"unreachable:<class> ..."` (a TLS failure is a broken or legacy endpoint, not
a bot defense); a host denied by our own proxy is `blocked: true` with
`reason: "proxy_denied ..."`.

**Fingerprint** (paper §4.4): one `GET /` per host. Labels from response
headers (`server`, `x-powered-by`, `x-vercel-id`, `x-nf-request-id`, `cf-ray`,
`x-shopify-stage`, `x-github-request-id`, `x-served-by`, `via`, ...),
`<meta name="generator">`, and HTML asset markers (mintlify, docusaurus,
readme.io, fern, nextra, mkdocs, nextjs, nuxt, `wp-content`, squarespace, wix,
shopify, ...). Three output fields:

- `fingerprint.platforms` / `primary`: application and hosting labels;
  `primary` is the most specific application-layer label if any, else the
  first hosting label, else `unknown`/`unreachable`.
- `fingerprint.cdn`: the edge layer (`cloudflare`, `fastly`, `akamai`,
  `cloudfront`), kept out of `platforms` so a Shopify store behind Cloudflare
  is stratified as Shopify. `server: cloudflare` on its own says nothing about
  Pages; `cloudflare-pages` requires a `*.pages.dev` asset origin in the HTML.
- `fingerprint.hints`: `hubspot`, `framer`, `gitbook`, `webflow` when the only
  evidence is a script/link tag (an embedded form or widget, or prose). They
  are never promoted to `platforms` or `primary`; a `generator` meta tag or a
  header still counts as a platform.

**Hygiene** (paper §4.6 a–d, post-review) runs for each *valid* MCP card, A2A
card and protected-resource doc on non-blocked hosts:

- endpoint (SEP-2127 `remotes[0].url`, SEP-1649 `url`/`transport.url`, A2A
  `url`, PRM `resource`): scheme is https; resolves (HEAD, falling back to GET
  on 0/405/501; "resolves" = any status other than 404/410, since 401/405 prove
  something is listening); `endpoint_third_party_hosted` when its registrable
  domain differs from the card host (note `third_party_hosted:endpoint`,
  informational);
- RFC 9728 PRM derived from the endpoint path
  (`/.well-known/oauth-protected-resource/<endpoint-path>`) first, then the
  root location; recorded in `prm_lookups[]`; `no_prm_for_endpoint` if neither
  is valid;
- the PRM's `resource` must equal the identifier its URL was derived from
  (RFC 9728 §3.3), else note `prm_resource_mismatch` (and the document does
  not count as the endpoint's PRM);
- `authorization_servers` declared (card, nested auth block, or the PRM found
  above); for each issuer the RFC 8414 metadata URL
  (`/.well-known/oauth-authorization-server[/issuer-path]`, OIDC fallback)
  returns 200; `issuer` matches; `code_challenge_methods_supported` includes
  `S256` (`pkce_advertised`; `plain` alone does not count; note
  `no_pkce_advertised`); issuer on another registrable domain ->
  `third_party_hosted:auth_server` (informational);
- PRM `bearer_methods_supported` must not include `query`
  (`bearer_query_allowed`);
- `Strict-Transport-Security` on the card response (`hsts`, note
  `no_hsts_on_card`) and `Cache-Control` recorded.

§4.6(e), unauthenticated MCP `initialize`, is **not** sent by `crawl`: the
inline field `mcp_unauthenticated_initialize` stays `null`. It is a separate,
gated pass over the crawl results (`npm run handshake`, below) that writes its
own file, so the handshake can be run (or not) independently of the crawl and
the disclosure clock starts from a known date.

## Handshake probe (paper §4.6e) — 0.5.0

```sh
npm run handshake -- --in out/tranco-1-1k-local.jsonl --dry-run                       # prints the target list; contacts nothing; no gate
export CRAWLER_CONTACT_URL=https://your-lab.example/crawler CRAWLER_CONTACT_EMAIL=crawler-optout@your-lab.example
npm run handshake -- --in out/tranco-1-1k-local.jsonl out/tranco-1k-10k-local.jsonl out/tranco-10k-100k-local.jsonl --out out/handshake.jsonl --rps 1 --i-have-read-the-ethics-section
npm run fixtures &  &&  npm run crawl:fixtures  &&  npm run handshake:fixtures   # end to end on the four mcp-*.fixture vhosts -> out/handshake-fixtures.jsonl
```

> Paper §4.6 (ethics-reviewed): *For MCP endpoints advertised in a valid card,
> and only those, we send one JSON-RPC `initialize` request without
> credentials. This is the step the MCP authorization specification tells
> clients to take before discovering metadata. We record the HTTP status, the
> `WWW-Authenticate` header and `serverInfo`, close any returned session with
> `DELETE`, and send nothing further. A 200 is classified as 'no authorization
> challenge at handshake'. We make no claim about whether tools can be invoked.*

The CLI prints this paragraph before doing anything.

### Ethics gate

A real run refuses to start (exit 2) unless **both** hold: `CRAWLER_CONTACT_URL`
and `CRAWLER_CONTACT_EMAIL` are set (same rule as `crawl`; waived only when
every target host is a `*.fixture`), **and** `--i-have-read-the-ethics-section`
is on the command line. `--dry-run` needs neither because it contacts nobody:
it lists every (host, endpoint) the real run would probe, one per line
(`host<TAB>rank<TAB>source<TAB>endpoint`), and flags hosts whose endpoint is
not yet known (`card re-fetch needed`). Run it first and read the list.

### Targets

Input is one or more `crawl` results files. A host is a target only when its
`mcp_card_path` is non-null (a *valid* MCP card was served). The endpoint URL is
taken from the hygiene entries of kind `mcp` (`endpoint.url`, which is
SEP-2127 `remotes[0].url` or SEP-1649 `url`/`transport.url`); when hygiene did
not record one (crawled with `--no-hygiene`, or the host was blocked at crawl
time, or the card had no URL) the card is re-fetched once (one `GET`, through
the limiter) and **every** `remotes[].url` plus the SEP-1649 URL is taken.
Endpoints from valid **A2A** cards are included only if they look like MCP
endpoints: same URL as an MCP card endpoint, or last path segment `mcp`; all
other A2A endpoints are skipped and counted (`a2a_skipped` in the banner), and
a host with an A2A card but no valid MCP card is never a target. Duplicate
(host, endpoint) pairs across files are probed once; rows already present in
`--out` are skipped, so a stopped run resumes.

### What it sends — and never sends

Per endpoint, in this order and nothing else:

1. **One** `POST <endpoint>` with body
   `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"AgentDiscoveryCrawler","version":"0.6.0"}}}`
   and headers `Accept: application/json, text/event-stream`,
   `Content-Type: application/json`, `MCP-Protocol-Version: 2025-11-25`,
   `Mcp-Method: initialize`, the crawler User-Agent. **No `Authorization`, no
   cookie, no token, ever.** 10 s timeout (`--timeout-ms`), 2 MiB cap; an SSE
   response is read up to the first event carrying data and then aborted, so a
   server that keeps the stream open does not hold the probe. A 307/308 is
   followed within the registrable domain (method preserved); a 301/302/303 is
   recorded, not followed (it would turn the POST into a GET).
2. **Only if** the response carried `Mcp-Session-Id`: one `DELETE <endpoint>`
   with that header (and `MCP-Protocol-Version`), the spec's way to close a
   session we were handed. Its status is recorded (`405` = server does not let
   clients terminate sessions; still fine).
3. **Only if** the response was a 401 whose `WWW-Authenticate` names a
   `resource_metadata` URL: one `GET` of that URL (RFC 9728 metadata, a public
   document) to record whether it resolves and whether it is the same document
   hygiene already found for the endpoint (`matches_hygiene_prm`). Disable with
   `--no-resource-metadata`.

No `notifications/initialized`, no `tools/list`, no `tools/call`, no GET to
the MCP endpoint, no second `initialize`, no retry. The self-test asserts this
against the fixture server's request log (exactly one POST per endpoint, every
POST body is `initialize`, DELETE exactly once per issued session, no
`Authorization` header on any request, nothing else). All requests go through
the global per-host limiter (`--rps`, default 1).

### Output (`out/handshake.jsonl`, one row per endpoint)

```jsonc
{
  "host": "mcp.example.com", "rank": 1234, "source": "mcp_card",            // or "a2a_card" (+ "a2a_reason")
  "card_path": "/.well-known/mcp-server-card", "endpoint": "https://mcp.example.com/mcp",
  "ts": "...", "crawler_version": "0.6.0", "protocol_version_sent": "2025-11-25",
  "request": { "method": "POST", "jsonrpc_method": "initialize", "headers": ["accept", "content-type", "user-agent", "mcp-protocol-version", "mcp-method"], "authorization_sent": false },
  "status": 401, "error": null, "final_url": "https://mcp.example.com/mcp", "content_type": "application/json", "elapsed_ms": 212,
  "www_authenticate": { "raw": "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp\"", "scheme": "Bearer", "realm": null, "resource_metadata": "https://mcp.example.com/.well-known/oauth-protected-resource/mcp", "error": null, "error_description": null, "scope": null },
  "mcp_session_id_present": false,
  "body_kind": "json",                     // json | sse | html | text | empty | other
  "jsonrpc": false,                        // body (or first SSE event) is a JSON-RPC message
  "result": null,                          // on success: { "protocol_version", "server_info": { "name", "version" }, "capabilities_keys": ["tools", ...], "instructions_present" }
  "jsonrpc_error": null,                   // { "code", "message", "data_keys" } when the body is a JSON-RPC error
  "classification": "challenge_401",
  "session_delete": null,                  // { "sent": true, "status": 204, "error": null } when a session id was issued
  "resource_metadata": { "url": "...", "status": 200, "error": null, "resolves": true, "is_prm": true, "matches_hygiene_prm": true, "hygiene_prm_urls": ["..."] },
  "requests_made": ["POST https://mcp.example.com/mcp", "GET https://mcp.example.com/.well-known/oauth-protected-resource/mcp"]
}
```

### Classification

| `classification` | rule | reading |
|---|---|---|
| `challenge_401` | 401 with a `WWW-Authenticate` header | the spec'd path: client goes to `resource_metadata` (or the default PRM location) and the OAuth flow |
| `challenge_401_no_header` | 401 without `WWW-Authenticate` | auth required, but the client is not told where (MCP auth spec / RFC 9728 §5.1 want the header) |
| `forbidden_403` | 403 | refused outright (Origin check, WAF, IP policy) |
| `no_challenge_200` | 2xx and the body (JSON, or the first SSE event) is a JSON-RPC `result` | **no authorization challenge at handshake** — `initialize` succeeded without credentials; nothing is claimed about tools |
| `jsonrpc_error_200` | 2xx with a JSON-RPC `error` | an MCP server that refused `initialize` at the protocol level (e.g. unsupported version) |
| `not_mcp` | 2xx that is not a JSON-RPC message (HTML, empty, 202/204) | the advertised URL is not an MCP endpoint (card points at a web page, a notification sink, ...) |
| `modern_no_initialize` | 400 or 404 whose body is a JSON-RPC error | a server on protocol revision 2026-07-28, which has **no** `initialize` method (`-32601` on 404, or `UnsupportedProtocolVersionError` on 400); see the note below |
| `redirect_3xx` | 301/302/303, or too many 307/308 hops | not followed for a POST |
| `error_4xx` / `error_5xx` | any other 4xx / 5xx (404 without a JSON-RPC body, 405, 429, 5xx) | |
| `unreachable` | no HTTP response (`error`: dns, refused, timeout, tls, reset, proxy_denied, cross_domain_redirect) | |

### What the spec says today (verified 2026-10-06) — a note for the paper

The current ("latest") MCP specification is revision **2026-07-28**, and it
**removed the `initialize` handshake and protocol-level sessions** from
Streamable HTTP: every POST is self-describing (protocol version, client info
and capabilities travel in `params._meta`, mirrored into `MCP-Protocol-Version`
/ `Mcp-Method` / `Mcp-Name` headers), there is no `Mcp-Session-Id`, no GET
stream, and a DELETE to the endpoint gets `405`. A 2026-07-28-only server
answers our `initialize` with `404` + JSON-RPC `-32601` (method not found) or
`400` + `UnsupportedProtocolVersionError`; the probe files that as
`modern_no_initialize`. The paper's §4.6 wording ("the step the MCP
authorization specification tells clients to take before discovering
metadata", "close any returned session with DELETE") describes protocol
revisions 2025-03-26 through **2025-11-25**, which is what nearly every deployed
remote MCP server speaks in 2026 and what the SEP-2127 card's
`remotes[].type: "streamable-http"` currently means. The probe therefore
speaks 2025-11-25 (`protocolVersion` in the body and the
`MCP-Protocol-Version` header), which 2026-07-28 says a client MAY do as its
compatibility fallback. Two wording adjustments are suggested: (1) cite the
revision ("the 2025-11-25 Streamable HTTP transport and authorization
specification"); (2) the authorization specification does not literally
instruct clients to send `initialize` *before* metadata discovery — it says a
client that receives a 401 uses `WWW-Authenticate` (or the default RFC 9728
location) to find the PRM, and clients MAY start with the PRM directly; the
accurate phrasing is "the first request a client sends to a Streamable HTTP
endpoint, and the request on which the specification says an authorization
challenge is delivered". Everything else in the paragraph matches the spec:
`initialize` carries no credentials by construction, `Mcp-Session-Id` MAY be
issued on the `InitializeResult` response, clients SHOULD close it with
`DELETE`, and the server MAY answer that `405`.

## Disclosure tooling — 0.5.0

```sh
npm run disclosure -- --in out/handshake.jsonl --results out/tranco-1-1k-local.jsonl out/tranco-1k-10k-local.jsonl out/tranco-10k-100k-local.jsonl --out release/disclosure/
npm run disclosure -- --in out/handshake.jsonl --results out/*.jsonl --out release/disclosure/ --fetch-security-txt   # also GET security.txt of hosts with findings for the Contact: line
```

Reads the handshake file and the crawl results (files named `*handshake.jsonl`
or `*webmcp*` in the `--results` list are ignored, so a shell glob is fine) and
writes, into `--out`:

- **`findings.csv`**, one row per (host, finding), ranked, columns `host, rank,
  finding, evidence, severity, contact_hint, notified_on, remediated_on, notes`.
  Findings: `no_challenge_200` (handshake; **medium**), `dead_card_endpoint`
  (hygiene `endpoint_unreachable`; low), `card_without_endpoint`
  (`no_endpoint_url_in_card`; info), `prm_issuer_mismatch` (`issuer_mismatch`
  on a resolved AS, **excluding** issuers under `shopify.com/authentication`;
  low), `no_pkce_advertised` (low), `prm_resource_mismatch` (low). `evidence` is
  the URL plus the status we saw. `contact_hint` is the security.txt `Contact:`
  line when the crawl archived the body (`--store-bodies`) or
  `--fetch-security-txt` re-fetched it; otherwise `security.txt: <url>` when
  the crawl validated one (bodies are not stored by default), otherwise
  `WHOIS/abuse`. `notified_on` / `remediated_on` are left blank for you to fill;
  the 90-day clock runs from `notified_on`.
  **Shopify storefronts** (fingerprint `shopify`, or any declared issuer under
  `shopify.com/authentication`) never get their own rows: all their findings,
  including the two-issuer `issuer_mismatch` pattern, are rolled into one row
  `shopify-platform-pattern` whose evidence carries the host count and
  per-finding counts — the fix is Shopify's, not the merchants'.
- **`email-template.md`**: a short, plain coordinated-disclosure email with
  `{{placeholders}}` (`{{host}}`, `{{findings_list}}`, `{{observed_on}}`,
  `{{user_agent}}`, `{{spec_pointer}}`, `{{publish_not_before}}`,
  `{{optout_email}}`, `{{contact_email}}`, `{{project_url}}`, ...): what we saw,
  how we saw it (one `initialize`, no credentials, DELETE, nothing else), what
  the spec says, the 90-day window, dataset opt-out, contact.
- **`summary.md`**: counts per finding type, hosts with findings, the Shopify
  roll-up, and the column legend.

The tool makes no network requests unless `--fetch-security-txt` is given
(then one GET per host with findings, through the limiter at 1 rps).


## WebMCP module (paper §4.2, "WebMCP" paragraph) — 0.4.0

```sh
npx playwright-core install chromium                     # once; or CRAWLER_CHROMIUM_PATH=/path/to/chrome, or --chromium PATH
npm run webmcp -- --hosts hosts/webmcp-sample.txt --out out/webmcp-sample.jsonl --concurrency 4 --pages 4 --progress
npm run fixtures &  &&  npm run webmcp:fixtures           # end to end on webmcp.fixture / webmcp-none.fixture -> out/webmcp-fixtures.jsonl
```

### What WebMCP is, as of this release (verified 2026-10-05)

WebMCP is the W3C Web Machine Learning CG proposal that lets a page hand
tools to an in-browser agent. Names changed between the explainer, the spec
draft and Chrome's preview, so the module watches **all of them**:

| surface | where it is named | what we do |
|---|---|---|
| `navigator.modelContext` | the explainer and Chrome's early-preview / origin-trial build (`chrome://flags/#enable-webmcp-testing`; blog coverage of the Chrome 149 trial shows `navigator.modelContext.registerTool({...})`) | feature-detect before shimming, then record |
| `document.modelContext` | the current spec draft's WebIDL (the README of the repo now documents `document.modelContext.registerTool(def, { signal, exposedTo })`, `getTools()`, `executeTool()` and a `toolchange` event) | same |
| `registerTool(tool)`, `unregisterTool(name)`, `provideContext({ tools: [...] })`, `clearContext()` | explainer (imperative API): `provideContext` replaces the whole tool set, `registerTool` adds one | recorded per tool (`provideContext` yields one row per tool in `tools[]`) |
| `getTools()`, `executeTool()` | spec draft | recorded as calls (`tool_name` null for `getTools`) |
| tool descriptor | `name`, `description`, `inputSchema` (JSON Schema), `execute` callback (also seen: `annotations`) | we keep `name`, `description`, the **keys** of `inputSchema.properties` (not the schema), and whether `execute` is a function |
| declarative API | `<form toolname="..." tooldescription="..." [toolautosubmit]>` with `toolparamdescription` on inputs ("Declarative API Explainer" in the repo) | DOM scan for `[toolname]` after load; params = `name`/`id` of `[toolparamdescription]` descendants |
| origin trial | Chrome origin-trial tokens, delivered as `<meta http-equiv="origin-trial" content="…">` or an `Origin-Trial` response header; a token is base64(version byte, 64-byte signature, 4-byte payload length, JSON payload `{origin, feature, expiry, isSubdomain, isThirdParty, …}`) | both channels read on every visited page; payload decoded (feature name, expiry as ISO), **signature not verified** |

Sources: [webmachinelearning/webmcp](https://github.com/webmachinelearning/webmcp)
(repo README, explainer, declarative-api-explainer), the spec draft at
<https://webmachinelearning.github.io/webmcp/>, Chrome-trial write-ups
([1](https://dev.to/thousand_miles_ai/webmcp-in-chrome-149-web-pages-get-a-tool-api-for-ai-agents-bfi),
[2](https://blog.imseankim.com/webmcp-chrome-149-origin-trial-agent-ready-website-2026/),
[3](https://www.pragma-code.de/en/blog-google-webmcp-origin-trial-guide)), and the
Chrome origin-trials token format (<https://github.com/GoogleChrome/OriginTrials>).
The exact origin-trial *feature* string is not asserted anywhere in the code:
whatever the payload says is recorded, and `origin_trial.feature` prefers a
token whose feature matches `/webmcp|modelcontext/i`, else the first token on
the host (sites run other trials too; look at `tokens[]`).

### What the module does per host

1. `GET /robots.txt` through the crawler's own HTTP layer (same UA, proxy and
   per-host limiter). Groups for `AgentDiscoveryCrawler` win over `*`; longest
   match, `Allow` wins ties, `*` / `$` patterns. 404 or no file = allowed.
   Disallowed URLs are never requested and are listed in `robots.skipped[]`;
   a disallowed homepage ends the host with `errors: ["robots_disallows_homepage"]`.
2. One fresh browser context per host (UA from `userAgent()`, service workers
   blocked, images / media / fonts aborted via request routing). The init
   script above runs in every frame before any page script.
3. Load `https://<host>/` (`domcontentloaded`, then up to 5 s for network
   idle, then 1 s settle for late registrations; 15 s navigation timeout),
   then up to `--pages - 1` (default 3) links from the homepage: same
   registrable domain (tldts), `http(s)` only, no assets, no logout-like
   paths, fragments stripped, deduped, links inside `nav` / `header` /
   `[role=navigation]` first. 1 s pause between page loads on one host.
4. After each page: read the shim's records, scan for declarative markup and
   for `script[type]`, `script[src]`, `meta[name|property]`, `link[rel]` that
   mention `webmcp` / `model-context`, read `meta[http-equiv=origin-trial]`
   and the `Origin-Trial` header of the navigation response.

Output, one JSONL row per host, idempotent resume like `crawl`:

```jsonc
{
  "host": "shop.example", "rank": 1234, "registrable_domain": "shop.example", "ts": "...", "crawler_version": "0.4.0", "duration_ms": 9531,
  "pages_visited": ["https://shop.example/", "https://shop.example/tools", "https://shop.example/pricing"],
  "native_modelContext": false,            // navigator.modelContext existed BEFORE our shim on any visited page
  "native_document_modelContext": false,   // document.modelContext (spec-draft name) existed before our shim
  "registrations": [
    { "page": "https://shop.example/", "method": "registerTool", "tool_name": "search_products", "description": "Search the catalog", "input_keys": ["query", "limit"], "has_execute": true },
    { "page": "https://shop.example/tools", "method": "provideContext", "tool_name": "add_to_cart", "description": "...", "input_keys": ["sku", "qty"], "has_execute": true },
    { "page": "https://shop.example/tools", "method": "unregisterTool", "tool_name": "get_cart", "description": null, "input_keys": [], "has_execute": false }
  ],
  "origin_trial": { "present": true, "feature": "WebMCP", "expiry": "2027-01-15T08:00:00.000Z",
    "tokens": [ { "source": "header", "page": "https://shop.example/", "version": 3, "feature": "WebMCP", "expiry": "...", "origin": "https://shop.example:443", "is_subdomain": false, "is_third_party": false } ] },
  "declarative_hits": [ { "page": "https://shop.example/tools", "kind": "declarative_form", "tag": "form", "toolname": "checkout", "tooldescription": "...", "toolautosubmit": true, "params": ["sku", "qty"] } ],
  "robots": { "status": 200, "error": null, "groups": 1, "skipped": ["/private/secret"] },
  "errors": []                             // "page:<url>: <message>" per failed navigation; a failed homepage ends the host
}
```

### Limits (read before quoting numbers)

- **Stock Chromium exposes no WebMCP API.** Without an origin-trial token (or
  the testing flag) `navigator.modelContext` does not exist, and our headless
  Chromium does not enroll in anything, so `native_modelContext` is expected
  to be `false` everywhere; a `true` would mean a Chromium that ships the API
  unflagged (worth checking the Chromium version in the UA). Registrations can
  therefore only be observed on sites that **feature-detect and then call the
  API**, which is exactly what our shim invites: it installs a fake
  `modelContext` so `if (navigator.modelContext)` / `'modelContext' in navigator`
  passes. What the module measures is **attempted registrations** (a page that
  would register tools if the API were there), plus origin-trial enrollment
  (the token is visible whether or not the browser honours it) and declarative
  markup. A page that gates on something else (a UA sniff, the trial flag via
  `document.featurePolicy`, or a server-side check) is missed.
- The shim is installed on both `navigator` and `document`; a page that uses a
  third name is missed. `input_keys` is `Object.keys(inputSchema.properties)`
  (first 50); nested schemas are not kept.
- Up to 4 pages from the homepage's links is a shallow sample of a site; a
  tool that is only registered behind login, on a product page, or after a
  click is missed.
- Playwright drives Chromium with the sandbox disabled (`chromiumSandbox:
  false`) so it runs as root in containers; on a laptop that is harmless but
  it is not a hardened browser — do not point it at hosts you distrust.
- Chromium does not read `NODE_EXTRA_CA_CERTS`: behind a TLS-intercepting
  egress proxy page loads fail with certificate errors (the sandbox this was
  developed in). TLS verification is never relaxed; run from a laptop or a
  plain VM. `HTTPS_PROXY`, when set, is passed to Chromium as its proxy with
  `localhost,127.0.0.1,*.fixture` bypassed.
- Subresource requests of a page are not paced by the per-host limiter (a
  browser cannot be); page loads on one host are serialized with a 1 s gap,
  and `robots.txt` goes through the limiter.
- `playwright-core` 1.63 expects Chromium revision 1243; `resolveChromiumPath()`
  falls back to any `chromium-*` under `PLAYWRIGHT_BROWSERS_PATH` /
  `~/.cache/ms-playwright` (or `CRAWLER_CHROMIUM_PATH`), so an older bundled
  build still launches. Fixture hosts are resolved inside Chromium with
  `--host-resolver-rules=MAP *.fixture 127.0.0.1:$CRAWLER_FIXTURE_PORT`.

### Fixtures and tests

`webmcp.fixture`: `/` calls `navigator.modelContext.registerTool({...})`
guarded by `if (navigator.modelContext)` and sends an `Origin-Trial` header;
`/tools` calls `provideContext({tools:[...]})` then `unregisterTool`, and
carries a declarative `<form toolname="checkout" toolautosubmit>`; `/trial`
has `<meta http-equiv="origin-trial">`; `/private/secret` registers a tool
named `SHOULD_NOT_BE_SEEN` and is `Disallow`ed by `/robots.txt`. The nav also
links an external host, a `.png` and a `#fragment` duplicate.
`webmcp-none.fixture` has two plain pages and no `robots.txt`. The self-test
starts the fixture server in-process on an ephemeral port, launches Chromium
and asserts: the three registration methods are recorded with name /
description / input keys / page; pages visited are home + 3 nav links with
`/private/secret` skipped; header and meta tokens decode to `feature: WebMCP`;
the declarative form is found with its params; `native_modelContext` is
`false` in stock Chromium; the no-WebMCP host yields empty arrays. The
synthetic token used by the fixture is unsigned (64 zero bytes) and would be
rejected by Chrome; we only parse the payload.

## WebMCP subsample (5,000 hosts)

```sh
npm run corpus:webmcp-sample                       # reads out/tranco-{1-1k,1k-10k,10k-100k}-local.jsonl
npm run corpus:webmcp-sample -- --target 5000 --seed 20261005 --results out/tranco-1-1k-local.jsonl out/tranco-1k-10k-local.jsonl out/tranco-10k-100k-local.jsonl out/more.jsonl
```

Strata: **every** reachable host (summarize's `reachable` class: not blocked,
not unreachable, not proxy-denied, not redirect-only) of the first results
file (the 1–1K band; 516 on the current run) is taken; the remaining slots up
to `--target` are filled by a seeded weighted draw without replacement
(Efraimidis–Spirakis keys over a mulberry32 PRNG, deterministic across
platforms) over the reachable hosts of the later files, with weight 2 for a
host that already publishes at least one valid artifact (any of the 14 probes
`valid`) and 1 otherwise — the 2x oversample of publishers. Files that do not
exist are reported and skipped; when only the first two band files exist the
draw takes what it can and prints `SHORTFALL n`, which is also in the meta.
Outputs `hosts/webmcp-sample.txt` (`rank,domain` rows in rank order, two `#`
header lines with seed / counts; the host reader and `webmcp` accept it as is)
and `hosts/webmcp-sample.meta.json` (seed, target, total, shortfall, strata,
weights, and per file: exists, rows, reachable, with_artifact, taken,
taken_with_artifact). Re-running with the same seed and the same inputs
reproduces the file; crawling more hosts first changes the pool and therefore
the draw, so keep the meta next to the results you publish.

## Sharding a band

`--shard i/n` (on `crawl` and `webmcp`) keeps every n-th host of the hosts
file starting at index i (0-based, over the full file order, before the
"already done" filter), so two machines can split a band:

```sh
# machine A
npm run crawl:tranco100k -- --shard 0/2 --out out/tranco-10k-100k-local.shard0.jsonl
# machine B
npm run crawl:tranco100k -- --shard 1/2 --out out/tranco-10k-100k-local.shard1.jsonl
# afterwards, anywhere
cat out/tranco-10k-100k-local.shard0.jsonl out/tranco-10k-100k-local.shard1.jsonl > out/tranco-10k-100k-local.jsonl
npm run summarize -- out/tranco-10k-100k-local.shard0.jsonl out/tranco-10k-100k-local.shard1.jsonl   # or the concatenated file
```

Shards are disjoint and tile the file, each shard resumes on its own `--out`,
and the rows can simply be concatenated (`summarize` also takes several files
and accumulates them). The banner says `(shard i/n of the file)`.
`crawl:tranco100k` runs 40 hosts in flight at 1 rps/host; expect roughly
90,000 hosts / 40 × 16 s ≈ 10 h per machine without sharding, half with
`--shard x/2`.

## Output schema (one JSON object per line)

```jsonc
{
  "host": "docs.example.com",
  "registrable_domain": "example.com",      // via tldts/PSL, null for IPs
  "vantage": "us",
  "ts": "2026-10-04T22:30:00.000Z",
  "crawler_version": "0.3.0",
  "duration_ms": 13200,
  "blocked": {
    "blocked": false,
    "reason": null,                          // "403 on 9/16 probes" | "challenge on ..." | "proxy_denied (...)" | "unreachable:timeout on ..." | "unreachable:tls on ..." | "redirect_only -> www.other.tld"
    "counts": { "200": 3, "404": 13 }        // status / error class histogram over the 16 requests
  },
  "redirect_only": false,                    // true: every request was a cross_domain_redirect; excluded from reachable
  "fingerprint": {
    "homepage_status": 200, "homepage_final_url": "https://docs.example.com/", "homepage_error": null,
    "server": "Vercel", "powered_by": null, "generator": null,
    "platforms": ["mintlify", "nextjs", "vercel"], "primary": "mintlify",
    "cdn": null,                             // "cloudflare" | "fastly" | "akamai" | "cloudfront" | null; never in platforms
    "hints": [],                             // e.g. ["hubspot"] from a script tag only; never primary
    "signals": ["html:mintlify", "html:nextjs", "header:x-vercel-id"]
  },
  "nx_baselines": [ { "path": "/__nx_ab12..", "status": 404, "sha256": "...", "simhash": "9f3c...", "content_type": "text/html", "bytes": 1234 }, { ... } ],
  "mcp_card_path": "/.well-known/mcp-server-card",   // or legacy path, or null
  "probe_order": ["/openapi.yaml", "/llms.txt", ...], // randomized per host
  "probes": [
    {
      "path": "/llms.txt", "artifact": "llms_txt",
      "status": 200,                         // 0 = no HTTP response; see error
      "final_url": "https://docs.example.com/llms.txt",
      "content_type": "text/plain; charset=utf-8", "bytes": 2048, "sha256": "...",
      "redirects": 0, "cross_origin_hit": false, "www_redirect": false, "elapsed_ms": 180,   // www_redirect: the only host change was apex <-> www (same site)
      "error": null,                         // timeout | reset | tls | dns | refused | proxy_denied | too_many_redirects | cross_domain_redirect | body_too_large | decode_error | other
      "simhash": "9f3c...", "nx_similarity": 0.42,
      "soft404": false,
      "valid": true,
      "card_spec": "sep-2127",               // MCP card probes only
      "hsts": "max-age=63072000", "cache_control": "public, max-age=300",
      "body_file": "out/bodies/docs.example.com/llms.txt.gz",   // only with --store-bodies
      "reasons": []                          // e.g. ["status:404"], ["soft404:hash_near_dup"], ["soft404:html_content_type"], ["json_parse_error"], ["schema:required:response_types_supported"], ["prm_resource_mismatch"], ["note:prm_no_authorization_servers"], ["note:h1_not_first"], ["swagger_2_not_3:2.0"], ["cross_origin_hit:https://docs.example.com"], ["www_redirect:https://www.example.com"]
    }
    // ... 14 entries, in canonical order
  ],
  "hygiene": [
    {
      "source": "mcp_server_card", "kind": "mcp", "card_spec": "sep-2127",
      "endpoint": { "url": "https://mcp.example.com/v1/mcp", "https": true, "status": 401, "reachable": true },
      "endpoint_third_party_hosted": false,
      "prm_lookups": [ { "url": "https://mcp.example.com/.well-known/oauth-protected-resource/v1/mcp", "location": "path_suffixed", "status": 200, "valid": true } ],
      "has_authorization_servers": true,
      "authorization_servers": [
        { "issuer": "https://auth.example.com", "https": true, "metadata_url": "https://auth.example.com/.well-known/oauth-authorization-server", "status": 200, "resolves": true, "issuer_match": true, "pkce_advertised": true, "third_party_hosted": false }
      ],
      "bearer_query_allowed": false,
      "hsts": "max-age=63072000", "cache_control": "public, max-age=300",
      "mcp_unauthenticated_initialize": null, // always null inline; the handshake probe writes its own file (npm run handshake)
      "notes": []                             // no_hsts_on_card | endpoint_not_https | endpoint_unreachable | no_endpoint_url_in_card | third_party_hosted:endpoint | no_prm_for_endpoint | prm_resource_mismatch | no_authorization_server_declared | empty_authorization_servers | auth_server_not_https | auth_server_metadata_unresolved | issuer_mismatch | no_pkce_advertised | third_party_hosted:auth_server | bearer_query_allowed
    }
  ]
}
```

Raw bodies are **not** stored by default (only sha256, SimHash, size,
content-type), which keeps the dataset small and satisfies the opt-out clause
in §4.9 by construction. `--store-bodies` archives valid, non-soft-404 200
bodies as `out/bodies/<host>/<path>.gz` for the consistency module (§4.5);
strip opt-out hosts from that directory before release.

`summarize` streams the JSONL line by line into fixed-size accumulators (a
corrupt partial line from a crashed run is skipped) and prints: counts of
reachable / target-blocked / unreachable / redirect-only / proxy-denied hosts;
per-path valid hits over all hosts and over reachable hosts with a Wilson 95%
interval, plus raw 200s, soft-404s, invalid-200s, and separate `x-origin`
(valid hit reached via a redirect to another origin in the domain) and `www`
(valid hit reached via an apex <-> www redirect) columns; a platform breakdown by
`fingerprint.primary` and a CDN-layer line; the blocked list; a hygiene table;
and per-host valid artifacts. The reachable denominator excludes blocked,
unreachable, proxy-denied and redirect-only hosts. The crawler's JSONL writer
honours stream backpressure (`drain`), so a slow disk throttles the crawl
instead of buffering results in memory.

## Layout

```
src/http.ts            undici client: proxy agent, per-timeout dispatcher, content decoding (gzip/br/deflate), same-domain redirects (303->GET), body cap, error classes, proxy-interstitial detection, UA from env, GLOBAL per-host rate limiter
src/types.ts           PROBE_SPECS (the 14 paths) and the output schema types
src/simhash.ts         64-bit SimHash over shingled tokens (soft-404 near-dup)
src/probe.ts           2 nx baselines, randomized probing, SimHash soft-404 + challenge classification, body archiving
src/validate.ts        per-artifact validators (Ajv schemas for JSON cards; Markdown/OpenAPI/text rules)
src/fingerprint.ts     platform fingerprint from the homepage; cdn and hints recorded separately
src/hygiene.ts         endpoint / path-suffixed PRM / authorization-server / PKCE / bearer-query / HSTS checks (§4.6 a–d)
src/handshake.ts       MCP initialize handshake probe (§4.6e): target collection from results, one POST initialize, WWW-Authenticate parsing, SSE first event, classification, DELETE, resource_metadata check
src/handshake-run.ts   handshake CLI (npm run handshake): ethics gate, --dry-run, resume, per-endpoint log
src/disclosure.ts      disclosure builder (npm run disclosure): findings.csv / email-template.md / summary.md, Shopify roll-up
src/run.ts             CLI, contact preflight, blocked / redirect-only rules, --shard, idempotent JSONL writer with backpressure
src/summarize.ts       streaming prevalence + platform + hygiene tables (one or several files)
src/webmcp.ts          WebMCP headless module: init-script shim, robots.txt, link picker, origin-trial decoding, Chromium launch
src/webmcp-run.ts      WebMCP CLI (npm run webmcp): concurrency, pages, resume, --shard
src/corpus/tranco.ts   Tranco corpus builder: zip download / --file, list id, PSL dedupe, rank bands, meta sidecar
src/corpus/subsample.ts 5K WebMCP subsample from results files (seeded, 2x artifact oversample, shortfall report)
src/rank-backfill.ts   adds rank to results crawled before 0.3.2
src/selftest.ts        self-test, 88 checks incl. a loopback HTTP server, the handshake fixtures and headless Chromium (npm test)
src/fixture-server.ts  local virtual-host fixtures for end-to-end runs (compressed responses, mcp-*.fixture handshake vhosts with a request log, WebMCP vhosts)
hosts/smoke.txt        ~110-host smoke corpus (NOT the paper corpus; see hosts/README.md)
hosts/fixtures.txt     the seven HTTP-crawl fixture vhosts + the four handshake vhosts
hosts/webmcp-fixtures.txt  the two WebMCP fixture vhosts
hosts/webmcp-sample.txt    output of corpus:webmcp-sample (not committed)
hosts/tranco-*         output of corpus:tranco (not committed; see below)
```

## Tranco corpus (paper §4.1)

```sh
npm run corpus:tranco                               # download https://tranco-list.eu/top-1m.csv.zip
npm run corpus:tranco -- --file top-1m.csv          # or an already-downloaded CSV / zip
npm run corpus:tranco -- --bands 1-1k,1k-10k        # default: 1-1k,1k-10k,10k-100k
npm run corpus:tranco -- --list-id K25GW            # supply the id if tranco-list.eu/top-1m-id is unreachable
```

The loader reads the list, records the list id from
`https://tranco-list.eu/top-1m-id` (null if unreachable; the files are then
tagged with today's date), reduces every row to its registrable domain
(tldts, PSL public section only: `foo.github.io` collapses to `github.io`
here, because for sampling purposes one operator is one site), keeps the first
occurrence in rank order with a seen-set that spans bands (a domain in `1-1k`
never reappears in `1k-10k`), and writes:

- `hosts/tranco-<listid-or-date>-<band>.txt`: `rank,domain` rows in rank order
  with a two-line `#` provenance header (the host reader accepts both);
- `hosts/tranco-latest-<band>.txt`: a copy of each band file (a copy, not a
  symlink, so it survives Windows checkouts and tarballs); this is what
  `crawl:tranco1k` reads;
- `hosts/tranco-<listid-or-date>.meta.json`: list id, source, download time,
  CSV row count, and per band `from`/`to`, input rows, hosts written, dedupe
  losses and unparseable rows (IP literals, bare TLDs). Since 0.5.0 a run
  **merges** into an existing sidecar for the same list id (same-label bands
  replaced, other bands kept, top-level provenance from the latest run), so
  `--bands 1k-10k` after `--bands 1-1k` leaves both entries in place.

Bands are `LO-HI` with `k`/`m` suffixes; `1-1k` is ranks 1..1000 and `1k-10k`
is 1001..10000, so the defaults tile 1..100000 without overlap. The zip is
unpacked with a minimal built-in central-directory reader (stored and deflate
members) so no new dependency was needed. `tranco-list.eu` is denied by the
sandbox egress proxy, so run `corpus:tranco` from the laptop; the self-test
covers the loader with an inline CSV and an in-memory zip.

## MCP-registry corpus (paper §4.1, corpus C) — 0.6.0

```
npm run corpus:registry                                   # official registry (no key); -> hosts/registry-latest.txt
GLAMA_API_KEY=... SMITHERY_API_KEY=... npm run corpus:registry -- --tranco hosts/tranco-latest-1-1k.txt,hosts/tranco-latest-1k-10k.txt,hosts/tranco-latest-10k-100k.txt
npm run corpus:registry -- --save-pages hosts/registry-official-pages.json   # keep the raw pages (provenance / offline replay with --from-json)
npm run crawl:registry                                    # the usual 14-path crawl over those hosts -> out/registry-local.jsonl
```

Pages the official registry (`/v0.1/servers?version=latest`, cursor
pagination), Glama (`/api/mcp/v1/servers`, needs a key) and Smithery
(`/servers`, needs a key; remote servers are fetched one by one for their
`connections[].deploymentUrl`), keeps every remote (streamable-http / SSE)
endpoint URL and reduces it to a **hostname**. Templates
(`https://{tenant}.example.com/mcp`), loopback, IPs and forge/registry hosts
(github.com, glama.ai, server.smithery.ai, ...) are dropped, which is why
Smithery contributes almost nothing: its hosted servers all live on one
hostname. One host appears once in the hosts file; the sidecar
`hosts/registry-<date>.endpoints.jsonl` keeps every (host, registry, server,
url, transport) row. With `--tranco` the hosts file carries the Tranco rank of
the host, else of its registrable domain with private suffixes honoured
(`mcp.example.com` gets `example.com`'s rank; `x.workers.dev`, `y.vercel.app`
and wildcard-DNS names like `1-2-3-4.sslip.io` get none) and the meta reports how many registry hosts are in the
top 100K at all. A registry that is unreachable or rejects its key is reported
and skipped. The self-test covers the extractors, the cursor walk and the
writer against recorded page shapes; the live calls run from the laptop.

## Commerce / fintech corpus via Cloudflare content categories (paper §4.1, corpus B) — 0.6.0

```
export CLOUDFLARE_API_TOKEN=...      # token with Account > Intel: Read
export CLOUDFLARE_ACCOUNT_ID=...     # the 32-hex id in your dashboard URL
npm run corpus:radar                 # labels all three Tranco bands; ~25 min at 3 req/s x 20 domains; resumable
npm run corpus:radar -- --from-cache # no network: rebuild the selection from hosts/radar-labels.jsonl
npm run crawl:commerce && npm run crawl:fintech   # -> out/commerce-local.jsonl, out/fintech-local.jsonl
```

Labels come from Cloudflare's Domain Intelligence API, `GET
/accounts/{account_id}/intel/domain/bulk?domain=a&domain=b...`, whose items
carry `content_categories[] {id, name, super_category_id}` and
`popularity_rank`. (The Radar ranking endpoint, `/radar/ranking/domain/{d}`,
was the first attempt and returns categories only for the ordered top 100, so
it cannot label a corpus; cache rows from that attempt carry no `source` field
and are ignored.) The loader asks in batches of 20 at a paced 3 requests/s
(Cloudflare's API limit is 1,200 per 5 minutes; 429s are honoured with
`Retry-After`), appends every answer, misses included, to
`hosts/radar-labels.jsonl`, and skips hosts already there, so an interrupted
run resumes and a second run costs nothing. Selection is a pure function of
the cache: a host is *commerce* when any category name matches `COMMERCE_RE`
(shopping, auctions, e-commerce, marketplace, retail, classifieds, coupons) and
*fintech* when any matches `FINTECH_RE` (financ*, bank*, insurance, invest*,
trading, brokerage, crypto, payment, lending, loans, accounting, tax); both
regexes are overridable on the command line and recorded in
`hosts/radar-<date>.meta.json` together with the category histogram, the
labelled / not-found / error counts and the window in which the labels were
fetched. The two corpora may overlap (the meta says by how much); the paper
treats these labels as a convenience classification, not ground truth, and the
fingerprint precision sample is the place to check them. The self-test runs
`labelHosts` against a loopback stand-in (`CRAWLER_INTEL_URL`) for the
cache-skip, legacy-row, batching, 429 retry, miss caching and token-rejection
paths, and the selection and writer on recorded answers.

## Fingerprint precision sample (paper §4.5, limitations) — 0.6.0

```
npm run fp:draw     # seeded stratified draw from the three band files -> out/fingerprint-sample.hosts.jsonl (+ .meta.json)
npm run fp:fetch    # re-fetch each homepage, collect rater evidence -> out/fingerprint-sample.jsonl, release/fingerprint-sample.blind.csv
#  ... a rater fills the `truth` column of the blind CSV (platform label as in fingerprint.ts, "none", or "?") ...
npm run fp:score    # precision / recall per label, accuracy, Cohen's kappa -> out/fingerprint-sample.score.json
```

Twenty reachable hosts per primary platform label with at least 20 hosts, plus
40 hosts the fingerprint left `unknown`, drawn without replacement with a fixed
seed (20261007) and shuffled so the sheet order reveals nothing. The rater
sees evidence that fingerprint.ts does **not** match on: the `<meta
name=generator>` tag, the registrable domains of every foreign script / link /
img / iframe asset on the homepage (most frequent first), which well-known
platform paths answer 200 (`/wp-login.php`, `/wp-json/`,
`/_next/static/chunks/`, `/_nuxt/`, `/cdn/shop/`, `/products.json`, ...), the
page title and the raw `Server` / `X-Powered-By` / `X-Generator` headers. The
predicted label stays in the hosts file and is joined back only at scoring
time. Precision per label is what the paper quotes; recall over the `unknown`
stratum says how much the fingerprint misses. The self-test covers the draw,
the evidence extractor, the CSV round trip and the scorer; the fetch runs from
the laptop.

## TODO

- **WebMCP module follow-ups** (§4.2): a `webmcp:summarize` table; a
  Chrome build with the trial flag on, to measure registrations that are
  gated on the real API rather than on feature detection; signature check of
  origin-trial tokens against Chrome's public key.
- **MCP initialize probe follow-ups** (§4.6e, landed in 0.5.0 as `handshake`):
  join `handshake.jsonl` back into the crawl rows
  (`mcp_unauthenticated_initialize` is still `null` inline); a 2026-07-28-style
  probe (a self-describing `tools/list`? — needs its own ethics review, it is
  not a handshake) for servers classified `modern_no_initialize`.
- **Corpus builders** (§4.1), remaining parts: Cloudflare Radar category join
  (Shopping, Finance); MCP registry / Smithery / Glama scrapers producing
  registrable domains; employer-domain exclusion. (Tranco download, rank
  bands and PSL dedupe landed in 0.3.1 as `corpus:tranco`.)
- **Consistency metric module** (§4.5): consume `out/bodies/` from
  `--store-bodies`; extract card `tools[]`, OpenAPI operationIds / method+path,
  llms.txt link + heading tokens; pairwise Jaccard; fraction of card tools
  without an OpenAPI counterpart.
- Re-score soft-404 threshold offline from stored `nx_similarity` (0.9 was set
  by review; validate against a hand-labelled sample).
- Formal JSON Schema for the SEP-2127 card once it is final; AI Card
  (`ai-catalog.json`) currently gets an object check only.
- The handshake probe POSTs to every `remotes[].url` regardless of
  `remotes[].type`; an `sse`-typed remote (legacy HTTP+SSE transport) answers
  the POST with 4xx/405 and is filed under `error_4xx`, not probed via GET.
- Second vantage (EU) runner and a `diff` command for vantage disagreements and
  §4.7 staleness (appeared / disappeared / changed-hash, llms.txt link rot).

## Changes in 0.3 (code review fixes)

1. **Content decoding (critical).** 0.2 advertised `accept-encoding` but never
   decoded, so every compressed artifact was hashed, SimHashed and validated
   as compressed bytes and the fingerprint read gzip. Fixed in `fetchUrl`;
   fixtures and self-tests cover gzip, br and deflate.
2. UA is `AgentDiscoveryCrawler/0.3` with `CRAWLER_CONTACT_URL` /
   `CRAWLER_CONTACT_EMAIL`; non-fixture crawls refuse to start without them.
3. TLS failures are `unreachable:tls`, no longer a blocked signal.
4. Fingerprint: `cdn` separated from `platforms`; `server: cloudflare` alone
   is not `cloudflare-pages`; hubspot/framer/gitbook/webflow from script/link
   tags only land in `hints[]`.
5. Validation: PRM `authorization_servers` optional (noted); PRM `resource`
   checked against the derived resource URL; `pkce_advertised` requires
   `S256`; A2A v1.0 `supportedInterfaces[].url`; RFC 8414/OIDC require
   `response_types_supported`; llms.txt `note:h1_not_first`.
6. Scale: global per-host limiter covering hygiene fetches; `--timeout-ms`
   wired into the dispatcher; `UV_THREADPOOL_SIZE=64`; streaming summarizer;
   JSONL backpressure; `redirect_only` hosts tagged and excluded from the
   reachable denominator.
7. IP-literal hosts never share a registrable domain unless identical;
   `303` continues with `GET`.

Results from 0.2 are not comparable for any host served compressed; re-crawl.

## Changes in 0.3.1

1. **www is same-site.** A redirect between `example.com` and
   `www.example.com` (either direction) no longer sets `cross_origin_hit`; the
   probe gets `www_redirect: true` (and `final_url`), reason
   `www_redirect:<origin>`. `docs.example.com` and other in-domain origin
   changes are still `cross_origin_hit`. `sameRegistrableDomain` also treats a
   bare www variant as the same domain regardless of the TLD. `summarize` shows
   `www` as its own column next to `x-origin`. New fixture vhost `apex.fixture`
   -> `www.apex.fixture`.
2. **Tranco corpus loader** `src/corpus/tranco.ts` / `npm run corpus:tranco`
   (see "Tranco corpus" above): zip download or `--file`, list id, PSL dedupe
   across rank bands, `hosts/tranco-<id>-<band>.txt`, `tranco-latest-<band>.txt`
   copies and a `.meta.json` sidecar. No new dependency.
3. `--vantage` defaults to `local`; a start banner reports host counts,
   concurrency, rps, UA and an estimated duration.
4. `--progress` prints a one-line status every 60 s to stderr; `SIGTERM` /
   `SIGINT` stop gracefully (in-flight hosts finish, JSONL flushed, exit 0),
   relying on the idempotent resume.
5. `npm run crawl:tranco1k` crawls `hosts/tranco-latest-1-1k.txt` with
   `--progress`.
6. `crawler_version` is `0.3.1`; the UA stays `AgentDiscoveryCrawler/0.3`.
   Results from 0.3.0 differ only in the new `www_redirect` field and in
   `cross_origin_hit` being false for apex <-> www hops; no re-crawl needed.


## Changes in 0.3.2

- `rank` is carried from `rank,domain` hosts files (Tranco bands) into every JSONL row (`null` for plain host lists), so rank-band splits can be done inside one results file.
- `npm run rank:backfill -- --hosts hosts/tranco-latest-1-1k.txt --in out/tranco-1-1k-local.jsonl` adds `rank` to a results file crawled before 0.3.2 (rewrites in place, keeps a `.bak`).
- `npm run crawl:tranco10k` crawls the 1K–10K band (after `npm run corpus:tranco -- --bands 1k-10k`).

## Changes in 0.4.0

1. **WebMCP headless module** (`src/webmcp.ts`, `npm run webmcp`): headless
   Chromium via `playwright-core`, homepage + up to 3 same-registrable-domain
   nav links, init-script shim that feature-detects `navigator.modelContext` /
   `document.modelContext` before installing recording proxies for
   `registerTool` / `unregisterTool` / `provideContext` / `clearContext` /
   `getTools` / `executeTool`, declarative `<form toolname>` scan, origin-trial
   token capture (meta + header) with payload decoding, robots.txt
   (Disallow honoured, skipped paths recorded), images / media / fonts
   blocked, 15 s navigation timeout, contact preflight, idempotent resume.
   New fixtures `webmcp.fixture` / `webmcp-none.fixture`
   (`hosts/webmcp-fixtures.txt`, `npm run webmcp:fixtures`). See "WebMCP
   module" for what it can and cannot see.
2. **New dependency `playwright-core`** (not `playwright`): `npm install` is
   required again; Chromium itself is a one-time
   `npx playwright-core install chromium` (or `CRAWLER_CHROMIUM_PATH`).
3. **5K WebMCP subsample** (`src/corpus/subsample.ts`, `npm run
   corpus:webmcp-sample`): all reachable 1–1K hosts + seeded weighted draw
   (artifact publishers x2) from the later bands, `hosts/webmcp-sample.txt`
   + `.meta.json`, works with only the first two band files (shortfall
   reported).
4. **Sharding**: `--shard i/n` on `crawl` and `webmcp`; `summarize` takes
   several files. `npm run crawl:tranco100k` (10K–100K band, 40 in flight,
   1 rps/host, `--progress`).
5. `src/fixture-server.ts` exports `startFixtureServer(port)` (the self-test
   starts it in-process on an ephemeral port). Fixed: `run.ts`'s main guard
   matched any `*run.ts` entry point (it would have started the HTTP crawler
   when imported by `webmcp-run.ts`).
6. `crawler_version` is `0.4.0`; the UA is `AgentDiscoveryCrawler/0.4`. The
   HTTP crawl output is unchanged apart from the version string; results from
   0.3.2 need no re-crawl.

## Changes in 0.6.1

Fingerprint rules tightened after the precision sample (560 hosts, 20 per
label, rated from evidence the rules do not use; `release/fingerprint-sample.blind.csv`,
`out/fingerprint-sample.score.json`): `nextra` (was 0% precision: the
substring matched font names such as "PantonExtraBold"), `readme.io` (0%:
matched prose and links) and `squarespace` (35%) now require an asset path,
a theme file or a bootstrap symbol; a `pages.dev` asset is a hint rather than
a platform (26%: widgets hosted on Pages). Unchanged labels and their
measured precision: shopify 100%, ghost 100%, hugo 100%, hubspot 100%,
webflow 100%, framer 95%, docusaurus 85%, gatsby 85%, wordpress 80%, wix 80%,
nextjs 70%, nuxt 40%; header-derived hosting labels 89–100% where the
re-fetch saw the same header (github-pages, vercel, netlify disagree mainly
because a CDN in front hid the origin header on re-fetch). Results files
crawled with 0.6.0 and earlier keep the old labels; the paper reports the
measured precision alongside them. UA `AgentDiscoveryCrawler/0.6`,
`crawler_version` `0.6.1`; probe set and output schema unchanged.

## Changes in 0.6.0

1. **MCP-registry corpus loader** (`src/corpus/registry.ts`, `npm run
   corpus:registry`) and **Cloudflare Radar commerce / fintech loader**
   (`src/corpus/radar.ts`, `npm run corpus:radar`), see the two sections
   above; `crawl:registry`, `crawl:commerce`, `crawl:fintech` scripts.
2. Version bump: UA `AgentDiscoveryCrawler/0.6`, `crawler_version` `0.6.0`.
   Nothing in the probe set, classification or output schema changed, so
   0.5.0 and 0.6.0 results files are directly comparable.
3. **Fingerprint precision sample** (`src/fingerprint-sample.ts`, `npm run fp:draw|fetch|score`), see its section.
4. Self-test: 100 checks (was 88).

## Changes in 0.5.0

1. **MCP `initialize` handshake probe** (`src/handshake.ts`,
   `src/handshake-run.ts`, `npm run handshake`; paper §4.6e). A separate pass
   over crawl results: for hosts with a valid MCP card, one JSON-RPC
   `initialize` (protocol 2025-11-25, no credentials) per advertised endpoint,
   record status / `WWW-Authenticate` / `serverInfo` / `Mcp-Session-Id`, close
   an issued session with `DELETE`, GET the `resource_metadata` URL from the
   challenge and compare it with hygiene's PRM, classify (see the table). Gated
   on the contact env vars **and** `--i-have-read-the-ethics-section`;
   `--dry-run` lists targets without contacting anyone; prints the §4.6
   paragraph at start. Verified against modelcontextprotocol.io on 2026-10-06:
   the latest revision (2026-07-28) has no `initialize`, so the probe speaks
   2025-11-25 and files 2026-07-28 servers as `modern_no_initialize` (see
   "What the spec says today").
2. **Disclosure tooling** (`src/disclosure.ts`, `npm run disclosure`):
   `findings.csv` (per host x finding, with severity and contact hint; Shopify
   storefronts rolled into one `shopify-platform-pattern` row), a plain
   coordinated-disclosure `email-template.md` with placeholders, `summary.md`.
3. **HTTP layer**: `fetchUrl` accepts `POST` (with body) and `DELETE`, extra
   headers, and an SSE early-stop; a POST/DELETE follows only 307/308. The
   fixture routing hook is `resolveFixtureTarget()`. GET/HEAD behaviour is
   unchanged.
4. **Fixtures**: `mcp-public.fixture` (JSON result + session id, DELETE
   handler), `mcp-sse.fixture` (result in an SSE stream that stays open),
   `mcp-protected.fixture` (401 + `WWW-Authenticate` with `resource_metadata`,
   plus the PRM and AS metadata), `mcp-html.fixture` (200 HTML); the fixture
   server logs every request (`FIXTURE_REQUEST_LOG`) and every terminated
   session, and the self-test asserts exactly one POST per endpoint, all
   `initialize`, one DELETE per session, no `Authorization` header, nothing
   else, and that `--dry-run` contacts nothing. `npm run handshake:fixtures`.
5. **Reporting fixes**: `corpus:tranco` merges bands into an existing
   `tranco-<id>.meta.json` instead of overwriting it; the `webmcp` progress
   line counts `webmcp-origin-trial` only for tokens whose feature is WebMCP
   and reports `other_trials` separately (the per-host line shows
   `trial=other:<feature>` for those).
6. `crawler_version` is `0.6.0`; the UA is `AgentDiscoveryCrawler/0.6`. The
   `crawl` output is unchanged apart from the version string; results from
   0.4.0 need no re-crawl and are valid input to `handshake`. No new
   dependency: `npm install` is not needed after 0.4.0. Self-test: 88 checks.
