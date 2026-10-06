# Host lists

## smoke.txt (~110 hosts)

A smoke corpus for exercising the crawler: ~30 popular sites, ~30
developer-docs sites likely to publish `llms.txt`, ~25 ecommerce/fintech
sites, ~20 known remote-MCP hosts, and the author-controlled test hosts
`nicky.me` / `pay.nicky.me`. It is **not** the paper corpus (§4.1: Tranco
strata, Tranco ∩ Cloudflare Radar Shopping/Finance, MCP registries); nothing
measured on it belongs in a results table.

**It must be run from a non-proxied vantage.** The sandbox this crawler was
developed in routes all egress through a policy proxy that refuses CONNECT for
every host on this list (and answers `github.com` paths itself), so
`out/smoke-us.jsonl` from that environment is 110 × `proxy_denied` and carries
no information about the sites. Run it from a developer laptop, a plain cloud
VM, or whichever US/EU vantage the paper uses:

```sh
export CRAWLER_CONTACT_URL=https://your-lab.example/crawler
export CRAWLER_CONTACT_EMAIL=crawler-optout@your-lab.example
npm run crawl:local        # -> out/smoke-local.jsonl, vantage=local, 10 hosts in flight, 1 req/s/host
npm run summarize -- out/smoke-local.jsonl
```

The crawler refuses to start on this list without both contact variables.

Expect roughly 25 minutes (16 requests per host at 1 req/s, 10 hosts in
parallel, plus hygiene follow-ups). Set `HTTPS_PROXY` only if your network
needs it; the crawler honors it via undici and never disables TLS checks.

## fixtures.txt

The seven virtual hosts served by `npm run fixtures`; see the README section
"Local end-to-end fixtures".

## webmcp-fixtures.txt

The two WebMCP fixture vhosts (`webmcp.fixture`, `webmcp-none.fixture`) for
`npm run webmcp:fixtures`; see the README section "WebMCP module".

## webmcp-sample.txt / webmcp-sample.meta.json (generated, not committed)

Output of `npm run corpus:webmcp-sample`: the 5,000-host stratified WebMCP
subsample (`rank,domain`, rank order, two `#` header lines) and its meta
sidecar (seed, per-file counts, shortfall). Input for `npm run webmcp`.

## tranco-*.txt / tranco-*.meta.json (generated, not committed)

Output of `npm run corpus:tranco` (see the README section "Tranco corpus"):
`tranco-<listid-or-date>-<band>.txt` per rank band, `tranco-latest-<band>.txt`
copies that `npm run crawl:tranco1k` reads, and a `.meta.json` sidecar with the
list id, download date and per-band counts. Rows are `rank,domain`, deduped to
registrable domain, in rank order.

## Format

One host per line. `#` comments, blank lines, `rank,domain` CSV rows (Tranco)
and full URLs are accepted; hosts are lower-cased and de-duplicated.
