# Agent-discovery crawl dataset

Measurements of the files websites publish for AI agents: `llms.txt`, MCP server cards, OAuth protected-resource and authorization-server metadata, A2A agent cards, `ai-catalog.json`, OpenAPI documents, `security.txt`, `ai.txt`, and in-page WebMCP tool registrations.

Data licence: CC BY 4.0. Code licence: MIT (see `LICENSE` at the repository root).

## What is in each file

| File | Rows | What it is |
| --- | --- | --- |
| `tranco-1-1k-local.jsonl.gz` | 1,000 | Tranco list 647LX, ranks 1-1,000, HTTP probes, 2026-10-05 |
| `tranco-1k-10k-local.jsonl.gz` | 8,999 | Tranco list 647LX, ranks 1,001-10,000, 2026-10-05 |
| `tranco-10k-100k-local.jsonl.gz` | ~90,000 | Tranco list 647LX, ranks 10,001-100,000, 2026-10-05/06 |
| `webmcp-sample.jsonl.gz` | 4,999 | Headless-Chromium WebMCP pass over a 5,000-host stratified subsample |
| `tranco-647LX.meta.json` | | Corpus build metadata: list id, download time, band counts, dedupe losses |
| `webmcp-sample.meta.json` | | Subsample seed, weights and strata |
| `*-summary.txt` | | Human-readable summaries used in the paper |
| `MANIFEST.json` | | SHA-256 and row counts for every data file |

One JSON object per host. Field names are documented in the repository README ("Output schema"). The `rank` field is the Tranco rank; `blocked`, `redirect_only` and per-probe `error` fields say why a host has no data.

## How it was collected

Fourteen `GET` probes per host over HTTPS at no more than one request per second per host, from a single residential vantage point in the United States, with a descriptive user agent and an opt-out address. Redirects were followed within the registrable domain. Soft-404s were detected by comparing each response with two random nonexistent paths on the same host (SimHash >= 0.9) and by content type. The WebMCP pass loaded the homepage and up to three same-domain pages in headless Chromium with a recording shim installed before page scripts ran, honoring `robots.txt`.

Full method: paper Section 4, and the repository README.

## What is withheld, and why

The `hygiene` field (per-host security findings: missing authorization metadata, issuer mismatches, unreachable advertised endpoints) is removed from this release. Operators are being notified under a 90-day coordinated-disclosure process; the field will be added when the window closes. Raw response bodies were never stored; only hashes, sizes and validation flags.

## Known limitations

- One vantage point so far. Bot-blocking rates (about 10 to 12 percent of hosts) are a lower bound on false negatives.
- Tranco ranks DNS popularity, not websites: 23 to 30 percent of hosts in each band have no site at the apex. Report prevalence over reachable hosts.
- The WebMCP subsample over-weights hosts that publish any other artifact by two to one; the top-1K stratum is a census, the rest is a weighted draw.
- Stock Chromium exposes no `modelContext` object, so WebMCP registrations are attempted registrations on pages that call the API unconditionally or carry an origin-trial token.
- Platform fingerprints are heuristic; precision has not yet been measured on a manual sample.

## Opting out

Operators who want their host's rows removed from future releases can write to the address in the crawler's user-agent string, or open an issue on the repository.

## Citation

Paper under review. Until it is published, cite this repository and the Tranco list id 647LX.
