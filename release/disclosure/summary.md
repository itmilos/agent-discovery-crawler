# Disclosure summary

Generated 2026-10-06T12:27:28.238Z by agent-discovery-crawler 0.5.0.
Inputs: handshake out/handshake.jsonl (85 rows); results out/tranco-1-1k-local.jsonl, out/tranco-10k-100k-local.jsonl, out/tranco-1k-10k-local.jsonl (99996 rows).

| finding | severity | rows |
|---|---|---|
| no_challenge_200 | medium | 32 |
| dead_card_endpoint | low | 13 |
| card_without_endpoint | info | 18 |
| prm_issuer_mismatch | low | 4 |
| no_pkce_advertised | low | 13 |
| prm_resource_mismatch | low | 12 |
| shopify-platform-pattern | info | 1 |

Hosts with at least one finding (Shopify storefronts excluded): 78.
Shopify storefront hosts rolled into one row: 360 (prm_issuer_mismatch=359, dead_card_endpoint=1).

Columns of findings.csv: host, rank, finding, evidence (URL + status), severity, contact_hint (security.txt Contact: line when the crawl stored or re-fetched it, else the security.txt URL the crawl validated, else WHOIS/abuse), notified_on, remediated_on, notes. Fill notified_on when the email goes out; the 90-day window counts from that date.

## Notification log

- 2026-10-06: 78 notices sent from milosrujevic@gmail.com (one per host; 93 findings). 90-day window closes 2027-01-04. Replies and opt-outs to be logged here.
