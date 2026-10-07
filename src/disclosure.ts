#!/usr/bin/env node
// Coordinated-disclosure tooling (paper §4.9): turns handshake + crawl results
// into a findings sheet, an email template and a per-finding summary.
//   npm run disclosure -- --in out/handshake.jsonl --results out/*.jsonl --out release/disclosure/
//
// Findings (one row per host x finding):
//   no_challenge_200      initialize answered without credentials (handshake file)       medium
//   dead_card_endpoint    card endpoint 404/410/unreachable (hygiene endpoint_unreachable) low
//   card_without_endpoint valid card, no endpoint URL (hygiene no_endpoint_url_in_card)    info
//   prm_issuer_mismatch   AS metadata `issuer` != declared issuer (hygiene issuer_mismatch),
//                         EXCLUDING the Shopify two-issuer platform pattern                low
//   no_pkce_advertised    AS metadata without S256 (hygiene no_pkce_advertised)            low
//   prm_resource_mismatch PRM `resource` != derived identifier (RFC 9728 §3.3)             low
// Shopify storefronts (fingerprint shopify, or an issuer under shopify.com/authentication)
// are rolled up into ONE row "shopify-platform-pattern" with counts: the fix is Shopify's,
// not the merchant's, and 10,000 identical rows would drown the sheet.
import { createReadStream, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { CRAWLER_VERSION, bodyText, fetchUrl, setGlobalRps } from './http.js';
import type { HandshakeResult } from './handshake.js';
import type { HostResult, HygieneEntry } from './types.js';

export type FindingType = 'no_challenge_200' | 'dead_card_endpoint' | 'card_without_endpoint' | 'prm_issuer_mismatch' | 'no_pkce_advertised' | 'prm_resource_mismatch' | 'shopify-platform-pattern';
export type Severity = 'info' | 'low' | 'medium';

export interface Finding {
  host: string;
  rank: number | null;
  finding: FindingType;
  evidence: string; // URL + status
  severity: Severity;
  contact_hint: string;
  notified_on: string;
  remediated_on: string;
  notes: string;
}

export const SEVERITY: Record<FindingType, Severity> = {
  no_challenge_200: 'medium',
  dead_card_endpoint: 'low',
  card_without_endpoint: 'info',
  prm_issuer_mismatch: 'low',
  no_pkce_advertised: 'low',
  prm_resource_mismatch: 'low',
  'shopify-platform-pattern': 'info',
};

export const SHOPIFY_ISSUER_RE = /^https?:\/\/([a-z0-9-]+\.)*shopify\.com\/authentication\b/i;

export function isShopifyIssuer(issuer: string): boolean {
  return SHOPIFY_ISSUER_RE.test(issuer);
}

/** Shopify storefront: fingerprint says so, or any hygiene entry declares a shopify.com/authentication issuer. */
export function isShopifyHost(row: Pick<HostResult, 'fingerprint' | 'hygiene'>): boolean {
  const fp = row.fingerprint;
  if (fp && (fp.primary === 'shopify' || (fp.platforms ?? []).includes('shopify'))) return true;
  return (row.hygiene ?? []).some((h) => (h.authorization_servers ?? []).some((a) => isShopifyIssuer(a.issuer)));
}

/** First `Contact:` line of a security.txt body (RFC 9116). */
export function securityTxtContact(text: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    const m = /^contact:\s*(.+?)\s*$/i.exec(line);
    if (m) return m[1];
  }
  return null;
}

async function* readRows<T>(path: string): AsyncGenerator<T> {
  if (!existsSync(path)) return;
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    try { yield JSON.parse(line) as T; } catch { /* partial line */ }
  }
}

export interface HostContext { rank: number | null; shopify: boolean; security_txt_valid: boolean; security_txt_url: string | null; security_txt_body_file: string | null }

/** Findings from the hygiene entries of one crawl row (not for Shopify hosts; the caller rolls those up). */
export function hygieneFindings(row: HostResult, ctx: HostContext, cardUrl: (path: string) => string): Omit<Finding, 'contact_hint' | 'notified_on' | 'remediated_on'>[] {
  const out: Omit<Finding, 'contact_hint' | 'notified_on' | 'remediated_on'>[] = [];
  const add = (finding: FindingType, evidence: string, notes = '') => out.push({ host: row.host, rank: ctx.rank, finding, evidence, severity: SEVERITY[finding], notes });
  for (const h of row.hygiene ?? []) {
    const src = cardUrl(sourcePath(h));
    if (h.notes.includes('endpoint_unreachable') && h.endpoint) add('dead_card_endpoint', `${h.endpoint.url} -> ${h.endpoint.status ?? h.endpoint.error ?? 'no response'}`, `advertised by ${src}`);
    if (h.notes.includes('no_endpoint_url_in_card')) add('card_without_endpoint', `${src} -> 200 (valid card, no endpoint URL)`);
    if (h.notes.includes('prm_resource_mismatch')) {
      const prm = h.kind === 'protected_resource' ? src : (h.prm_lookups.find((p) => p.status === 200)?.url ?? src);
      add('prm_resource_mismatch', `${prm} -> 200 (resource does not match the URL it was served from, RFC 9728 §3.3)`);
    }
    for (const a of h.authorization_servers ?? []) {
      if (a.resolves && a.issuer_match === false && !isShopifyIssuer(a.issuer)) { // Shopify two-issuer pattern: rolled up by the caller
        add('prm_issuer_mismatch', `${a.metadata_url} -> ${a.status} (issuer in metadata != ${a.issuer})`, `declared by ${src}`);
      }
      if (a.resolves && a.pkce_advertised === false) add('no_pkce_advertised', `${a.metadata_url} -> ${a.status} (code_challenge_methods_supported lacks S256)`, `declared by ${src}`);
    }
  }
  return out;
}

function sourcePath(h: HygieneEntry): string {
  switch (h.source) {
    case 'mcp_server_card': return '/.well-known/mcp-server-card';
    case 'mcp_server_card_legacy': return '/.well-known/mcp/server-card.json';
    case 'a2a_agent_card': return '/.well-known/agent-card.json';
    case 'a2a_agent_json': return '/.well-known/agent.json';
    case 'oauth_protected_resource': return '/.well-known/oauth-protected-resource';
    default: return `/${h.source}`;
  }
}

export function csvEscape(v: string | number | null | undefined): string {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export const CSV_COLUMNS = ['host', 'rank', 'finding', 'evidence', 'severity', 'contact_hint', 'notified_on', 'remediated_on', 'notes'] as const;

export function renderCsv(findings: Finding[]): string {
  const lines = [CSV_COLUMNS.join(',')];
  for (const f of findings) lines.push(CSV_COLUMNS.map((c) => csvEscape(f[c] as string | number | null)).join(','));
  return lines.join('\n') + '\n';
}

export interface BuildOptions { handshakeFile: string; resultsFiles: string[]; scheme?: 'https' | 'http'; fetchSecurityTxt?: boolean; timeoutMs?: number; log?: (s: string) => void }

export interface BuildOutput { findings: Finding[]; counts: Record<string, number>; hosts: number; shopify: { hosts: number; by_finding: Record<string, number> }; inputs: { handshake_rows: number; result_rows: number }; generated_at: string }

export async function buildFindings(opts: BuildOptions): Promise<BuildOutput> {
  const scheme = opts.scheme ?? 'https';
  const ctx = new Map<string, HostContext>();
  const raw: Omit<Finding, 'contact_hint' | 'notified_on' | 'remediated_on'>[] = [];
  const shopifyCounts: Record<string, number> = {};
  const shopifyHosts = new Set<string>();
  let resultRows = 0;
  for (const f of opts.resultsFiles) {
    for await (const row of readRows<HostResult>(f)) {
      resultRows++;
      const sec = row.probes?.find((p) => p.path === '/.well-known/security.txt');
      const c: HostContext = { rank: row.rank ?? null, shopify: isShopifyHost(row), security_txt_valid: !!sec?.valid, security_txt_url: sec?.valid ? (sec.final_url || `${scheme}://${row.host}/.well-known/security.txt`) : null, security_txt_body_file: sec?.body_file ?? null };
      ctx.set(row.host, c);
      const found = hygieneFindings(row, c, (p) => `${scheme}://${row.host}${p}`);
      if (c.shopify) {
        for (const x of found) { shopifyCounts[x.finding] = (shopifyCounts[x.finding] ?? 0) + 1; shopifyHosts.add(row.host); }
        // the excluded Shopify two-issuer issuer_mismatch is counted too, so the aggregate row says how big the pattern is
        for (const h of row.hygiene ?? []) for (const a of h.authorization_servers ?? []) if (a.resolves && a.issuer_match === false && isShopifyIssuer(a.issuer)) { shopifyCounts.issuer_mismatch_two_issuer = (shopifyCounts.issuer_mismatch_two_issuer ?? 0) + 1; shopifyHosts.add(row.host); }
        continue;
      }
      raw.push(...found);
    }
  }
  let handshakeRows = 0;
  for await (const r of readRows<HandshakeResult>(opts.handshakeFile)) {
    handshakeRows++;
    if (r.classification !== 'no_challenge_200') continue;
    const c = ctx.get(r.host);
    if (c?.shopify) { shopifyCounts.no_challenge_200 = (shopifyCounts.no_challenge_200 ?? 0) + 1; shopifyHosts.add(r.host); continue; }
    const si = r.result?.server_info ? `${r.result.server_info.name ?? '?'}@${r.result.server_info.version ?? '?'}` : 'serverInfo absent';
    raw.push({ host: r.host, rank: r.rank ?? c?.rank ?? null, finding: 'no_challenge_200', evidence: `POST initialize ${r.endpoint} -> ${r.status} (${r.body_kind}, ${si}${r.mcp_session_id_present ? ', session id issued, closed with DELETE' : ''})`, severity: SEVERITY.no_challenge_200, notes: `card ${scheme}://${r.host}${r.card_path ?? ''}; probe ${r.ts}` });
  }
  // contact hints
  const contactCache = new Map<string, string>();
  const findings: Finding[] = [];
  for (const f of raw.sort((a, b) => (a.rank ?? 1e12) - (b.rank ?? 1e12) || a.host.localeCompare(b.host) || a.finding.localeCompare(b.finding))) {
    let hint = contactCache.get(f.host);
    if (hint === undefined) {
      hint = await contactHint(f.host, ctx.get(f.host), opts);
      contactCache.set(f.host, hint);
    }
    findings.push({ ...f, contact_hint: hint, notified_on: '', remediated_on: '' });
  }
  // dedupe identical (host, finding, evidence)
  const seen = new Set<string>();
  const deduped = findings.filter((f) => { const k = `${f.host}|${f.finding}|${f.evidence}`; if (seen.has(k)) return false; seen.add(k); return true; });
  if (shopifyHosts.size) {
    deduped.push({ host: 'shopify-platform-pattern', rank: null, finding: 'shopify-platform-pattern', evidence: `${shopifyHosts.size} Shopify storefront hosts; ${Object.entries(shopifyCounts).map(([k, v]) => `${k}=${v}`).join(', ')}`, severity: 'info', contact_hint: 'Shopify (platform; one report, not per merchant)', notified_on: '', remediated_on: '', notes: 'storefront rows aggregated: merchants cannot change the platform OAuth metadata' });
  }
  const counts: Record<string, number> = {};
  for (const f of deduped) counts[f.finding] = (counts[f.finding] ?? 0) + 1;
  return { findings: deduped, counts, hosts: new Set(deduped.filter((f) => f.finding !== 'shopify-platform-pattern').map((f) => f.host)).size, shopify: { hosts: shopifyHosts.size, by_finding: shopifyCounts }, inputs: { handshake_rows: handshakeRows, result_rows: resultRows }, generated_at: new Date().toISOString() };
}

async function contactHint(host: string, c: HostContext | undefined, opts: BuildOptions): Promise<string> {
  if (!c?.security_txt_valid) return 'WHOIS/abuse';
  // 1. archived body (--store-bodies) -> the Contact: line without touching the network
  if (c.security_txt_body_file && existsSync(c.security_txt_body_file)) {
    try {
      const contact = securityTxtContact(gunzipSync(readFileSync(c.security_txt_body_file)).toString('utf8'));
      if (contact) return contact;
    } catch { /* fall through */ }
  }
  // 2. opt-in re-fetch (one GET of a public file)
  if (opts.fetchSecurityTxt && c.security_txt_url) {
    const r = await fetchUrl(c.security_txt_url, { timeoutMs: opts.timeoutMs ?? 10_000, accept: 'text/plain' });
    const contact = r.status === 200 ? securityTxtContact(bodyText(r)) : null;
    if (contact) return contact;
    opts.log?.(`[${host}] security.txt re-fetch -> ${r.status || r.error}, no Contact: line`);
  }
  // 3. the crawl saw a valid security.txt (bodies are not stored): point at it
  return `security.txt: ${c.security_txt_url}`;
}

export const EMAIL_TEMPLATE = `Subject: Agent-discovery metadata on {{host}} — research notice (no action required to reply)

Hello {{contact_name_or_team}},

We are researchers at {{institution}} measuring how web sites publish
machine-readable "agent discovery" files (MCP server cards, A2A agent
cards, OAuth protected-resource metadata, llms.txt) across the Tranco
top sites. {{host}} is in our sample. This is a courtesy notice, not a
vulnerability report in the usual sense; nothing we found exposes data.

What we saw (on {{observed_on}}, from {{vantage}}):

{{findings_list}}

How we saw it: our crawler fetched the public well-known paths with a
descriptive User-Agent ({{user_agent}}), at most one request per second
per host. For MCP endpoints named in a valid card we sent one JSON-RPC
\`initialize\` request without credentials — the first step the MCP
authorization specification tells every client to take — recorded the
response, closed any session the server opened with an HTTP DELETE, and
sent nothing else. We did not list or call tools, and we make no claim
about what an authenticated or further request would have returned.

What the specification says: {{spec_pointer}}
(MCP authorization: an endpoint that requires authorization answers
\`initialize\` with 401 and a WWW-Authenticate header pointing at RFC 9728
metadata; RFC 9728 §3.3: the \`resource\` value must match the URL the
metadata is served from; RFC 8414 §3.3: \`issuer\` must equal the URL the
metadata was derived from; RFC 9700 §2.1.1: PKCE with S256.)

Timeline: we plan to publish aggregate results, without naming hosts
below rank {{anonymity_rank}}, no earlier than 90 days from this notice
({{publish_not_before}}). If you would like {{host}} removed from the
released dataset entirely, reply to this address or to
{{optout_email}} and we will do so, no questions asked.

Questions, corrections (including "this is intentional"), or a different
contact for future notices are welcome at {{contact_email}}. Project page:
{{project_url}}.

Thank you,
{{sender_name}}
{{institution}}
`;

export function renderSummary(b: BuildOutput, opts: { handshakeFile: string; resultsFiles: string[] }): string {
  const lines = [
    `# Disclosure summary`,
    ``,
    `Generated ${b.generated_at} by agent-discovery-crawler ${CRAWLER_VERSION}.`,
    `Inputs: handshake ${opts.handshakeFile} (${b.inputs.handshake_rows} rows); results ${opts.resultsFiles.join(', ')} (${b.inputs.result_rows} rows).`,
    ``,
    `| finding | severity | rows |`,
    `|---|---|---|`,
  ];
  for (const k of Object.keys(SEVERITY) as FindingType[]) if (b.counts[k]) lines.push(`| ${k} | ${SEVERITY[k]} | ${b.counts[k]} |`);
  lines.push(``, `Hosts with at least one finding (Shopify storefronts excluded): ${b.hosts}.`);
  if (b.shopify.hosts) lines.push(`Shopify storefront hosts rolled into one row: ${b.shopify.hosts} (${Object.entries(b.shopify.by_finding).map(([k, v]) => `${k}=${v}`).join(', ')}).`);
  lines.push(``, `Columns of findings.csv: host, rank, finding, evidence (URL + status), severity, contact_hint (security.txt Contact: line when the crawl stored or re-fetched it, else the security.txt URL the crawl validated, else WHOIS/abuse), notified_on, remediated_on, notes. Fill notified_on when the email goes out; the 90-day window counts from that date.`, ``);
  return lines.join('\n');
}

interface Args { in: string; results: string[]; out: string; scheme: 'https' | 'http'; fetchSecurityTxt: boolean; timeoutMs: number }

function parseArgs(argv: string[]): Args {
  const a: Args = { in: '', results: [], out: 'release/disclosure', scheme: 'https', fetchSecurityTxt: false, timeoutMs: 10_000 };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i]; const v = argv[i + 1];
    switch (k) {
      case '--in': a.in = v; i++; break;
      case '--results': while (argv[i + 1] && !argv[i + 1].startsWith('--')) a.results.push(argv[++i]); break;
      case '--out': a.out = v; i++; break;
      case '--scheme': a.scheme = v === 'http' ? 'http' : 'https'; i++; break;
      case '--fetch-security-txt': a.fetchSecurityTxt = true; break;
      case '--timeout-ms': a.timeoutMs = Number(v); i++; break;
      case '-h': case '--help':
        console.log('usage: disclosure.ts --in out/handshake.jsonl --results out/a.jsonl [out/b.jsonl ...] [--out release/disclosure/] [--fetch-security-txt]');
        process.exit(0);
    }
  }
  if (!a.in || !a.results.length) { console.error('error: --in HANDSHAKE.jsonl and --results FILE... are required'); process.exit(2); }
  return a;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  setGlobalRps(1);
  const results = args.results.filter((f) => !f.endsWith('handshake.jsonl') && !/webmcp/.test(f) && f !== args.in);
  const b = await buildFindings({ handshakeFile: args.in, resultsFiles: results, scheme: args.scheme, fetchSecurityTxt: args.fetchSecurityTxt, timeoutMs: args.timeoutMs, log: (s) => console.error(s) });
  mkdirSync(args.out, { recursive: true });
  writeFileSync(join(args.out, 'findings.csv'), renderCsv(b.findings));
  writeFileSync(join(args.out, 'email-template.md'), EMAIL_TEMPLATE);
  writeFileSync(join(args.out, 'summary.md'), renderSummary(b, { handshakeFile: args.in, resultsFiles: results }));
  console.error(`findings: ${b.findings.length} rows over ${b.hosts} hosts${b.shopify.hosts ? ` (+ ${b.shopify.hosts} Shopify storefronts in one aggregated row)` : ''} -> ${args.out}/findings.csv, email-template.md, summary.md`);
  for (const [k, v] of Object.entries(b.counts)) console.error(`  ${k.padEnd(26)} ${v}`);
}

const isMain = process.argv[1] && /disclosure\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
