#!/usr/bin/env node
// Corpus builder (paper §4.1, corpus B): commerce and fintech hosts, selected
// from the Tranco bands by Cloudflare's content categories.
//   CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... npm run corpus:radar -- --tranco hosts/tranco-latest-1-1k.txt,hosts/tranco-latest-1k-10k.txt,hosts/tranco-latest-10k-100k.txt
//   npm run corpus:radar -- --from-cache                      # offline: rebuild the selection from hosts/radar-labels.jsonl
//
// Categories come from Cloudflare's Domain Intelligence API,
// GET /accounts/{account_id}/intel/domain/bulk?domain=a&domain=b..., whose items
// carry `content_categories[] {id, name, super_category_id}` and
// `popularity_rank`. (The Radar ranking endpoint we tried first,
// /radar/ranking/domain/{domain}, returns categories only for the ordered top
// 100, so it cannot label a corpus.) The token needs **Account > Intel: Read**
// and the account id from the dashboard URL; both are free. Lookups go in
// batches (default 20 domains per call) at a paced rate inside Cloudflare's
// 1,200-requests-per-5-minutes API limit, so the three Tranco bands label in
// well under an hour; every answer, misses included, is appended to
// hosts/radar-labels.jsonl and a re-run only asks about hosts it has not
// seen. The selection step is pure and re-runnable from the cache:
//   commerce = any category whose name matches COMMERCE_RE
//   fintech  = any category whose name matches FINTECH_RE
// Outputs: hosts/commerce-latest.txt, hosts/fintech-latest.txt (rank,domain in
// Tranco order; the two may overlap and the meta says by how much) and
// hosts/radar-<date>.meta.json (counts, category histogram, regexes used, the
// labels' retrieval window). The paper's limitations note that these labels are
// a convenience classification, not ground truth.
import { createReadStream, existsSync, mkdirSync, writeFileSync, appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { request } from 'undici';
import pLimit from 'p-limit';
import { CRAWLER_VERSION, getDispatcher, userAgent } from '../http.js';
import { parseHostLine, type HostEntry } from '../run.js';

export const CF_API = 'https://api.cloudflare.com/client/v4';
export const LABEL_SOURCE = 'intel'; // cache rows from the earlier Radar-ranking attempt have no `source` and are ignored
export const COMMERCE_RE = /shopping|auction|e-?commerce|marketplace|retail|classifieds|coupons?/i;
export const FINTECH_RE = /financ|bank|insurance|invest|trading|brokerage|crypto|payment|fintech|lending|loans?|accounting|tax/i;

export interface RadarCategory { id: number | null; name: string; superCategoryId: number | null }
export interface RadarLabel {
  host: string;
  rank: number | null; // our Tranco rank
  fetched_at: string;
  status: 'ok' | 'not_found' | 'error';
  radar_rank: number | null; // Cloudflare's popularity_rank when it has one
  bucket: string | null; // unused by the Intel API; kept for cache compatibility
  categories: RadarCategory[];
  source?: string; // LABEL_SOURCE
  error?: string;
}

// ---------------------------------------------------------------------------
// Parse one Radar answer (pure)
// ---------------------------------------------------------------------------

/** One Intel item (an element of the bulk `result[]`, or the single endpoint's `result`) -> label. */
export function parseIntelItem(host: string, rank: number | null, item: unknown, now = new Date()): RadarLabel {
  const d = item as Record<string, unknown> | null;
  if (!d || typeof d !== 'object') {
    return { host, rank, fetched_at: now.toISOString(), status: 'not_found', radar_rank: null, bucket: null, categories: [], source: LABEL_SOURCE, error: 'no item for domain' };
  }
  const cats = ((d.content_categories as Array<Record<string, unknown>> | undefined) ?? []).map((c) => ({
    id: typeof c.id === 'number' ? c.id : null,
    name: String(c.name ?? ''),
    superCategoryId: typeof c.super_category_id === 'number' ? c.super_category_id : null,
  })).filter((c) => c.name);
  return {
    host, rank, fetched_at: now.toISOString(), status: 'ok',
    radar_rank: typeof d.popularity_rank === 'number' ? d.popularity_rank : null,
    bucket: null,
    categories: cats,
    source: LABEL_SOURCE,
  };
}

/** A whole API body (bulk or single) -> labels for the hosts asked, in order; hosts missing from the answer are `not_found`. */
export function parseIntelBody(hosts: HostEntry[], body: unknown, now = new Date()): RadarLabel[] {
  const b = body as { success?: boolean; result?: unknown; errors?: Array<{ message?: string }> };
  if (!b || typeof b !== 'object' || !b.success) {
    const msg = (b && typeof b === 'object' && b.errors?.map((e) => e.message).filter(Boolean).join('; ')) || 'malformed body';
    return hosts.map((h) => ({ host: h.host, rank: h.rank, fetched_at: now.toISOString(), status: 'error' as const, radar_rank: null, bucket: null, categories: [], source: LABEL_SOURCE, error: msg }));
  }
  const items = Array.isArray(b.result) ? b.result : [b.result];
  const byDomain = new Map<string, unknown>();
  for (const it of items) {
    const d = (it as { domain?: unknown })?.domain;
    if (typeof d === 'string') byDomain.set(d.toLowerCase().replace(/\.$/, ''), it);
  }
  return hosts.map((h) => parseIntelItem(h.host, h.rank, byDomain.get(h.host) ?? null, now));
}

export function classify(label: RadarLabel, commerceRe = COMMERCE_RE, fintechRe = FINTECH_RE): { commerce: boolean; fintech: boolean } {
  const names = label.categories.map((c) => c.name);
  return { commerce: names.some((n) => commerceRe.test(n)), fintech: names.some((n) => fintechRe.test(n)) };
}

// ---------------------------------------------------------------------------
// Cache (append-only JSONL, one label per host; last one wins)
// ---------------------------------------------------------------------------

export async function readLabels(path: string): Promise<Map<string, RadarLabel>> {
  const m = new Map<string, RadarLabel>();
  if (!existsSync(path)) return m;
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    try { const l = JSON.parse(line) as RadarLabel; if (l?.host && l.source === LABEL_SOURCE) m.set(l.host, l); } catch { /* partial line */ }
  }
  return m;
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

export async function fetchIntelBulk(hosts: HostEntry[], token: string, accountId: string, timeoutMs: number): Promise<unknown> {
  const base = process.env.CRAWLER_INTEL_URL ?? `${CF_API}/accounts/${encodeURIComponent(accountId)}/intel/domain/bulk`; // overridable for the offline self-test
  const qs = hosts.map((h) => 'domain=' + encodeURIComponent(h.host)).join('&');
  const res = await request(`${base}?${qs}`, {
    method: 'GET',
    dispatcher: getDispatcher(timeoutMs),
    headers: { 'user-agent': userAgent(), accept: 'application/json', authorization: `Bearer ${token}` },
    headersTimeout: timeoutMs,
    bodyTimeout: timeoutMs,
  });
  const text = await res.body.text();
  if (res.statusCode === 429) throw Object.assign(new Error('HTTP 429'), { retryAfter: Math.max(0, Number(res.headers['retry-after']) || 30) });
  if (res.statusCode === 401 || res.statusCode === 403) throw Object.assign(new Error(`HTTP ${res.statusCode}: token or account rejected (needs Account > Intel: Read and the right CLOUDFLARE_ACCOUNT_ID): ${text.slice(0, 200)}`), { fatal: true });
  try { return JSON.parse(text); } catch { return { success: false, errors: [{ message: `HTTP ${res.statusCode}: non-JSON body` }] }; }
}

/** Minimal token bucket: at most `rps` starts per second across all workers. */
export function makePacer(rps: number): () => Promise<void> {
  const interval = 1000 / rps;
  let next = Date.now();
  return async () => {
    const now = Date.now();
    const at = Math.max(now, next);
    next = at + interval;
    if (at > now) await new Promise((r) => setTimeout(r, at - now));
  };
}

export interface LabelOpts { token: string; accountId: string; cachePath: string; have: Map<string, RadarLabel>; rps: number; concurrency: number; batch: number; timeoutMs: number; log: (s: string) => void }

export async function labelHosts(hosts: HostEntry[], opts: LabelOpts): Promise<{ asked: number; ok: number; not_found: number; errors: number; requests: number }> {
  const todo = hosts.filter((h) => !opts.have.has(h.host));
  const batches: HostEntry[][] = [];
  for (let i = 0; i < todo.length; i += Math.max(1, opts.batch)) batches.push(todo.slice(i, i + Math.max(1, opts.batch)));
  const limit = pLimit(opts.concurrency);
  const pace = makePacer(opts.rps);
  let asked = 0, ok = 0, not_found = 0, errors = 0, requests = 0;
  let stop = false;
  const started = Date.now();
  await Promise.all(batches.map((batch) => limit(async () => {
    if (stop) return;
    let labels: RadarLabel[];
    for (let attempt = 0; ; attempt++) {
      await pace();
      requests++;
      try {
        labels = parseIntelBody(batch, await fetchIntelBulk(batch, opts.token, opts.accountId, opts.timeoutMs));
        break;
      } catch (e) {
        const err = e as Error & { retryAfter?: number; fatal?: boolean };
        if (err.fatal) { stop = true; throw err; }
        if (err.retryAfter !== undefined && attempt < 5) { opts.log(`  429: pausing ${err.retryAfter}s`); await new Promise((r) => setTimeout(r, err.retryAfter! * 1000)); continue; }
        labels = batch.map((h) => ({ host: h.host, rank: h.rank, fetched_at: new Date().toISOString(), status: 'error' as const, radar_rank: null, bucket: null, categories: [], source: LABEL_SOURCE, error: err.message }));
        break;
      }
    }
    for (const label of labels) {
      asked++;
      if (label.status === 'ok') ok++; else if (label.status === 'not_found') not_found++; else errors++;
      opts.have.set(label.host, label);
      appendFileSync(opts.cachePath, JSON.stringify(label) + '\n');
    }
    if (requests % 25 === 0) {
      const el = (Date.now() - started) / 1000;
      opts.log(`  ${asked}/${todo.length} labelled (${ok} ok, ${not_found} not found, ${errors} errors); ${(asked / el).toFixed(1)} hosts/s; ~${Math.round((todo.length - asked) / (asked / el) / 60)} min left`);
    }
  })));
  return { asked, ok, not_found, errors, requests };
}

// ---------------------------------------------------------------------------
// Select + write
// ---------------------------------------------------------------------------

export interface RadarMeta {
  built_at: string;
  crawler_version: string;
  tranco_files: string[];
  hosts_considered: number;
  labelled: { ok: number; not_found: number; error: number; unlabelled: number };
  labels_window: { first: string | null; last: string | null };
  commerce_regex: string;
  fintech_regex: string;
  commerce: number;
  fintech: number;
  overlap: number;
  categories_top: Array<{ name: string; hosts: number }>;
  files: { commerce: string; fintech: string; labels: string };
}

export function selectCorpora(hosts: HostEntry[], labels: Map<string, RadarLabel>, commerceRe = COMMERCE_RE, fintechRe = FINTECH_RE): { commerce: HostEntry[]; fintech: HostEntry[]; histogram: Map<string, number>; counts: RadarMeta['labelled']; window: RadarMeta['labels_window'] } {
  const commerce: HostEntry[] = []; const fintech: HostEntry[] = [];
  const histogram = new Map<string, number>();
  const counts = { ok: 0, not_found: 0, error: 0, unlabelled: 0 };
  let first: string | null = null; let last: string | null = null;
  for (const h of hosts) {
    const l = labels.get(h.host);
    if (!l) { counts.unlabelled++; continue; }
    counts[l.status === 'ok' ? 'ok' : l.status === 'not_found' ? 'not_found' : 'error']++;
    if (!first || l.fetched_at < first) first = l.fetched_at;
    if (!last || l.fetched_at > last) last = l.fetched_at;
    if (l.status !== 'ok') continue;
    for (const c of new Set(l.categories.map((c) => c.name))) histogram.set(c, (histogram.get(c) ?? 0) + 1);
    const k = classify(l, commerceRe, fintechRe);
    if (k.commerce) commerce.push(h);
    if (k.fintech) fintech.push(h);
  }
  return { commerce, fintech, histogram, counts, window: { first, last } };
}

function renderHosts(title: string, hosts: HostEntry[], now: Date, meta: string): string {
  return [`# ${title}; generated ${now.toISOString()}`, `# ${hosts.length} hosts; ${meta}; rank,domain (Tranco order)`]
    .concat(hosts.map((h) => (h.rank !== null ? `${h.rank},${h.host}` : h.host))).join('\n') + '\n';
}

export function writeRadarCorpus(hosts: HostEntry[], labels: Map<string, RadarLabel>, opts: { outDir: string; trancoFiles: string[]; labelsPath: string; commerceRe?: RegExp; fintechRe?: RegExp; now?: Date }): { meta: RadarMeta; metaPath: string } {
  const now = opts.now ?? new Date();
  const commerceRe = opts.commerceRe ?? COMMERCE_RE; const fintechRe = opts.fintechRe ?? FINTECH_RE;
  mkdirSync(opts.outDir, { recursive: true });
  const sel = selectCorpora(hosts, labels, commerceRe, fintechRe);
  const fin = new Set(sel.fintech.map((h) => h.host));
  const overlap = sel.commerce.filter((h) => fin.has(h.host)).length;
  const tag = now.toISOString().slice(0, 10);
  const commerceFile = join(opts.outDir, 'commerce-latest.txt');
  const fintechFile = join(opts.outDir, 'fintech-latest.txt');
  writeFileSync(commerceFile, renderHosts(`commerce corpus (Cloudflare Radar categories matching ${commerceRe})`, sel.commerce, now, `from ${hosts.length} Tranco hosts`));
  writeFileSync(fintechFile, renderHosts(`fintech corpus (Cloudflare Radar categories matching ${fintechRe})`, sel.fintech, now, `from ${hosts.length} Tranco hosts`));
  writeFileSync(join(opts.outDir, `commerce-${tag}.txt`), renderHosts(`commerce corpus (Cloudflare Radar categories matching ${commerceRe})`, sel.commerce, now, `from ${hosts.length} Tranco hosts`));
  writeFileSync(join(opts.outDir, `fintech-${tag}.txt`), renderHosts(`fintech corpus (Cloudflare Radar categories matching ${fintechRe})`, sel.fintech, now, `from ${hosts.length} Tranco hosts`));
  const meta: RadarMeta = {
    built_at: now.toISOString(),
    crawler_version: CRAWLER_VERSION,
    tranco_files: opts.trancoFiles,
    hosts_considered: hosts.length,
    labelled: sel.counts,
    labels_window: sel.window,
    commerce_regex: commerceRe.source,
    fintech_regex: fintechRe.source,
    commerce: sel.commerce.length,
    fintech: sel.fintech.length,
    overlap,
    categories_top: [...sel.histogram.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40).map(([name, n]) => ({ name, hosts: n })),
    files: { commerce: commerceFile, fintech: fintechFile, labels: opts.labelsPath },
  };
  const metaPath = join(opts.outDir, `radar-${tag}.meta.json`);
  writeFileSync(metaPath, JSON.stringify(meta, null, 2) + '\n');
  return { meta, metaPath };
}

export async function readTrancoHosts(files: string[]): Promise<HostEntry[]> {
  const out: HostEntry[] = []; const seen = new Set<string>();
  for (const f of files) {
    if (!existsSync(f)) { console.error(`warning: ${f} not found; skipped`); continue; }
    const rl = createInterface({ input: createReadStream(f), crlfDelay: Infinity });
    for await (const line of rl) { const e = parseHostLine(line); if (e && !seen.has(e.host)) { seen.add(e.host); out.push(e); } }
  }
  return out;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface CliArgs { outDir: string; tranco: string[]; fromCache: boolean; max: number; rps: number; concurrency: number; batch: number; timeoutMs: number; commerceRe: RegExp; fintechRe: RegExp }

function parseArgs(argv: string[]): CliArgs {
  const a: CliArgs = { outDir: 'hosts', tranco: ['hosts/tranco-latest-1-1k.txt', 'hosts/tranco-latest-1k-10k.txt', 'hosts/tranco-latest-10k-100k.txt'], fromCache: false, max: Infinity, rps: 3, concurrency: 4, batch: 20, timeoutMs: 30_000, commerceRe: COMMERCE_RE, fintechRe: FINTECH_RE };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i]; const v = argv[i + 1];
    switch (k) {
      case '--out-dir': a.outDir = v; i++; break;
      case '--tranco': a.tranco = v.split(',').map((s) => s.trim()).filter(Boolean); i++; break;
      case '--from-cache': a.fromCache = true; break;
      case '--max': a.max = Number(v); i++; break;
      case '--rps': a.rps = Number(v); i++; break;
      case '--concurrency': a.concurrency = Number(v); i++; break;
      case '--batch': a.batch = Number(v); i++; break;
      case '--timeout-ms': a.timeoutMs = Number(v); i++; break;
      case '--commerce-regex': a.commerceRe = new RegExp(v, 'i'); i++; break;
      case '--fintech-regex': a.fintechRe = new RegExp(v, 'i'); i++; break;
      case '-h': case '--help':
        console.log('usage: radar.ts [--tranco a.txt,b.txt] [--out-dir hosts] [--max N] [--rps 3] [--concurrency 4] [--batch 20] [--from-cache] [--commerce-regex RE] [--fintech-regex RE]');
        console.log('env: CLOUDFLARE_API_TOKEN (Account > Intel: Read) and CLOUDFLARE_ACCOUNT_ID; neither needed with --from-cache');
        process.exit(0);
    }
  }
  return a;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const log = (s: string) => console.error(s);
  const labelsPath = join(args.outDir, 'radar-labels.jsonl');
  mkdirSync(args.outDir, { recursive: true });
  let hosts = await readTrancoHosts(args.tranco);
  if (Number.isFinite(args.max)) hosts = hosts.slice(0, args.max);
  const have = await readLabels(labelsPath);
  log(`${hosts.length} Tranco hosts; ${[...have.keys()].filter((h) => hosts.some((x) => x.host === h)).length} already labelled in ${labelsPath}`);
  if (!args.fromCache) {
    const token = process.env.CLOUDFLARE_API_TOKEN; const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
    if (!token || !accountId) { log('error: set CLOUDFLARE_API_TOKEN (a token with Account > Intel: Read) and CLOUDFLARE_ACCOUNT_ID (the 32-hex id in your dashboard URL), or pass --from-cache to reuse existing labels'); process.exit(2); }
    const r = await labelHosts(hosts, { token, accountId, cachePath: labelsPath, have, rps: args.rps, concurrency: args.concurrency, batch: args.batch, timeoutMs: args.timeoutMs, log });
    log(`asked Cloudflare Intel about ${r.asked} hosts in ${r.requests} requests: ${r.ok} ok, ${r.not_found} not found, ${r.errors} errors`);
  }
  const { meta, metaPath } = writeRadarCorpus(hosts, have, { outDir: args.outDir, trancoFiles: args.tranco, labelsPath, commerceRe: args.commerceRe, fintechRe: args.fintechRe });
  log(`commerce: ${meta.commerce} hosts -> ${meta.files.commerce}; fintech: ${meta.fintech} hosts -> ${meta.files.fintech}; overlap ${meta.overlap}`);
  log(`labelled: ${JSON.stringify(meta.labelled)}; top categories: ${meta.categories_top.slice(0, 8).map((c) => `${c.name} (${c.hosts})`).join(', ')}`);
  log(`meta -> ${metaPath}`);
}

const isMain = process.argv[1] && /radar\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
