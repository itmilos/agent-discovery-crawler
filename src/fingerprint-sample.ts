#!/usr/bin/env node
// Fingerprint precision sample (paper §4.5 / limitations): how often is the
// platform label right?
//
//   npm run fp:draw   -- --results out/tranco-1-1k-local.jsonl out/tranco-1k-10k-local.jsonl out/tranco-10k-100k-local.jsonl
//                        # seeded stratified draw -> out/fingerprint-sample.hosts.jsonl (host, rank, predicted)
//   npm run fp:fetch                       # re-fetch each homepage, keep INDEPENDENT evidence -> out/fingerprint-sample.jsonl
//                                          # and write release/fingerprint-sample.blind.csv (no predicted column) for the rater
//   (rater fills the `truth` column of the blind CSV: a label from LABELS, "none", or "?" when undecidable)
//   npm run fp:score  -- --truth release/fingerprint-sample.blind.csv
//                        # per-label precision / recall, Cohen's kappa, confusion list -> stdout + out/fingerprint-sample.score.json
//
// Design: 20 hosts per primary label that has at least 20 reachable hosts, 40
// hosts labelled `unknown` (to estimate what the fingerprint misses), drawn
// without replacement with a fixed seed from the reachable hosts of the given
// results files. The evidence shown to the rater is deliberately different
// from what fingerprint.ts matches on: the homepage's <meta name=generator>,
// the registrable domains of every script/link/img asset, the set of
// well-known platform paths that answer 200 (/wp-login.php, /_next/static/,
// /_nuxt/, /cdn/shop/), the HTML <title>, and the raw Server / X-Powered-By /
// X-Generator headers. The rater sees those and the host name, not the label.
import { appendFileSync, createReadStream, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname } from 'node:path';
import pLimit from 'p-limit';
import { getDomain } from 'tldts';
import { fetchUrl } from './http.js';
import { mulberry32 } from './corpus/subsample.js';
import { hostClass } from './summarize.js';
import type { HostResult } from './types.js';

export const PER_LABEL = 20;
export const UNKNOWN_N = 40;
export const DEFAULT_SEED = 20261007;
export const PLATFORM_PATHS = ['/wp-login.php', '/wp-json/', '/_next/static/chunks/', '/_nuxt/', '/cdn/shop/', '/products.json', '/.well-known/apple-developer-merchantid-domain-association', '/sitemap.xml'];

export interface SampleHost { host: string; rank: number | null; predicted: string; stratum: string; source: string }

export interface Evidence {
  host: string;
  rank: number | null;
  fetched_at: string;
  status: number;
  final_url: string | null;
  error?: string;
  title: string | null;
  generator: string | null;
  server: string | null;
  powered_by: string | null;
  x_generator: string | null;
  asset_domains: string[]; // registrable domains of script/link/img/iframe URLs on the page, most frequent first
  asset_domain_counts: Record<string, number>;
  platform_paths_200: string[]; // which of PLATFORM_PATHS answered 200 (not soft-404-checked; a hint, not proof)
  html_head: string; // first 2,000 chars of <head>, tags stripped of attributes longer than 200 chars
}

// ---------------------------------------------------------------------------
// Draw
// ---------------------------------------------------------------------------

export async function readReachable(files: string[]): Promise<Array<{ host: string; rank: number | null; primary: string; source: string }>> {
  const out: Array<{ host: string; rank: number | null; primary: string; source: string }> = [];
  const seen = new Set<string>();
  for (const f of files) {
    if (!existsSync(f)) { console.error(`warning: ${f} not found; skipped`); continue; }
    const rl = createInterface({ input: createReadStream(f), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      let r: HostResult; try { r = JSON.parse(line); } catch { continue; }
      if (!r?.host || seen.has(r.host) || hostClass(r) !== 'reachable') continue;
      seen.add(r.host);
      out.push({ host: r.host, rank: typeof r.rank === 'number' ? r.rank : null, primary: r.fingerprint?.primary ?? 'unknown', source: f });
    }
  }
  return out;
}

/** Fisher–Yates on a copy with a seeded PRNG. */
export function shuffle<T>(xs: T[], rng: () => number): T[] {
  const a = xs.slice();
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rng() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}

export function drawSample(pool: Array<{ host: string; rank: number | null; primary: string; source: string }>, opts: { perLabel?: number; unknownN?: number; seed?: number; minHosts?: number } = {}): { sample: SampleHost[]; strata: Record<string, { pool: number; drawn: number }> } {
  const perLabel = opts.perLabel ?? PER_LABEL, unknownN = opts.unknownN ?? UNKNOWN_N, minHosts = opts.minHosts ?? perLabel;
  const rng = mulberry32(opts.seed ?? DEFAULT_SEED);
  const byLabel = new Map<string, typeof pool>();
  for (const p of pool) { if (!byLabel.has(p.primary)) byLabel.set(p.primary, []); byLabel.get(p.primary)!.push(p); }
  const sample: SampleHost[] = [];
  const strata: Record<string, { pool: number; drawn: number }> = {};
  for (const label of [...byLabel.keys()].sort()) {
    const xs = byLabel.get(label)!;
    const want = label === 'unknown' ? unknownN : label === 'unreachable' ? 0 : xs.length >= minHosts ? perLabel : 0;
    const picked = want ? shuffle(xs, rng).slice(0, want) : [];
    strata[label] = { pool: xs.length, drawn: picked.length };
    for (const p of picked) sample.push({ host: p.host, rank: p.rank, predicted: p.primary, stratum: label, source: p.source });
  }
  return { sample: shuffle(sample, rng), strata }; // shuffled so the blind CSV order carries no label information
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

export function extractEvidence(host: string, rank: number | null, html: string, headers: Record<string, string>, status: number, finalUrl: string | null): Omit<Evidence, 'fetched_at' | 'platform_paths_200'> {
  const h = (k: string) => headers[k] ?? headers[k.toLowerCase()] ?? null;
  const title = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(html)?.[1]?.replace(/\s+/g, ' ').trim() ?? null;
  const generator = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,200})["']/i.exec(html)?.[1] ?? /<meta[^>]+content=["']([^"']{1,200})["'][^>]+name=["']generator["']/i.exec(html)?.[1] ?? null;
  const counts: Record<string, number> = {};
  const re = /<(?:script|link|img|iframe)\b[^>]*?(?:src|href)=["'](https?:)?\/\/([a-z0-9.-]+\.[a-z]{2,})[/"']/gi;
  let m: RegExpExecArray | null;
  const self = getDomain(host, { allowPrivateDomains: true }) ?? host;
  while ((m = re.exec(html))) {
    const d = getDomain(m[2].toLowerCase(), { allowPrivateDomains: true }) ?? m[2].toLowerCase();
    if (d === self) continue;
    counts[d] = (counts[d] ?? 0) + 1;
  }
  const asset_domains = Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([d]) => d).slice(0, 25);
  const headM = /<head[^>]*>([\s\S]*?)<\/head>/i.exec(html);
  const headRaw = (headM ? headM[1] : html.slice(0, 6000)).replace(/\s+/g, ' ').replace(/="[^"]{200,}"/g, '="…"');
  return { host, rank, status, final_url: finalUrl, title, generator, server: h('server'), powered_by: h('x-powered-by'), x_generator: h('x-generator'), asset_domains, asset_domain_counts: counts, html_head: headRaw.slice(0, 2000) };
}

export async function collectEvidence(s: SampleHost, timeoutMs: number): Promise<Evidence> {
  const now = new Date().toISOString();
  let page;
  try { page = await fetchUrl(`https://${s.host}/`, { timeoutMs, accept: 'text/html,application/xhtml+xml,*/*;q=0.8' }); } catch (e) {
    return { host: s.host, rank: s.rank, fetched_at: now, status: 0, final_url: null, error: (e as Error).message, title: null, generator: null, server: null, powered_by: null, x_generator: null, asset_domains: [], asset_domain_counts: {}, platform_paths_200: [], html_head: '' };
  }
  const html = page.body.toString('utf8').slice(0, 512 * 1024);
  const ev = extractEvidence(s.host, s.rank, html, page.headers, page.status, page.finalUrl);
  const base = page.finalUrl && /^https?:/.test(page.finalUrl) ? new URL(page.finalUrl).origin : `https://${s.host}`;
  const platform_paths_200: string[] = [];
  for (const p of PLATFORM_PATHS) {
    try {
      const r = await fetchUrl(base + p, { timeoutMs, method: 'HEAD' });
      if (r.status === 200) platform_paths_200.push(p);
    } catch { /* ignore */ }
  }
  return { ...ev, fetched_at: now, platform_paths_200, error: page.error };
}

export function csvEscape(v: unknown): string { const s = v === null || v === undefined ? '' : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }

export function renderBlindCsv(evs: Evidence[]): string {
  const head = ['host', 'rank', 'status', 'final_url', 'title', 'generator', 'server', 'powered_by', 'x_generator', 'asset_domains', 'platform_paths_200', 'truth', 'rater_note'];
  return [head.join(',')].concat(evs.map((e) => [e.host, e.rank, e.status, e.final_url, e.title, e.generator, e.server, e.powered_by, e.x_generator, e.asset_domains.join(' '), e.platform_paths_200.join(' '), '', ''].map(csvEscape).join(','))).join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Score
// ---------------------------------------------------------------------------

export function parseCsv(text: string): Array<Record<string, string>> {
  const rows: string[][] = []; let row: string[] = []; let cell = ''; let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; }
    else if (c !== '\r') cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  const [head, ...body] = rows;
  return body.filter((r) => r.some((x) => x !== '')).map((r) => Object.fromEntries(head.map((k, i) => [k, r[i] ?? ''])));
}

export interface Score { n: number; rated: number; undecidable: number; accuracy: number; kappa: number; per_label: Record<string, { predicted: number; truth: number; tp: number; precision: number | null; recall: number | null }>; confusions: Array<{ host: string; predicted: string; truth: string }> }

/** Precision per predicted label, recall per true label, overall accuracy and Cohen's kappa over rated hosts ("?" rows excluded). */
export function score(sample: SampleHost[], truth: Map<string, string>): Score {
  const pred = new Map(sample.map((s) => [s.host, s.predicted]));
  const pairs: Array<[string, string, string]> = [];
  let undecidable = 0;
  for (const s of sample) {
    const t = (truth.get(s.host) ?? '').trim().toLowerCase();
    if (!t || t === '?') { undecidable++; continue; }
    pairs.push([s.host, s.predicted, t === 'none' ? 'unknown' : t]);
  }
  const labels = new Set<string>(); for (const [, p, t] of pairs) { labels.add(p); labels.add(t); }
  const per: Score['per_label'] = {};
  for (const l of [...labels].sort()) {
    const predicted = pairs.filter(([, p]) => p === l).length, tr = pairs.filter(([, , t]) => t === l).length, tp = pairs.filter(([, p, t]) => p === l && t === l).length;
    per[l] = { predicted, truth: tr, tp, precision: predicted ? tp / predicted : null, recall: tr ? tp / tr : null };
  }
  const agree = pairs.filter(([, p, t]) => p === t).length;
  const n = pairs.length;
  const po = n ? agree / n : 0;
  let pe = 0; for (const l of labels) pe += (per[l].predicted / (n || 1)) * (per[l].truth / (n || 1));
  const kappa = pe === 1 ? 1 : (po - pe) / (1 - pe);
  return { n: sample.length, rated: n, undecidable, accuracy: po, kappa, per_label: per, confusions: pairs.filter(([, p, t]) => p !== t).map(([host, predicted, truth]) => ({ host, predicted, truth })) };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function argList(name: string): string[] { const i = process.argv.indexOf(`--${name}`); if (i < 0) return []; const out: string[] = []; for (let j = i + 1; j < process.argv.length && !process.argv[j].startsWith('--'); j++) out.push(process.argv[j]); return out; }
function arg(name: string): string | undefined { return argList(name)[0]; }

async function main() {
  const mode = process.argv[2];
  const hostsPath = arg('hosts') ?? 'out/fingerprint-sample.hosts.jsonl';
  const evPath = arg('out') ?? 'out/fingerprint-sample.jsonl';
  const blindPath = arg('blind') ?? 'release/fingerprint-sample.blind.csv';
  if (mode === 'draw') {
    const files = argList('results'); if (!files.length) files.push('out/tranco-1-1k-local.jsonl', 'out/tranco-1k-10k-local.jsonl', 'out/tranco-10k-100k-local.jsonl');
    const pool = await readReachable(files);
    const { sample, strata } = drawSample(pool, { seed: Number(arg('seed') ?? DEFAULT_SEED), perLabel: Number(arg('per-label') ?? PER_LABEL), unknownN: Number(arg('unknown') ?? UNKNOWN_N) });
    mkdirSync(dirname(hostsPath), { recursive: true });
    writeFileSync(hostsPath, sample.map((s) => JSON.stringify(s)).join('\n') + '\n');
    writeFileSync(hostsPath.replace(/\.jsonl$/, '.meta.json'), JSON.stringify({ built_at: new Date().toISOString(), seed: Number(arg('seed') ?? DEFAULT_SEED), results: files, pool: pool.length, strata, sample: sample.length }, null, 2) + '\n');
    console.error(`pool ${pool.length} reachable hosts; drew ${sample.length}: ${Object.entries(strata).filter(([, s]) => s.drawn).map(([l, s]) => `${l}=${s.drawn}/${s.pool}`).join(', ')} -> ${hostsPath}`);
  } else if (mode === 'fetch') {
    const sample: SampleHost[] = readFileSync(hostsPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const done = new Set<string>(existsSync(evPath) ? readFileSync(evPath, 'utf8').split('\n').filter(Boolean).map((l) => (JSON.parse(l) as Evidence).host) : []);
    const limit = pLimit(Number(arg('concurrency') ?? 8));
    let n = 0;
    await Promise.all(sample.filter((s) => !done.has(s.host)).map((s) => limit(async () => {
      const ev = await collectEvidence(s, Number(arg('timeout-ms') ?? 15_000));
      appendFileSync(evPath, JSON.stringify(ev) + '\n');
      if (++n % 20 === 0) console.error(`  ${n} fetched`);
    })));
    const evs: Evidence[] = readFileSync(evPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const order = new Map(sample.map((s, i) => [s.host, i]));
    evs.sort((a, b) => (order.get(a.host) ?? 0) - (order.get(b.host) ?? 0));
    mkdirSync(dirname(blindPath), { recursive: true });
    writeFileSync(blindPath, renderBlindCsv(evs));
    console.error(`${evs.length} hosts with evidence -> ${evPath}; blind rating sheet -> ${blindPath} (fill the "truth" column; labels: platform name as in fingerprint.ts, "none", or "?")`);
  } else if (mode === 'score') {
    const sample: SampleHost[] = readFileSync(hostsPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const rows = parseCsv(readFileSync(arg('truth') ?? blindPath, 'utf8'));
    const truth = new Map(rows.map((r) => [r.host, r.truth]));
    const sc = score(sample, truth);
    writeFileSync(evPath.replace(/\.jsonl$/, '.score.json'), JSON.stringify(sc, null, 2) + '\n');
    console.log(`rated ${sc.rated} of ${sc.n} (${sc.undecidable} undecidable); accuracy ${(sc.accuracy * 100).toFixed(1)}%; Cohen's kappa ${sc.kappa.toFixed(3)}`);
    console.log('label              pred truth  tp  precision  recall');
    for (const [l, v] of Object.entries(sc.per_label)) console.log(`${l.padEnd(18)} ${String(v.predicted).padStart(4)} ${String(v.truth).padStart(5)} ${String(v.tp).padStart(3)}  ${v.precision === null ? '    -' : (v.precision * 100).toFixed(0).padStart(4) + '%'}      ${v.recall === null ? '  -' : (v.recall * 100).toFixed(0).padStart(3) + '%'}`);
    if (sc.confusions.length) console.log('disagreements: ' + sc.confusions.map((c) => `${c.host} (${c.predicted} -> ${c.truth})`).join('; '));
  } else {
    console.error('usage: fingerprint-sample.ts draw [--results a.jsonl b.jsonl] [--seed N] [--per-label 20] [--unknown 40] | fetch [--concurrency 8] | score [--truth file.csv]');
    process.exit(2);
  }
}

const isMain = process.argv[1] && /fingerprint-sample\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
