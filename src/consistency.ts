#!/usr/bin/env node
// Consistency pass (paper §4.4, Table 3): do a host's MCP server card and its
// OpenAPI document name the same tools, and does its llms.txt point at either?
//
//   npm run consistency -- --in out/tranco-*-local.jsonl out/registry-local.jsonl --out out/consistency.jsonl --sample out/consistency-sample.csv
//   npm run consistency -- --in out/registry-local.jsonl --dry-run         # count candidate hosts, fetch nothing
//
// Selection is from crawl results: a *pair host* has a valid MCP card (either
// path) AND a valid OpenAPI document (json or yaml); a *coverage host* has a
// valid llms.txt and at least one of those. Bodies are not kept in the crawl
// output, so the artifacts are re-fetched here (same UA, 1 rps per host by
// default), which also makes the pass a small staleness check.
//
// Matching: a card tool name and an OpenAPI operation are the same thing when
// their normalized keys agree. "strict" lowercases and strips separators
// (`listUsers` = `list_users` = `list-users`). "loose" additionally tokenizes
// camel/snake/kebab, sorts tokens (verb/noun order), folds common verb
// synonyms (fetch/retrieve/read -> get, search/find/query -> list, create/add
// -> post, update/modify/edit -> put, remove -> delete) and drops filler
// tokens (api, v1, v2, the, a, an). An operation without an operationId is keyed
// by method + path segments with `{params}` removed. Jaccard is over the key
// sets. Both numbers are reported; the paper quotes loose and footnotes strict.
import { createReadStream, createWriteStream, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname } from 'node:path';
import { something } from './http.js'; 
import YAML from 'yaml';
import pLimit from 'p-limit';
import { bodyText, fetchUrl, hostLimiter, setGlobalRps, type FetchResult } from './http.js';
import { contactPreflight } from './run.js';
import { MCP_CARD_ARTIFACTS, type HostResult } from './types.js';

export const OPENAPI_ARTIFACTS = ['openapi_json', 'openapi_yaml'] as const;
const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'options', 'head', 'trace'];
const VERB_SYNONYMS: Record<string, string> = {
  fetch: 'get', retrieve: 'get', read: 'get', show: 'get', describe: 'get',
  search: 'list', find: 'list', query: 'list', lookup: 'list', browse: 'list',
  create: 'post', add: 'post', insert: 'post', new: 'post', submit: 'post',
  update: 'put', modify: 'put', edit: 'put', set: 'put', change: 'put', patch: 'put',
  remove: 'delete', destroy: 'delete', del: 'delete',
};
const FILLER = new Set(['api', 'v1', 'v2', 'v3', 'the', 'a', 'an', 'of', 'for', 'by', 'to', 'and', 'with']);

export interface Op { key: string; operationId: string | null; method: string; path: string }

/** Card tool names: `tools[]` at the top level (SEP-1649 shape), under capabilities, or under each remote/server (some SEP-2127-era cards inline them). */
export function extractCardTools(card: unknown): string[] {
  const out: string[] = [];
  const take = (arr: unknown) => {
    if (!Array.isArray(arr)) return;
    for (const t of arr) {
      if (typeof t === 'string') out.push(t);
      else if (t && typeof t === 'object' && typeof (t as { name?: unknown }).name === 'string') out.push((t as { name: string }).name);
    }
  };
  if (!card || typeof card !== 'object') return [];
  const c = card as Record<string, unknown>;
  take(c.tools);
  take((c.capabilities as Record<string, unknown> | undefined)?.tools);
  for (const k of ['remotes', 'servers', 'endpoints']) {
    const arr = c[k];
    if (Array.isArray(arr)) for (const r of arr) if (r && typeof r === 'object') take((r as Record<string, unknown>).tools);
  }
  return [...new Set(out.map((s) => s.trim()).filter(Boolean))];
}

/** OpenAPI operations: operationId when present, else method + path. */
export function extractOpenApiOps(doc: unknown): Op[] {
  const out: Op[] = [];
  const paths = (doc as { paths?: unknown })?.paths;
  if (!paths || typeof paths !== 'object') return out;
  for (const [path, item] of Object.entries(paths as Record<string, unknown>)) {
    if (!item || typeof item !== 'object') continue;
    for (const m of METHODS) {
      const op = (item as Record<string, unknown>)[m];
      if (!op || typeof op !== 'object') continue;
      const id = (op as { operationId?: unknown }).operationId;
      const operationId = typeof id === 'string' && id.trim() ? id.trim() : null;
      out.push({ key: operationId ?? `${m} ${path}`, operationId, method: m, path });
    }
  }
  return out;
}

export function parseStructured(text: string, isYamlPath: boolean): unknown {
  const t = text.replace(/^﻿/, '');
  if (!isYamlPath) { try { return JSON.parse(t); } catch { /* fall through */ } }
  try { return YAML.parse(t); } catch { return null; }
}

/** Case- and separator-insensitive key: `listUsers` = `list_users` = `list-users` = `List Users`. */
export function strictKey(name: string): string { return name.toLowerCase().replace(/[^a-z0-9]+/g, ''); }

export function tokens(s: string): string[] {
  return s
    .replace(/\{[^}]*\}/g, ' ') // path params
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2') // camelCase
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2') // HTTPServer -> HTTP Server
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t && !FILLER.has(t))
    .map((t) => VERB_SYNONYMS[t] ?? t)
    .map((t) => (t.length > 3 && /[^sui]s$/.test(t) ? t.slice(0, -1) : t)); // crude plural fold: users -> user (status, analysis, class untouched)
}

/** Order-free token key with verb synonyms folded. */
export function looseKey(s: string): string { return [...new Set(tokens(s))].sort().join(' '); }
export function looseKeyForOp(op: Op): string { return op.operationId ? looseKey(op.operationId) : looseKey(`${op.method} ${op.path}`); }

export function jaccard(a: Set<string>, b: Set<string>): number | null {
  const union = new Set([...a, ...b]);
  if (union.size === 0) return null;
  let inter = 0; for (const x of a) if (b.has(x)) inter++;
  return inter / union.size;
}

export interface PairMatch {
  n_tools: number; n_ops: number;
  matched_strict: number; matched_loose: number;
  jaccard_strict: number | null; jaccard_loose: number | null;
  unmatched_tools: string[]; // loose
  /** for the hand-coded sample: each tool with its nearest operation by token overlap */
  candidates: { tool: string; best_op: string | null; overlap: number; matched: boolean }[];
}

export function matchPair(toolNames: string[], ops: Op[]): PairMatch {
  const ts = new Set(toolNames.map(strictKey)), os = new Set(ops.map((o) => strictKey(o.operationId ?? `${o.method} ${o.path}`)));
  const tl = new Set(toolNames.map(looseKey)), ol = new Set(ops.map(looseKeyForOp));
  const opTok = ops.map((o) => ({ o, t: new Set(tokens(o.operationId ?? `${o.method} ${o.path}`)) }));
  const candidates = toolNames.map((tool) => {
    const tt = new Set(tokens(tool)); let best: Op | null = null; let bestOv = 0;
    for (const { o, t } of opTok) { let ov = 0; for (const x of tt) if (t.has(x)) ov++; const score = tt.size ? ov / Math.max(tt.size, t.size) : 0; if (score > bestOv) { bestOv = score; best = o; } }
    return { tool, best_op: best ? (best.operationId ?? `${best.method} ${best.path}`) : null, overlap: Number(bestOv.toFixed(2)), matched: ol.has(looseKey(tool)) };
  });
  const ms = [...ts].filter((k) => os.has(k)).length, ml = [...tl].filter((k) => ol.has(k)).length;
  return {
    n_tools: toolNames.length, n_ops: ops.length, matched_strict: ms, matched_loose: ml,
    jaccard_strict: jaccard(ts, os), jaccard_loose: jaccard(tl, ol),
    unmatched_tools: toolNames.filter((t) => !ol.has(looseKey(t))), candidates,
  };
}

// ---------- llms.txt coverage ----------

export interface LlmsLinks { openapi: string[]; card: string[]; total: number }

const OPENAPI_LINK = /(openapi|swagger)[^/]*\.(json|ya?ml)$|\/openapi(\.json|\.yaml|\.yml)?$|\/swagger(\.json)?$/i;
const CARD_LINK = /\/\.well-known\/(mcp-server-card|mcp\/server-card\.json|agent-card\.json|agent\.json)$/i;

/** Markdown and bare links in an llms.txt, resolved against the file's URL; classified by what they point at. */
export function llmsLinks(text: string, baseUrl: string): LlmsLinks {
  const urls = new Set<string>();
  for (const m of text.matchAll(/\[[^\]]*\]\(\s*<?([^\s)>]+)>?(?:\s+"[^"]*")?\s*\)/g)) urls.add(m[1]);
  for (const m of text.matchAll(/(?<![(\]])\bhttps?:\/\/[^\s<>)"']+/g)) urls.add(m[0].replace(/[.,;:]+$/, ''));
  const openapi: string[] = [], card: string[] = [];
  for (const u of urls) {
    let abs: string; try { abs = new URL(u, baseUrl).toString(); } catch { continue; }
    const path = (() => { try { return new URL(abs).pathname; } catch { return abs; } })();
    if (OPENAPI_LINK.test(path)) openapi.push(abs); else if (CARD_LINK.test(path)) card.push(abs);
  }
  return { openapi: [...new Set(openapi)], card: [...new Set(card)], total: urls.size };
}

// ---------- selection ----------

export interface Candidate {
  host: string; rank: number | null; source: string;
  card_url: string | null; card_artifact: string | null; card_spec: string | null;
  /** other valid card paths on the host (a SEP-2127 card at the canonical path rarely lists tools; the legacy SEP-1649 card beside it often does) */
  card_alt_urls: string[];
  openapi_url: string | null; openapi_artifact: string | null;
  llms_url: string | null;
  pair: boolean; coverage: boolean;
}

export function selectCandidates(r: HostResult, source: string): Candidate | null {
  const cards = r.probes.filter((p) => p.valid && (MCP_CARD_ARTIFACTS as string[]).includes(p.artifact));
  const card = cards[0];
  const oa = r.probes.find((p) => p.valid && (OPENAPI_ARTIFACTS as readonly string[]).includes(p.artifact));
  const llms = r.probes.find((p) => p.valid && p.artifact === 'llms_txt');
  const pair = !!(card && oa), coverage = !!(llms && (card || oa));
  if (!pair && !coverage) return null;
  return {
    host: r.host, rank: r.rank ?? null, source,
    card_url: card?.final_url ?? null, card_artifact: card?.artifact ?? null, card_spec: card?.card_spec ?? null,
    card_alt_urls: cards.slice(1).map((p) => p.final_url),
    openapi_url: oa?.final_url ?? null, openapi_artifact: oa?.artifact ?? null,
    llms_url: llms?.final_url ?? null, pair, coverage,
  };
}

export async function readCandidates(files: string[]): Promise<Candidate[]> {
  const out: Candidate[] = []; const seen = new Set<string>();
  for (const f of files) {
    if (!existsSync(f)) throw new Error(`${f} not found`);
    const rl = createInterface({ input: createReadStream(f), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      let r: HostResult; try { r = JSON.parse(line); } catch { continue; }
      if (!r?.host || seen.has(r.host)) continue;
      const c = selectCandidates(r, f.replace(/^.*\//, '').replace(/\.jsonl$/, ''));
      if (c) { seen.add(r.host); out.push(c); }
    }
  }
  return out;
}

// ---------- per-host result ----------

export interface ConsistencyResult extends Candidate {
  ts: string;
  fetch: { card: number | null; openapi: number | null; llms: number | null; errors: string[] };
  /** null when the host is not a pair host or a fetch failed */
  match: PairMatch | null;
  /** card parsed but lists no tools (SEP-2127 cards normally do not) */
  card_lists_no_tools: boolean | null;
  /** tools came from a second valid card path (card_url is updated to it) */
  card_used_alt?: boolean;
  openapi_has_no_ops: boolean | null;
  llms: (LlmsLinks & { openapi_resolves: boolean[]; card_resolves: boolean[] }) | null;
}

async function get(url: string, timeoutMs: number): Promise<FetchResult> {
  await hostLimiter(new URL(url).hostname).wait();
  return fetchUrl(url, { timeoutMs, accept: 'application/json, application/yaml, text/yaml, text/markdown, text/plain;q=0.9, */*;q=0.5' });
}

export async function checkHost(c: Candidate, opts: { timeoutMs: number; fetch?: (url: string, timeoutMs: number) => Promise<FetchResult> } = { timeoutMs: 10_000 }): Promise<ConsistencyResult> {
  const f = opts.fetch ?? get;
  const res: ConsistencyResult = { ...c, ts: new Date().toISOString(), fetch: { card: null, openapi: null, llms: null, errors: [] }, match: null, card_lists_no_tools: null, openapi_has_no_ops: null, llms: null };
  let tools: string[] | null = null, ops: Op[] | null = null;
  if (c.pair && c.card_url && c.openapi_url) {
    const [cr, orr] = await Promise.all([f(c.card_url, opts.timeoutMs), f(c.openapi_url, opts.timeoutMs)]);
    res.fetch.card = cr.status; res.fetch.openapi = orr.status;
    if (cr.error) res.fetch.errors.push(`card:${cr.error}`); if (orr.error) res.fetch.errors.push(`openapi:${orr.error}`);
    if (cr.status === 200) { const card = parseStructured(bodyText(cr), false); tools = card ? extractCardTools(card) : null; if (!card) res.fetch.errors.push('card:unparseable'); }
    // a tool-less card at the canonical path: look at the other valid card path(s) before concluding the host advertises no tools
    for (const alt of c.card_alt_urls) {
      if (tools && tools.length) break;
      const ar = await f(alt, opts.timeoutMs);
      if (ar.status !== 200) continue;
      const altCard = parseStructured(bodyText(ar), false); const altTools = altCard ? extractCardTools(altCard) : [];
      if (altTools.length) { tools = altTools; res.card_url = alt; res.card_used_alt = true; res.card_spec = /\/mcp\/server-card\.json$/.test(alt) ? 'sep-1649' : res.card_spec; }
    }
    if (orr.status === 200) { const doc = parseStructured(bodyText(orr), c.openapi_artifact === 'openapi_yaml'); ops = doc ? extractOpenApiOps(doc) : null; if (!doc) res.fetch.errors.push('openapi:unparseable'); }
    if (tools && ops) {
      res.card_lists_no_tools = tools.length === 0; res.openapi_has_no_ops = ops.length === 0;
      res.match = matchPair(tools, ops);
    }
  }
  if (c.coverage && c.llms_url) {
    const lr = await f(c.llms_url, opts.timeoutMs);
    res.fetch.llms = lr.status; if (lr.error) res.fetch.errors.push(`llms:${lr.error}`);
    if (lr.status === 200) {
      const links = llmsLinks(bodyText(lr), lr.finalUrl || c.llms_url);
      const resolve = async (u: string) => { try { const r = await f(u, opts.timeoutMs); return r.status === 200; } catch { return false; } };
      res.llms = { ...links, openapi_resolves: await Promise.all(links.openapi.slice(0, 5).map(resolve)), card_resolves: await Promise.all(links.card.slice(0, 5).map(resolve)) };
    }
  }
  return res;
}

// ---------- summary ----------

export function median(xs: number[]): number | null { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; }

export function summarize(rows: ConsistencyResult[]): string {
  const pairs = rows.filter((r) => r.pair);
  const fetched = pairs.filter((r) => r.match);
  const scored = fetched.filter((r) => r.match!.n_tools > 0 && r.match!.n_ops > 0);
  const noTools = fetched.filter((r) => r.card_lists_no_tools).length, noOps = fetched.filter((r) => r.openapi_has_no_ops).length;
  const jl = scored.map((r) => r.match!.jaccard_loose!), js = scored.map((r) => r.match!.jaccard_strict!);
  const toolsTotal = scored.reduce((a, r) => a + r.match!.n_tools, 0), unmatched = scored.reduce((a, r) => a + r.match!.unmatched_tools.length, 0);
  const perHostUnmatched = scored.map((r) => r.match!.unmatched_tools.length / r.match!.n_tools);
  const bySpec: Record<string, number> = {}; for (const r of scored) bySpec[r.card_spec ?? 'unknown'] = (bySpec[r.card_spec ?? 'unknown'] ?? 0) + 1;
  const L: string[] = [];
  L.push(`pair hosts (valid card + valid OpenAPI in crawl): ${pairs.length}; both re-fetched and parsed: ${fetched.length}; card lists no tools: ${noTools}; OpenAPI has no operations: ${noOps}`);
  L.push(`scored (>=1 tool and >=1 operation): ${scored.length} (card spec: ${Object.entries(bySpec).map(([k, v]) => `${k} ${v}`).join(', ') || 'none'})`);
  L.push(`median Jaccard, loose: ${fmt(median(jl))}; strict: ${fmt(median(js))}; hosts with Jaccard=0 (loose): ${jl.filter((x) => x === 0).length}; =1: ${jl.filter((x) => x === 1).length}`);
  L.push(`card tools with no OpenAPI counterpart (loose): ${unmatched} of ${toolsTotal} pooled (${pct(unmatched, toolsTotal)}); per-host median share ${fmt(median(perHostUnmatched))}`);
  const cov = rows.filter((r) => r.coverage), covF = cov.filter((r) => r.llms);
  const linkAny = covF.filter((r) => r.llms!.openapi.length || r.llms!.card.length);
  const linkOA = covF.filter((r) => r.llms!.openapi.length), linkCard = covF.filter((r) => r.llms!.card.length);
  const resolves = linkAny.filter((r) => r.llms!.openapi_resolves.some(Boolean) || r.llms!.card_resolves.some(Boolean));
  L.push(`coverage hosts (valid llms.txt + card or OpenAPI): ${cov.length}; llms.txt re-fetched: ${covF.length}; link to OpenAPI: ${linkOA.length}; link to a card: ${linkCard.length}; link to either: ${linkAny.length} (${pct(linkAny.length, covF.length)}); of those, at least one such link resolves (200): ${resolves.length} (${pct(resolves.length, linkAny.length)})`);
  const errs = rows.filter((r) => r.fetch.errors.length).length;
  if (errs) L.push(`hosts with a fetch/parse error on re-fetch: ${errs} (artifact gone or changed since the crawl; see fetch.errors)`);
  return L.join('\n') + '\n';
}
const fmt = (x: number | null) => (x === null ? 'n/a' : x.toFixed(2));
const pct = (k: number, n: number) => (n ? `${((100 * k) / n).toFixed(1)}%` : 'n/a');

/** Hand-coding sheet: `n` (tool, nearest operation) pairs drawn with a fixed seed, stratified half matched / half unmatched; `truth` column left blank (same/different/unsure). */
export function renderSampleCsv(rows: ConsistencyResult[], n = 100, seed = 7): string {
  const all = rows.flatMap((r) => (r.match?.candidates ?? []).map((c) => ({ host: r.host, ...c })));
  const rnd = mulberry(seed);
  const pick = (xs: typeof all, k: number) => { const a = [...xs]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a.slice(0, k); };
  const m = all.filter((c) => c.matched), u = all.filter((c) => !c.matched);
  const half = Math.floor(n / 2);
  const chosen = pick([...pick(m, half), ...pick(u, n - Math.min(half, m.length))], n);
  const esc = (s: string) => (/[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
  return ['host,card_tool,nearest_openapi_operation,token_overlap,auto_matched,truth', ...chosen.map((c) => [c.host, c.tool, c.best_op ?? '', String(c.overlap), c.matched ? 'yes' : 'no', ''].map(esc).join(','))].join('\n') + '\n';
}
function mulberry(a: number) { return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

// ---------- CLI ----------

function arg(name: string): string | undefined { const i = process.argv.indexOf(`--${name}`); return i >= 0 ? process.argv[i + 1] : undefined; }
function args(name: string): string[] { const i = process.argv.indexOf(`--${name}`); const out: string[] = []; if (i < 0) return out; for (let j = i + 1; j < process.argv.length && !process.argv[j].startsWith('--'); j++) out.push(process.argv[j]); return out; }

async function readDone(path: string): Promise<Map<string, ConsistencyResult>> {
  const m = new Map<string, ConsistencyResult>();
  if (!existsSync(path)) return m;
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of rl) { if (!line.trim()) continue; try { const r = JSON.parse(line) as ConsistencyResult; if (r?.host) m.set(r.host, r); } catch { /* partial */ } }
  return m;
}

async function main() {
  const inputs = args('in'); const out = arg('out'); const dry = process.argv.includes('--dry-run');
  if (!inputs.length || (!out && !dry)) { console.error('usage: consistency.ts --in RESULTS.jsonl [MORE...] --out consistency.jsonl [--sample sample.csv] [--rps 1] [--concurrency 10] [--timeout-ms 10000] [--dry-run]'); process.exit(2); }
  const cands = await readCandidates(inputs);
  const pairs = cands.filter((c) => c.pair).length, cov = cands.filter((c) => c.coverage).length;
  console.error(`candidates: ${cands.length} hosts (${pairs} card+OpenAPI pairs, ${cov} llms.txt coverage hosts) from ${inputs.length} file(s)`);
  if (dry) { for (const c of cands.filter((x) => x.pair)) console.log(`${c.host}\t${c.card_spec}\t${c.card_url}\t${c.openapi_url}`); return; }
  const contact = contactPreflight(cands.map((c) => c.host));
  if (contact) { console.error(contact); process.exit(2); }
  const done = await readDone(out!);
  const todo = cands.filter((c) => !done.has(c.host));
  console.error(`resuming: ${done.size} done, ${todo.length} to fetch`);
  setGlobalRps(Number(arg('rps') ?? 1));
  const limit = pLimit(Number(arg('concurrency') ?? 10)); const timeoutMs = Number(arg('timeout-ms') ?? 10_000);
  mkdirSync(dirname(out!), { recursive: true });
  const ws = createWriteStream(out!, { flags: 'a' });
  let k = 0;
  await Promise.all(todo.map((c) => limit(async () => {
    const r = await checkHost(c, { timeoutMs });
    done.set(c.host, r); ws.write(JSON.stringify(r) + '\n');
    if (++k % 25 === 0) console.error(`  ${k}/${todo.length}`);
  })));
  await new Promise((res) => ws.end(res));
  const rows = [...done.values()];
  process.stdout.write(summarize(rows));
  const sample = arg('sample');
  if (sample) { writeFileSync(sample, renderSampleCsv(rows)); console.error(`-> ${sample} (hand-code the truth column: same / different / unsure)`); }
}

const isMain = process.argv[1] && /consistency\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
