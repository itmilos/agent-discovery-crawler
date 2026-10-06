#!/usr/bin/env node
// Stratified WebMCP subsample (paper §4.2): 5,000 hosts drawn from the HTTP
// crawl's results files.
//   npm run corpus:webmcp-sample            # defaults below
//   npm run corpus:webmcp-sample -- --target 5000 --seed 20261005 --results out/tranco-1-1k-local.jsonl out/tranco-1k-10k-local.jsonl out/tranco-10k-100k-local.jsonl
//
// Rules: every reachable host of the FIRST results file (the 1-1K band) is
// taken; the remaining slots are filled by a seeded weighted draw without
// replacement over the reachable hosts of the later files, where a host that
// already publishes any valid artifact has weight 2 (oversampled 2x) and every
// other reachable host weight 1. Files that do not exist yet are reported and
// skipped; when the pool is smaller than the target the draw takes everything
// and reports the shortfall. Output: hosts/webmcp-sample.txt (rank,domain, in
// rank order) + hosts/webmcp-sample.meta.json (seed, per-file counts, shortfall).
import { createReadStream, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname } from 'node:path';
import type { Readable } from 'node:stream';
import { hostClass } from '../summarize.js';
import { CRAWLER_VERSION } from '../http.js';
import type { HostResult } from '../types.js';

export interface PoolHost { host: string; rank: number | null; artifact: boolean; source: string }

export interface FileStat { file: string; exists: boolean; rows: number; reachable: number; with_artifact: number; taken: number; taken_with_artifact: number }

export interface SubsampleMeta {
  crawler_version: string;
  built_at: string;
  seed: number;
  target: number;
  total: number;
  shortfall: number;
  strata: { all_reachable_from: string | null; drawn_from: string[] };
  weights: { with_artifact: number; without_artifact: number };
  files: FileStat[];
}

/** mulberry32: small seeded PRNG, deterministic across platforms. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Read one results JSONL into pool hosts (reachable only) + counts. Corrupt lines are skipped. */
export async function readPool(input: Readable, label: string): Promise<{ hosts: PoolHost[]; rows: number; reachable: number; with_artifact: number }> {
  const hosts: PoolHost[] = [];
  let rows = 0; let reachable = 0; let with_artifact = 0;
  const rl = createInterface({ input, crlfDelay: Infinity });
  const seen = new Set<string>();
  for await (const line of rl) {
    if (!line.trim()) continue;
    let r: HostResult;
    try { r = JSON.parse(line); } catch { continue; }
    if (!r?.host || seen.has(r.host)) continue;
    seen.add(r.host);
    rows++;
    if (hostClass(r) !== 'reachable') continue;
    reachable++;
    const artifact = (r.probes ?? []).some((p) => p.valid);
    if (artifact) with_artifact++;
    hosts.push({ host: r.host, rank: typeof r.rank === 'number' ? r.rank : null, artifact, source: label });
  }
  return { hosts, rows, reachable, with_artifact };
}

/**
 * Weighted sampling without replacement (Efraimidis–Spirakis): key = u^(1/w),
 * keep the k largest. Deterministic for a given seed and input order.
 */
export function weightedDraw<T>(items: T[], weight: (x: T) => number, k: number, rng: () => number): T[] {
  if (k >= items.length) return items.slice();
  const keyed = items.map((x) => ({ x, key: Math.pow(rng(), 1 / Math.max(weight(x), 1e-9)) }));
  keyed.sort((a, b) => b.key - a.key);
  return keyed.slice(0, k).map((e) => e.x);
}

export interface BuildOptions { target: number; seed: number; weightArtifact?: number; weightOther?: number }

export function buildSubsample(pools: { label: string; exists: boolean; hosts: PoolHost[]; rows: number; reachable: number; with_artifact: number }[], opts: BuildOptions): { hosts: PoolHost[]; meta: SubsampleMeta } {
  const wA = opts.weightArtifact ?? 2;
  const wO = opts.weightOther ?? 1;
  const files: FileStat[] = pools.map((p) => ({ file: p.label, exists: p.exists, rows: p.rows, reachable: p.reachable, with_artifact: p.with_artifact, taken: 0, taken_with_artifact: 0 }));
  const first = pools.find((p) => p.exists);
  const chosen: PoolHost[] = [];
  const seen = new Set<string>();
  if (first) for (const h of first.hosts) if (!seen.has(h.host)) { seen.add(h.host); chosen.push(h); }
  const rest = pools.filter((p) => p.exists && p !== first);
  const pool = rest.flatMap((p) => p.hosts).filter((h) => !seen.has(h.host));
  const need = Math.max(0, opts.target - chosen.length);
  const drawn = weightedDraw(pool, (h) => (h.artifact ? wA : wO), need, mulberry32(opts.seed));
  for (const h of drawn) { seen.add(h.host); chosen.push(h); }
  for (const h of chosen) {
    const f = files.find((x) => x.file === h.source)!;
    f.taken++;
    if (h.artifact) f.taken_with_artifact++;
  }
  chosen.sort((a, b) => (a.rank ?? Infinity) - (b.rank ?? Infinity) || a.host.localeCompare(b.host));
  const meta: SubsampleMeta = {
    crawler_version: CRAWLER_VERSION,
    built_at: new Date().toISOString(),
    seed: opts.seed,
    target: opts.target,
    total: chosen.length,
    shortfall: Math.max(0, opts.target - chosen.length),
    strata: { all_reachable_from: first?.label ?? null, drawn_from: rest.map((p) => p.label) },
    weights: { with_artifact: wA, without_artifact: wO },
    files,
  };
  return { hosts: chosen, meta };
}

export function renderSampleFile(hosts: PoolHost[], meta: SubsampleMeta): string {
  const head = [
    `# webmcp subsample: ${meta.total} hosts (target ${meta.target}, shortfall ${meta.shortfall}), seed ${meta.seed}, built ${meta.built_at} by agent-discovery-crawler ${meta.crawler_version}`,
    `# all reachable hosts of ${meta.strata.all_reachable_from ?? '-'} + weighted draw (artifact x${meta.weights.with_artifact}) from ${meta.strata.drawn_from.join(', ') || '-'}`,
  ];
  return head.join('\n') + '\n' + hosts.map((h) => (h.rank !== null ? `${h.rank},${h.host}` : h.host)).join('\n') + '\n';
}

export const DEFAULT_RESULTS = ['out/tranco-1-1k-local.jsonl', 'out/tranco-1k-10k-local.jsonl', 'out/tranco-10k-100k-local.jsonl'];

async function main() {
  const argv = process.argv.slice(2);
  let target = 5000; let seed = 20261005; let out = 'hosts/webmcp-sample.txt';
  let results: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i]; const v = argv[i + 1];
    if (k === '--target') { target = Number(v); i++; }
    else if (k === '--seed') { seed = Number(v); i++; }
    else if (k === '--out') { out = v; i++; }
    else if (k === '--results') { while (argv[i + 1] && !argv[i + 1].startsWith('--')) results.push(argv[++i]); }
    else if (k === '-h' || k === '--help') { console.log('usage: subsample.ts [--target 5000] [--seed 20261005] [--out hosts/webmcp-sample.txt] [--results a.jsonl b.jsonl ...]'); process.exit(0); }
  }
  if (!results.length) results = DEFAULT_RESULTS;
  const pools = [];
  for (const f of results) {
    if (!existsSync(f)) { console.error(`missing: ${f} (skipped)`); pools.push({ label: f, exists: false, hosts: [], rows: 0, reachable: 0, with_artifact: 0 }); continue; }
    const p = await readPool(createReadStream(f), f);
    console.error(`${f}: ${p.rows} rows, ${p.reachable} reachable, ${p.with_artifact} with >=1 valid artifact`);
    pools.push({ label: f, exists: true, ...p });
  }
  if (!pools.some((p) => p.exists)) { console.error('error: none of the results files exist; crawl a band first'); process.exit(2); }
  const { hosts, meta } = buildSubsample(pools, { target, seed });
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, renderSampleFile(hosts, meta));
  const metaPath = out.replace(/\.txt$/, '') + '.meta.json';
  writeFileSync(metaPath, JSON.stringify(meta, null, 2) + '\n');
  for (const f of meta.files) console.error(`  ${f.file}: took ${f.taken} (${f.taken_with_artifact} with artifact)${f.exists ? '' : ' [missing]'}`);
  console.error(`wrote ${hosts.length} hosts -> ${out} (target ${target}${meta.shortfall ? `, SHORTFALL ${meta.shortfall}: crawl more bands and re-run` : ''}); meta -> ${metaPath}`);
}

const isMain = process.argv[1] && /(^|[\\/])subsample\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
