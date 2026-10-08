#!/usr/bin/env node
// Compare the same hosts crawled from two vantages (paper §4.3, Table 1b):
//   npm run vantage:compare -- --a out/tranco-1-1k-local.jsonl --b out/tranco-1-1k-eu.jsonl [--label-a local --label-b eu] [--out out/compare-1-1k.json]
//
// Reports, over hosts present in both files: reachability by vantage
// (reachable / blocked / unreachable / redirect-only, as a 2x2 of classes),
// per-probe-path agreement on `valid` among hosts reachable at both, the hosts
// that are valid at one vantage only (what a single-vantage crawl would miss or
// invent), and the union-vs-either prevalence the paper quotes. Hosts blocked
// at exactly one vantage are listed with the blocking vantage, which is the
// bot-manager asymmetry the paper's method section anticipates.
import { createReadStream, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname } from 'node:path';
import { hostClass } from './summarize.js';
import { PROBE_SPECS, type HostResult } from './types.js';

export type Cls = ReturnType<typeof hostClass>;

export interface PathAgreement { path: string; both_valid: number; a_only: number; b_only: number; neither: number; agreement: number; a_valid: number; b_valid: number; union_valid: number }

export interface CompareResult {
  label_a: string; label_b: string;
  hosts_a: number; hosts_b: number; common: number;
  class_matrix: Record<string, Record<string, number>>; // class at a -> class at b -> hosts
  reachable_both: number;
  blocked_one_vantage: { a_only: string[]; b_only: string[] };
  paths: PathAgreement[];
  any_artifact: { a: number; b: number; both: number; union: number; a_only_hosts: string[]; b_only_hosts: string[] };
  cross_origin_disagreements: number; // probes where final origin differed between vantages (geo-routing)
}

export async function readResults(file: string): Promise<Map<string, HostResult>> {
  const m = new Map<string, HostResult>();
  if (!existsSync(file)) throw new Error(`${file} not found`);
  const rl = createInterface({ input: createReadStream(file), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    try { const r = JSON.parse(line) as HostResult; if (r?.host && !m.has(r.host)) m.set(r.host, r); } catch { /* partial */ }
  }
  return m;
}

const SEC = '/.well-known/security.txt';

export function compare(a: Map<string, HostResult>, b: Map<string, HostResult>, labelA = 'a', labelB = 'b'): CompareResult {
  const common = [...a.keys()].filter((h) => b.has(h));
  const matrix: Record<string, Record<string, number>> = {};
  const blockedA: string[] = [], blockedB: string[] = [];
  const reachBoth: string[] = [];
  for (const h of common) {
    const ca = hostClass(a.get(h)!), cb = hostClass(b.get(h)!);
    (matrix[ca] ??= {})[cb] = ((matrix[ca] ??= {})[cb] ?? 0) + 1;
    if (ca === 'blocked' && cb !== 'blocked') blockedA.push(h);
    if (cb === 'blocked' && ca !== 'blocked') blockedB.push(h);
    if (ca === 'reachable' && cb === 'reachable') reachBoth.push(h);
  }
  const valid = (r: HostResult, path: string) => r.probes.some((p) => p.path === path && p.valid);
  const paths: PathAgreement[] = PROBE_SPECS.map((s) => {
    let both = 0, ao = 0, bo = 0, nei = 0;
    for (const h of reachBoth) {
      const va = valid(a.get(h)!, s.path), vb = valid(b.get(h)!, s.path);
      if (va && vb) both++; else if (va) ao++; else if (vb) bo++; else nei++;
    }
    const n = reachBoth.length || 1;
    return { path: s.path, both_valid: both, a_only: ao, b_only: bo, neither: nei, agreement: (both + nei) / n, a_valid: both + ao, b_valid: both + bo, union_valid: both + ao + bo };
  });
  const anyV = (r: HostResult) => r.probes.some((p) => p.valid && p.path !== SEC);
  let anyA = 0, anyB = 0, anyBoth = 0; const aOnly: string[] = [], bOnly: string[] = [];
  for (const h of reachBoth) {
    const va = anyV(a.get(h)!), vb = anyV(b.get(h)!);
    if (va) anyA++; if (vb) anyB++; if (va && vb) anyBoth++;
    if (va && !vb) aOnly.push(h); if (vb && !va) bOnly.push(h);
  }
  let xo = 0;
  for (const h of reachBoth) {
    const pa = new Map(a.get(h)!.probes.map((p) => [p.path, p.final_url])), pb = new Map(b.get(h)!.probes.map((p) => [p.path, p.final_url]));
    for (const [path, fa] of pa) { const fb = pb.get(path); if (fa && fb && origin(fa) !== origin(fb)) xo++; }
  }
  return {
    label_a: labelA, label_b: labelB, hosts_a: a.size, hosts_b: b.size, common: common.length,
    class_matrix: matrix, reachable_both: reachBoth.length,
    blocked_one_vantage: { a_only: blockedA.sort(), b_only: blockedB.sort() },
    paths,
    any_artifact: { a: anyA, b: anyB, both: anyBoth, union: anyA + anyB - anyBoth, a_only_hosts: aOnly.sort(), b_only_hosts: bOnly.sort() },
    cross_origin_disagreements: xo,
  };
}

function origin(u: string): string { try { return new URL(u).origin; } catch { return u; } }

export function renderCompare(c: CompareResult): string {
  const L: string[] = [];
  L.push(`${c.label_a}: ${c.hosts_a} hosts; ${c.label_b}: ${c.hosts_b} hosts; in both files: ${c.common}; reachable at both: ${c.reachable_both}`);
  L.push(`host class ${c.label_a} \\ ${c.label_b}:`);
  const classes = ['reachable', 'blocked', 'unreachable', 'redirect_only', 'proxy_denied'].filter((k) => c.class_matrix[k] || Object.values(c.class_matrix).some((m) => m[k]));
  L.push('  ' + ''.padEnd(14) + classes.map((k) => k.padStart(14)).join(''));
  for (const ra of classes) L.push('  ' + ra.padEnd(14) + classes.map((rb) => String(c.class_matrix[ra]?.[rb] ?? 0).padStart(14)).join(''));
  L.push(`blocked at ${c.label_a} only: ${c.blocked_one_vantage.a_only.length}; at ${c.label_b} only: ${c.blocked_one_vantage.b_only.length}`);
  L.push(`\nvalid-artifact agreement over the ${c.reachable_both} hosts reachable at both (${c.label_a} only / ${c.label_b} only = what one vantage misses):`);
  L.push('  ' + 'path'.padEnd(44) + 'both'.padStart(6) + `${c.label_a}-only`.padStart(11) + `${c.label_b}-only`.padStart(11) + 'agree'.padStart(8) + 'union'.padStart(7));
  for (const p of c.paths) L.push('  ' + p.path.padEnd(44) + String(p.both_valid).padStart(6) + String(p.a_only).padStart(11) + String(p.b_only).padStart(11) + (p.agreement * 100).toFixed(1).padStart(7) + '%' + String(p.union_valid).padStart(7));
  const A = c.any_artifact;
  L.push(`any artifact (excl. security.txt): ${c.label_a} ${A.a}, ${c.label_b} ${A.b}, both ${A.both}, union ${A.union}; ${c.label_a}-only ${A.a_only_hosts.length}, ${c.label_b}-only ${A.b_only_hosts.length}`);
  L.push(`probes whose final origin differed between vantages (geo-routing): ${c.cross_origin_disagreements}`);
  if (A.a_only_hosts.length) L.push(`  ${c.label_a}-only hosts: ${A.a_only_hosts.slice(0, 40).join(', ')}${A.a_only_hosts.length > 40 ? ', …' : ''}`);
  if (A.b_only_hosts.length) L.push(`  ${c.label_b}-only hosts: ${A.b_only_hosts.slice(0, 40).join(', ')}${A.b_only_hosts.length > 40 ? ', …' : ''}`);
  return L.join('\n') + '\n';
}

function arg(name: string): string | undefined { const i = process.argv.indexOf(`--${name}`); return i >= 0 ? process.argv[i + 1] : undefined; }

async function main() {
  const fa = arg('a'), fb = arg('b');
  if (!fa || !fb) { console.error('usage: vantage-compare.ts --a A.jsonl --b B.jsonl [--label-a local --label-b eu] [--out compare.json]'); process.exit(2); }
  const la = arg('label-a') ?? 'a', lb = arg('label-b') ?? 'b';
  const c = compare(await readResults(fa), await readResults(fb), la, lb);
  process.stdout.write(renderCompare(c));
  const out = arg('out');
  if (out) { mkdirSync(dirname(out), { recursive: true }); writeFileSync(out, JSON.stringify(c, null, 2) + '\n'); console.error(`-> ${out}`); }
}

const isMain = process.argv[1] && /vantage-compare\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
