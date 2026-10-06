#!/usr/bin/env node
// Summarize a results JSONL: prevalence per artifact (all / reachable hosts),
// soft-404 and invalid counts, platform breakdown, blocked reasons, hygiene.
//   npm run summarize -- out/smoke-us.jsonl [out/more.jsonl ...] [--platform-table]
//
// The file is streamed line by line into an accumulator; nothing but the
// per-host one-liners (blocked list, hygiene rows, per-host hits) is retained,
// so a million-host run summarizes in constant memory.
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import type { Readable } from 'node:stream';
import { PROBE_SPECS, MCP_CARD_ARTIFACTS, A2A_CARD_ARTIFACTS, type HostResult } from './types.js';

function pct(n: number, d: number): string {
  return d ? `${((100 * n) / d).toFixed(1)}%` : '-';
}

/** Wilson 95% interval for a proportion. */
export function wilson(k: number, n: number, z = 1.96): [number, number] {
  if (!n) return [0, 0];
  const p = k / n;
  const den = 1 + (z * z) / n;
  const c = p + (z * z) / (2 * n);
  const m = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [(c - m) / den, (c + m) / den];
}

function table(rows: string[][], header: string[]): string {
  const all = [header, ...rows];
  const w = header.map((_, i) => Math.max(...all.map((r) => (r[i] ?? '').length)));
  const line = (r: string[]) => r.map((c, i) => (c ?? '').padEnd(w[i])).join('  ');
  return [line(header), w.map((x) => '-'.repeat(x)).join('  '), ...rows.map(line)].join('\n');
}

const bump = (m: Map<string, number>, k: string, by = 1) => m.set(k, (m.get(k) ?? 0) + by);

/** Reachability class of one host record. `redirect_only` hosts are outside the reachable denominator. */
export function hostClass(r: HostResult): 'reachable' | 'blocked' | 'unreachable' | 'proxy_denied' | 'redirect_only' {
  if (r.blocked.blocked) return r.blocked.reason?.startsWith('proxy_denied') ? 'proxy_denied' : 'blocked';
  if (r.redirect_only) return 'redirect_only';
  if (r.blocked.reason?.startsWith('unreachable')) return 'unreachable';
  return 'reachable';
}

interface PathAcc { validAll: number; validReach: number; s200: number; soft: number; invalid: number; xo: number; www: number }
interface PlatAcc { hosts: number; llms: number; oapi: number; cards: number; oauth: number; blk: number }

const cardArtifacts = [...MCP_CARD_ARTIFACTS, ...A2A_CARD_ARTIFACTS];

export class Summary {
  total = 0;
  classes = new Map<string, number>();
  paths = new Map<string, PathAcc>(PROBE_SPECS.map((s) => [s.path, { validAll: 0, validReach: 0, s200: 0, soft: 0, invalid: 0, xo: 0, www: 0 }]));
  anyValid = 0;
  anyAgent = 0;
  cardPaths = new Map<string, number>();
  cardSpecs = new Map<string, number>();
  soft = { near: 0, html: 0 };
  byPlat = new Map<string, PlatAcc>();
  byCdn = new Map<string, number>();
  allPlat = new Map<string, number>();
  allHints = new Map<string, number>();
  notReachable: string[] = [];
  hygieneRows: string[][] = [];
  hostHits: string[] = [];

  add(r: HostResult): void {
    this.total++;
    const cls = hostClass(r);
    bump(this.classes, cls);
    const reach = cls === 'reachable';
    for (const p of r.probes) {
      const a = this.paths.get(p.path);
      if (!a) continue;
      if (p.valid) { a.validAll++; if (reach) a.validReach++; if (p.cross_origin_hit) a.xo++; if (p.www_redirect) a.www++; }
      if (p.status === 200) a.s200++;
      if (p.soft404) a.soft++;
      if (p.status === 200 && !p.soft404 && !p.valid) a.invalid++;
      if (p.reasons.includes('soft404:hash_near_dup')) this.soft.near++;
      if (p.reasons.includes('soft404:html_content_type')) this.soft.html++;
      if (reach && p.valid && p.card_spec) bump(this.cardSpecs, p.card_spec);
    }
    if (reach) {
      if (r.probes.some((p) => p.valid)) this.anyValid++;
      if (r.probes.some((p) => p.valid && cardArtifacts.includes(p.artifact))) this.anyAgent++;
      if (r.mcp_card_path) bump(this.cardPaths, r.mcp_card_path);
    }
    const k = r.fingerprint?.primary ?? 'unknown';
    const pa = this.byPlat.get(k) ?? { hosts: 0, llms: 0, oapi: 0, cards: 0, oauth: 0, blk: 0 };
    pa.hosts++;
    if (r.probes.find((p) => p.path === '/llms.txt')?.valid) pa.llms++;
    if (r.probes.some((p) => p.artifact.startsWith('openapi') && p.valid)) pa.oapi++;
    if (r.probes.some((p) => p.valid && cardArtifacts.includes(p.artifact))) pa.cards++;
    if (r.probes.some((p) => p.valid && ['oauth_protected_resource', 'oauth_authorization_server', 'openid_configuration'].includes(p.artifact))) pa.oauth++;
    if (r.blocked.blocked) pa.blk++;
    this.byPlat.set(k, pa);
    bump(this.byCdn, r.fingerprint?.cdn ?? 'none');
    for (const p of r.fingerprint?.platforms ?? []) bump(this.allPlat, p);
    for (const p of r.fingerprint?.hints ?? []) bump(this.allHints, p);

    if (cls !== 'reachable') this.notReachable.push(`  ${r.host.padEnd(32)} ${r.blocked.blocked ? 'BLOCKED ' : ''}${r.blocked.reason ?? cls}`);
    for (const h of r.hygiene ?? []) {
      this.hygieneRows.push([
        r.host,
        h.kind + (h.card_spec ? `/${h.card_spec}` : ''),
        h.endpoint ? `${h.endpoint.https ? 'https' : 'HTTP!'} ${h.endpoint.status ?? h.endpoint.error ?? '?'}` : '-',
        h.prm_lookups.length ? (h.prm_lookups.find((x) => x.valid)?.location ?? 'none') : '-',
        h.has_authorization_servers ? `${h.authorization_servers.filter((a) => a.resolves).length}/${h.authorization_servers.length} resolve` : 'none',
        h.authorization_servers.some((a) => a.issuer_match === false) ? 'MISMATCH' : h.authorization_servers.some((a) => a.issuer_match) ? 'ok' : '-',
        h.authorization_servers.some((a) => a.pkce_advertised) ? 'yes' : h.authorization_servers.some((a) => a.pkce_advertised === false) ? 'NO' : '-',
        h.hsts ? 'yes' : 'no',
        h.notes.join(','),
      ]);
    }
    const hits = r.probes.filter((p) => p.valid).map((p) => p.path);
    if (hits.length) this.hostHits.push(`  ${r.host.padEnd(32)} [${r.fingerprint.primary}${r.fingerprint.cdn ? ' via ' + r.fingerprint.cdn : ''}] ${hits.join(' ')}`);
  }

  render(opts: { platformTable?: boolean } = {}): string {
    const total = this.total;
    const n = (k: string) => this.classes.get(k) ?? 0;
    const reachable = n('reachable');
    const lines: string[] = [];
    lines.push(`hosts: ${total}   reachable: ${reachable}   blocked-by-target: ${n('blocked')}   unreachable: ${n('unreachable')}   redirect-only: ${n('redirect_only')}   proxy-denied (crawler egress policy): ${n('proxy_denied')}`);
    lines.push('');

    const rows: string[][] = [];
    for (const spec of PROBE_SPECS) {
      const a = this.paths.get(spec.path)!;
      const [lo, hi] = wilson(a.validReach, reachable);
      rows.push([
        spec.path + (spec.legacy ? ' (legacy)' : ''),
        `${a.validAll} (${pct(a.validAll, total)})`,
        `${a.validReach} (${pct(a.validReach, reachable)})`,
        `[${(100 * lo).toFixed(1)}, ${(100 * hi).toFixed(1)}]`,
        String(a.s200),
        String(a.soft),
        String(a.invalid),
        String(a.xo),
        String(a.www),
      ]);
    }
    lines.push('Prevalence (valid hits):');
    lines.push(table(rows, ['path', 'all hosts', 'reachable', 'wilson95 (reach)', '200s', 'soft404', 'invalid', 'x-origin', 'www']));
    lines.push('');

    lines.push(`reachable hosts with >=1 valid artifact: ${this.anyValid} (${pct(this.anyValid, reachable)}); with a valid MCP/A2A card: ${this.anyAgent}`);
    if (this.cardPaths.size) lines.push(`MCP card path that answered: ${[...this.cardPaths].map(([k, v]) => `${k}=${v}`).join(', ')}; card_spec: ${[...this.cardSpecs].map(([k, v]) => `${k}=${v}`).join(', ')}`);
    lines.push(`soft-404 reasons over all probes: hash_near_dup=${this.soft.near} html_content_type=${this.soft.html}`);
    lines.push('');

    const platRows = [...this.byPlat.entries()]
      .sort((a, b) => b[1].hosts - a[1].hosts)
      .map(([k, a]) => [k, String(a.hosts), `${a.llms} (${pct(a.llms, a.hosts)})`, String(a.oapi), String(a.cards), String(a.oauth), String(a.blk)]);
    lines.push('Platform breakdown (primary fingerprint; CDN layer is recorded separately):');
    lines.push(table(platRows, ['platform', 'hosts', 'llms.txt', 'openapi', 'mcp/a2a', 'oauth/oidc', 'blocked']));
    lines.push('');
    lines.push(`CDN layer: ${[...this.byCdn.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}=${v}`).join(', ')}`);
    lines.push('');

    if (opts.platformTable) {
      lines.push('All platform labels (multi-label):');
      lines.push(table([...this.allPlat.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, String(v)]), ['label', 'hosts']));
      if (this.allHints.size) {
        lines.push('Hints (script/link-tag evidence only; never primary):');
        lines.push(table([...this.allHints.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, String(v)]), ['hint', 'hosts']));
      }
      lines.push('');
    }

    if (this.notReachable.length) {
      lines.push('Blocked / unreachable / redirect-only / proxy-denied hosts:');
      lines.push(...this.notReachable);
      lines.push('');
    }

    if (this.hygieneRows.length) {
      lines.push('Hygiene (valid MCP/A2A cards and protected-resource docs):');
      lines.push(table(this.hygieneRows, ['host', 'kind', 'endpoint', 'prm', 'auth servers', 'issuer', 'pkce', 'hsts', 'notes']));
      lines.push('');
    }

    lines.push('Per-host valid artifacts:');
    lines.push(...this.hostHits);
    return lines.join('\n');
  }
}

/** Stream a JSONL file (or any readable) into a Summary without holding the records. */
export async function summarizeStream(input: Readable, s = new Summary()): Promise<Summary> {
  const rl = createInterface({ input, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let r: HostResult;
    try {
      r = JSON.parse(line);
    } catch {
      continue; // corrupt partial line (crashed run)
    }
    s.add(r);
  }
  return s;
}

export async function summarizeFile(path: string, opts: { platformTable?: boolean } = {}): Promise<string> {
  return summarizeFiles([path], opts);
}

/** Several results files (e.g. the shards of one band) are accumulated into one summary. */
export async function summarizeFiles(paths: string[], opts: { platformTable?: boolean } = {}): Promise<string> {
  const s = new Summary();
  for (const p of paths) await summarizeStream(createReadStream(p), s);
  return s.render(opts);
}

/** In-memory convenience (tests). */
export function summarize(results: HostResult[], opts: { platformTable?: boolean } = {}): string {
  const s = new Summary();
  for (const r of results) s.add(r);
  return s.render(opts);
}

async function main() {
  const argv = process.argv.slice(2);
  const files = argv.filter((a) => !a.startsWith('--'));
  if (!files.length) {
    console.error('usage: summarize.ts results.jsonl [more.jsonl ...] [--platform-table]');
    process.exit(2);
  }
  if (files.length > 1) console.log(`# ${files.length} files: ${files.join(' ')}\n`);
  console.log(await summarizeFiles(files, { platformTable: argv.includes('--platform-table') }));
}

const isMain = process.argv[1] && /summarize\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
