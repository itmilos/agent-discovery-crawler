#!/usr/bin/env node
// CLI: crawl a host list and write one JSONL line per host.
//   npm run crawl -- --hosts hosts/smoke.txt --out out/smoke-us.jsonl --vantage us --concurrency 20 --rps-per-host 1
import { createReadStream, createWriteStream, existsSync, mkdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { dirname, join } from 'node:path';
import pLimit from 'p-limit';
import { getDomain } from 'tldts';
import { probeHost, isChallenge } from './probe.js';
import { fingerprintHost } from './fingerprint.js';
import { runHygiene } from './hygiene.js';
import { PROBE_SPECS, MCP_CARD_ARTIFACTS, type Blocked, type HostResult, type NxBaseline, type ProbeResult } from './types.js';
import { CRAWLER_VERSION, contactInfo, setGlobalRps, userAgent, type FetchResult } from './http.js';

export { CRAWLER_VERSION };

interface Args {
  hosts: string;
  out: string;
  vantage: string;
  concurrency: number;
  rpsPerHost: number;
  timeoutMs: number;
  limit: number | null;
  noHygiene: boolean;
  scheme: 'https' | 'http';
  storeBodies: boolean;
  progress: boolean;
  shard: Shard | null;
}

export interface Shard { index: number; count: number }

/** `--shard i/n`: this process takes every n-th host starting at i (0-based), over the full hosts file order. */
export function parseShard(v: string | undefined): Shard {
  const m = /^(\d+)\/(\d+)$/.exec((v ?? '').trim());
  if (!m) throw new Error(`--shard expects i/n (e.g. 0/2), got "${v ?? ''}"`);
  const index = Number(m[1]);
  const count = Number(m[2]);
  if (count < 1 || index >= count) throw new Error(`--shard ${v}: index must be in 0..${count - 1}`);
  return { index, count };
}

export function applyShard<T>(items: T[], shard: Shard | null): T[] {
  if (!shard) return items;
  return items.filter((_, i) => i % shard.count === shard.index);
}

function parseArgs(argv: string[]): Args {
  const a: Args = { hosts: '', out: '', vantage: 'local', concurrency: 20, rpsPerHost: 1, timeoutMs: 10_000, limit: null, noHygiene: false, scheme: 'https', storeBodies: false, progress: false, shard: null };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const v = argv[i + 1];
    switch (k) {
      case '--hosts': a.hosts = v; i++; break;
      case '--out': a.out = v; i++; break;
      case '--vantage': a.vantage = v; i++; break;
      case '--concurrency': a.concurrency = Number(v); i++; break;
      case '--rps-per-host': a.rpsPerHost = Number(v); i++; break;
      case '--timeout-ms': a.timeoutMs = Number(v); i++; break;
      case '--limit': a.limit = Number(v); i++; break;
      case '--no-hygiene': a.noHygiene = true; break;
      case '--store-bodies': a.storeBodies = true; break;
      case '--progress': a.progress = true; break;
      case '--shard':
        try { a.shard = parseShard(v); } catch (e) { console.error(`error: ${(e as Error).message}`); process.exit(2); }
        i++; break;
      case '--scheme': a.scheme = v === 'http' ? 'http' : 'https'; i++; break; // http is for local fixtures only
      case '-h': case '--help':
        console.log('usage: run.ts --hosts FILE --out FILE.jsonl [--vantage local] [--concurrency 20] [--rps-per-host 1] [--timeout-ms 10000] [--limit N] [--no-hygiene] [--store-bodies] [--progress] [--shard i/n] [--scheme https|http]');
        process.exit(0);
    }
  }
  if (!a.hosts || !a.out) {
    console.error('error: --hosts and --out are required');
    process.exit(2);
  }
  return a;
}

export interface HostEntry { host: string; rank: number | null }

/** Parse one hosts-file line: "domain", "rank,domain" (Tranco), or a URL. */
export function parseHostLine(line: string): HostEntry | null {
  let s = line.trim();
  if (!s || s.startsWith('#')) return null;
  let rank: number | null = null;
  if (s.includes(',')) {
    const parts = s.split(',').map((x) => x.trim());
    const r = Number(parts[0]);
    if (parts.length >= 2 && Number.isInteger(r) && r >= 1) rank = r;
    s = parts[parts.length - 1];
  }
  s = s.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(s)) return null;
  return { host: s, rank };
}

export function normalizeHost(line: string): string | null {
  return parseHostLine(line)?.host ?? null;
}

export async function readHosts(path: string): Promise<HostEntry[]> {
  const text = await readFile(path, 'utf8');
  const seen = new Set<string>();
  const out: HostEntry[] = [];
  for (const line of text.split(/\r?\n/)) {
    const e = parseHostLine(line);
    if (e && !seen.has(e.host)) {
      seen.add(e.host);
      out.push(e);
    }
  }
  return out;
}

export async function readDone(path: string): Promise<Set<string>> {
  const done = new Set<string>();
  if (!existsSync(path)) return done;
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    try {
      const o = JSON.parse(line) as { host?: string };
      if (o.host) done.add(o.host);
    } catch {
      /* skip corrupt partial line */
    }
  }
  return done;
}

/**
 * Preflight (paper §4.9): a real crawl must identify itself. The UA carries
 * CRAWLER_CONTACT_URL and CRAWLER_CONTACT_EMAIL; if either is unset we refuse to
 * run against anything but the local *.fixture corpus. Returns an error string.
 */
export function contactPreflight(hosts: string[], env: { url?: string; email?: string } = contactInfo()): string | null {
  const fixturesOnly = hosts.length > 0 && hosts.every((h) => h.endsWith('.fixture'));
  if (fixturesOnly) return null;
  const missing = [!env.url && 'CRAWLER_CONTACT_URL', !env.email && 'CRAWLER_CONTACT_EMAIL'].filter(Boolean) as string[];
  if (!missing.length) return null;
  return `refusing to crawl a non-fixture corpus without ${missing.join(' and ')} set (they go into the User-Agent so operators can reach us / opt out)`;
}

/**
 * Blocked rule (paper §4.3): ONLY 403 / 429 / bot-challenge / connection reset
 * count toward blocked, on more than half of requests. We count over the 14
 * canonical probes + 2 nx baselines (16 requests). DNS failure / timeout /
 * refused / TLS failure are reported as "unreachable:<class>", never "blocked"
 * (a TLS failure is a misconfigured or legacy endpoint, not a bot defense).
 */
export function computeBlocked(probes: ProbeResult[], raw: Map<string, FetchResult>, baselines: NxBaseline[]): Blocked {
  const counts: Record<string, number> = {};
  const bump = (k: string) => (counts[k] = (counts[k] ?? 0) + 1);
  const total = probes.length + baselines.length;
  let blockedSignals = 0;
  let unreachable = 0;
  let proxyDenied = 0;
  const consider = (status: number, error: string | undefined, challenge: boolean) => {
    if (error === 'proxy_denied') { bump('proxy_denied'); proxyDenied++; return; }
    if (challenge) { bump('challenge'); blockedSignals++; return; }
    if (status === 403) { bump('403'); blockedSignals++; return; }
    if (status === 429) { bump('429'); blockedSignals++; return; }
    if (status === 0) {
      bump(error ?? 'error');
      if (error === 'reset') blockedSignals++;
      else unreachable++;
      return;
    }
    bump(String(status));
  };
  for (const b of baselines) consider(b.status, b.error, false);
  for (const p of probes) consider(p.status, p.error, isChallenge(raw.get(p.path)!));

  // Our own egress proxy refused the tunnel: this says nothing about the target.
  // Reported as blocked=true with an explicit reason so it is excluded from the
  // reachable denominator but never attributed to the site's bot defenses.
  if (proxyDenied * 2 > total) {
    return { blocked: true, reason: `proxy_denied (crawler egress policy, not target) on ${proxyDenied}/${total} probes`, counts };
  }
  if (blockedSignals * 2 > total) {
    const top = Object.entries(counts)
      .filter(([k]) => ['403', '429', 'challenge', 'reset'].includes(k))
      .sort((a, b) => b[1] - a[1])[0];
    return { blocked: true, reason: `${top?.[0] ?? 'blocked'} on ${blockedSignals}/${total} probes`, counts };
  }
  if (unreachable * 2 > total) {
    const top = Object.entries(counts).filter(([k]) => ['dns', 'timeout', 'refused', 'tls', 'other', 'cross_domain_redirect', 'too_many_redirects', 'decode_error', 'body_too_large'].includes(k)).sort((a, b) => b[1] - a[1])[0];
    return { blocked: false, reason: `unreachable:${top?.[0] ?? 'error'} on ${unreachable}/${total} probes`, counts };
  }
  return { blocked: false, reason: null, counts };
}

/** Requests per host: 14 probes + 2 nx baselines + 1 homepage, before any hygiene follow-ups. */
export const REQUESTS_PER_HOST = PROBE_SPECS.length + 2;

/**
 * Rough wall-clock estimate for the banner: each host costs ~16 requests paced
 * at rps, and `concurrency` hosts run in parallel. Hygiene follow-ups, DNS and
 * slow hosts are not modelled, so this is a floor, not a promise.
 */
export function estimateDurationSec(hosts: number, concurrency: number, rps: number, requestsPerHost = REQUESTS_PER_HOST): number {
  if (!hosts || concurrency <= 0) return 0;
  const perHost = rps > 0 ? requestsPerHost / rps : 1;
  return Math.ceil(hosts / concurrency) * perHost;
}

export function fmtDuration(sec: number): string {
  if (!isFinite(sec) || sec < 0) return '?';
  const s = Math.round(sec);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m${String(s % 60).padStart(2, '0')}s`;
  const h = Math.floor(m / 60);
  return `${h}h${String(m % 60).padStart(2, '0')}m`;
}

export interface ProgressState { done: number; total: number; reachable: number; blocked: number; startedAt: number }

/** One-line status for --progress (stderr), tail-friendly. */
export function progressLine(p: ProgressState, now = Date.now()): string {
  const elapsed = (now - p.startedAt) / 1000;
  const rate = p.done > 0 && elapsed > 0 ? p.done / elapsed : 0;
  const eta = rate > 0 ? (p.total - p.done) / rate : Infinity;
  return `progress: ${p.done}/${p.total} done (${p.total ? ((100 * p.done) / p.total).toFixed(1) : '0.0'}%)  reachable=${p.reachable} blocked=${p.blocked}  elapsed=${fmtDuration(elapsed)}  eta=${isFinite(eta) ? fmtDuration(eta) : '?'}`;
}

/** Every request left the registrable domain: the host is a redirector (e.g. apex -> www.other.tld), not a site. */
export function isRedirectOnly(probes: ProbeResult[], baselines: NxBaseline[]): boolean {
  const all = [...probes.map((p) => p.error), ...baselines.map((b) => b.error)];
  return all.length > 0 && all.every((e) => e === 'cross_domain_redirect');
}

async function crawlHost(host: string, args: Args, rank: number | null = null): Promise<HostResult> {
  const start = Date.now();
  const { fp } = await fingerprintHost(host, args.timeoutMs, args.scheme);
  const { baselines, probes, order, raw } = await probeHost(host, {
    timeoutMs: args.timeoutMs,
    scheme: args.scheme,
    bodiesDir: args.storeBodies ? join(dirname(args.out), 'bodies') : undefined,
  });
  const blocked = computeBlocked(probes, raw, baselines);
  const redirect_only = isRedirectOnly(probes, baselines);
  if (redirect_only && !blocked.blocked) {
    const to = probes[0]?.final_url ? (() => { try { return new URL(probes[0].final_url).host; } catch { return '?'; } })() : '?';
    blocked.reason = `redirect_only -> ${to}`;
  }
  const mcpCard = PROBE_SPECS.filter((s) => MCP_CARD_ARTIFACTS.includes(s.artifact)).map((s) => probes.find((p) => p.path === s.path)!).find((p) => p.valid);
  let hygiene: HostResult['hygiene'] = [];
  if (!args.noHygiene && !blocked.blocked) {
    try {
      hygiene = await runHygiene(host, probes, args.timeoutMs, args.scheme);
    } catch (e) {
      hygiene = [];
      console.error(`[${host}] hygiene error: ${(e as Error).message}`);
    }
  }
  return {
    host,
    rank,
    registrable_domain: getDomain(host, { allowPrivateDomains: true }),
    vantage: args.vantage,
    ts: new Date().toISOString(),
    crawler_version: CRAWLER_VERSION,
    blocked,
    redirect_only,
    fingerprint: fp,
    nx_baselines: baselines,
    mcp_card_path: mcpCard?.path ?? null,
    probe_order: order,
    probes: probes.map(({ parsed: _p, ...rest }) => rest),
    hygiene,
    duration_ms: Date.now() - start,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const all = applyShard(await readHosts(args.hosts), args.shard);
  const refusal = contactPreflight(all.map((e) => e.host));
  if (refusal) {
    console.error(`error: ${refusal}`);
    process.exit(2);
  }
  setGlobalRps(args.rpsPerHost);
  const done = await readDone(args.out);
  let todo = all.filter((e) => !done.has(e.host));
  if (args.limit !== null) todo = todo.slice(0, args.limit);

  // Start banner.
  const est = estimateDurationSec(todo.length, args.concurrency, args.rpsPerHost);
  console.error(`agent-discovery-crawler ${CRAWLER_VERSION}`);
  console.error(`hosts: ${all.length} total${args.shard ? ` (shard ${args.shard.index}/${args.shard.count} of the file)` : ''}, ${done.size} already done, ${todo.length} to crawl -> ${args.out}`);
  console.error(`vantage=${args.vantage} concurrency=${args.concurrency} rps/host=${args.rpsPerHost} timeout=${args.timeoutMs}ms hygiene=${args.noHygiene ? 'off' : 'on'} store-bodies=${args.storeBodies ? 'on' : 'off'}`);
  console.error(`user-agent: ${userAgent()}`);
  console.error(`estimated duration: ~${fmtDuration(est)} (${todo.length} hosts / ${args.concurrency} in flight x ${REQUESTS_PER_HOST} requests at ${args.rpsPerHost} rps; hygiene follow-ups not included)`);
  if (process.env.HTTPS_PROXY || process.env.https_proxy) console.error(`proxy: ${process.env.HTTPS_PROXY ?? process.env.https_proxy} (via undici EnvHttpProxyAgent)`);

  mkdirSync(dirname(args.out), { recursive: true });
  const out = createWriteStream(args.out, { flags: 'a' });
  const limit = pLimit(args.concurrency);
  const prog: ProgressState = { done: 0, total: todo.length, reachable: 0, blocked: 0, startedAt: Date.now() };

  // --progress: one line every 60 s so `tail -f crawl.log` shows where a long run is.
  const ticker = args.progress ? setInterval(() => console.error(progressLine(prog)), 60_000) : null;
  if (ticker) ticker.unref();

  // Graceful stop: SIGTERM/SIGINT stops scheduling new hosts, lets in-flight hosts
  // finish, flushes the JSONL and exits 0. Re-running the same command resumes
  // (hosts already in --out are skipped). A second signal exits at once.
  let stopping = false;
  const onSignal = (sig: string) => {
    if (stopping) {
      console.error(`${sig} again: exiting now (in-flight hosts are dropped; resume by re-running)`);
      out.end(() => process.exit(0));
      setTimeout(() => process.exit(0), 2000).unref();
      return;
    }
    stopping = true;
    console.error(`${sig}: finishing in-flight hosts, then flushing ${args.out} (send again to exit immediately)`);
  };
  process.on('SIGTERM', () => onSignal('SIGTERM'));
  process.on('SIGINT', () => onSignal('SIGINT'));

  await Promise.all(
    todo.map(({ host, rank }) =>
      limit(async () => {
        if (stopping) return;
        let result: HostResult;
        try {
          result = await crawlHost(host, args, rank);
        } catch (e) {
          console.error(`[${host}] fatal: ${(e as Error).stack ?? e}`);
          return;
        }
        prog.done++;
        if (result.blocked.blocked) prog.blocked++;
        else if (!result.redirect_only && !result.blocked.reason?.startsWith('unreachable')) prog.reachable++;
        const hits = result.probes.filter((p) => p.valid).map((p) => p.path);
        console.error(`[${prog.done}/${todo.length}] ${host} ${result.blocked.blocked ? 'BLOCKED(' + result.blocked.reason + ')' : result.blocked.reason ?? 'ok'} fp=${result.fingerprint.primary} valid=${hits.length ? hits.join(',') : '-'} ${result.duration_ms}ms`);
        // Respect backpressure: a slow disk must not let 20 in-flight hosts pile up lines in memory.
        if (!out.write(JSON.stringify(result) + '\n')) await once(out, 'drain');
      }),
    ),
  );
  if (ticker) clearInterval(ticker);
  await new Promise<void>((r) => out.end(r));
  if (args.progress) console.error(progressLine(prog));
  console.error(`${stopping ? 'stopped' : 'done'}: ${prog.done} hosts in ${fmtDuration((Date.now() - prog.startedAt) / 1000)}, ${prog.blocked} blocked${stopping ? `, ${todo.length - prog.done} left for resume` : ''} -> ${args.out}`);
  if (stopping) process.exit(0);
}

const isMain = process.argv[1] && /(^|[\/])run\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => {
  console.error(e);
  process.exit(1);
});
