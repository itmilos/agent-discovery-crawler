#!/usr/bin/env node
// CLI for the MCP initialize handshake probe (src/handshake.ts, paper §4.6(e)).
//   npm run handshake -- --in out/a.jsonl [out/b.jsonl ...] --out out/handshake.jsonl --rps 1 --i-have-read-the-ethics-section
//   npm run handshake -- --in out/a.jsonl --out /dev/null --dry-run        # list endpoints, contact nothing
import { createWriteStream, existsSync, mkdirSync } from 'node:fs';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { dirname } from 'node:path';
import pLimit from 'p-limit';
import { CRAWLER_VERSION, contactInfo, setGlobalRps, userAgent } from './http.js';
import { contactPreflight, fmtDuration } from './run.js';
import { ETHICS_WORDING, MCP_PROTOCOL_VERSION, collectEndpoints, probeHandshake, type EndpointTarget, type HandshakeResult } from './handshake.js';

interface Args { inputs: string[]; out: string; rps: number; concurrency: number; timeoutMs: number; dryRun: boolean; ethics: boolean; scheme: 'https' | 'http'; limit: number | null; noResourceMetadata: boolean }

function parseArgs(argv: string[]): Args {
  const a: Args = { inputs: [], out: '', rps: 1, concurrency: 10, timeoutMs: 10_000, dryRun: false, ethics: false, scheme: 'https', limit: null, noResourceMetadata: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i]; const v = argv[i + 1];
    switch (k) {
      case '--in':
        while (argv[i + 1] && !argv[i + 1].startsWith('--')) a.inputs.push(argv[++i]);
        break;
      case '--out': a.out = v; i++; break;
      case '--rps': a.rps = Number(v); i++; break;
      case '--concurrency': a.concurrency = Number(v); i++; break;
      case '--timeout-ms': a.timeoutMs = Number(v); i++; break;
      case '--limit': a.limit = Number(v); i++; break;
      case '--dry-run': a.dryRun = true; break;
      case '--i-have-read-the-ethics-section': a.ethics = true; break;
      case '--no-resource-metadata': a.noResourceMetadata = true; break;
      case '--scheme': a.scheme = v === 'http' ? 'http' : 'https'; i++; break; // fixtures only
      case '-h': case '--help':
        console.log('usage: handshake-run.ts --in RESULTS.jsonl [MORE.jsonl ...] --out handshake.jsonl [--rps 1] [--concurrency 10] [--timeout-ms 10000] [--limit N] [--dry-run] [--no-resource-metadata] --i-have-read-the-ethics-section');
        process.exit(0);
    }
  }
  if (!a.inputs.length || (!a.out && !a.dryRun)) { console.error('error: --in FILE... and --out FILE are required (--out may be omitted with --dry-run)'); process.exit(2); }
  return a;
}

/**
 * Disclosure gate: a real run needs the contact identity in the UA (same rule
 * as `crawl`, waived for an all-fixture target set) AND the explicit flag. A
 * dry run contacts nobody and needs neither.
 */
export function handshakeGate(hosts: string[], flags: { ethics: boolean; dryRun: boolean }, env: { url?: string; email?: string } = contactInfo()): string | null {
  if (flags.dryRun) return null;
  const contact = contactPreflight(hosts, env);
  if (contact) return contact;
  if (!flags.ethics) return 'refusing to send initialize requests without --i-have-read-the-ethics-section (paper §4.6; see README "Handshake probe")';
  return null;
}

async function readDoneKeys(path: string): Promise<Set<string>> {
  const done = new Set<string>();
  if (!path || !existsSync(path)) return done;
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    try { const o = JSON.parse(line) as { host?: string; endpoint?: string }; if (o.host && o.endpoint) done.add(`${o.host} ${o.endpoint}`); } catch { /* partial line */ }
  }
  return done;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  console.error(`agent-discovery-crawler ${CRAWLER_VERSION} / MCP initialize handshake probe`);
  console.error(ETHICS_WORDING);
  console.error('');
  for (const f of args.inputs) if (!existsSync(f)) { console.error(`error: ${f} not found`); process.exit(2); }
  setGlobalRps(args.rps);

  // Pass 1 (no network): what would be contacted. The gate is evaluated on these hosts.
  const dry = await collectEndpoints(args.inputs, { refetch: false, scheme: args.scheme });
  const hosts = [...new Set(dry.targets.map((t) => t.host))];
  const refusal = handshakeGate(hosts, { ethics: args.ethics, dryRun: args.dryRun });
  if (refusal) { console.error(`error: ${refusal}`); process.exit(2); }

  if (args.dryRun) {
    console.error(`dry run: ${dry.stats.rows} rows, ${dry.stats.hosts_with_mcp_card} hosts with a valid MCP card, ${dry.targets.length} targets (${dry.stats.needs_refetch} need a card re-fetch to learn the endpoint; A2A entries: ${dry.stats.a2a_entries}, included as MCP: ${dry.stats.a2a_included}, skipped: ${dry.stats.a2a_skipped}). Nothing was contacted.`);
    for (const t of dry.targets) console.log(`${t.host}\t${t.rank ?? ''}\t${t.source}\t${t.endpoint ?? '(endpoint unknown: card re-fetch needed ' + args.scheme + '://' + t.host + t.card_path + ')'}${t.a2a_reason ? '\t' + t.a2a_reason : ''}`);
    return;
  }

  // Pass 2: re-fetch cards whose endpoint hygiene did not record (one GET each, through the limiter), then probe.
  const { targets, stats } = await collectEndpoints(args.inputs, { refetch: true, timeoutMs: args.timeoutMs, scheme: args.scheme, log: (s) => console.error(s) });
  const done = await readDoneKeys(args.out);
  let todo = targets.filter((t): t is EndpointTarget & { endpoint: string } => !!t.endpoint && !done.has(`${t.host} ${t.endpoint}`));
  if (args.limit !== null) todo = todo.slice(0, args.limit);
  console.error(`inputs: ${args.inputs.join(', ')} (${stats.rows} rows, ${stats.hosts_with_mcp_card} hosts with a valid MCP card)`);
  console.error(`targets: ${targets.length} (${stats.mcp_endpoints} MCP card endpoints, ${stats.a2a_included} A2A endpoints that look like MCP, ${stats.a2a_skipped} A2A skipped, ${stats.refetched} cards re-fetched, ${stats.refetch_failed} without an endpoint), ${done.size} already done, ${todo.length} to probe -> ${args.out}`);
  console.error(`protocol-version=${MCP_PROTOCOL_VERSION} rps/host=${args.rps} concurrency=${args.concurrency} timeout=${args.timeoutMs}ms resource-metadata-check=${args.noResourceMetadata ? 'off' : 'on'}`);
  console.error(`user-agent: ${userAgent()}`);
  console.error(`per endpoint: 1 POST initialize (no credentials) [+ 1 DELETE if a session id is returned] [+ 1 GET of the WWW-Authenticate resource_metadata URL]; nothing else is ever sent`);

  mkdirSync(dirname(args.out), { recursive: true });
  const out = createWriteStream(args.out, { flags: 'a' });
  const limit = pLimit(args.concurrency);
  const counts: Record<string, number> = {};
  const startedAt = Date.now();
  let n = 0;
  let stopping = false;
  const onSignal = (sig: string) => { if (stopping) { out.end(() => process.exit(0)); return; } stopping = true; console.error(`${sig}: finishing in-flight endpoints, then flushing ${args.out}`); };
  process.on('SIGTERM', () => onSignal('SIGTERM'));
  process.on('SIGINT', () => onSignal('SIGINT'));

  await Promise.all(todo.map((t) => limit(async () => {
    if (stopping) return;
    let r: HandshakeResult;
    try {
      r = await probeHandshake(t, { timeoutMs: args.timeoutMs, checkResourceMetadata: !args.noResourceMetadata });
    } catch (e) {
      console.error(`[${t.host}] fatal: ${(e as Error).stack ?? e}`);
      return;
    }
    n++;
    counts[r.classification] = (counts[r.classification] ?? 0) + 1;
    const si = r.result?.server_info ? ` serverInfo=${r.result.server_info.name ?? '?'}@${r.result.server_info.version ?? '?'}` : '';
    const rm = r.resource_metadata ? ` prm=${r.resource_metadata.status ?? r.resource_metadata.error}${r.resource_metadata.matches_hygiene_prm === null ? '' : r.resource_metadata.matches_hygiene_prm ? '(matches hygiene)' : '(differs from hygiene)'}` : '';
    const del = r.session_delete ? ` delete=${r.session_delete.status ?? r.session_delete.error}` : '';
    console.error(`[${n}/${todo.length}] ${t.host} ${t.endpoint} -> ${r.status || r.error} ${r.classification}${si}${rm}${del} ${r.elapsed_ms}ms`);
    if (!out.write(JSON.stringify(r) + '\n')) await once(out, 'drain');
  })));
  await new Promise<void>((res) => out.end(res));
  console.error(`${stopping ? 'stopped' : 'done'}: ${n} endpoints in ${fmtDuration((Date.now() - startedAt) / 1000)} -> ${args.out}`);
  console.error(`classification: ${Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}=${v}`).join(' ') || '-'}`);
  if (stopping) process.exit(0);
}

const isMain = process.argv[1] && /handshake-run\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
