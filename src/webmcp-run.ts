#!/usr/bin/env node
// CLI for the WebMCP headless module (src/webmcp.ts): one JSONL row per host.
//   npm run webmcp -- --hosts hosts/webmcp-sample.txt --out out/webmcp-sample.jsonl --concurrency 4 --pages 4
import { createWriteStream, mkdirSync } from 'node:fs';
import { once } from 'node:events';
import { dirname } from 'node:path';
import pLimit from 'p-limit';
import { CRAWLER_VERSION, setGlobalRps, userAgent } from './http.js';
import { applyShard, contactPreflight, fmtDuration, parseShard, readDone, readHosts, type Shard } from './run.js';
import { crawlHostWebMCP, launchChromium, resolveChromiumPath, DEFAULT_NAV_TIMEOUT_MS, type WebMCPResult } from './webmcp.js';

interface Args { hosts: string; out: string; concurrency: number; pages: number; timeoutMs: number; limit: number | null; scheme: 'https' | 'http'; progress: boolean; shard: Shard | null; chromium: string | null }

function parseArgs(argv: string[]): Args {
  const a: Args = { hosts: '', out: '', concurrency: 4, pages: 4, timeoutMs: DEFAULT_NAV_TIMEOUT_MS, limit: null, scheme: 'https', progress: false, shard: null, chromium: null };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i]; const v = argv[i + 1];
    switch (k) {
      case '--hosts': a.hosts = v; i++; break;
      case '--out': a.out = v; i++; break;
      case '--concurrency': a.concurrency = Number(v); i++; break;
      case '--pages': a.pages = Math.max(1, Number(v)); i++; break;
      case '--timeout-ms': a.timeoutMs = Number(v); i++; break;
      case '--limit': a.limit = Number(v); i++; break;
      case '--progress': a.progress = true; break;
      case '--chromium': a.chromium = v; i++; break;
      case '--shard': try { a.shard = parseShard(v); } catch (e) { console.error(`error: ${(e as Error).message}`); process.exit(2); } i++; break;
      case '--scheme': a.scheme = v === 'http' ? 'http' : 'https'; i++; break;
      case '-h': case '--help':
        console.log('usage: webmcp-run.ts --hosts FILE --out FILE.jsonl [--concurrency 4] [--pages 4] [--timeout-ms 15000] [--limit N] [--progress] [--shard i/n] [--chromium PATH] [--scheme https|http]');
        process.exit(0);
    }
  }
  if (!a.hosts || !a.out) { console.error('error: --hosts and --out are required'); process.exit(2); }
  return a;
}

/** 'webmcp' if any token's feature matches WebMCP / modelContext, 'other' if there are tokens but none does, null for no tokens. */
export function originTrialKind(tokens: { feature: string | null }[]): 'webmcp' | 'other' | null {
  if (!tokens.length) return null;
  return tokens.some((t) => t.feature && /webmcp|modelcontext/i.test(t.feature)) ? 'webmcp' : 'other';
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const all = applyShard(await readHosts(args.hosts), args.shard);
  const refusal = contactPreflight(all.map((e) => e.host));
  if (refusal) { console.error(`error: ${refusal}`); process.exit(2); }
  const exe = args.chromium ?? resolveChromiumPath();
  if (!exe) { console.error('error: no Chromium found. Run `npx playwright-core install chromium` (one-time, ~150 MB) or set CRAWLER_CHROMIUM_PATH / --chromium'); process.exit(2); }
  setGlobalRps(1); // robots.txt fetches share the crawler's per-host limiter
  const done = await readDone(args.out);
  let todo = all.filter((e) => !done.has(e.host));
  if (args.limit !== null) todo = todo.slice(0, args.limit);

  console.error(`agent-discovery-crawler ${CRAWLER_VERSION} / webmcp module`);
  console.error(`hosts: ${all.length} total${args.shard ? ` (shard ${args.shard.index}/${args.shard.count})` : ''}, ${done.size} already done, ${todo.length} to crawl -> ${args.out}`);
  console.error(`concurrency=${args.concurrency} pages/host<=${args.pages} nav-timeout=${args.timeoutMs}ms scheme=${args.scheme}`);
  console.error(`chromium: ${exe}`);
  console.error(`user-agent: ${userAgent()}`);
  const estSec = Math.ceil(todo.length / args.concurrency) * args.pages * 4; // ~4 s per page (load + settle + gap)
  console.error(`estimated duration: ~${fmtDuration(estSec)} (${todo.length} hosts / ${args.concurrency} in flight x ${args.pages} pages x ~4 s)`);

  const browser = await launchChromium({ executablePath: exe });
  mkdirSync(dirname(args.out), { recursive: true });
  const out = createWriteStream(args.out, { flags: 'a' });
  const limit = pLimit(args.concurrency);
  const prog = { done: 0, withReg: 0, native: 0, trial: 0, otherTrials: 0, declarative: 0, failed: 0, startedAt: Date.now() };
  const line = () => `progress: ${prog.done}/${todo.length} done  registrations=${prog.withReg} native=${prog.native} webmcp-origin-trial=${prog.trial} other_trials=${prog.otherTrials} declarative=${prog.declarative} homepage-failed=${prog.failed}  elapsed=${fmtDuration((Date.now() - prog.startedAt) / 1000)}`;
  const ticker = args.progress ? setInterval(() => console.error(line()), 60_000) : null;
  if (ticker) ticker.unref();

  let stopping = false;
  const onSignal = (sig: string) => {
    if (stopping) { out.end(() => process.exit(0)); setTimeout(() => process.exit(0), 2000).unref(); return; }
    stopping = true;
    console.error(`${sig}: finishing in-flight hosts, then flushing ${args.out} (send again to exit immediately)`);
  };
  process.on('SIGTERM', () => onSignal('SIGTERM'));
  process.on('SIGINT', () => onSignal('SIGINT'));

  await Promise.all(todo.map(({ host, rank }) => limit(async () => {
    if (stopping) return;
    let r: WebMCPResult;
    try {
      r = await crawlHostWebMCP(browser, host, { pages: args.pages, timeoutMs: args.timeoutMs, scheme: args.scheme }, rank);
    } catch (e) {
      console.error(`[${host}] fatal: ${(e as Error).stack ?? e}`);
      return;
    }
    prog.done++;
    if (r.registrations.length) prog.withReg++;
    if (r.native_modelContext || r.native_document_modelContext) prog.native++;
    // count only tokens whose feature is WebMCP; sites run other origin trials too
    const trialKind = originTrialKind(r.origin_trial.tokens);
    if (trialKind === 'webmcp') prog.trial++;
    else if (trialKind === 'other') prog.otherTrials++;
    if (r.declarative_hits.length) prog.declarative++;
    if (!r.pages_visited.length) prog.failed++;
    const tools = r.registrations.filter((x) => x.tool_name).map((x) => x.tool_name).slice(0, 5);
    console.error(`[${prog.done}/${todo.length}] ${host} pages=${r.pages_visited.length} reg=${r.registrations.length}${tools.length ? '(' + tools.join(',') + ')' : ''} native=${r.native_modelContext ? 'Y' : 'n'} trial=${r.origin_trial.present ? (originTrialKind(r.origin_trial.tokens) === 'webmcp' ? r.origin_trial.feature : 'other:' + (r.origin_trial.feature ?? '?')) : 'n'} decl=${r.declarative_hits.length} robots-skipped=${r.robots.skipped.length}${r.errors.length ? ' err=' + r.errors[0] : ''} ${r.duration_ms}ms`);
    if (!out.write(JSON.stringify(r) + '\n')) await once(out, 'drain');
  })));
  if (ticker) clearInterval(ticker);
  await browser.close().catch(() => {});
  await new Promise<void>((res) => out.end(res));
  console.error(line());
  console.error(`${stopping ? 'stopped' : 'done'}: ${prog.done} hosts${stopping ? `, ${todo.length - prog.done} left for resume` : ''} -> ${args.out}`);
  if (stopping) process.exit(0);
}

const isMain = process.argv[1] && /webmcp-run\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
