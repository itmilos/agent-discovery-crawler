#!/usr/bin/env node
// Corpus builder (paper §4.1, corpus C): hosts named by MCP registries.
//   npm run corpus:registry                                  # official registry only (no key needed)
//   GLAMA_API_KEY=... SMITHERY_API_KEY=... npm run corpus:registry
//   npm run corpus:registry -- --from-json fixtures/registry-official.json   # offline: replay a saved page set
//   npm run corpus:registry -- --tranco hosts/tranco-latest-1-1k.txt,hosts/tranco-latest-1k-10k.txt
//
// For each registry we page through its public server list, keep every remote
// (streamable-http / sse) endpoint URL, and reduce it to a HOSTNAME (not the
// registrable domain: `mcp.example.com` and `www.example.com` are different
// operators' choices and the crawl probes well-known paths per host). One host
// may carry many servers; the hosts file has it once, and the sidecar
// `registry-<date>.endpoints.jsonl` keeps every (host, registry, server name,
// endpoint URL, transport) row so the handshake can be aimed at the endpoint
// itself rather than at a card.
//
// Sources
//   official  GET https://registry.modelcontextprotocol.io/v0.1/servers?limit=100&cursor=..   (no auth)
//             -> { servers: [{ server: { name, remotes: [{ type, url }] } }], metadata: { nextCursor } }
//   glama     GET https://glama.ai/api/mcp/v1/servers?first=100&after=..                       (Bearer GLAMA_API_KEY)
//             -> { servers: [...], pageInfo: { endCursor, hasNextPage } }; endpoint fields vary, so we walk
//                each record for http(s) URLs under keys matching /url|endpoint/i and drop registry/VCS hosts.
//   smithery  GET https://registry.smithery.ai/servers?page=N&pageSize=100                     (Bearer SMITHERY_API_KEY)
//             -> { servers: [{ qualifiedName, remote }], pagination: { totalPages } }; remote servers are
//                fetched one by one (GET /servers/{qualifiedName}) for connections[].deploymentUrl.
//                Nearly all resolve to server.smithery.ai, which the hosts file therefore lists once.
// A registry that is unreachable or refuses the key is reported and skipped;
// the run still writes what the others returned.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { request } from 'undici';
import { getDomain } from 'tldts';
import { CRAWLER_VERSION, getDispatcher, userAgent } from '../http.js';
import { parseHostLine } from '../run.js';

export const OFFICIAL_URL = 'https://registry.modelcontextprotocol.io/v0.1/servers';
export const GLAMA_URL = 'https://glama.ai/api/mcp/v1/servers';
export const SMITHERY_URL = 'https://registry.smithery.ai/servers';

export type RegistryName = 'official' | 'glama' | 'smithery';

export interface EndpointRow {
  host: string;
  registry: RegistryName;
  server: string; // registry's identifier for the server
  url: string; // remote endpoint as listed
  transport: string | null; // "streamable-http" | "sse" | other registry wording | null
}

/** Hosts that are a registry, a package index or a code forge, never an MCP endpoint operator in our sense. */
const NON_ENDPOINT_HOSTS = /(^|\.)(github\.com|gitlab\.com|bitbucket\.org|npmjs\.com|pypi\.org|glama\.ai|smithery\.ai|modelcontextprotocol\.io|docker\.com|hub\.docker\.com|localhost)$/i;

/** Hostname of an http(s) URL, lowercased, or null for anything else (templates with {var} hosts, stdio, bad URLs, loopback). */
export function endpointHost(url: string): string | null {
  if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) return null;
  let u: URL;
  try { u = new URL(url); } catch { return null; }
  if (/[{}$<>]/.test(u.hostname)) return null; // URL templates: `https://{tenant}.example.com/mcp`
  const h = parseHostLine(u.hostname)?.host ?? null; // same shape rule as the hosts file
  if (!h || NON_ENDPOINT_HOSTS.test(h) || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return null;
  return h;
}

// ---------------------------------------------------------------------------
// Per-registry extraction (pure; tested against recorded pages)
// ---------------------------------------------------------------------------

export function extractOfficial(page: unknown): EndpointRow[] {
  const out: EndpointRow[] = [];
  const servers = (page as { servers?: unknown[] })?.servers ?? [];
  for (const entry of servers) {
    const s = ((entry as { server?: Record<string, unknown> })?.server ?? entry) as Record<string, unknown>;
    const name = String(s?.name ?? '');
    for (const r of (s?.remotes as Array<Record<string, unknown>> | undefined) ?? []) {
      const url = String(r?.url ?? '');
      const host = endpointHost(url);
      if (host) out.push({ host, registry: 'official', server: name, url, transport: typeof r.type === 'string' ? r.type : null });
    }
  }
  return out;
}

export function officialNextCursor(page: unknown): string | null {
  const c = (page as { metadata?: { nextCursor?: unknown } })?.metadata?.nextCursor;
  return typeof c === 'string' && c ? c : null;
}

/** Walk a record for http(s) URLs under url/endpoint-ish keys (depth-limited). */
export function collectUrls(v: unknown, depth = 0, keyHint = '', out: Array<{ key: string; url: string }> = []): Array<{ key: string; url: string }> {
  if (depth > 4 || v === null || v === undefined) return out;
  if (typeof v === 'string') {
    if (/url|endpoint|href/i.test(keyHint) && /^https?:\/\//i.test(v)) out.push({ key: keyHint, url: v });
    return out;
  }
  if (Array.isArray(v)) { for (const x of v) collectUrls(x, depth + 1, keyHint, out); return out; }
  if (typeof v === 'object') for (const [k, x] of Object.entries(v as Record<string, unknown>)) collectUrls(x, depth + 1, k, out);
  return out;
}

export function extractGlama(page: unknown): EndpointRow[] {
  const out: EndpointRow[] = [];
  const servers = (page as { servers?: unknown[] })?.servers ?? [];
  for (const s of servers as Array<Record<string, unknown>>) {
    const name = String(s?.slug ?? s?.name ?? s?.id ?? '');
    for (const { key, url } of collectUrls(s)) {
      if (/repository|homepage|image|avatar|icon|docs?|website/i.test(key)) continue;
      const host = endpointHost(url);
      if (host) out.push({ host, registry: 'glama', server: name, url, transport: /sse/i.test(key) ? 'sse' : null });
    }
  }
  return out;
}

export function glamaNext(page: unknown): string | null {
  const p = (page as { pageInfo?: { endCursor?: unknown; hasNextPage?: unknown } })?.pageInfo;
  return p?.hasNextPage && typeof p.endCursor === 'string' ? p.endCursor : null;
}

export function extractSmitheryDetail(qualifiedName: string, detail: unknown): EndpointRow[] {
  const out: EndpointRow[] = [];
  const d = detail as Record<string, unknown>;
  const conns = (d?.connections as Array<Record<string, unknown>> | undefined) ?? [];
  for (const c of conns) {
    const url = String(c?.deploymentUrl ?? c?.url ?? '');
    const host = endpointHost(url);
    if (host) out.push({ host, registry: 'smithery', server: qualifiedName, url, transport: typeof c.type === 'string' ? c.type : null });
  }
  if (!conns.length && typeof d?.deploymentUrl === 'string') {
    const host = endpointHost(d.deploymentUrl);
    if (host) out.push({ host, registry: 'smithery', server: qualifiedName, url: d.deploymentUrl, transport: null });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

export interface Fetcher { (url: string, headers?: Record<string, string>): Promise<unknown> }

export function makeFetcher(timeoutMs: number): Fetcher {
  return async (url, headers = {}) => {
    const res = await request(url, {
      method: 'GET',
      dispatcher: getDispatcher(timeoutMs),
      maxRedirections: 3,
      headers: { 'user-agent': userAgent(), accept: 'application/json', ...headers },
      headersTimeout: timeoutMs,
      bodyTimeout: timeoutMs,
    });
    const text = await res.body.text();
    if (res.statusCode !== 200) throw new Error(`GET ${url} -> HTTP ${res.statusCode}${text ? ': ' + text.slice(0, 160) : ''}`);
    return JSON.parse(text);
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function pageOfficial(fetch: Fetcher, log: (s: string) => void, pages: unknown[] = []): Promise<{ rows: EndpointRow[]; servers: number; pages: unknown[] }> {
  const rows: EndpointRow[] = [];
  let servers = 0;
  let cursor: string | null = null;
  let n = 0;
  do {
    const url = `${OFFICIAL_URL}?limit=100&version=latest${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
    const page = await fetch(url);
    pages.push(page);
    servers += ((page as { servers?: unknown[] }).servers ?? []).length;
    rows.push(...extractOfficial(page));
    cursor = officialNextCursor(page);
    if (++n % 10 === 0) log(`  official: ${n} pages, ${servers} servers, ${rows.length} remote endpoints`);
    await sleep(250);
  } while (cursor && n < 2_000);
  return { rows, servers, pages };
}

export async function pageGlama(fetch: Fetcher, key: string, log: (s: string) => void): Promise<{ rows: EndpointRow[]; servers: number }> {
  const rows: EndpointRow[] = [];
  let servers = 0;
  let after: string | null = null;
  let n = 0;
  do {
    const url = `${GLAMA_URL}?first=100${after ? `&after=${encodeURIComponent(after)}` : ''}`;
    const page = await fetch(url, { authorization: `Bearer ${key}` });
    servers += ((page as { servers?: unknown[] }).servers ?? []).length;
    rows.push(...extractGlama(page));
    after = glamaNext(page);
    if (++n % 10 === 0) log(`  glama: ${n} pages, ${servers} servers, ${rows.length} remote endpoints`);
    await sleep(250);
  } while (after && n < 2_000);
  return { rows, servers };
}

export async function pageSmithery(fetch: Fetcher, key: string, log: (s: string) => void): Promise<{ rows: EndpointRow[]; servers: number; remote: number }> {
  const rows: EndpointRow[] = [];
  const headers = { authorization: `Bearer ${key}` };
  let servers = 0; let remote = 0;
  let page = 1; let totalPages = 1;
  const remoteNames: string[] = [];
  do {
    const list = await fetch(`${SMITHERY_URL}?page=${page}&pageSize=100`, headers) as { servers?: Array<Record<string, unknown>>; pagination?: { totalPages?: number } };
    totalPages = Number(list.pagination?.totalPages ?? 1);
    for (const s of list.servers ?? []) {
      servers++;
      if (s.remote === true && typeof s.qualifiedName === 'string') remoteNames.push(s.qualifiedName);
    }
    if (page % 10 === 0) log(`  smithery: ${page}/${totalPages} pages, ${servers} servers, ${remoteNames.length} remote`);
    await sleep(250);
  } while (++page <= totalPages && page < 2_000);
  remote = remoteNames.length;
  let i = 0;
  for (const qn of remoteNames) {
    try {
      const d = await fetch(`${SMITHERY_URL}/${encodeURIComponent(qn)}`, headers);
      rows.push(...extractSmitheryDetail(qn, d));
    } catch (e) { log(`  smithery: ${qn}: ${(e as Error).message}`); }
    if (++i % 50 === 0) log(`  smithery: ${i}/${remote} details, ${rows.length} endpoints`);
    await sleep(250);
  }
  return { rows, servers, remote };
}

// ---------------------------------------------------------------------------
// Assemble + write
// ---------------------------------------------------------------------------

export interface RegistryMeta {
  built_at: string;
  crawler_version: string;
  sources: Partial<Record<RegistryName, { servers: number; endpoints: number; hosts: number; error?: string }>>;
  hosts: number;
  hosts_in_tranco: number | null;
  tranco_files: string[];
  files: { hosts: string; endpoints: string; latest: string };
}

export function dedupeHosts(rows: EndpointRow[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of rows) if (!seen.has(r.host)) { seen.add(r.host); out.push(r.host); }
  return out.sort();
}

export function loadTrancoRanks(files: string[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const f of files) {
    if (!existsSync(f)) continue;
    for (const line of readFileSync(f, 'utf8').split(/\r?\n/)) {
      const e = parseHostLine(line);
      if (e && e.rank !== null && !m.has(e.host)) m.set(e.host, e.rank);
    }
  }
  return m;
}

/**
 * A registry host's Tranco rank: the exact hostname, else its registrable
 * domain *including private suffixes* (`mcp.example.com` -> `example.com`, but
 * `foo.workers.dev`, `x.vercel.app`, `1-2-3-4.sslip.io` stay themselves, so a
 * throwaway subdomain of a hosting platform does not inherit the platform's
 * rank). Null when neither is in the given files.
 */
export function trancoRankFor(host: string, ranks: Map<string, number>): number | null {
  const exact = ranks.get(host);
  if (exact !== undefined) return exact;
  const reg = getDomain(host, { allowPrivateDomains: true });
  if (!reg || reg === host || WILDCARD_DNS.has(reg)) return null;
  return ranks.get(reg) ?? null;
}

/** Wildcard-DNS / tunnel services the PSL does not list as private suffixes: any subdomain is someone else's box. */
export const WILDCARD_DNS = new Set(['sslip.io', 'nip.io', 'xip.io', 'traefik.me', 'localtest.me', 'lvh.me', 'trycloudflare.com', 'ngrok.io', 'ngrok.app', 'ngrok-free.app', 'loca.lt', 'serveo.net', 'localhost.run']);

export function writeRegistryCorpus(rows: EndpointRow[], sources: RegistryMeta['sources'], opts: { outDir: string; trancoFiles: string[]; now?: Date }): { meta: RegistryMeta; metaPath: string } {
  const now = opts.now ?? new Date();
  const tag = now.toISOString().slice(0, 10);
  mkdirSync(opts.outDir, { recursive: true });
  const hosts = dedupeHosts(rows);
  const ranks = loadTrancoRanks(opts.trancoFiles);
  let inTranco = 0;
  const lines = hosts.map((h) => {
    const r = trancoRankFor(h, ranks);
    if (r !== null) inTranco++;
    return r !== null ? `${r},${h}` : h;
  });
  for (const [name, s] of Object.entries(sources)) if (s) s.hosts = new Set(rows.filter((r) => r.registry === name).map((r) => r.host)).size;
  const hostsFile = join(opts.outDir, `registry-${tag}.txt`);
  const latest = join(opts.outDir, 'registry-latest.txt');
  const endpointsFile = join(opts.outDir, `registry-${tag}.endpoints.jsonl`);
  const head = [
    `# MCP-registry corpus; generated ${now.toISOString()}; sources: ${Object.keys(sources).join(', ')}`,
    `# ${hosts.length} endpoint hosts from ${rows.length} remote endpoints; "rank,host" where the host or its parent is in the given Tranco files, else bare host`,
  ];
  writeFileSync(hostsFile, head.concat(lines).join('\n') + '\n');
  writeFileSync(latest, head.concat(lines).join('\n') + '\n');
  writeFileSync(endpointsFile, rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''));
  const meta: RegistryMeta = {
    built_at: now.toISOString(),
    crawler_version: CRAWLER_VERSION,
    sources,
    hosts: hosts.length,
    hosts_in_tranco: opts.trancoFiles.length ? inTranco : null,
    tranco_files: opts.trancoFiles,
    files: { hosts: hostsFile, endpoints: endpointsFile, latest },
  };
  const metaPath = join(opts.outDir, `registry-${tag}.meta.json`);
  writeFileSync(metaPath, JSON.stringify(meta, null, 2) + '\n');
  return { meta, metaPath };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface CliArgs { outDir: string; timeoutMs: number; tranco: string[]; fromJson: string | null; savePages: string | null; only: Set<RegistryName> | null }

function parseArgs(argv: string[]): CliArgs {
  const a: CliArgs = { outDir: 'hosts', timeoutMs: 30_000, tranco: [], fromJson: null, savePages: null, only: null };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i]; const v = argv[i + 1];
    switch (k) {
      case '--out-dir': a.outDir = v; i++; break;
      case '--timeout-ms': a.timeoutMs = Number(v); i++; break;
      case '--tranco': a.tranco = v.split(',').map((s) => s.trim()).filter(Boolean); i++; break;
      case '--from-json': a.fromJson = v; i++; break; // replay saved official-registry pages (array of page objects)
      case '--save-pages': a.savePages = v; i++; break; // write the official pages as fetched (for provenance / replay)
      case '--only': a.only = new Set(v.split(',') as RegistryName[]); i++; break;
      case '-h': case '--help':
        console.log('usage: registry.ts [--out-dir hosts] [--tranco a.txt,b.txt] [--only official,glama,smithery] [--save-pages file.json] [--from-json file.json] [--timeout-ms 30000]');
        console.log('env: GLAMA_API_KEY, SMITHERY_API_KEY (each optional; the registry is skipped without it)');
        process.exit(0);
    }
  }
  return a;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const log = (s: string) => console.error(s);
  const want = (r: RegistryName) => !args.only || args.only.has(r);
  const fetch = makeFetcher(args.timeoutMs);
  const rows: EndpointRow[] = [];
  const sources: RegistryMeta['sources'] = {};

  if (want('official')) {
    try {
      if (args.fromJson) {
        const pages = JSON.parse(readFileSync(args.fromJson, 'utf8')) as unknown[];
        const r = pages.flatMap(extractOfficial);
        rows.push(...r);
        const servers = pages.reduce<number>((n, p) => n + (((p as { servers?: unknown[] }).servers ?? []).length), 0);
        sources.official = { servers, endpoints: r.length, hosts: 0 };
        log(`official (replay ${args.fromJson}): ${servers} servers, ${r.length} remote endpoints`);
      } else {
        log(`official: paging ${OFFICIAL_URL}`);
        const r = await pageOfficial(fetch, log);
        rows.push(...r.rows);
        sources.official = { servers: r.servers, endpoints: r.rows.length, hosts: 0 };
        if (args.savePages) writeFileSync(args.savePages, JSON.stringify(r.pages));
        log(`official: ${r.servers} servers, ${r.rows.length} remote endpoints`);
      }
    } catch (e) { sources.official = { servers: 0, endpoints: 0, hosts: 0, error: (e as Error).message }; log(`official: FAILED ${(e as Error).message}`); }
  }
  if (want('glama')) {
    const key = process.env.GLAMA_API_KEY;
    if (!key) log('glama: skipped (set GLAMA_API_KEY)');
    else {
      try {
        const r = await pageGlama(fetch, key, log);
        rows.push(...r.rows);
        sources.glama = { servers: r.servers, endpoints: r.rows.length, hosts: 0 };
        log(`glama: ${r.servers} servers, ${r.rows.length} remote endpoints`);
      } catch (e) { sources.glama = { servers: 0, endpoints: 0, hosts: 0, error: (e as Error).message }; log(`glama: FAILED ${(e as Error).message}`); }
    }
  }
  if (want('smithery')) {
    const key = process.env.SMITHERY_API_KEY;
    if (!key) log('smithery: skipped (set SMITHERY_API_KEY)');
    else {
      try {
        const r = await pageSmithery(fetch, key, log);
        rows.push(...r.rows);
        sources.smithery = { servers: r.servers, endpoints: r.rows.length, hosts: 0 };
        log(`smithery: ${r.servers} servers (${r.remote} remote), ${r.rows.length} endpoints`);
      } catch (e) { sources.smithery = { servers: 0, endpoints: 0, hosts: 0, error: (e as Error).message }; log(`smithery: FAILED ${(e as Error).message}`); }
    }
  }

  const { meta, metaPath } = writeRegistryCorpus(rows, sources, { outDir: args.outDir, trancoFiles: args.tranco });
  log(`hosts: ${meta.hosts}${meta.hosts_in_tranco !== null ? ` (${meta.hosts_in_tranco} in the given Tranco files)` : ''} -> ${meta.files.hosts} (+ ${meta.files.latest}); endpoints -> ${meta.files.endpoints}; meta -> ${metaPath}`);
}

const isMain = process.argv[1] && /registry\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
