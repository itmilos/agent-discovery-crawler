#!/usr/bin/env node
// Canary experiment kit (paper §4.6 RQ3, Table 5): do commercial agents read
// discovery artifacts before acting?
//
//   npm run canary:plan -- --domains hosts/canary-domains.txt --out canary [--seed 20261108]
//   npm run canary:analyze -- --manifest canary/manifest.json --trials canary/trials.csv --logs canary/logs/*.log --out canary/results.json
//
// `plan` assigns each cooperating domain to one cell of the 2x2 (artifacts
// linked from the homepage or not; canary present or absent), mints one unique,
// pronounceable, otherwise-unindexed token per artifact type per canary domain,
// and writes a complete static site per domain under <out>/sites/<domain>/ plus
// manifest.json (the key: domain, cell, tokens) and tasks.csv (five task
// prompts per domain; two do not name any artifact, three do). Control domains
// get the same files with generic content and no token, so a "canary" in an
// agent's answer for a control domain is a false positive by construction.
// robots.txt disallows search-engine crawlers (so the token cannot leak into a
// web index) and explicitly allows the agent user agents.
//
// `analyze` joins a trials sheet (one row per agent x domain x task with its
// time window and the agent's answer text) against the cooperating hosts'
// access logs (nginx/Apache combined format, file named <domain>.log, or Caddy
// JSON lines) and reports, per agent product: fetched llms.txt / server card /
// any artifact during the trial window, answer contained the domain's canary,
// broken down by cell, with domain-clustered bootstrap intervals (trials
// cluster within domains, so binomial intervals would be too narrow).
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname, join, basename } from 'node:path';

// ---------- tokens ----------

export function mulberry32(a: number) { return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

const C = 'bdfgklmnprstvz', V = 'aeiou';
/** Pronounceable nonsense word, 3 syllables, e.g. "velmora". Not a real word in the common languages we checked by eye; uniqueness is enforced by the caller. */
export function nonsenseWord(rnd: () => number, syllables = 3): string {
  let w = '';
  for (let i = 0; i < syllables; i++) w += C[Math.floor(rnd() * C.length)] + V[Math.floor(rnd() * V.length)] + (i === syllables - 1 && rnd() < 0.5 ? C[Math.floor(rnd() * C.length)] : '');
  return w;
}

export type ArtifactKey = 'llms' | 'card' | 'openapi' | 'a2a';
export const ARTIFACT_KEYS: ArtifactKey[] = ['llms', 'card', 'openapi', 'a2a'];
export interface Cell { linked: boolean; canary: boolean }
export interface DomainPlan { domain: string; cell: Cell; cell_label: string; tokens: Record<ArtifactKey, string> | null }
export interface Manifest { seed: number; created: string; domains: DomainPlan[] }

export function cellLabel(c: Cell): string { return `${c.linked ? 'linked' : 'unlinked'}/${c.canary ? 'canary' : 'control'}`; }

/** Balanced assignment to the four cells (round-robin over a seeded shuffle), one token set per canary domain, all tokens distinct across the whole plan. */
export function plan(domains: string[], seed: number): Manifest {
  const rnd = mulberry32(seed);
  const d = [...new Set(domains.map((x) => x.trim().toLowerCase()).filter(Boolean))];
  for (let i = d.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [d[i], d[j]] = [d[j], d[i]]; }
  const cells: Cell[] = [{ linked: true, canary: true }, { linked: false, canary: true }, { linked: true, canary: false }, { linked: false, canary: false }];
  const used = new Set<string>();
  const mint = () => { for (;;) { const w = nonsenseWord(rnd); if (!used.has(w)) { used.add(w); return w; } } };
  const out: DomainPlan[] = d.map((domain, i) => {
    const cell = cells[i % 4];
    const tokens = cell.canary ? { llms: `${mint()} ${mint()}`, card: `${mint()}_${mint()}`, openapi: `${mint()}${cap(mint())}`, a2a: `${mint()}-${mint()}` } : null;
    return { domain, cell, cell_label: cellLabel(cell), tokens };
  });
  return { seed, created: new Date().toISOString().slice(0, 10), domains: out };
}
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);

// ---------- static site ----------

/**
 * robots.txt allows every user agent. Keeping the tokens out of web indexes is
 * done with `noindex` instead (a <meta> on the page and an X-Robots-Tag header
 * on every response, see deploy/canary-README.md), because the fetchers behind
 * the agents' web tools do not all announce a distinct user agent, and a
 * Disallow aimed at search crawlers could silently block the very fetch we
 * want to observe. Search engines that can fetch a noindex page do not index it.
 */
export function robotsTxt(): string {
  return ['# Canary site for a web-measurement study of agent discovery files. Fetching is welcome;', '# every response carries X-Robots-Tag: noindex so nothing here enters a web index.', '# Contact: see /.well-known/security.txt', '', 'User-agent: *', 'Allow: /', ''].join('\n');
}

export interface SiteFiles { [path: string]: string } // path -> content

export function renderSite(p: DomainPlan, contact: { email: string; url: string }): SiteFiles {
  const { domain, cell } = p; const t = p.tokens;
  const origin = `https://${domain}`;
  const toolName = t ? t.card : 'search_pages';
  const opId = t ? t.openapi : 'searchPages';
  const skill = t ? t.a2a : 'page-search';
  const codename = t ? t.llms : null;
  const llms = [`# ${domain}`, '', `> Developer notes for ${domain}, a small example service used in a web-measurement study of agent discovery files.`, '', ...(codename ? [`Internal project codename: **${codename}**.`, ''] : []), '## Docs', `- [API description (OpenAPI)](${origin}/openapi.json)`, `- [MCP server card](${origin}/.well-known/mcp-server-card)`, `- [Agent card](${origin}/.well-known/agent-card.json)`, ''].join('\n');
  const card2127 = { name: `${domain.split('.')[0]}.notes`, version: '1.0.0', description: `Read-only page search for ${domain}.`, remotes: [{ type: 'streamable-http', url: `${origin}/mcp` }], tools: [{ name: toolName, description: 'Search the public pages of this site.' , inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] } }] };
  const card1649 = { name: `${domain.split('.')[0]}-notes`, version: '1.0', transport: { type: 'streamable-http', url: `${origin}/mcp` }, tools: card2127.tools };
  const openapi = { openapi: '3.1.0', info: { title: `${domain} notes API`, version: '1.0.0' }, servers: [{ url: `${origin}/api` }], paths: { '/search': { get: { operationId: opId, summary: 'Search public pages', parameters: [{ name: 'q', in: 'query', schema: { type: 'string' } }], responses: { '200': { description: 'results' } } } } } };
  const a2a = { name: `${domain} notes agent`, description: 'Answers questions about the public pages of this site.', url: `${origin}/a2a`, version: '1.0.0', capabilities: { streaming: false }, defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'], skills: [{ id: skill, name: skill, description: 'Search the public pages of this site.', tags: ['search'] }] };
  const links = cell.linked
    ? `<link rel="alternate" type="text/markdown" href="/llms.txt" title="llms.txt">\n<link rel="alternate" type="application/json" href="/.well-known/mcp-server-card" title="MCP server card">\n<link rel="alternate" type="application/json" href="/openapi.json" title="OpenAPI">`
    : '';
  const nav = cell.linked ? `<p>For agents and developers: <a href="/llms.txt">llms.txt</a> · <a href="/.well-known/mcp-server-card">MCP server card</a> · <a href="/openapi.json">OpenAPI</a> · <a href="/.well-known/agent-card.json">agent card</a></p>` : '';
  const index = `<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>${domain} — developer notes</title><meta name="robots" content="noindex, noarchive">\n${links}\n<style>body{font:16px/1.5 system-ui;max-width:40em;margin:3em auto;padding:0 1em;color:#222}</style></head>\n<body><h1>${domain}</h1>\n<p>A small example service taking part in a web-measurement study of how AI agents discover what a site offers. There is nothing to buy here. The service exposes a read-only page search.</p>\n${nav}\n<p>Questions about the study: <a href="mailto:${contact.email}">${contact.email}</a> · <a href="${contact.url}">${contact.url}</a></p>\n</body></html>\n`;
  const security = `Contact: mailto:${contact.email}\nExpires: 2027-12-31T00:00:00.000Z\nPreferred-Languages: en\nPolicy: ${contact.url}\n`;
  return {
    'index.html': index,
    'robots.txt': robotsTxt(),
    'llms.txt': llms,
    '.well-known/mcp-server-card': JSON.stringify(card2127, null, 2) + '\n',
    '.well-known/mcp/server-card.json': JSON.stringify(card1649, null, 2) + '\n',
    'openapi.json': JSON.stringify(openapi, null, 2) + '\n',
    '.well-known/agent-card.json': JSON.stringify(a2a, null, 2) + '\n',
    '.well-known/security.txt': security,
  };
}

// ---------- tasks ----------

export interface Task { task_id: string; leading: boolean; targets: ArtifactKey[]; prompt: string }

/** Five prompts per domain. T1–T2 never name a file (does the agent go looking?); T3–T5 name the artifact (can it fetch and read one when told?). */
export function tasksFor(domain: string): Task[] {
  return [
    { task_id: 'T1', leading: false, targets: ['card', 'openapi', 'a2a', 'llms'], prompt: `I want to connect an AI agent to ${domain}. What tools or operations does the site expose for agents? Give me the exact tool names.` },
    { task_id: 'T2', leading: false, targets: ['llms'], prompt: `What is the internal project codename of the service at ${domain}? Answer with the codename only, or say you cannot find it.` },
    { task_id: 'T3', leading: true, targets: ['card'], prompt: `Read the MCP server card published by ${domain} and tell me the exact name of the tool it lists.` },
    { task_id: 'T4', leading: true, targets: ['openapi'], prompt: `Open the OpenAPI document at ${domain}/openapi.json and tell me the operationId of the search operation.` },
    { task_id: 'T5', leading: true, targets: ['a2a', 'llms'], prompt: `${domain} publishes an llms.txt and an A2A agent card. What skill id does the agent card advertise, and what codename does llms.txt give the project?` },
  ];
}

export function renderTasksCsv(m: Manifest): string {
  const esc = (s: string) => (/[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
  const rows = ['domain,cell,task_id,leading,targets,prompt'];
  for (const d of m.domains) for (const t of tasksFor(d.domain)) rows.push([d.domain, d.cell_label, t.task_id, t.leading ? 'yes' : 'no', t.targets.join('|'), t.prompt].map(esc).join(','));
  return rows.join('\n') + '\n';
}

export const TRIALS_HEADER = 'agent,domain,task_id,start_utc,end_utc,answer';

/** One Caddy site block per domain: static root, JSON type for the extensionless card, noindex header on every response, one access log per domain (what `analyze` reads). */
export function renderCaddyfile(m: Manifest, root = '/srv/canary', logDir = '/var/log/caddy'): string {
  return m.domains.map((d) => `${d.domain} {
    root * ${root}/sites/${d.domain}
    file_server
    header X-Robots-Tag "noindex, nofollow, noarchive"
    @card path /.well-known/mcp-server-card
    header @card Content-Type application/json
    @txt path *.txt
    header @txt Content-Type "text/plain; charset=utf-8"
    log {
        output file ${logDir}/${d.domain}.log
    }
}
`).join('\n');
}

export function writePlan(m: Manifest, outDir: string, contact: { email: string; url: string }): string[] {
  const written: string[] = [];
  mkdirSync(outDir, { recursive: true });
  const w = (rel: string, content: string) => { const f = join(outDir, rel); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, content); written.push(f); };
  w('manifest.json', JSON.stringify(m, null, 2) + '\n');
  w('tasks.csv', renderTasksCsv(m));
  w('Caddyfile', renderCaddyfile(m));
  if (!existsSync(join(outDir, 'trials.csv'))) w('trials.csv', TRIALS_HEADER + '\n');
  for (const d of m.domains) for (const [rel, content] of Object.entries(renderSite(d, contact))) w(join('sites', d.domain, rel), content);
  return written;
}

// ---------- analysis ----------

export const ARTIFACT_PATHS: Record<ArtifactKey, string[]> = {
  llms: ['/llms.txt', '/llms-full.txt'],
  card: ['/.well-known/mcp-server-card', '/.well-known/mcp/server-card.json'],
  openapi: ['/openapi.json', '/openapi.yaml'],
  a2a: ['/.well-known/agent-card.json', '/.well-known/agent.json'],
};

export interface LogHit { host: string | null; ts: number; path: string; ua: string; status: number }

const COMBINED = /^(\S+) \S+ \S+ \[([^\]]+)\] "(?:GET|HEAD|POST) ([^ "]+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?/;
const MONTHS: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

/** One access-log line -> hit. Combined format (host from the file name) or Caddy JSON (`request.host`). Returns null for lines it cannot read. */
export function parseLogLine(line: string, hostFromFile: string | null): LogHit | null {
  if (!line.trim()) return null;
  if (line[0] === '{') {
    try {
      const j = JSON.parse(line) as { ts?: number; request?: { host?: string; uri?: string; headers?: Record<string, string[]> }; status?: number };
      if (!j.request?.uri) return null;
      return { host: j.request.host?.toLowerCase().replace(/:\d+$/, '') ?? hostFromFile, ts: Math.round((j.ts ?? 0) * 1000), path: j.request.uri.split('?')[0], ua: j.request.headers?.['User-Agent']?.[0] ?? '', status: j.status ?? 0 };
    } catch { return null; }
  }
  const m = COMBINED.exec(line);
  if (!m) return null;
  const d = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$/.exec(m[2]);
  if (!d) return null;
  const off = (d[7][0] === '-' ? -1 : 1) * (Number(d[7].slice(1, 3)) * 60 + Number(d[7].slice(3, 5))) * 60_000;
  const ts = Date.UTC(Number(d[3]), MONTHS[d[2]] ?? 0, Number(d[1]), Number(d[4]), Number(d[5]), Number(d[6])) - off;
  return { host: hostFromFile, ts, path: m[3].split('?')[0], ua: m[5] ?? '', status: Number(m[4]) };
}

export async function readLogs(files: string[]): Promise<LogHit[]> {
  const out: LogHit[] = [];
  for (const f of files) {
    const stem = basename(f).replace(/\.(log|jsonl|txt)(\.\d+)?$/, '').toLowerCase();
    const hostFromFile = stem.includes('.') ? stem : null;
    const rl = createInterface({ input: createReadStream(f), crlfDelay: Infinity });
    for await (const line of rl) { const h = parseLogLine(line, hostFromFile); if (h) out.push(h); }
  }
  return out;
}

export interface Trial { agent: string; domain: string; task_id: string; start: number; end: number; answer: string; reported_urls: string[]; error: string }

export function parseCsv(text: string): Record<string, string>[] {
  const rows: string[][] = []; let row: string[] = []; let cell = ''; let q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) { if (ch === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += ch; }
    else if (ch === '"') q = true; else if (ch === ',') { row.push(cell); cell = ''; } else if (ch === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; } else if (ch !== '\r') cell += ch;
  }
  if (cell.length || row.length) { row.push(cell); rows.push(row); }
  const [h, ...body] = rows.filter((r) => r.length > 1 || r[0]);
  return body.map((r) => Object.fromEntries(h.map((k, i) => [k.trim(), r[i] ?? ''])));
}

export function readTrials(text: string): Trial[] {
  return parseCsv(text).filter((r) => r.agent && r.domain).map((r) => ({ agent: r.agent.trim(), domain: r.domain.trim().toLowerCase(), task_id: r.task_id.trim(), start: Date.parse(r.start_utc), end: Date.parse(r.end_utc), answer: r.answer ?? '', reported_urls: (r.reported_urls ?? '').split(/\s+/).filter(Boolean), error: r.error ?? '' }));
}

const norm = (s: string) => s.toLowerCase().replace(/[\s_\-]+/g, ' ').trim();

/** Does the answer contain any of the domain's tokens (separator- and case-insensitive)? Control domains have none, so this is always false for them. */
export function answerHasCanary(answer: string, tokens: Record<ArtifactKey, string> | null): ArtifactKey[] {
  if (!tokens) return [];
  const a = norm(answer);
  return ARTIFACT_KEYS.filter((k) => a.includes(norm(tokens[k])));
}

export interface TrialResult extends Trial { cell: string; fetched: Record<ArtifactKey, boolean>; fetched_any: boolean; /** the agent's own tool trace names an artifact URL on this domain (log-independent signal) */ reported_artifact: boolean; canary_in_answer: ArtifactKey[]; hits: { path: string; ua: string; status: number }[] }

export function scoreTrials(m: Manifest, trials: Trial[], hits: LogHit[], slackMs = 60_000): TrialResult[] {
  const byDomain = new Map(m.domains.map((d) => [d.domain, d]));
  return trials.map((t) => {
    const d = byDomain.get(t.domain);
    const inWin = hits.filter((h) => (h.host === null || h.host === t.domain || h.host === `www.${t.domain}`) && h.ts >= t.start - slackMs && h.ts <= t.end + slackMs);
    const fetched = Object.fromEntries(ARTIFACT_KEYS.map((k) => [k, inWin.some((h) => ARTIFACT_PATHS[k].includes(h.path))])) as Record<ArtifactKey, boolean>;
    const art = inWin.filter((h) => ARTIFACT_KEYS.some((k) => ARTIFACT_PATHS[k].includes(h.path)));
    const allPaths = ARTIFACT_KEYS.flatMap((k) => ARTIFACT_PATHS[k]);
    const reported_artifact = t.reported_urls.some((u) => { try { const x = new URL(u); return (x.hostname === t.domain || x.hostname === `www.${t.domain}`) && allPaths.includes(x.pathname); } catch { return false; } });
    return { ...t, cell: d?.cell_label ?? 'unknown', fetched, fetched_any: Object.values(fetched).some(Boolean), reported_artifact, canary_in_answer: answerHasCanary(t.answer, d?.tokens ?? null), hits: art.map((h) => ({ path: h.path, ua: h.ua, status: h.status })) };
  });
}

/** Domain-clustered bootstrap percentile interval for a proportion over trials. */
export function clusteredCI(rows: { domain: string; v: boolean }[], reps = 2000, seed = 1): [number, number] | null {
  const groups = new Map<string, boolean[]>();
  for (const r of rows) (groups.get(r.domain) ?? groups.set(r.domain, []).get(r.domain)!).push(r.v);
  const G = [...groups.values()]; if (G.length < 2) return null;
  const rnd = mulberry32(seed); const est: number[] = [];
  for (let i = 0; i < reps; i++) { let k = 0, n = 0; for (let j = 0; j < G.length; j++) { const g = G[Math.floor(rnd() * G.length)]; n += g.length; k += g.filter(Boolean).length; } est.push(n ? k / n : 0); }
  est.sort((a, b) => a - b);
  return [est[Math.floor(0.025 * reps)], est[Math.min(reps - 1, Math.floor(0.975 * reps))]];
}

/** Trials on the same domain whose windows overlap cannot be told apart in the server log; the protocol runs one trial per domain at a time. */
export function overlappingWindows(trials: Trial[], slackMs = 60_000): [Trial, Trial][] {
  const out: [Trial, Trial][] = [];
  const byDom = new Map<string, Trial[]>();
  for (const t of trials) (byDom.get(t.domain) ?? byDom.set(t.domain, []).get(t.domain)!).push(t);
  for (const ts of byDom.values()) for (let i = 0; i < ts.length; i++) for (let j = i + 1; j < ts.length; j++) if (ts[i].start - slackMs <= ts[j].end + slackMs && ts[j].start - slackMs <= ts[i].end + slackMs) out.push([ts[i], ts[j]]);
  return out;
}

export interface AgentRow { agent: string; n: number; errors: number; fetched_llms: number; fetched_card: number; fetched_any: number; reported_artifact: number; canary: number; ci_fetched_any: [number, number] | null; ci_canary: [number, number] | null; by_cell: Record<string, { n: number; fetched_any: number; canary: number }>; by_task: Record<string, { n: number; fetched_any: number; canary: number }>; false_positive_controls: number }

export function tabulate(results: TrialResult[]): AgentRow[] {
  const agents = [...new Set(results.map((r) => r.agent))].sort();
  return agents.map((agent) => {
    const all = results.filter((r) => r.agent === agent);
    const R = all.filter((r) => !r.error); // errored API calls are not trials: no answer, no fetch
    const cnt = (f: (r: TrialResult) => boolean) => R.filter(f).length;
    const canaryDomains = R.filter((r) => r.cell.endsWith('/canary'));
    const group = (key: (r: TrialResult) => string) => { const o: Record<string, { n: number; fetched_any: number; canary: number }> = {}; for (const r of R) { const k = key(r); (o[k] ??= { n: 0, fetched_any: 0, canary: 0 }); o[k].n++; if (r.fetched_any) o[k].fetched_any++; if (r.canary_in_answer.length) o[k].canary++; } return o; };
    return {
      agent, n: R.length, errors: all.length - R.length, reported_artifact: cnt((r) => r.reported_artifact),
      fetched_llms: cnt((r) => r.fetched.llms), fetched_card: cnt((r) => r.fetched.card), fetched_any: cnt((r) => r.fetched_any),
      canary: canaryDomains.filter((r) => r.canary_in_answer.length).length,
      ci_fetched_any: clusteredCI(R.map((r) => ({ domain: r.domain, v: r.fetched_any }))),
      ci_canary: clusteredCI(canaryDomains.map((r) => ({ domain: r.domain, v: r.canary_in_answer.length > 0 }))),
      by_cell: group((r) => r.cell), by_task: group((r) => r.task_id),
      false_positive_controls: R.filter((r) => r.cell.endsWith('/control') && r.canary_in_answer.length).length,
    };
  });
}

/** Artifact-path hits outside every trial window (scanner noise the windows exclude) and the user agents seen inside windows. */
export function hitContext(trials: Trial[], hits: LogHit[], slackMs = 60_000): { background: number; background_ua: Record<string, number>; in_window_ua: Record<string, number> } {
  const allPaths = ARTIFACT_KEYS.flatMap((k) => ARTIFACT_PATHS[k]);
  const art = hits.filter((h) => allPaths.includes(h.path));
  const inWin = (h: LogHit) => trials.some((t) => (h.host === null || h.host === t.domain || h.host === `www.${t.domain}`) && h.ts >= t.start - slackMs && h.ts <= t.end + slackMs);
  const bg: Record<string, number> = {}, iw: Record<string, number> = {};
  const key = (ua: string) => ua.replace(/\/[\d.]+.*$/, '').slice(0, 60) || '(none)';
  let background = 0;
  for (const h of art) { if (inWin(h)) iw[key(h.ua)] = (iw[key(h.ua)] ?? 0) + 1; else { background++; bg[key(h.ua)] = (bg[key(h.ua)] ?? 0) + 1; } }
  return { background, background_ua: bg, in_window_ua: iw };
}

export function renderTable(rows: AgentRow[]): string {
  const pct = (k: number, n: number) => (n ? `${((100 * k) / n).toFixed(0)}%` : 'n/a');
  const ci = (c: [number, number] | null) => (c ? ` [${(100 * c[0]).toFixed(0)}, ${(100 * c[1]).toFixed(0)}]` : '');
  const L = ['agent'.padEnd(22) + 'trials'.padStart(7) + 'llms.txt'.padStart(10) + 'card'.padStart(7) + 'any artifact (log)'.padStart(22) + 'reported (trace)'.padStart(17) + 'canary in answer'.padStart(26)];
  for (const r of rows) {
    const nCanary = Object.entries(r.by_cell).filter(([k]) => k.endsWith('/canary')).reduce((a, [, v]) => a + v.n, 0);
    L.push(r.agent.padEnd(22) + String(r.n).padStart(7) + pct(r.fetched_llms, r.n).padStart(10) + pct(r.fetched_card, r.n).padStart(7) + (pct(r.fetched_any, r.n) + ci(r.ci_fetched_any)).padStart(22) + pct(r.reported_artifact, r.n).padStart(17) + (pct(r.canary, nCanary) + ci(r.ci_canary)).padStart(26) + (r.errors ? `  (${r.errors} errored)` : ''));
    for (const [cell, v] of Object.entries(r.by_cell).sort()) L.push('  ' + cell.padEnd(20) + String(v.n).padStart(7) + ''.padStart(17) + pct(v.fetched_any, v.n).padStart(22) + ''.padStart(17) + (cell.endsWith('/canary') ? pct(v.canary, v.n) : '—').padStart(26));
    for (const [task, v] of Object.entries(r.by_task).sort()) L.push('  ' + task.padEnd(20) + String(v.n).padStart(7) + ''.padStart(17) + pct(v.fetched_any, v.n).padStart(22) + ''.padStart(17) + pct(v.canary, v.n).padStart(26));
    if (r.false_positive_controls) L.push(`  ! ${r.false_positive_controls} control-domain answer(s) matched a token — check the trials sheet`);
  }
  return L.join('\n') + '\n';
}

// ---------- CLI ----------

function arg(name: string): string | undefined { const i = process.argv.indexOf(`--${name}`); return i >= 0 ? process.argv[i + 1] : undefined; }
function args(name: string): string[] { const i = process.argv.indexOf(`--${name}`); const out: string[] = []; if (i < 0) return out; for (let j = i + 1; j < process.argv.length && !process.argv[j].startsWith('--'); j++) out.push(process.argv[j]); return out; }

async function main() {
  const cmd = process.argv[2];
  if (cmd === 'plan') {
    const file = arg('domains'); const out = arg('out') ?? 'canary';
    if (!file || !existsSync(file)) { console.error('usage: kit.ts plan --domains FILE --out DIR [--seed N] (CRAWLER_CONTACT_EMAIL / CRAWLER_CONTACT_URL go on the pages)'); process.exit(2); }
    const email = process.env.CRAWLER_CONTACT_EMAIL, url = process.env.CRAWLER_CONTACT_URL;
    if (!email || !url) { console.error('set CRAWLER_CONTACT_EMAIL and CRAWLER_CONTACT_URL (they are printed on every canary page)'); process.exit(2); }
    const domains = readFileSync(file, 'utf8').split(/\r?\n/).map((l) => l.replace(/#.*/, '').trim()).filter(Boolean);
    const m = plan(domains, Number(arg('seed') ?? 20261108));
    const written = writePlan(m, out, { email, url });
    const cells: Record<string, number> = {}; for (const d of m.domains) cells[d.cell_label] = (cells[d.cell_label] ?? 0) + 1;
    console.error(`${m.domains.length} domains -> ${Object.entries(cells).map(([k, v]) => `${k} ${v}`).join(', ')}; ${written.length} files under ${out}/ (manifest.json is the key: keep it out of the public sites)`);
    return;
  }
  if (cmd === 'analyze') {
    const mf = arg('manifest'), tf = arg('trials'), logs = args('logs'), out = arg('out');
    if (!mf || !tf) { console.error('usage: kit.ts analyze --manifest canary/manifest.json --trials canary/trials.csv --logs LOG... [--agents openai,anthropic] [--out results.json] [--slack-ms 60000]'); process.exit(2); }
    const m = JSON.parse(readFileSync(mf, 'utf8')) as Manifest;
    const only = arg('agents')?.split(',').map((x) => x.trim()).filter(Boolean);
    const trials = readTrials(readFileSync(tf, 'utf8')).filter((t) => !only || only.includes(t.agent));
    const hits = await readLogs(logs);
    const slack = Number(arg('slack-ms') ?? 60_000);
    const ov = overlappingWindows(trials, slack);
    if (ov.length) console.error(`warning: ${ov.length} pair(s) of trials on the same domain have overlapping windows (incl. ${slack / 1000}s slack) and cannot be separated in the log, e.g. ${ov[0][0].agent}/${ov[0][0].task_id} vs ${ov[0][1].agent}/${ov[0][1].task_id} on ${ov[0][0].domain}`);
    const results = scoreTrials(m, trials, hits, slack);
    const rows = tabulate(results);
    process.stdout.write(renderTable(rows));
    const ctx = hitContext(trials.filter((t) => !t.error), hits, slack);
    const top = (o: Record<string, number>) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => `${k} ${v}`).join('; ') || 'none';
    process.stdout.write(`\nartifact fetches inside trial windows, by user agent: ${top(ctx.in_window_ua)}\nartifact fetches outside every window (background, excluded): ${ctx.background} — ${top(ctx.background_ua)}\n`);
    console.error(`${trials.length} trials, ${hits.length} log lines, ${results.filter((r) => r.hits.length).length} trials with an artifact fetch in window`);
    if (out) { mkdirSync(dirname(out), { recursive: true }); writeFileSync(out, JSON.stringify({ agents: rows, trials: results }, null, 2) + '\n'); console.error(`-> ${out}`); }
    return;
  }
  console.error('usage: kit.ts plan|analyze ...'); process.exit(2);
}

const isMain = process.argv[1] && /canary[\\/]kit\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
