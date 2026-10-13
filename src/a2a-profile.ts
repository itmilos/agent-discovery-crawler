#!/usr/bin/env node
// A2A agent-card profile and A2UI discoverability (paper §4.2 / §5.1, "A2A and A2UI"):
//   npm run a2a:profile -- --in out/registry-local.jsonl out/tranco-*-local.jsonl ... --out out/a2a-profile.jsonl
//   npm run a2a:profile -- --in ... --dry-run     # count hosts, fetch nothing
//
// The crawl records whether /.well-known/agent-card.json (A2A >= 0.3) or the
// legacy /.well-known/agent.json validates, and hygiene checks the endpoint.
// This pass re-fetches every valid card and profiles what it declares:
//  - protocolVersion and spec generation (v1.0 `supportedInterfaces[]` vs 0.2/0.3 `url` + `preferredTransport`)
//  - transports / protocol bindings advertised
//  - capabilities: streaming, pushNotifications, stateTransitionHistory, extended card
//  - security: securitySchemes types (none / apiKey / http bearer / oauth2 / openIdConnect / mutualTLS) and whether `security` requires any
//  - skills: count, tags, input/output media types
//  - extensions: every `capabilities.extensions[].uri`, with A2UI picked out
//    (A2UI is not a separate discovery file: an agent advertises it as an A2A
//    extension, URI `https://a2ui.org/a2a-extension/a2ui/<version>`, and
//    renders UI through DataParts with mimeType `application/json+a2ui`;
//    we also count cards whose output modes list that media type)
//  - signatures (JWS-signed cards), provider, documentationUrl, iconUrl
//  - whether the same body is served at both paths, and whether it is a
//    copy of a published example (fingerprinted by a few well-known names)
import { createReadStream, createWriteStream, existsSync, mkdirSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname } from 'node:path';
import pLimit from 'p-limit';
import { bodyText, fetchUrl, hostLimiter, setGlobalRps, type FetchResult } from './http.js';
import { contactPreflight } from './run.js';
import { A2A_CARD_ARTIFACTS, type HostResult } from './types.js';

export const A2UI_EXTENSION_PREFIX = 'https://a2ui.org/a2a-extension/a2ui/';
export const A2UI_MIME = 'application/json+a2ui';

export interface A2ACandidate { host: string; rank: number | null; source: string; card_url: string; card_artifact: string; alt_url: string | null }

export function selectA2A(r: HostResult, source: string): A2ACandidate | null {
  const cards = r.probes.filter((p) => p.valid && (A2A_CARD_ARTIFACTS as string[]).includes(p.artifact));
  if (!cards.length) return null;
  return { host: r.host, rank: r.rank ?? null, source, card_url: cards[0].final_url, card_artifact: cards[0].artifact, alt_url: cards[1]?.final_url ?? null };
}

export async function readA2ACandidates(files: string[]): Promise<A2ACandidate[]> {
  const out: A2ACandidate[] = []; const seen = new Set<string>();
  for (const f of files) {
    if (!existsSync(f)) throw new Error(`${f} not found`);
    const rl = createInterface({ input: createReadStream(f), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      let r: HostResult; try { r = JSON.parse(line); } catch { continue; }
      if (!r?.host || seen.has(r.host)) continue;
      const c = selectA2A(r, f.replace(/^.*\//, '').replace(/\.jsonl$/, ''));
      if (c) { seen.add(r.host); out.push(c); }
    }
  }
  return out;
}

export interface A2AProfile {
  protocol_version: string | null;
  /** 'v1' = supportedInterfaces[] present; 'v03' = url + preferredTransport; 'legacy' = url only; 'unknown' */
  generation: 'v1' | 'v03' | 'legacy' | 'unknown';
  transports: string[];
  endpoint_urls: string[];
  streaming: boolean | null; push_notifications: boolean | null; state_transition_history: boolean | null; extended_card: boolean | null;
  security_scheme_types: string[]; // e.g. ["http:bearer","apiKey","oauth2"]
  security_required: boolean; // `security` non-empty
  skills: number; skill_tags: string[];
  input_modes: string[]; output_modes: string[];
  extensions: { uri: string; required: boolean }[];
  a2ui: { declared: boolean; versions: string[]; via_output_mode: boolean; required: boolean; catalogs: string[] };
  signed: boolean; provider: string | null; has_docs_url: boolean; has_icon: boolean;
  example_copy: string | null; // name of a published sample this card appears to be a copy of
}

const str = (x: unknown): string | null => (typeof x === 'string' && x.trim() ? x.trim() : null);
const bool = (x: unknown): boolean | null => (typeof x === 'boolean' ? x : null);
const arr = (x: unknown): unknown[] => (Array.isArray(x) ? x : []);
const obj = (x: unknown): Record<string, unknown> => (x && typeof x === 'object' && !Array.isArray(x) ? (x as Record<string, unknown>) : {});

const EXAMPLE_NAMES: [RegExp, string][] = [
  [/^hello ?world agent$/i, 'a2a-samples helloworld'], [/^currency ?agent$/i, 'a2a-samples currency'], [/^weather ?agent$/i, 'a2a-samples weather'],
  [/^(google ?maps|maps) agent$/i, 'a2a-samples maps'], [/^expense ?reimbursement agent$/i, 'a2a-samples reimbursement'], [/^dice agent$/i, 'a2a-samples dice'],
];

export function profileA2A(card: unknown): A2AProfile {
  const c = obj(card); const caps = obj(c.capabilities);
  const ifaces = arr(c.supportedInterfaces ?? c.additionalInterfaces).map(obj);
  const transports = new Set<string>(); const urls = new Set<string>();
  for (const i of ifaces) { const t = str(i.protocolBinding ?? i.transport); if (t) transports.add(t.toUpperCase()); const u = str(i.url); if (u) urls.add(u); }
  const pt = str(c.preferredTransport); if (pt) transports.add(pt.toUpperCase());
  const url = str(c.url); if (url) urls.add(url);
  const generation: A2AProfile['generation'] = Array.isArray(c.supportedInterfaces) ? 'v1' : pt ? 'v03' : url ? 'legacy' : 'unknown';
  if (generation !== 'v1' && !transports.size && url) transports.add('JSONRPC'); // 0.2/0.3 default
  const schemes = obj(c.securitySchemes);
  const schemeTypes = Object.values(schemes).map(obj).map((s) => { const t = str(s.type) ?? 'unknown'; const sub = str(s.scheme); return t === 'http' && sub ? `http:${sub.toLowerCase()}` : t; });
  const skills = arr(c.skills).map(obj);
  const tags = [...new Set(skills.flatMap((s) => arr(s.tags).map(String)))];
  const inModes = [...new Set([...arr(c.defaultInputModes).map(String), ...skills.flatMap((s) => arr(s.inputModes).map(String))])];
  const outModes = [...new Set([...arr(c.defaultOutputModes).map(String), ...skills.flatMap((s) => arr(s.outputModes).map(String))])];
  const exts = arr(caps.extensions).map(obj).map((e) => ({ uri: str(e.uri) ?? '', required: e.required === true, params: obj(e.params) })).filter((e) => e.uri);
  const a2uiExts = exts.filter((e) => e.uri.startsWith(A2UI_EXTENSION_PREFIX) || /a2ui\.org/i.test(e.uri));
  const viaMode = outModes.some((m) => m.toLowerCase() === A2UI_MIME);
  const name = str(c.name) ?? '';
  const example = EXAMPLE_NAMES.find(([re]) => re.test(name))?.[1] ?? null;
  return {
    protocol_version: str(c.protocolVersion), generation, transports: [...transports].sort(), endpoint_urls: [...urls],
    streaming: bool(caps.streaming), push_notifications: bool(caps.pushNotifications), state_transition_history: bool(caps.stateTransitionHistory),
    extended_card: bool(caps.extendedAgentCard ?? c.supportsAuthenticatedExtendedCard),
    security_scheme_types: [...new Set(schemeTypes)].sort(), security_required: arr(c.security).length > 0,
    skills: skills.length, skill_tags: tags.slice(0, 20), input_modes: inModes, output_modes: outModes,
    extensions: exts.map(({ uri, required }) => ({ uri, required })),
    a2ui: { declared: a2uiExts.length > 0 || viaMode, versions: [...new Set(a2uiExts.map((e) => e.uri.replace(A2UI_EXTENSION_PREFIX, '').replace(/\/.*$/, '')))], via_output_mode: viaMode, required: a2uiExts.some((e) => e.required), catalogs: [...new Set(a2uiExts.flatMap((e) => arr(e.params.supportedCatalogIds).map(String)))] },
    signed: arr(c.signatures).length > 0, provider: str(obj(c.provider).organization) ?? null, has_docs_url: !!str(c.documentationUrl), has_icon: !!str(c.iconUrl),
    example_copy: example,
  };
}

export interface A2ARow extends A2ACandidate { ts: string; status: number | null; error?: string; sha256: string | null; alt_same_body: boolean | null; profile: A2AProfile | null }

async function get(url: string, timeoutMs: number): Promise<FetchResult> { await hostLimiter(new URL(url).hostname).wait(); return fetchUrl(url, { timeoutMs, accept: 'application/json, */*;q=0.5' }); }

export async function checkA2A(c: A2ACandidate, opts: { timeoutMs: number; fetch?: typeof get } = { timeoutMs: 10_000 }): Promise<A2ARow> {
  const f = opts.fetch ?? get;
  const row: A2ARow = { ...c, ts: new Date().toISOString(), status: null, sha256: null, alt_same_body: null, profile: null };
  const r = await f(c.card_url, opts.timeoutMs);
  row.status = r.status; if (r.error) row.error = r.error;
  if (r.status === 200) {
    row.sha256 = r.sha256;
    let card: unknown = null; try { card = JSON.parse(bodyText(r).replace(/^﻿/, '')); } catch { row.error = 'unparseable'; }
    if (card && typeof card === 'object') row.profile = profileA2A(card);
    if (c.alt_url) { const a = await f(c.alt_url, opts.timeoutMs); row.alt_same_body = a.status === 200 ? a.sha256 === r.sha256 : null; }
  }
  return row;
}

export function summarizeA2A(rows: A2ARow[]): string {
  const ok = rows.filter((r) => r.profile); const P = ok.map((r) => r.profile!);
  const n = P.length; const pct = (k: number) => (n ? `${k} (${((100 * k) / n).toFixed(1)}%)` : '0');
  const count = <T,>(xs: T[]) => { const m = new Map<T, number>(); for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1); return [...m.entries()].sort((a, b) => b[1] - a[1]); };
  const top = <T,>(xs: T[], k = 8) => count(xs).slice(0, k).map(([v, c]) => `${String(v)} ${c}`).join(', ') || 'none';
  const L: string[] = [];
  L.push(`A2A cards: ${rows.length} hosts with a valid card in the crawl; re-fetched and parsed: ${n}; both paths served the same body: ${rows.filter((r) => r.alt_same_body === true).length} of ${rows.filter((r) => r.alt_url).length} with two valid paths`);
  L.push(`spec generation: ${top(P.map((p) => p.generation))}; protocolVersion: ${top(P.map((p) => p.protocol_version ?? '(absent)'))}`);
  L.push(`transports: ${top(P.flatMap((p) => (p.transports.length ? p.transports : ['(none)'])))}`);
  L.push(`capabilities: streaming ${pct(P.filter((p) => p.streaming).length)}, pushNotifications ${pct(P.filter((p) => p.push_notifications).length)}, extended card ${pct(P.filter((p) => p.extended_card).length)}`);
  L.push(`security: no securitySchemes ${pct(P.filter((p) => !p.security_scheme_types.length).length)}; schemes declared: ${top(P.flatMap((p) => p.security_scheme_types))}; security requirement set: ${pct(P.filter((p) => p.security_required).length)}`);
  const sk = P.map((p) => p.skills).sort((a, b) => a - b);
  L.push(`skills per card: median ${sk.length ? sk[sk.length >> 1] : 'n/a'}, zero skills ${pct(P.filter((p) => !p.skills).length)}; top tags: ${top(P.flatMap((p) => p.skill_tags))}`);
  L.push(`output modes: ${top(P.flatMap((p) => p.output_modes))}`);
  L.push(`extensions declared: ${pct(P.filter((p) => p.extensions.length).length)}; URIs: ${top(P.flatMap((p) => p.extensions.map((e) => e.uri)))}`);
  const a2ui = P.filter((p) => p.a2ui.declared);
  L.push(`A2UI: ${pct(a2ui.length)} cards advertise it (extension ${P.filter((p) => p.a2ui.versions.length).length}, output mode ${P.filter((p) => p.a2ui.via_output_mode).length}, marked required ${P.filter((p) => p.a2ui.required).length}); versions: ${top(a2ui.flatMap((p) => p.a2ui.versions))}; catalogs: ${top(a2ui.flatMap((p) => p.a2ui.catalogs))}`);
  L.push(`signed cards: ${pct(P.filter((p) => p.signed).length)}; provider set: ${pct(P.filter((p) => p.provider).length)}; documentationUrl: ${pct(P.filter((p) => p.has_docs_url).length)}; copies of published samples: ${pct(P.filter((p) => p.example_copy).length)} (${top(P.map((p) => p.example_copy).filter(Boolean))})`);
  const errs = rows.filter((r) => r.error || (r.status !== null && r.status !== 200)).length;
  if (errs) L.push(`re-fetch failed or non-200: ${errs}`);
  return L.join('\n') + '\n';
}

function arg(name: string): string | undefined { const i = process.argv.indexOf(`--${name}`); return i >= 0 ? process.argv[i + 1] : undefined; }
function args(name: string): string[] { const i = process.argv.indexOf(`--${name}`); const out: string[] = []; if (i < 0) return out; for (let j = i + 1; j < process.argv.length && !process.argv[j].startsWith('--'); j++) out.push(process.argv[j]); return out; }

async function readDone(path: string): Promise<Map<string, A2ARow>> {
  const m = new Map<string, A2ARow>(); if (!existsSync(path)) return m;
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of rl) { if (!line.trim()) continue; try { const r = JSON.parse(line) as A2ARow; if (r?.host) m.set(r.host, r); } catch { /* partial */ } }
  return m;
}

async function main() {
  const inputs = args('in'); const out = arg('out'); const dry = process.argv.includes('--dry-run');
  if (!inputs.length || (!out && !dry)) { console.error('usage: a2a-profile.ts --in RESULTS.jsonl [MORE...] --out a2a-profile.jsonl [--rps 1] [--concurrency 10] [--timeout-ms 10000] [--dry-run]'); process.exit(2); }
  const cands = await readA2ACandidates(inputs);
  console.error(`${cands.length} hosts with a valid A2A card (${cands.filter((c) => c.alt_url).length} valid at both paths)`);
  if (dry) { for (const c of cands) console.log(`${c.host}\t${c.card_artifact}\t${c.card_url}`); return; }
  const contact = contactPreflight(cands.map((c) => c.host)); if (contact) { console.error(contact); process.exit(2); }
  const done = await readDone(out!); const todo = cands.filter((c) => !done.has(c.host));
  console.error(`resuming: ${done.size} done, ${todo.length} to fetch`);
  setGlobalRps(Number(arg('rps') ?? 1)); const limit = pLimit(Number(arg('concurrency') ?? 10)); const timeoutMs = Number(arg('timeout-ms') ?? 10_000);
  mkdirSync(dirname(out!), { recursive: true }); const ws = createWriteStream(out!, { flags: 'a' }); let k = 0;
  await Promise.all(todo.map((c) => limit(async () => { const r = await checkA2A(c, { timeoutMs }); done.set(c.host, r); ws.write(JSON.stringify(r) + '\n'); if (++k % 50 === 0) console.error(`  ${k}/${todo.length}`); })));
  await new Promise((res) => ws.end(res));
  process.stdout.write(summarizeA2A([...done.values()]));
}

const isMain = process.argv[1] && /a2a-profile\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
