#!/usr/bin/env node
// Canary trial runner (paper §4.6 RQ3): put each task prompt to each agent
// product through its vendor API with the vendor's own web tools enabled, and
// append one row per trial to trials.csv with exact UTC start/end stamps, the
// answer text, and the URLs the agent's own tool trace says it opened.
//
//   OPENAI_API_KEY=... ANTHROPIC_API_KEY=... GEMINI_API_KEY=... \
//   npm run canary:run -- --manifest canary/manifest.json --tasks canary/tasks.csv --out canary/trials.csv [--agents openai,anthropic,gemini] [--parallel-domains 5] [--gap-ms 150000] [--limit N] [--dry-run]
//
// Keys come from the environment only; never put them on the command line or
// in a file in the repo. Models default to the vendors' current general
// models and can be overridden with OPENAI_MODEL / ANTHROPIC_MODEL /
// GEMINI_MODEL (vendors rename them; a 404 on the first call means set one).
//
// Scheduling: trials on the same domain run strictly one after another with a
// gap (default 150 s, > 2x the analyzer's 60 s slack) so that server-log
// windows never overlap; different domains run in parallel. Resumable: rows
// already in the output file are skipped.
import { appendFileSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseCsv, TRIALS_HEADER, type Manifest } from './kit.js';

export type AgentId = 'openai' | 'anthropic' | 'gemini';
export const AGENT_IDS: AgentId[] = ['openai', 'anthropic', 'gemini'];
export const TRIALS_HEADER_V2 = TRIALS_HEADER; // one header, shared with kit.ts plan (which pre-creates trials.csv)
const TRIALS_HEADER_V1 = 'agent,domain,task_id,start_utc,end_utc,answer'; // written by plan before 0.6.4; rows always had the three extra cells

/// Rewrite a trials.csv whose header is the old six-column one so the parser sees model, reported_urls and error (otherwise errored rows count as done and are never retried).
export function upgradeTrialsHeader(text: string): string {
  const nl = text.indexOf('\n'); const first = (nl < 0 ? text : text.slice(0, nl)).trim();
  return first === TRIALS_HEADER_V1 ? TRIALS_HEADER + (nl < 0 ? '\n' : text.slice(nl)) : text;
}

export interface AgentResult { answer: string; reportedUrls: string[]; model: string; error?: string; raw?: unknown }

const SYSTEM = 'You are a helpful assistant with web access. Use your web tools to look things up when a question is about a specific website. Answer concisely.';

// ---------- response parsing (pure; tested) ----------

export function parseOpenAI(j: unknown): { answer: string; urls: string[] } {
  const o = j as { output?: { type: string; content?: { type: string; text?: string }[]; action?: { type?: string; url?: string; query?: string } }[]; output_text?: string };
  const texts: string[] = []; const urls: string[] = [];
  for (const it of o.output ?? []) {
    if (it.type === 'message') for (const c of it.content ?? []) if (c.type === 'output_text' && c.text) texts.push(c.text);
    if (it.type === 'web_search_call' && it.action?.url) urls.push(it.action.url);
  }
  return { answer: o.output_text ?? texts.join('\n'), urls: [...new Set(urls)] };
}

export function parseAnthropic(j: unknown): { answer: string; urls: string[] } {
  const o = j as { content?: { type: string; text?: string; name?: string; input?: { url?: string; query?: string }; content?: { type?: string; url?: string } | { type?: string; url?: string }[] }[] };
  const texts: string[] = []; const urls: string[] = [];
  for (const b of o.content ?? []) {
    if (b.type === 'text' && b.text) texts.push(b.text);
    if (b.type === 'server_tool_use' && b.input?.url) urls.push(b.input.url);
    if (b.type === 'web_fetch_tool_result' && b.content && !Array.isArray(b.content) && b.content.url) urls.push(b.content.url);
    if (b.type === 'web_search_tool_result' && Array.isArray(b.content)) for (const r of b.content) if (r.url) urls.push(r.url);
  }
  return { answer: texts.join('\n'), urls: [...new Set(urls)] };
}

export function parseGemini(j: unknown): { answer: string; urls: string[] } {
  const o = j as { candidates?: { content?: { parts?: { text?: string }[] }; url_context_metadata?: { url_metadata?: { retrieved_url?: string }[] }; urlContextMetadata?: { urlMetadata?: { retrievedUrl?: string }[] }; grounding_metadata?: { grounding_chunks?: { web?: { uri?: string } }[] }; groundingMetadata?: { groundingChunks?: { web?: { uri?: string } }[] } }[] };
  const c = o.candidates?.[0];
  const answer = (c?.content?.parts ?? []).map((p) => p.text ?? '').join('');
  const urls: string[] = [];
  for (const m of c?.url_context_metadata?.url_metadata ?? []) if (m.retrieved_url) urls.push(m.retrieved_url);
  for (const m of c?.urlContextMetadata?.urlMetadata ?? []) if (m.retrievedUrl) urls.push(m.retrievedUrl);
  for (const g of c?.grounding_metadata?.grounding_chunks ?? []) if (g.web?.uri) urls.push(g.web.uri);
  for (const g of c?.groundingMetadata?.groundingChunks ?? []) if (g.web?.uri) urls.push(g.web.uri);
  return { answer, urls: [...new Set(urls)] };
}

// ---------- vendor calls ----------

async function post(url: string, headers: Record<string, string>, body: unknown, timeoutMs: number): Promise<unknown> {
  const ac = new AbortController(); const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body), signal: ac.signal });
    const text = await r.text();
    let j: unknown; try { j = JSON.parse(text); } catch { j = { raw: text }; }
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${text.slice(0, 300)}`);
    return j;
  } finally { clearTimeout(t); }
}

export async function askOpenAI(prompt: string, timeoutMs: number): Promise<AgentResult> {
  const key = process.env.OPENAI_API_KEY; const model = process.env.OPENAI_MODEL ?? 'gpt-5';
  if (!key) return { answer: '', reportedUrls: [], model, error: 'OPENAI_API_KEY not set' };
  const j = await post('https://api.openai.com/v1/responses', { authorization: `Bearer ${key}` }, { model, instructions: SYSTEM, input: prompt, tools: [{ type: 'web_search' }], tool_choice: 'auto', store: false }, timeoutMs);
  const p = parseOpenAI(j); return { ...p, reportedUrls: p.urls, model, raw: j };
}

export async function askAnthropic(prompt: string, timeoutMs: number): Promise<AgentResult> {
  const key = process.env.ANTHROPIC_API_KEY; const model = process.env.ANTHROPIC_MODEL ?? 'claude-sonnet-4-5';
  if (!key) return { answer: '', reportedUrls: [], model, error: 'ANTHROPIC_API_KEY not set' };
  const j = await post('https://api.anthropic.com/v1/messages', { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'anthropic-beta': 'web-fetch-2025-09-10' },
    { model, max_tokens: 1500, system: SYSTEM, messages: [{ role: 'user', content: prompt }], tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 8 }, { type: 'web_fetch_20250910', name: 'web_fetch', max_uses: 8 }] }, timeoutMs);
  const p = parseAnthropic(j); return { ...p, reportedUrls: p.urls, model, raw: j };
}

export async function askGemini(prompt: string, timeoutMs: number): Promise<AgentResult> {
  const key = process.env.GEMINI_API_KEY; const model = process.env.GEMINI_MODEL ?? 'gemini-3.1-pro-preview';
  if (!key) return { answer: '', reportedUrls: [], model, error: 'GEMINI_API_KEY not set' };
  const j = await post(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, { 'x-goog-api-key': key },
    { system_instruction: { parts: [{ text: SYSTEM }] }, contents: [{ role: 'user', parts: [{ text: prompt }] }], tools: [{ google_search: {} }, { url_context: {} }] }, timeoutMs);
  const p = parseGemini(j); return { ...p, reportedUrls: p.urls, model, raw: j };
}

export const ASK: Record<AgentId, (prompt: string, timeoutMs: number) => Promise<AgentResult>> = { openai: askOpenAI, anthropic: askAnthropic, gemini: askGemini };

// ---------- trial loop ----------

export interface TaskRow { domain: string; task_id: string; prompt: string }

export function csvRow(cells: string[]): string { return cells.map((s) => (/[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s)).join(',') + '\n'; }

export function doneKeys(csvText: string): Set<string> {
  return new Set(parseCsv(csvText).filter((r) => r.agent && r.domain && r.task_id && !r.error).map((r) => `${r.agent}|${r.domain}|${r.task_id}`));
}

export interface RunOpts { agents: AgentId[]; gapMs: number; parallelDomains: number; timeoutMs: number; limit: number | null; dryRun: boolean; ask?: typeof ASK; now?: () => number; sleep?: (ms: number) => Promise<void> }

export async function runTrials(tasks: TaskRow[], out: string, done: Set<string>, o: RunOpts, log: (s: string) => void = (s) => console.error(s)): Promise<number> {
  const ask = o.ask ?? ASK; const now = o.now ?? Date.now; const sleep = o.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const byDomain = new Map<string, TaskRow[]>();
  for (const t of tasks) (byDomain.get(t.domain) ?? byDomain.set(t.domain, []).get(t.domain)!).push(t);
  const domains = [...byDomain.keys()];
  let written = 0, budget = o.limit ?? Infinity;
  const worker = async (domain: string) => {
    for (const t of byDomain.get(domain)!) for (const agent of o.agents) {
      const key = `${agent}|${domain}|${t.task_id}`;
      if (done.has(key)) continue;
      if (budget <= 0) return; budget--;
      if (o.dryRun) { log(`would run ${key}`); continue; }
      const start = new Date(now()).toISOString();
      let res: AgentResult;
      try { res = await ask[agent](t.prompt, o.timeoutMs); } catch (e) { res = { answer: '', reportedUrls: [], model: '', error: String(e instanceof Error ? e.message : e).slice(0, 300) }; }
      const end = new Date(now()).toISOString();
      appendFileSync(out, csvRow([agent, domain, t.task_id, start, end, res.answer, res.model, res.reportedUrls.join(' '), res.error ?? '']));
      written++; done.add(key);
      log(`${key} ${res.error ? 'ERROR ' + res.error : `${res.answer.length} chars, ${res.reportedUrls.length} urls`}`);
      await sleep(o.gapMs);
    }
  };
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(o.parallelDomains, domains.length) }, async () => { while (i < domains.length) await worker(domains[i++]); }));
  return written;
}

// ---------- CLI ----------

function arg(name: string): string | undefined { const i = process.argv.indexOf(`--${name}`); return i >= 0 ? process.argv[i + 1] : undefined; }

async function main() {
  const mf = arg('manifest'), tf = arg('tasks'), out = arg('out');
  if (!mf || !tf || !out) { console.error('usage: run.ts --manifest canary/manifest.json --tasks canary/tasks.csv --out canary/trials.csv [--agents openai,anthropic,gemini] [--parallel-domains 5] [--gap-ms 150000] [--timeout-ms 180000] [--limit N] [--dry-run]'); process.exit(2); }
  const m = JSON.parse(readFileSync(mf, 'utf8')) as Manifest;
  const known = new Set(m.domains.map((d) => d.domain));
  const tasks = parseCsv(readFileSync(tf, 'utf8')).filter((r) => known.has(r.domain)).map((r) => ({ domain: r.domain, task_id: r.task_id, prompt: r.prompt }));
  const agents = (arg('agents') ?? 'openai,anthropic,gemini').split(',').map((s) => s.trim()).filter((s): s is AgentId => (AGENT_IDS as string[]).includes(s));
  const dryRun = process.argv.includes('--dry-run');
  if (!dryRun) for (const a of agents) { const k = { openai: 'OPENAI_API_KEY', anthropic: 'ANTHROPIC_API_KEY', gemini: 'GEMINI_API_KEY' }[a]; if (!process.env[k]) { console.error(`${k} not set (export it in the shell; never pass keys on the command line)`); process.exit(2); } }
  mkdirSync(dirname(out), { recursive: true });
  if (!existsSync(out) || !readFileSync(out, 'utf8').trim()) writeFileSync(out, TRIALS_HEADER_V2 + '\n');
  else { const cur = readFileSync(out, 'utf8'); const up = upgradeTrialsHeader(cur); if (up !== cur) { writeFileSync(out, up); console.error(`${out}: upgraded six-column header to the nine-column one`); } }
  const done = doneKeys(readFileSync(out, 'utf8'));
  console.error(`${tasks.length} tasks x ${agents.length} agents = ${tasks.length * agents.length} trials; ${done.size} already done`);
  const n = await runTrials(tasks, out, done, { agents, gapMs: Number(arg('gap-ms') ?? 150_000), parallelDomains: Number(arg('parallel-domains') ?? 5), timeoutMs: Number(arg('timeout-ms') ?? 180_000), limit: arg('limit') ? Number(arg('limit')) : null, dryRun });
  console.error(`${n} trial rows appended to ${out}`);
}

const isMain = process.argv[1] && /canary[\\/]run\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
