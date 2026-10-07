// MCP `initialize` handshake probe (paper §4.6(e), ethics-reviewed wording).
//
// For MCP endpoints advertised in a valid card, and only those, we send ONE
// JSON-RPC `initialize` request without credentials. This is the step the MCP
// authorization specification tells clients to take before discovering
// metadata (the 401 + `WWW-Authenticate: Bearer resource_metadata=...`
// challenge, RFC 9728). We record the HTTP status, the WWW-Authenticate header
// and `serverInfo`, close any returned session with `DELETE`, and send nothing
// further. A 200 is classified as "no authorization challenge at handshake".
// We make no claim about whether tools can be invoked.
//
// Wire format verified 2026-10-06 against modelcontextprotocol.io:
//   - protocol version 2025-11-25 (the last revision that defines `initialize`,
//     `Mcp-Session-Id` and HTTP DELETE; revision 2026-07-28 removed the
//     handshake and protocol-level sessions, see README "Handshake probe").
//   - request: POST, body {"jsonrpc":"2.0","id":1,"method":"initialize",
//     "params":{"protocolVersion","capabilities":{},"clientInfo":{name,version}}}
//   - headers: Accept: application/json, text/event-stream (MUST);
//     MCP-Protocol-Version: 2025-11-25 (2025-11-25: on subsequent requests,
//     2026-07-28: on every POST; sending it on initialize is harmless);
//     Mcp-Method: initialize (2026-07-28 mirrored header; harmless to older servers).
//   - response: application/json (one object) or text/event-stream (first event
//     holds the InitializeResult); `Mcp-Session-Id` MAY be set on that response.
//   - termination: HTTP DELETE with `Mcp-Session-Id`; server MAY answer 405.
import { createReadStream, existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { CRAWLER_VERSION, bodyText, fetchUrl, mediaType, type FetchResult } from './http.js';
import { extractEndpoint } from './hygiene.js';
import { parseJson } from './validate.js';
import type { HostResult, HygieneEntry } from './types.js';

export const MCP_PROTOCOL_VERSION = '2025-11-25';
export const HANDSHAKE_CLIENT_NAME = 'AgentDiscoveryCrawler';

export const ETHICS_WORDING = `Paper §4.6 (ethics-reviewed): For MCP endpoints advertised in a valid card, and only those, we send one JSON-RPC \`initialize\` request without credentials. This is the step the MCP authorization specification tells clients to take before discovering metadata. We record the HTTP status, the \`WWW-Authenticate\` header and \`serverInfo\`, close any returned session with \`DELETE\`, and send nothing further. A 200 is classified as 'no authorization challenge at handshake'. We make no claim about whether tools can be invoked.`;

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

export function buildInitializeRequest(id = 1): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id,
    method: 'initialize',
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: HANDSHAKE_CLIENT_NAME, version: CRAWLER_VERSION },
    },
  };
}

/** Headers sent with the one POST (no Authorization, ever). */
export function initializeHeaders(): Record<string, string> {
  return { 'mcp-protocol-version': MCP_PROTOCOL_VERSION, 'mcp-method': 'initialize' };
}

// ---------------------------------------------------------------------------
// WWW-Authenticate (RFC 9110 §11.6.1 challenge list; we read the first Bearer challenge)
// ---------------------------------------------------------------------------

export interface WwwAuthenticate {
  raw: string;
  scheme: string | null;
  realm: string | null;
  resource_metadata: string | null;
  error: string | null;
  error_description: string | null;
  scope: string | null;
}

export function parseWwwAuthenticate(raw: string | null | undefined): WwwAuthenticate | null {
  if (!raw || !raw.trim()) return null;
  const out: WwwAuthenticate = { raw, scheme: null, realm: null, resource_metadata: null, error: null, error_description: null, scope: null };
  // Prefer a Bearer challenge if several are listed ("Basic realm=x, Bearer resource_metadata=...").
  const m = /(?:^|,\s*)(Bearer)\b\s*(.*)$/i.exec(raw) ?? /^\s*([A-Za-z][A-Za-z0-9._~+/-]*)\s*(.*)$/.exec(raw);
  if (!m) return out;
  out.scheme = m[1];
  const params = m[2];
  const re = /([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g;
  let p: RegExpExecArray | null;
  while ((p = re.exec(params))) {
    const key = p[1].toLowerCase();
    const val = (p[2] !== undefined ? p[2].replace(/\\(.)/g, '$1') : p[3]).trim();
    if (key === 'realm') out.realm = val;
    else if (key === 'resource_metadata') out.resource_metadata = val;
    else if (key === 'error') out.error = val;
    else if (key === 'error_description') out.error_description = val;
    else if (key === 'scope') out.scope = val;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Response body
// ---------------------------------------------------------------------------

/** First SSE event's `data:` lines joined, per the SSE spec (comments and id/event/retry fields ignored). */
export function firstSseData(text: string): string | null {
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data: string[] = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
    }
    if (data.length && data.join('\n').trim()) return data.join('\n');
  }
  return null;
}

export interface InitializeResultSummary {
  protocol_version: string | null;
  server_info: { name: string | null; version: string | null } | null;
  capabilities_keys: string[];
  instructions_present: boolean;
}

export interface JsonRpcErrorSummary { code: number | null; message: string | null; data_keys: string[] }

export type BodyKind = 'json' | 'sse' | 'html' | 'text' | 'empty' | 'other';

export interface ParsedBody {
  kind: BodyKind;
  jsonrpc: boolean; // body (or first SSE event) is a JSON-RPC message
  result: InitializeResultSummary | null;
  error: JsonRpcErrorSummary | null;
}

const rec = (v: unknown): Record<string, unknown> | null => (typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null);

export function parseHandshakeBody(contentType: string | null, body: string): ParsedBody {
  const mt = mediaType(contentType);
  const text = body.trim();
  const none: ParsedBody = { kind: 'empty', jsonrpc: false, result: null, error: null };
  if (!text) return none;
  let kind: BodyKind = 'other';
  let payload: string | null = null;
  if (mt === 'text/event-stream') {
    kind = 'sse';
    payload = firstSseData(text);
  } else if (mt === 'application/json' || mt.endsWith('+json') || /^[\[{]/.test(text)) {
    kind = 'json';
    payload = text;
  } else if (mt === 'text/html' || /^\s*<(!doctype|html)/i.test(text)) {
    kind = 'html';
  } else if (mt.startsWith('text/')) {
    kind = 'text';
  }
  const out: ParsedBody = { kind, jsonrpc: false, result: null, error: null };
  if (payload === null) return out;
  const p = parseJson(payload);
  if (!p.ok) return out;
  const msg = rec(p.value);
  if (!msg || msg.jsonrpc !== '2.0') return out;
  out.jsonrpc = true;
  const result = rec(msg.result);
  const error = rec(msg.error);
  if (result) {
    const si = rec(result.serverInfo);
    const caps = rec(result.capabilities);
    out.result = {
      protocol_version: typeof result.protocolVersion === 'string' ? result.protocolVersion : null,
      server_info: si ? { name: typeof si.name === 'string' ? si.name : null, version: typeof si.version === 'string' ? si.version : null } : null,
      capabilities_keys: caps ? Object.keys(caps).slice(0, 20) : [],
      instructions_present: typeof result.instructions === 'string',
    };
  }
  if (error) {
    out.error = { code: typeof error.code === 'number' ? error.code : null, message: typeof error.message === 'string' ? error.message.slice(0, 200) : null, data_keys: rec(error.data) ? Object.keys(rec(error.data)!).slice(0, 10) : [] };
  }
  return out;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

export type HandshakeClass =
  | 'challenge_401' // 401 with a WWW-Authenticate header (the spec'd path to RFC 9728 metadata)
  | 'challenge_401_no_header' // 401 without WWW-Authenticate
  | 'forbidden_403'
  | 'no_challenge_200' // initialize answered with a JSON-RPC result, no credentials
  | 'jsonrpc_error_200' // 200 with a JSON-RPC error (an MCP server that refused initialize at the protocol level)
  | 'not_mcp' // 2xx but not a JSON-RPC message (HTML, empty, 202/204)
  | 'modern_no_initialize' // 400/404 whose body is a JSON-RPC error: a 2026-07-28 server (no initialize handshake)
  | 'redirect_3xx' // 301/302/303 (not followed for POST) or too many 307/308 hops
  | 'error_4xx'
  | 'error_5xx'
  | 'unreachable';

export function classifyHandshake(status: number, www: WwwAuthenticate | null, body: ParsedBody): HandshakeClass {
  if (status === 0) return 'unreachable';
  if (status === 401) return www ? 'challenge_401' : 'challenge_401_no_header';
  if (status === 403) return 'forbidden_403';
  if (status >= 200 && status < 300) {
    if (body.result) return 'no_challenge_200';
    if (body.error) return 'jsonrpc_error_200';
    return 'not_mcp';
  }
  if (status >= 300 && status < 400) return 'redirect_3xx';
  if ((status === 400 || status === 404) && body.error) return 'modern_no_initialize';
  if (status >= 400 && status < 500) return 'error_4xx';
  return 'error_5xx';
}

// ---------------------------------------------------------------------------
// Endpoint collection from results files
// ---------------------------------------------------------------------------

export interface EndpointTarget {
  host: string;
  rank: number | null;
  source: 'mcp_card' | 'a2a_card';
  card_path: string | null;
  card_spec: string | null;
  endpoint: string | null; // null = hygiene did not record one and dry-run did not re-fetch
  needs_card_refetch: boolean;
  /** valid PRM URLs hygiene already found for this endpoint (to compare with resource_metadata) */
  hygiene_prm_urls: string[];
  hygiene_endpoint_status: number | null;
  a2a_reason?: string;
}

export interface CollectStats { rows: number; hosts_with_mcp_card: number; mcp_endpoints: number; a2a_entries: number; a2a_included: number; a2a_skipped: number; needs_refetch: number; refetched: number; refetch_failed: number }

async function* readRows(path: string): AsyncGenerator<HostResult> {
  if (!existsSync(path)) return;
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    try { yield JSON.parse(line) as HostResult; } catch { /* corrupt partial line */ }
  }
}

/** A2A endpoints are only MCP endpoints when the card says so; hygiene keeps the URL only, so we accept an A2A URL that coincides with an MCP card endpoint or whose last path segment is `mcp`. Everything else is skipped and counted. */
export function a2aLooksLikeMcp(url: string, mcpEndpoints: Set<string>): string | null {
  if (mcpEndpoints.has(url)) return 'same_url_as_mcp_card_endpoint';
  try {
    const last = new URL(url).pathname.replace(/\/$/, '').split('/').pop() ?? '';
    if (/^mcp$/i.test(last)) return 'path_ends_in_mcp';
  } catch { /* fallthrough */ }
  return null;
}

/** All endpoint URLs in a card: SEP-2127 remotes[].url (every remote), SEP-1649 url / transport.url. */
export function extractAllEndpoints(doc: Record<string, unknown>): string[] {
  const out: string[] = [];
  if (Array.isArray(doc.remotes)) {
    for (const x of doc.remotes) {
      const r = rec(x);
      if (r && typeof r.url === 'string') out.push(r.url);
    }
  }
  const one = extractEndpoint(doc);
  if (one) out.push(one);
  return [...new Set(out)];
}

export interface CollectOptions { refetch?: boolean; timeoutMs?: number; scheme?: 'https' | 'http'; log?: (s: string) => void }

export async function collectEndpoints(files: string[], opts: CollectOptions = {}): Promise<{ targets: EndpointTarget[]; stats: CollectStats }> {
  const stats: CollectStats = { rows: 0, hosts_with_mcp_card: 0, mcp_endpoints: 0, a2a_entries: 0, a2a_included: 0, a2a_skipped: 0, needs_refetch: 0, refetched: 0, refetch_failed: 0 };
  const targets: EndpointTarget[] = [];
  const seen = new Set<string>();
  const a2aCandidates: { row: HostResult; h: HygieneEntry }[] = [];
  const mcpUrls = new Set<string>();
  const push = (t: EndpointTarget) => {
    const key = `${t.host} ${t.endpoint ?? '?'}`;
    if (seen.has(key)) return;
    seen.add(key);
    targets.push(t);
  };
  for (const f of files) {
    for await (const row of readRows(f)) {
      stats.rows++;
      if (!row.mcp_card_path) continue; // only hosts with a valid MCP card (A2A-only hosts are out of scope by §4.6)
      stats.hosts_with_mcp_card++;
      const mcpEntries = (row.hygiene ?? []).filter((h) => h.kind === 'mcp');
      const withUrl = mcpEntries.filter((h) => h.endpoint?.url);
      if (withUrl.length) {
        for (const h of withUrl) {
          mcpUrls.add(h.endpoint!.url);
          stats.mcp_endpoints++;
          push({ host: row.host, rank: row.rank ?? null, source: 'mcp_card', card_path: row.mcp_card_path, card_spec: h.card_spec ?? null, endpoint: h.endpoint!.url, needs_card_refetch: false, hygiene_prm_urls: h.prm_lookups.filter((p) => p.valid).map((p) => p.url), hygiene_endpoint_status: h.endpoint!.status });
        }
      } else {
        // hygiene recorded no endpoint (crawled with --no-hygiene, blocked host, or no_endpoint_url_in_card): re-derive from the card itself
        stats.needs_refetch++;
        const cardUrl = `${opts.scheme ?? 'https'}://${row.host}${row.mcp_card_path}`;
        if (opts.refetch) {
          const r = await fetchUrl(cardUrl, { timeoutMs: opts.timeoutMs ?? 10_000, accept: 'application/json' });
          const p = r.status === 200 ? parseJson(bodyText(r)) : null;
          const doc = p && p.ok ? rec(p.value) : null;
          const urls = doc ? extractAllEndpoints(doc) : [];
          if (urls.length) {
            stats.refetched++;
            for (const u of urls) {
              mcpUrls.add(u);
              stats.mcp_endpoints++;
              push({ host: row.host, rank: row.rank ?? null, source: 'mcp_card', card_path: row.mcp_card_path, card_spec: mcpEntries[0]?.card_spec ?? null, endpoint: u, needs_card_refetch: true, hygiene_prm_urls: [], hygiene_endpoint_status: null });
            }
          } else {
            stats.refetch_failed++;
            opts.log?.(`[${row.host}] card re-fetch ${cardUrl} -> ${r.status || r.error}: no endpoint URL`);
            push({ host: row.host, rank: row.rank ?? null, source: 'mcp_card', card_path: row.mcp_card_path, card_spec: null, endpoint: null, needs_card_refetch: true, hygiene_prm_urls: [], hygiene_endpoint_status: null });
          }
        } else {
          push({ host: row.host, rank: row.rank ?? null, source: 'mcp_card', card_path: row.mcp_card_path, card_spec: null, endpoint: null, needs_card_refetch: true, hygiene_prm_urls: [], hygiene_endpoint_status: null });
        }
      }
      for (const h of (row.hygiene ?? []).filter((x) => x.kind === 'a2a' && x.endpoint?.url)) a2aCandidates.push({ row, h });
    }
  }
  for (const { row, h } of a2aCandidates) {
    stats.a2a_entries++;
    const url = h.endpoint!.url;
    const why = a2aLooksLikeMcp(url, mcpUrls);
    if (!why) { stats.a2a_skipped++; continue; }
    if (seen.has(`${row.host} ${url}`)) { stats.a2a_skipped++; continue; } // already probed as the MCP card endpoint
    stats.a2a_included++;
    push({ host: row.host, rank: row.rank ?? null, source: 'a2a_card', card_path: null, card_spec: null, endpoint: url, needs_card_refetch: false, hygiene_prm_urls: h.prm_lookups.filter((p) => p.valid).map((p) => p.url), hygiene_endpoint_status: h.endpoint!.status, a2a_reason: why });
  }
  return { targets, stats };
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

export interface HandshakeResult {
  host: string;
  rank: number | null;
  source: 'mcp_card' | 'a2a_card';
  card_path: string | null;
  endpoint: string;
  ts: string;
  crawler_version: string;
  protocol_version_sent: string;
  request: { method: 'POST'; jsonrpc_method: 'initialize'; headers: string[]; authorization_sent: false };
  status: number; // 0 = no HTTP response (see error)
  error: string | null;
  final_url: string;
  content_type: string | null;
  elapsed_ms: number;
  www_authenticate: WwwAuthenticate | null;
  mcp_session_id_present: boolean;
  body_kind: BodyKind;
  jsonrpc: boolean;
  result: InitializeResultSummary | null;
  jsonrpc_error: JsonRpcErrorSummary | null;
  classification: HandshakeClass;
  /** DELETE sent only when the response carried Mcp-Session-Id */
  session_delete: { sent: boolean; status: number | null; error: string | null } | null;
  /** GET of the WWW-Authenticate resource_metadata URL (RFC 9728), when present */
  resource_metadata: { url: string; status: number | null; error: string | null; resolves: boolean; is_prm: boolean | null; matches_hygiene_prm: boolean | null; hygiene_prm_urls: string[] } | null;
  /** every request this probe made to anyone, in order: "POST <url>", "DELETE <url>", "GET <url>" */
  requests_made: string[];
}

export interface ProbeOptions { timeoutMs?: number; checkResourceMetadata?: boolean }

export async function probeHandshake(t: EndpointTarget & { endpoint: string }, opts: ProbeOptions = {}): Promise<HandshakeResult> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const headers = initializeHeaders();
  const requests: string[] = [];
  const body = JSON.stringify(buildInitializeRequest(1));
  requests.push(`POST ${t.endpoint}`);
  const r: FetchResult = await fetchUrl(t.endpoint, { method: 'POST', body, headers, timeoutMs, accept: 'application/json, text/event-stream', stopAfterFirstSseEvent: true });
  const www = parseWwwAuthenticate(r.headers['www-authenticate']);
  const parsed = parseHandshakeBody(r.contentType, bodyText(r));
  const sessionId = r.headers['mcp-session-id'] ?? null;
  const out: HandshakeResult = {
    host: t.host,
    rank: t.rank,
    source: t.source,
    card_path: t.card_path,
    endpoint: t.endpoint,
    ts: new Date().toISOString(),
    crawler_version: CRAWLER_VERSION,
    protocol_version_sent: MCP_PROTOCOL_VERSION,
    request: { method: 'POST', jsonrpc_method: 'initialize', headers: ['accept', 'content-type', 'user-agent', ...Object.keys(headers)], authorization_sent: false },
    status: r.status,
    error: r.error ?? null,
    final_url: r.finalUrl,
    content_type: r.contentType,
    elapsed_ms: r.elapsedMs,
    www_authenticate: www,
    mcp_session_id_present: sessionId !== null && sessionId !== '',
    body_kind: parsed.kind,
    jsonrpc: parsed.jsonrpc,
    result: parsed.result,
    jsonrpc_error: parsed.error,
    classification: classifyHandshake(r.status, www, parsed),
    session_delete: null,
    resource_metadata: null,
    requests_made: requests,
  };
  // Close the session we were handed (2025-11-25 §Session Management item 5). Nothing else is ever sent.
  if (sessionId) {
    const url = r.finalUrl || t.endpoint;
    requests.push(`DELETE ${url}`);
    const d = await fetchUrl(url, { method: 'DELETE', headers: { 'mcp-session-id': sessionId, 'mcp-protocol-version': MCP_PROTOCOL_VERSION }, timeoutMs, accept: 'application/json, text/event-stream', maxRedirects: 0 });
    out.session_delete = { sent: true, status: d.status || null, error: d.error ?? null };
  }
  if (www?.resource_metadata && opts.checkResourceMetadata !== false) {
    let abs: string | null = null;
    try { abs = new URL(www.resource_metadata, t.endpoint).toString(); } catch { abs = null; }
    if (abs) {
      requests.push(`GET ${abs}`);
      const g = await fetchUrl(abs, { timeoutMs, accept: 'application/json' });
      let isPrm: boolean | null = null;
      if (g.status === 200) {
        const p = parseJson(bodyText(g));
        isPrm = p.ok && !!rec(p.value) && typeof rec(p.value)!.resource === 'string';
      }
      const norm = (u: string) => u.replace(/\/$/, '');
      out.resource_metadata = {
        url: abs,
        status: g.status || null,
        error: g.error ?? null,
        resolves: g.status === 200,
        is_prm: isPrm,
        matches_hygiene_prm: t.hygiene_prm_urls.length ? t.hygiene_prm_urls.some((u) => norm(u) === norm(abs!)) : null,
        hygiene_prm_urls: t.hygiene_prm_urls,
      };
    } else {
      out.resource_metadata = { url: www.resource_metadata, status: null, error: 'invalid_url', resolves: false, is_prm: null, matches_hygiene_prm: null, hygiene_prm_urls: t.hygiene_prm_urls };
    }
  }
  return out;
}
