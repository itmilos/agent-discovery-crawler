// Hygiene checks for valid MCP/A2A cards and protected-resource docs
// (paper §4.6 a–d, post-review). Check (e) — unauthenticated MCP initialize —
// is deliberately NOT performed in this pass; see TODO below and README.
import { fetchUrl, bodyText, sameRegistrableDomain } from './http.js';
import { parseJson, validateJsonArtifact } from './validate.js';
import type { AuthServerCheck, EndpointCheck, HygieneEntry, PrmCheck, ProbeResult } from './types.js';
import { MCP_CARD_ARTIFACTS, A2A_CARD_ARTIFACTS } from './types.js';

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** Pull the endpoint URL out of an MCP card (SEP-2127 remotes[] or SEP-1649 url/transport) or an A2A card. */
export function extractEndpoint(doc: Record<string, unknown>): string | null {
  if (Array.isArray(doc.remotes)) {
    for (const x of doc.remotes) {
      const r = asRecord(x);
      if (r && typeof r.url === 'string') return r.url;
    }
  }
  // A2A v1.0: supportedInterfaces[] of { url, protocolBinding, ... }; legacy cards use top-level url.
  if (Array.isArray(doc.supportedInterfaces)) {
    for (const x of doc.supportedInterfaces) {
      const r = asRecord(x);
      if (r && typeof r.url === 'string') return r.url;
    }
  }
  if (typeof doc.url === 'string') return doc.url;
  if (typeof doc.endpoint === 'string') return doc.endpoint;
  const t = asRecord(doc.transport);
  if (t && typeof t.url === 'string') return t.url;
  for (const key of ['transports', 'servers']) {
    const arr = doc[key];
    if (Array.isArray(arr)) {
      for (const x of arr) {
        const r = asRecord(x);
        if (r && typeof r.url === 'string') return r.url;
      }
    }
  }
  return null;
}

function authServersFrom(doc: Record<string, unknown>): string[] {
  const out: string[] = [];
  const direct = doc.authorization_servers;
  if (Array.isArray(direct)) for (const s of direct) if (typeof s === 'string') out.push(s);
  // Some MCP cards nest auth metadata
  const auth = asRecord(doc.authentication) ?? asRecord(doc.auth) ?? asRecord(doc.securitySchemes);
  if (auth) {
    for (const v of Object.values(auth)) {
      const r = asRecord(v);
      if (r) {
        if (typeof r.issuer === 'string') out.push(r.issuer);
        if (typeof r.authorization_server === 'string') out.push(r.authorization_server);
        if (Array.isArray(r.authorization_servers)) for (const s of r.authorization_servers) if (typeof s === 'string') out.push(s);
      }
    }
  }
  return [...new Set(out)];
}

async function checkEndpoint(url: string, timeoutMs: number): Promise<EndpointCheck> {
  let u: URL | null = null;
  try {
    u = new URL(url);
  } catch {
    return { url, https: false, status: null, error: 'invalid_url', reachable: false };
  }
  const https = u.protocol === 'https:';
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    return { url, https, status: null, error: `non_http_scheme:${u.protocol}`, reachable: false };
  }
  // HEAD first; many MCP endpoints 405 on HEAD, so fall back to GET.
  let r = await fetchUrl(url, { method: 'HEAD', timeoutMs, accept: 'application/json, text/event-stream, */*' });
  if (r.status === 0 || r.status === 405 || r.status === 501) {
    r = await fetchUrl(url, { method: 'GET', timeoutMs, accept: 'application/json, text/event-stream, */*' });
  }
  // "Resolves" = we got any HTTP status back (even 401/405 means something is listening at that URL).
  const reachable = r.status > 0 && r.status !== 404 && r.status !== 410;
  return { url, https, status: r.status || null, error: r.error, reachable };
}

/** RFC 9700 §2.1.1 / MCP auth spec: PKCE means S256; a server advertising only "plain" does not count. */
export function pkceFromMetadata(rec: Record<string, unknown>): boolean {
  const m = rec.code_challenge_methods_supported;
  return Array.isArray(m) && m.includes('S256');
}

/** RFC 8414 metadata URL construction: insert /.well-known/oauth-authorization-server before the issuer path. */
export function authServerMetadataUrl(issuer: string): string | null {
  try {
    const u = new URL(issuer);
    const path = u.pathname.replace(/\/$/, '');
    return `${u.origin}/.well-known/oauth-authorization-server${path}`;
  } catch {
    return null;
  }
}

function oidcMetadataUrl(issuer: string): string | null {
  try {
    const u = new URL(issuer);
    const path = u.pathname.replace(/\/$/, '');
    return `${u.origin}${path}/.well-known/openid-configuration`;
  } catch {
    return null;
  }
}

/** RFC 9728 §3: PRM for a resource with a path lives at /.well-known/oauth-protected-resource/<path>. */
export function prmUrlsForEndpoint(endpoint: string): { url: string; location: PrmCheck['location'] }[] {
  try {
    const u = new URL(endpoint);
    const out: { url: string; location: PrmCheck['location'] }[] = [];
    const path = u.pathname.replace(/\/$/, '');
    if (path && path !== '/') out.push({ url: `${u.origin}/.well-known/oauth-protected-resource${path}`, location: 'path_suffixed' });
    out.push({ url: `${u.origin}/.well-known/oauth-protected-resource`, location: 'root' });
    return out;
  } catch {
    return [];
  }
}

async function checkPrm(endpoint: string, timeoutMs: number): Promise<{ checks: PrmCheck[]; doc: Record<string, unknown> | null; resourceMismatch: boolean }> {
  const checks: PrmCheck[] = [];
  let found: Record<string, unknown> | null = null;
  let resourceMismatch = false;
  for (const { url, location } of prmUrlsForEndpoint(endpoint)) {
    const r = await fetchUrl(url, { timeoutMs, accept: 'application/json' });
    let valid = false;
    if (r.status === 200) {
      // RFC 9728 §3.3: resource must equal the identifier the URL was derived from.
      const v = validateJsonArtifact('oauth_protected_resource', bodyText(r), r.contentType, url);
      valid = v.valid;
      if (v.reasons.includes('prm_resource_mismatch')) resourceMismatch = true;
      if (valid && !found) found = v.parsed as Record<string, unknown>;
    }
    checks.push({ url, location, status: r.status || null, valid, error: r.error });
    if (valid) break; // path-suffixed takes precedence; stop at first valid
  }
  return { checks, doc: found, resourceMismatch };
}

async function checkAuthServer(issuer: string, cardHost: URL, timeoutMs: number): Promise<AuthServerCheck> {
  const https = issuer.startsWith('https://');
  const url = authServerMetadataUrl(issuer);
  let third_party_hosted = false;
  try {
    third_party_hosted = !sameRegistrableDomain(cardHost, new URL(issuer));
  } catch {
    /* invalid issuer handled below */
  }
  if (!url) return { issuer, https, metadata_url: '', status: null, error: 'invalid_issuer_url', resolves: false, issuer_match: null, pkce_advertised: null, third_party_hosted };
  let r = await fetchUrl(url, { timeoutMs, accept: 'application/json' });
  let used = url;
  if (r.status !== 200) {
    // Fallback: OIDC discovery location (RFC 8414 §5 compatibility note).
    const alt = oidcMetadataUrl(issuer);
    if (alt) {
      const r2 = await fetchUrl(alt, { timeoutMs, accept: 'application/json' });
      if (r2.status === 200) {
        r = r2;
        used = alt;
      }
    }
  }
  let issuer_match: boolean | null = null;
  let pkce_advertised: boolean | null = null;
  if (r.status === 200) {
    const p = parseJson(bodyText(r));
    const rec = p.ok ? asRecord(p.value) : null;
    if (rec) {
      if (typeof rec.issuer === 'string') issuer_match = rec.issuer.replace(/\/$/, '') === issuer.replace(/\/$/, '');
      pkce_advertised = pkceFromMetadata(rec);
    }
  }
  return { issuer, https, metadata_url: used, status: r.status || null, error: r.error, resolves: r.status === 200, issuer_match, pkce_advertised, third_party_hosted };
}

export async function runHygiene(host: string, probes: ProbeResult[], timeoutMs = 10_000, scheme = 'https'): Promise<HygieneEntry[]> {
  const out: HygieneEntry[] = [];
  const cardHost = new URL(`${scheme}://${host}/`);
  for (const p of probes) {
    if (!p.valid || !p.parsed) continue;
    const doc = asRecord(p.parsed);
    if (!doc) continue;
    let kind: HygieneEntry['kind'] | null = null;
    if (MCP_CARD_ARTIFACTS.includes(p.artifact)) kind = 'mcp';
    else if (A2A_CARD_ARTIFACTS.includes(p.artifact)) kind = 'a2a';
    else if (p.artifact === 'oauth_protected_resource') kind = 'protected_resource';
    if (!kind) continue;

    const notes: string[] = [];
    const entry: HygieneEntry = {
      source: p.artifact,
      kind,
      card_spec: p.card_spec,
      endpoint_third_party_hosted: null,
      prm_lookups: [],
      authorization_servers: [],
      has_authorization_servers: false,
      bearer_query_allowed: null,
      hsts: p.hsts ?? null,
      cache_control: p.cache_control ?? null,
      // TODO(paper §4.6e): send a JSON-RPC `initialize` to the MCP endpoint
      // without credentials and record whether it is accepted. Not done in
      // this pass: requires a disclosure process (>=45 days) before publication.
      mcp_unauthenticated_initialize: null,
      notes,
    };
    if (!entry.hsts) notes.push('no_hsts_on_card');

    let prmDoc: Record<string, unknown> | null = null;
    if (kind === 'mcp' || kind === 'a2a') {
      const ep = extractEndpoint(doc);
      if (ep) {
        entry.endpoint = await checkEndpoint(ep, timeoutMs);
        try {
          entry.endpoint_third_party_hosted = !sameRegistrableDomain(cardHost, new URL(ep));
        } catch { /* invalid url already noted */ }
        if (!entry.endpoint.https) notes.push('endpoint_not_https');
        if (!entry.endpoint.reachable) notes.push('endpoint_unreachable');
        if (entry.endpoint_third_party_hosted) notes.push('third_party_hosted:endpoint');
        // (a) RFC 9728 PRM derived from the endpoint path, then root.
        if (entry.endpoint.https || entry.endpoint.url.startsWith('http:')) {
          const prm = await checkPrm(ep, timeoutMs);
          entry.prm_lookups = prm.checks;
          prmDoc = prm.doc;
          if (prm.resourceMismatch) notes.push('prm_resource_mismatch');
          if (!prmDoc) notes.push('no_prm_for_endpoint');
        }
      } else {
        notes.push('no_endpoint_url_in_card');
      }
    } else {
      // protected resource: `resource` is the endpoint identifier
      prmDoc = doc;
      const res = typeof doc.resource === 'string' ? doc.resource : null;
      if (p.reasons.includes('prm_resource_mismatch')) notes.push('prm_resource_mismatch');
      if (res) {
        entry.endpoint = await checkEndpoint(res, timeoutMs);
        if (!entry.endpoint.https) notes.push('resource_not_https');
        try {
          entry.endpoint_third_party_hosted = !sameRegistrableDomain(cardHost, new URL(res));
        } catch { /* noted via invalid_url */ }
      }
    }

    if (prmDoc) {
      const bm = prmDoc.bearer_methods_supported;
      entry.bearer_query_allowed = Array.isArray(bm) ? bm.includes('query') : false;
      if (entry.bearer_query_allowed) notes.push('bearer_query_allowed');
    }

    const servers = [...new Set([...authServersFrom(doc), ...(prmDoc && prmDoc !== doc ? authServersFrom(prmDoc) : [])])];
    entry.has_authorization_servers = servers.length > 0;
    if (!servers.length) notes.push(kind === 'protected_resource' ? 'empty_authorization_servers' : 'no_authorization_server_declared');
    for (const s of servers.slice(0, 5)) {
      const c = await checkAuthServer(s, cardHost, timeoutMs);
      entry.authorization_servers.push(c);
      if (!c.https) notes.push('auth_server_not_https');
      if (!c.resolves) notes.push('auth_server_metadata_unresolved');
      else {
        if (c.issuer_match === false) notes.push('issuer_mismatch');
        if (c.pkce_advertised === false) notes.push('no_pkce_advertised');
      }
      if (c.third_party_hosted) notes.push('third_party_hosted:auth_server');
    }
    entry.notes = [...new Set(notes)];
    out.push(entry);
  }
  return out;
}
