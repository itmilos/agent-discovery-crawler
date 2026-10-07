// HTTP client wrapper: undici with explicit proxy support, redirect following
// within the registrable domain, content decoding, timeouts, body size cap and
// a GLOBAL per-target-host rate limiter that every fetch (probes and hygiene
// follow-ups to third-party IdPs/endpoints alike) goes through.
// TLS verification is never disabled.
import { Agent, EnvHttpProxyAgent, type Dispatcher, request } from 'undici';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { brotliDecompressSync, gunzipSync, inflateSync, inflateRawSync } from 'node:zlib';
import { getDomain } from 'tldts';

export const CRAWLER_VERSION = '0.6.0';
export const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MiB cap per response (post-decoding)
export const DEFAULT_TIMEOUT_MS = 10_000;
export const MAX_REDIRECTS = 3;

// ---------------------------------------------------------------------------
// Identity (paper §4.9: descriptive UA with project page and opt-out)
// ---------------------------------------------------------------------------

export function contactInfo(): { url: string | undefined; email: string | undefined } {
  return { url: process.env.CRAWLER_CONTACT_URL?.trim() || undefined, email: process.env.CRAWLER_CONTACT_EMAIL?.trim() || undefined };
}

/** UA is built lazily so tests and the CLI preflight see the current env. */
export function userAgent(): string {
  const { url, email } = contactInfo();
  return `AgentDiscoveryCrawler/${CRAWLER_VERSION.split('.').slice(0, 2).join('.')} (+${url ?? 'unset'}; research; opt-out: mailto:${email ?? 'unset'})`;
}

// ---------------------------------------------------------------------------
// Dispatcher (proxy + timeouts)
// ---------------------------------------------------------------------------

const dispatchers = new Map<number, Dispatcher>();

/**
 * Native fetch in Node does NOT honor HTTPS_PROXY unless NODE_USE_ENV_PROXY=1
 * (Node >= 22.21). To be portable to Node 20 we build an undici
 * EnvHttpProxyAgent explicitly when HTTPS_PROXY/HTTP_PROXY is set. Node already
 * picks up NODE_EXTRA_CA_CERTS for the proxy's CA bundle. One dispatcher per
 * distinct timeout so --timeout-ms reaches connect/headers/body timeouts.
 */
export function getDispatcher(timeoutMs = DEFAULT_TIMEOUT_MS): Dispatcher {
  const cached = dispatchers.get(timeoutMs);
  if (cached) return cached;
  const proxy = process.env.HTTPS_PROXY ?? process.env.https_proxy ?? process.env.HTTP_PROXY ?? process.env.http_proxy;
  const common = {
    connect: { timeout: timeoutMs, rejectUnauthorized: true },
    headersTimeout: timeoutMs,
    bodyTimeout: timeoutMs,
  };
  const d = proxy ? new EnvHttpProxyAgent(common) : new Agent(common);
  dispatchers.set(timeoutMs, d);
  return d;
}

// ---------------------------------------------------------------------------
// Global per-target-host rate limiter
// ---------------------------------------------------------------------------

export interface RateLimiter {
  wait(): Promise<void>;
}

export function makeRateLimiter(rps: number): RateLimiter {
  const interval = rps > 0 ? 1000 / rps : 0;
  let next = 0;
  return {
    async wait() {
      if (!interval) return;
      const now = Date.now();
      const at = Math.max(now, next);
      next = at + interval;
      if (at > now) await new Promise((r) => setTimeout(r, at - now));
    },
  };
}

let globalRps = 1;
const hostLimiters = new Map<string, RateLimiter>();

/** Set the per-target-host request rate for every fetch in this process (default 1 rps). */
export function setGlobalRps(rps: number): void {
  globalRps = rps;
  hostLimiters.clear();
}

export function hostLimiter(hostname: string): RateLimiter {
  let l = hostLimiters.get(hostname);
  if (!l) {
    l = makeRateLimiter(globalRps);
    hostLimiters.set(hostname, l);
  }
  return l;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FetchResult {
  url: string; // requested URL
  finalUrl: string; // after redirects
  status: number; // 0 = network error
  headers: Record<string, string>;
  contentType: string | null;
  contentEncoding: string | null; // as received; body below is DECODED
  body: Buffer;
  bytes: number; // decoded length
  sha256: string; // of decoded body
  redirects: number;
  /** final origin (scheme+host) differs from the probed origin (redirect within registrable domain), excluding a bare www. hop */
  cross_origin_hit: boolean;
  /** the only host change was example.com <-> www.example.com (same site; never counted as cross_origin_hit) */
  www_redirect: boolean;
  error?: string; // network/timeout/tls error class
  elapsedMs: number;
}

export type ErrorClass =
  | 'timeout'
  | 'reset'
  | 'tls'
  | 'dns'
  | 'refused'
  | 'proxy_denied' // the crawler's OWN egress proxy refused CONNECT (policy) — not the target site
  | 'too_many_redirects'
  | 'cross_domain_redirect' // redirect left the probed registrable domain; not followed
  | 'body_too_large'
  | 'decode_error' // content-encoding declared but body would not decode
  | 'other';

export function classifyError(err: unknown): ErrorClass {
  const e = err as { code?: string; name?: string; message?: string; cause?: unknown };
  const code = e?.code ?? (e?.cause as { code?: string } | undefined)?.code ?? '';
  const name = e?.name ?? '';
  const msg = (e?.message ?? '') + ' ' + ((e?.cause as { message?: string } | undefined)?.message ?? '');
  // undici reports a refused CONNECT as RequestAbortedError("Proxy response (403) !== 200 when HTTP Tunneling")
  if (/Proxy response \(\d+\)|HTTP Tunneling|407/i.test(msg)) return 'proxy_denied';
  if (name === 'AbortError' || code === 'UND_ERR_CONNECT_TIMEOUT' || code === 'UND_ERR_HEADERS_TIMEOUT' || code === 'UND_ERR_BODY_TIMEOUT' || code === 'ETIMEDOUT')
    return 'timeout';
  if (code === 'ECONNRESET' || code === 'UND_ERR_SOCKET' || /socket hang up|other side closed/i.test(msg)) return 'reset';
  if (/CERT|certificate|TLS|SSL|handshake/i.test(code + ' ' + msg)) return 'tls';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'dns';
  if (code === 'ECONNREFUSED') return 'refused';
  if (/proxy|407|tunnel/i.test(msg)) return 'proxy_denied';
  return 'other';
}

/**
 * Some egress proxies answer the tunnelled request themselves with an HTTP
 * error instead of refusing CONNECT (e.g. a GitHub API gateway that only
 * passes repository-scoped paths). Recognize the known signatures so the
 * result is attributed to the crawler's own egress policy, not the target.
 */
export function isProxyInterstitial(status: number, headers: Record<string, string>, body: Buffer): boolean {
  if (status !== 403 && status !== 407) return false;
  const text = body.subarray(0, 4096).toString('utf8');
  // Agent-proxy GitHub gateway: JSON error bodies that point at the proxy's own docs.
  if (/sessions are bound to their configured repositories|not enabled for this session|docs\.anthropic\.com\/en\/docs\/claude-code/i.test(text)) return true;
  if (headers['x-agentproxy-denied'] !== undefined || headers['proxy-authenticate'] !== undefined) return true;
  return false;
}

function sameOrigin(a: URL, b: URL): boolean {
  return a.protocol === b.protocol && a.host === b.host;
}

/**
 * `example.com` <-> `www.example.com` (either direction) is the same site, not
 * a different origin: the apex/www split is a DNS convention, and treating it
 * as cross-origin would misfile most apex-redirecting sites. Only a bare
 * leading `www.` counts; `docs.example.com` stays a different origin. The
 * scheme may differ (http -> https upgrade on the same hop).
 */
export function isWwwVariant(a: URL, b: URL): boolean {
  const ha = a.hostname.toLowerCase();
  const hb = b.hostname.toLowerCase();
  if (ha === hb) return false;
  const strip = (h: string) => h.replace(/^www\./, '');
  return strip(ha) === strip(hb) && (ha.startsWith('www.') !== hb.startsWith('www.'));
}

/**
 * Same registrable domain (PSL via tldts, private section enabled). IP
 * literals never share a domain unless they are the same address. Unknown
 * TLDs (e.g. *.fixture test hosts) fall back to the last two labels.
 */
export function sameRegistrableDomain(a: URL, b: URL): boolean {
  const ha = a.hostname.replace(/^\[|\]$/g, '');
  const hb = b.hostname.replace(/^\[|\]$/g, '');
  if (isIP(ha) || isIP(hb)) return ha === hb;
  if (isWwwVariant(a, b)) return true; // apex <-> www is the same site whatever the PSL says about the TLD
  const da = getDomain(ha, { allowPrivateDomains: true });
  const db = getDomain(hb, { allowPrivateDomains: true });
  if (da && db) return da === db;
  const tail = (h: string) => h.split('.').slice(-2).join('.');
  return tail(ha) === tail(hb);
}

// ---------------------------------------------------------------------------
// Body handling
// ---------------------------------------------------------------------------

async function readBodyCapped(body: Dispatcher.ResponseData['body'], cap: number): Promise<{ buf: Buffer; truncated: boolean }> {
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  for await (const chunk of body) {
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += b.length;
    if (total > cap) {
      chunks.push(b.subarray(0, b.length - (total - cap)));
      truncated = true;
      try {
        for await (const _ of body) { /* drain */ }
      } catch { /* ignore */ }
      break;
    }
    chunks.push(b);
  }
  return { buf: Buffer.concat(chunks), truncated };
}

/**
 * Read an SSE stream up to and including the first complete event (a blank
 * line), then abort the request so a server that keeps the stream open does
 * not hold the probe until its timeout. Capped at 64 KiB.
 */
async function readFirstSseEvent(body: Dispatcher.ResponseData['body'], ac: AbortController): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  let text = '';
  try {
    for await (const chunk of body) {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      chunks.push(b);
      total += b.length;
      text += b.toString('utf8');
      // skip leading comment/priming events that carry no data (": keepalive", "id: 1\ndata: \n\n")
      if (/(^|\n)data:[^\n]*\S[^\n]*\n(?:[^\n]*\n)*?\n/.test(text) || total > 64 * 1024) {
        ac.abort();
        break;
      }
    }
  } catch { /* aborted by us, or stream ended */ }
  return Buffer.concat(chunks);
}

/**
 * undici.request() does NOT decode content-encoding (fetch() does). Decode
 * gzip / x-gzip / deflate / br here, in the order listed in the header
 * (last applied first), capping the decoded size. identity/unknown -> as is.
 */
export function decodeBody(buf: Buffer, contentEncoding: string | null | undefined): { buf: Buffer; error?: 'decode_error' | 'body_too_large' } {
  if (!contentEncoding || buf.length === 0) return { buf };
  const codings = contentEncoding.split(',').map((c) => c.trim().toLowerCase()).filter(Boolean).reverse();
  let out = buf;
  for (const c of codings) {
    try {
      const opts = { maxOutputLength: MAX_BODY_BYTES + 1 };
      if (c === 'gzip' || c === 'x-gzip') out = gunzipSync(out, opts);
      else if (c === 'deflate') {
        try { out = inflateSync(out, opts); } catch { out = inflateRawSync(out, opts); } // some servers send raw deflate
      } else if (c === 'br') out = brotliDecompressSync(out, opts);
      else if (c === 'identity') continue;
      else return { buf, error: 'decode_error' };
    } catch (e) {
      if ((e as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE') return { buf: out.subarray(0, MAX_BODY_BYTES), error: 'body_too_large' };
      return { buf, error: 'decode_error' };
    }
  }
  if (out.length > MAX_BODY_BYTES) return { buf: out.subarray(0, MAX_BODY_BYTES), error: 'body_too_large' };
  return { buf: out };
}

// ---------------------------------------------------------------------------
// fetchUrl
// ---------------------------------------------------------------------------

export interface FetchOptions {
  method?: 'GET' | 'HEAD' | 'POST' | 'DELETE';
  timeoutMs?: number;
  maxRedirects?: number;
  accept?: string;
  /** request body (POST only; the handshake probe's single JSON-RPC `initialize`) */
  body?: string;
  /** extra request headers (lower-case names); never an Authorization header from this crawler */
  headers?: Record<string, string>;
  /**
   * SSE early stop: when the response is `text/event-stream`, stop reading
   * after the first complete event (`\n\n`) and abort the stream instead of
   * waiting for the server to close it. Used by the handshake probe.
   */
  stopAfterFirstSseEvent?: boolean;
}

/**
 * Test hook: *.fixture hosts are routed to the local fixture server on
 * 127.0.0.1:$CRAWLER_FIXTURE_PORT, keeping the original Host header. Inert
 * unless the env var is set. Exported so the handshake probe shares it.
 */
export function resolveFixtureTarget(current: URL): { target: URL; extraHeaders: Record<string, string> } {
  const fixturePort = process.env.CRAWLER_FIXTURE_PORT;
  const extraHeaders: Record<string, string> = {};
  let target: URL = current;
  if (fixturePort && current.hostname.endsWith('.fixture')) {
    target = new URL(current.toString());
    target.protocol = 'http:';
    target.hostname = '127.0.0.1';
    target.port = fixturePort;
    extraHeaders.host = current.host;
  }
  return { target, extraHeaders };
}

/**
 * GET (or HEAD) a URL, following up to MAX_REDIRECTS redirects that stay within
 * the probed host's registrable domain (e.g. example.com -> docs.example.com is
 * followed and flagged cross_origin_hit; example.com <-> www.example.com is
 * followed and flagged www_redirect only; example.com -> other.net is not
 * followed: error=cross_domain_redirect, Location kept in finalUrl). A 303
 * always switches the method to GET. Every hop waits on the global limiter for
 * its target hostname.
 */
export async function fetchUrl(url: string, opts: FetchOptions = {}): Promise<FetchResult> {
  let method = opts.method ?? 'GET';
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = opts.maxRedirects ?? MAX_REDIRECTS;
  const start = Date.now();
  let current = new URL(url);
  const origin = new URL(url);
  let redirects = 0;

  for (;;) {
    await hostLimiter(current.hostname).wait();
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      // Test hook: route *.fixture hosts to the local fixture server, keeping the Host header.
      const { target, extraHeaders } = resolveFixtureTarget(current);
      const hasBody = method === 'POST' && opts.body !== undefined;
      const res = await request(target, {
        method,
        dispatcher: getDispatcher(timeoutMs),
        signal: ac.signal,
        maxRedirections: 0,
        headers: {
          'user-agent': userAgent(),
          accept: opts.accept ?? 'application/json, text/markdown, text/plain, application/yaml, text/yaml, text/html;q=0.5, */*;q=0.1',
          'accept-encoding': 'gzip, br, deflate',
          ...(hasBody ? { 'content-type': 'application/json' } : {}),
          ...(opts.headers ?? {}),
          ...extraHeaders,
        },
        body: hasBody ? opts.body : undefined,
      });
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
      }
      const status = res.statusCode;
      // A POST/DELETE is only re-sent on 307/308 (method-preserving); a 301/302/303
      // would turn it into a GET, which the handshake probe must never send.
      const followable = method === 'GET' || method === 'HEAD' ? [301, 302, 303, 307, 308] : [307, 308];
      if (followable.includes(status) && headers.location) {
        try { for await (const _ of res.body) { /* drain */ } } catch { /* ignore */ }
        let next: URL;
        try {
          next = new URL(headers.location, current);
        } catch {
          clearTimeout(timer);
          return finish(status, headers, Buffer.alloc(0), 'other');
        }
        if (!sameRegistrableDomain(origin, next)) {
          clearTimeout(timer);
          return { ...finish(status, headers, Buffer.alloc(0), 'cross_domain_redirect'), finalUrl: next.toString() };
        }
        if (redirects >= maxRedirects) {
          clearTimeout(timer);
          return finish(status, headers, Buffer.alloc(0), 'too_many_redirects');
        }
        if (status === 303) method = 'GET';
        redirects++;
        current = next;
        clearTimeout(timer);
        continue;
      }
      let raw: Buffer = Buffer.alloc(0);
      let truncated = false;
      if (method !== 'HEAD') {
        // Read up to the cap of *encoded* bytes too, so a zip bomb cannot blow memory before decoding.
        if (opts.stopAfterFirstSseEvent && mediaType(headers['content-type']) === 'text/event-stream') {
          raw = await readFirstSseEvent(res.body, ac);
        } else {
          ({ buf: raw, truncated } = await readBodyCapped(res.body, MAX_BODY_BYTES));
        }
      } else {
        try { for await (const _ of res.body) { /* drain */ } } catch { /* ignore */ }
      }
      clearTimeout(timer);
      // A truncated encoded stream cannot decode; report the cap, not a decode failure.
      const dec = truncated ? { buf: raw } : decodeBody(raw, headers['content-encoding']);
      const error = truncated ? 'body_too_large' : dec.error;
      if (isProxyInterstitial(status, headers, dec.buf)) return finish(status, headers, dec.buf, 'proxy_denied');
      return finish(status, headers, dec.buf, error);
    } catch (err) {
      clearTimeout(timer);
      return finish(0, {}, Buffer.alloc(0), classifyError(err));
    }
  }

  function finish(status: number, headers: Record<string, string>, body: Buffer, error?: string): FetchResult {
    return {
      url,
      finalUrl: current.toString(),
      status,
      headers,
      contentType: headers['content-type'] ?? null,
      contentEncoding: headers['content-encoding'] ?? null,
      body,
      bytes: body.length,
      sha256: createHash('sha256').update(body).digest('hex'),
      redirects,
      cross_origin_hit: !sameOrigin(origin, current) && !isWwwVariant(origin, current),
      www_redirect: isWwwVariant(origin, current),
      error,
      elapsedMs: Date.now() - start,
    };
  }
}

/** Decode body to utf-8 text (best-effort; we do not sniff charsets beyond utf-8). */
export function bodyText(r: FetchResult): string {
  return r.body.toString('utf8');
}

/** Normalize content-type: strip parameters, lowercase. */
export function mediaType(ct: string | null): string {
  if (!ct) return '';
  return ct.split(';')[0].trim().toLowerCase();
}
