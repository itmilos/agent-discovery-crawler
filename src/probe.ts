// Probe a host: GET the fourteen canonical paths (randomized order) plus two
// random nonexistent paths for a soft-404 baseline. Paper §4.2 (post-review).
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { join } from 'node:path';
import { fetchUrl, bodyText, mediaType, type FetchResult } from './http.js';
import { PROBE_SPECS, type NxBaseline, type ProbeResult, type ProbeSpec } from './types.js';
import { validateArtifact, looksLikeHtml } from './validate.js';
import { simhash, similarity } from './simhash.js';

export const SOFT404_SIMILARITY = 0.9;

// Rate limiting: there is no per-call limiter here any more. Every fetchUrl()
// waits on the process-wide per-target-host limiter in http.ts (set with
// setGlobalRps), so probes and hygiene follow-ups to third-party hosts share it.

export async function fetchNxBaseline(host: string, scheme = 'https', timeoutMs = 10_000): Promise<NxBaseline> {
  const path = `/__nx_${randomBytes(6).toString('hex')}`;
  const r = await fetchUrl(`${scheme}://${host}${path}`, { timeoutMs });
  return { path, status: r.status, sha256: r.sha256, simhash: simhash(bodyText(r)), content_type: r.contentType, bytes: r.bytes, error: r.error };
}

export function isStructuredKind(spec: ProbeSpec): boolean {
  return spec.kind === 'json' || spec.kind === 'openapi' || spec.kind === 'markdown';
}

/** Fisher–Yates; order is randomized per host so position effects (rate limits kicking in late) average out. */
export function shuffled<T>(xs: readonly T[]): T[] {
  const a = xs.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

export function classifyProbe(spec: ProbeSpec, r: FetchResult, baselines: NxBaseline[]): ProbeResult {
  const reasons: string[] = [];
  let soft404 = false;
  let valid = false;
  let parsed: unknown;
  let card_spec: ProbeResult['card_spec'];
  const text = r.bytes ? bodyText(r) : '';
  const sh = simhash(text);
  let nx_similarity: number | null = null;

  if (r.error) reasons.push(`error:${r.error}`);

  if (r.error === 'proxy_denied') {
    // Response was produced by our own egress proxy; nothing below applies.
  } else if (r.status === 200) {
    const mt = mediaType(r.contentType);
    // Soft-404 rules (paper §4.2):
    //  (a) simhash similarity >= 0.9 to either nonexistent-path baseline that itself returned 200
    //  (b) text/html for a path whose artifact is JSON / Markdown / OpenAPI
    const live = baselines.filter((b) => b.status === 200 && b.bytes > 0);
    if (r.bytes > 0 && live.length) {
      nx_similarity = Math.max(...live.map((b) => similarity(sh, b.simhash)));
      if (live.some((b) => b.sha256 === r.sha256) || nx_similarity >= SOFT404_SIMILARITY) {
        soft404 = true;
        reasons.push('soft404:hash_near_dup');
      }
    }
    if (isStructuredKind(spec) && (mt === 'text/html' || (mt === '' && looksLikeHtml(text)))) {
      soft404 = true;
      reasons.push('soft404:html_content_type');
    }
    if (r.bytes === 0) {
      reasons.push('empty_body');
    } else if (!soft404) {
      const v = validateArtifact(spec.artifact, spec.kind, spec.path, text, r.contentType, r.finalUrl);
      valid = v.valid;
      parsed = v.parsed;
      card_spec = v.card_spec;
      reasons.push(...v.reasons);
    }
  } else if (r.status > 0) {
    reasons.push(`status:${r.status}`);
    if (r.error === 'cross_domain_redirect') reasons.push(`redirect_to:${r.finalUrl}`);
  }
  if (r.cross_origin_hit) reasons.push(`cross_origin_hit:${new URL(r.finalUrl).origin}`);
  if (r.www_redirect) reasons.push(`www_redirect:${new URL(r.finalUrl).origin}`);

  return {
    path: spec.path,
    artifact: spec.artifact,
    status: r.status,
    final_url: r.finalUrl,
    content_type: r.contentType,
    bytes: r.bytes,
    sha256: r.sha256,
    redirects: r.redirects,
    cross_origin_hit: r.cross_origin_hit,
    www_redirect: r.www_redirect,
    elapsed_ms: r.elapsedMs,
    error: r.error,
    simhash: sh,
    nx_similarity,
    soft404,
    valid,
    card_spec,
    hsts: r.headers['strict-transport-security'] ?? null,
    cache_control: r.headers['cache-control'] ?? null,
    reasons,
    parsed,
  };
}

/** Detect bot-challenge pages (Cloudflare, Akamai, PerimeterX, DataDome, Vercel). */
export function isChallenge(r: FetchResult): boolean {
  const h = r.headers;
  if (h['cf-mitigated'] === 'challenge') return true;
  if (h['server'] === 'cloudflare' && (r.status === 403 || r.status === 503) && /cf-chl|challenge-platform|Just a moment/i.test(bodyText(r))) return true;
  if (h['x-vercel-mitigated'] === 'challenge') return true;
  if (h['x-datadome'] || h['x-px-block'] || /_px|datadome|perimeterx/i.test(h['set-cookie'] ?? '')) return r.status === 403 || r.status === 429;
  if (/akamai|Access Denied|Reference #\d+\.\w+\.\d+/i.test(bodyText(r)) && r.status === 403) return true;
  return false;
}

export interface ProbeHostOutput {
  baselines: NxBaseline[];
  probes: ProbeResult[];
  order: string[];
  raw: Map<string, FetchResult>; // path -> result (for hygiene / debugging)
  challengeCount: number;
}

export interface ProbeOptions {
  timeoutMs?: number;
  scheme?: string;
  /** directory to archive 200 bodies into (gzip), e.g. out/bodies; undefined = off */
  bodiesDir?: string;
}

function safeName(path: string): string {
  return path.replace(/^\//, '').replace(/[^a-zA-Z0-9._-]+/g, '_') || 'root';
}

export async function probeHost(host: string, opts: ProbeOptions = {}): Promise<ProbeHostOutput> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const scheme = opts.scheme ?? 'https';
  // Two baselines first so soft-404 comparison is available immediately.
  const baselines = [await fetchNxBaseline(host, scheme, timeoutMs), await fetchNxBaseline(host, scheme, timeoutMs)];
  const order = shuffled(PROBE_SPECS);
  const byPath = new Map<string, ProbeResult>();
  const raw = new Map<string, FetchResult>();
  let challengeCount = 0;
  let hostDir: string | null = null;
  for (const spec of order) {
    const r = await fetchUrl(`${scheme}://${host}${spec.path}`, { timeoutMs });
    raw.set(spec.path, r);
    if (isChallenge(r)) challengeCount++;
    const p = classifyProbe(spec, r, baselines);
    if (opts.bodiesDir && r.status === 200 && r.bytes > 0 && !p.soft404 && r.error !== 'proxy_denied') {
      try {
        if (!hostDir) {
          hostDir = join(opts.bodiesDir, host);
          await mkdir(hostDir, { recursive: true });
        }
        const file = join(hostDir, `${safeName(spec.path)}.gz`);
        await writeFile(file, gzipSync(r.body));
        p.body_file = file;
      } catch (e) {
        p.reasons.push(`body_store_error:${(e as Error).message}`);
      }
    }
    byPath.set(spec.path, p);
  }
  // Emit in canonical order regardless of probe order.
  const probes = PROBE_SPECS.map((s) => byPath.get(s.path)!);
  return { baselines, probes, order: order.map((s) => s.path), raw, challengeCount };
}
