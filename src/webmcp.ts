// WebMCP headless detection module (paper §4.2, "WebMCP" paragraph).
//
// For each host a headless Chromium (playwright-core) loads the homepage and up
// to N-1 same-registrable-domain links from it. Before any page script runs an
// init script (a) feature-detects `navigator.modelContext` / `document.modelContext`
// (the two names the explainer and the spec have used), (b) installs a recording
// shim for every method the explainer / spec / Chrome preview name
// (registerTool, unregisterTool, provideContext, clearContext, getTools,
// executeTool), so a page that feature-detects and registers tools is observed
// even though stock Chromium exposes no API, (c) after load scans the DOM for the
// declarative form API (`toolname` / `tooldescription` / `toolparamdescription` /
// `toolautosubmit`) and for script/meta/link hints naming webmcp, and (d) records
// origin-trial tokens from `<meta http-equiv="origin-trial">` and the
// `Origin-Trial` response header, decoding the payload (feature, expiry).
//
// Because Chromium without a trial token exposes NO API, what this measures is
// *attempted* registrations: a site has to feature-detect and call the API for
// us to see it. See README "WebMCP module".
import { readdirSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { chromium, type Browser, type BrowserContext, type Page, type Response } from 'playwright-core';
import { getDomain } from 'tldts';
import { fetchUrl, userAgent, sameRegistrableDomain, CRAWLER_VERSION, bodyText, mediaType } from './http.js';

export const WEBMCP_METHODS = ['registerTool', 'unregisterTool', 'provideContext', 'clearContext', 'getTools', 'executeTool'] as const;
export const WEBMCP_DECLARATIVE_ATTRS = ['toolname', 'tooldescription', 'toolparamdescription', 'toolautosubmit'] as const;
export const DEFAULT_NAV_TIMEOUT_MS = 15_000;
export const ROBOTS_UA_TOKEN = 'AgentDiscoveryCrawler';

// ---------------------------------------------------------------------------
// Output schema
// ---------------------------------------------------------------------------

export interface WebMCPRegistration {
  page: string;
  method: (typeof WEBMCP_METHODS)[number];
  tool_name: string | null;
  description: string | null;
  input_keys: string[];
  /** the descriptor carried an execute() callback (imperative API) */
  has_execute: boolean;
}

export interface OriginTrialToken {
  source: 'meta' | 'header';
  page: string;
  feature: string | null;
  expiry: string | null; // ISO
  origin: string | null;
  is_subdomain: boolean | null;
  is_third_party: boolean | null;
  version: number | null;
  decode_error?: string;
}

export interface DeclarativeHit {
  page: string;
  kind: 'declarative_form' | 'script_type' | 'script_src' | 'meta' | 'link_rel';
  tag?: string;
  toolname?: string | null;
  tooldescription?: string | null;
  toolautosubmit?: boolean;
  params?: string[];
  value?: string;
  name?: string;
  content?: string;
  href?: string;
}

export interface WebMCPResult {
  host: string;
  rank: number | null;
  registrable_domain: string | null;
  ts: string;
  crawler_version: string;
  duration_ms: number;
  pages_visited: string[];
  /** `navigator.modelContext` existed before our shim ran (any visited page) */
  native_modelContext: boolean;
  /** `document.modelContext` (spec draft name) existed before our shim ran */
  native_document_modelContext: boolean;
  registrations: WebMCPRegistration[];
  origin_trial: { present: boolean; feature: string | null; expiry: string | null; tokens: OriginTrialToken[] };
  declarative_hits: DeclarativeHit[];
  robots: { status: number | null; error: string | null; groups: number; skipped: string[] };
  errors: string[];
}

// ---------------------------------------------------------------------------
// Init script (runs in the page before any page script)
// ---------------------------------------------------------------------------

export const SHIM_GLOBAL = '__agentDiscoveryWebMCP';

/**
 * The recording shim. Feature detection happens FIRST (prototype and instance,
 * so a lazily-materialized attribute is still seen). When the API exists
 * natively the methods are wrapped (record, then call through); when it does
 * not, a fake `modelContext` object is installed on both navigator and
 * document so a feature-detecting page proceeds to register.
 */
export const WEBMCP_INIT_SCRIPT = `(() => {
  const S = { native_navigator: false, native_document: false, registrations: [] };
  try { S.native_navigator = ('modelContext' in Navigator.prototype) || ('modelContext' in navigator); } catch (e) {}
  try { S.native_document = ('modelContext' in Document.prototype) || ('modelContext' in document); } catch (e) {}
  const str = (v, n) => (typeof v === 'string' ? v.slice(0, n) : null);
  const keysOf = (schema) => { try { const p = schema && schema.properties; return p && typeof p === 'object' ? Object.keys(p).slice(0, 50) : []; } catch (e) { return []; } };
  const rec = (method, tool) => {
    if (S.registrations.length >= 500) return;
    const t = tool && typeof tool === 'object' ? tool : null;
    S.registrations.push({
      method,
      tool_name: t ? str(t.name, 200) : (typeof tool === 'string' ? tool.slice(0, 200) : null),
      description: t ? str(t.description, 500) : null,
      input_keys: t ? keysOf(t.inputSchema || t.input_schema || t.parameters) : [],
      has_execute: !!(t && typeof t.execute === 'function'),
    });
  };
  const handlers = {
    registerTool(tool) { rec('registerTool', tool); },
    unregisterTool(name) { rec('unregisterTool', name && typeof name === 'object' ? name : { name: name }); },
    provideContext(ctx) { const tools = ctx && Array.isArray(ctx.tools) ? ctx.tools : []; if (!tools.length) rec('provideContext', null); for (const t of tools) rec('provideContext', t); },
    clearContext() { rec('clearContext', null); },
    getTools() { rec('getTools', null); return []; },
    executeTool(tool) { rec('executeTool', tool); throw new Error('executeTool is not available in this environment'); },
  };
  const names = Object.keys(handlers);
  const wrapNative = (target) => {
    for (const m of names) {
      const orig = typeof target[m] === 'function' ? target[m].bind(target) : null;
      try {
        Object.defineProperty(target, m, { configurable: true, writable: true, value: function () {
          try { handlers[m].apply(null, arguments); } catch (e) {}
          if (orig) return orig.apply(null, arguments);
          return m === 'getTools' ? Promise.resolve([]) : Promise.resolve();
        } });
      } catch (e) {}
    }
  };
  const shim = {};
  for (const m of names) shim[m] = function () { let r; try { r = handlers[m].apply(null, arguments); } catch (e) { return Promise.reject(e); } return Promise.resolve(r); };
  shim.addEventListener = function () {}; shim.removeEventListener = function () {}; shim.dispatchEvent = function () { return true; };
  const owners = [[navigator, 'native_navigator'], [document, 'native_document']];
  for (const pair of owners) {
    const owner = pair[0], flag = pair[1];
    try {
      const existing = S[flag] ? owner.modelContext : null;
      if (existing && typeof existing === 'object') wrapNative(existing);
      else Object.defineProperty(owner, 'modelContext', { configurable: true, enumerable: true, get: () => shim });
    } catch (e) {}
  }
  try { Object.defineProperty(window, '${SHIM_GLOBAL}', { value: S, configurable: true }); } catch (e) {}
})();`;

// ---------------------------------------------------------------------------
// Origin-trial token decoding
// ---------------------------------------------------------------------------

/**
 * Chrome origin-trial token: base64( version(1) | signature(64) | payloadLength(4, BE) | payload JSON ).
 * Versions 2 and 3 share the layout (3 adds the third-party / usage fields).
 * We never verify the signature; we only read feature / expiry / origin.
 */
export function decodeOriginTrialToken(token: string): Omit<OriginTrialToken, 'source' | 'page'> {
  const empty = { feature: null, expiry: null, origin: null, is_subdomain: null, is_third_party: null, version: null } as Omit<OriginTrialToken, 'source' | 'page'>;
  let buf: Buffer;
  try {
    buf = Buffer.from(token.trim(), 'base64');
  } catch (e) {
    return { ...empty, decode_error: 'base64' };
  }
  if (buf.length < 1 + 64 + 4) return { ...empty, decode_error: 'too_short' };
  const version = buf[0];
  if (version !== 2 && version !== 3) return { ...empty, version, decode_error: `unknown_version:${version}` };
  const len = buf.readUInt32BE(65);
  const payload = buf.subarray(69, 69 + len);
  if (payload.length !== len) return { ...empty, version, decode_error: 'length_mismatch' };
  try {
    const j = JSON.parse(payload.toString('utf8')) as Record<string, unknown>;
    const exp = typeof j.expiry === 'number' ? new Date(j.expiry * 1000).toISOString() : null;
    return {
      version,
      feature: typeof j.feature === 'string' ? j.feature : null,
      expiry: exp,
      origin: typeof j.origin === 'string' ? j.origin : null,
      is_subdomain: typeof j.isSubdomain === 'boolean' ? j.isSubdomain : null,
      is_third_party: typeof j.isThirdParty === 'boolean' ? j.isThirdParty : null,
    };
  } catch {
    return { ...empty, version, decode_error: 'payload_json' };
  }
}

/** Build a syntactically valid (unsigned) token, for fixtures and tests. */
export function makeFakeOriginTrialToken(payload: Record<string, unknown>, version = 3): string {
  const json = Buffer.from(JSON.stringify(payload));
  const len = Buffer.alloc(4);
  len.writeUInt32BE(json.length, 0);
  return Buffer.concat([Buffer.from([version]), Buffer.alloc(64, 0), len, json]).toString('base64');
}

// ---------------------------------------------------------------------------
// robots.txt
// ---------------------------------------------------------------------------

export interface RobotsGroup { agents: string[]; rules: { allow: boolean; path: string }[] }

export function parseRobots(text: string): RobotsGroup[] {
  const groups: RobotsGroup[] = [];
  let cur: RobotsGroup | null = null;
  let lastWasAgent = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    if (key === 'user-agent') {
      if (!cur || !lastWasAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(val.toLowerCase());
      lastWasAgent = true;
    } else if (key === 'allow' || key === 'disallow') {
      lastWasAgent = false;
      if (!cur) continue;
      if (key === 'disallow' && val === '') continue; // "Disallow:" = allow all
      cur.rules.push({ allow: key === 'allow', path: val });
    } else {
      lastWasAgent = false;
    }
  }
  return groups;
}

function robotsPatternMatches(pattern: string, path: string): boolean {
  // '*' wildcard, '$' end anchor (Google / RFC 9309 semantics).
  let re = '';
  for (const ch of pattern) {
    if (ch === '*') re += '.*';
    else if (ch === '$') re += '$';
    else re += ch.replace(/[.+?^{}()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + re).test(path);
}

/**
 * Longest-match rule within the most specific group (our UA token first, then
 * `*`); no group or no matching rule means allowed. Allow wins ties.
 */
export function robotsAllows(groups: RobotsGroup[], path: string, uaToken = ROBOTS_UA_TOKEN): boolean {
  const token = uaToken.toLowerCase();
  const pick = groups.filter((g) => g.agents.some((a) => a === token || (a !== '*' && token.startsWith(a))));
  const group = pick.length ? pick : groups.filter((g) => g.agents.includes('*'));
  if (!group.length) return true;
  let best: { allow: boolean; len: number } | null = null;
  for (const g of group) for (const r of g.rules) {
    if (!robotsPatternMatches(r.path, path)) continue;
    const len = r.path.length;
    if (!best || len > best.len || (len === best.len && r.allow && !best.allow)) best = { allow: r.allow, len };
  }
  return best ? best.allow : true;
}

export async function fetchRobots(host: string, scheme: 'https' | 'http', timeoutMs: number): Promise<{ groups: RobotsGroup[]; status: number | null; error: string | null }> {
  const r = await fetchUrl(`${scheme}://${host}/robots.txt`, { timeoutMs, accept: 'text/plain, */*;q=0.1' });
  if (r.status === 0) return { groups: [], status: null, error: r.error ?? 'other' };
  if (r.status !== 200) return { groups: [], status: r.status, error: null };
  const mt = mediaType(r.contentType);
  if (mt === 'text/html') return { groups: [], status: r.status, error: 'html_body' }; // soft-404 robots: no rules
  return { groups: parseRobots(bodyText(r)), status: r.status, error: null };
}

// ---------------------------------------------------------------------------
// Link selection
// ---------------------------------------------------------------------------

const ASSET_RE = /\.(png|jpe?g|gif|svg|webp|ico|css|js|mjs|json|xml|pdf|zip|gz|tgz|mp[34]|webm|woff2?|ttf|eot|txt|csv|rss|atom)(\?|#|$)/i;

export interface LinkCandidate { href: string; nav: boolean }

/**
 * Pick up to `max` links from the homepage: same registrable domain, http(s),
 * not an asset, not the page itself, deduped on URL-without-fragment, nav
 * links first (document order within each group).
 */
export function pickLinks(pageUrl: string, links: LinkCandidate[], max: number): string[] {
  const base = new URL(pageUrl);
  const seen = new Set<string>([base.toString().replace(/#.*$/, '')]);
  const nav: string[] = [];
  const rest: string[] = [];
  for (const l of links) {
    let u: URL;
    try { u = new URL(l.href, base); } catch { continue; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
    if (!sameRegistrableDomain(base, u)) continue;
    u.hash = '';
    const key = u.toString();
    if (seen.has(key)) continue;
    if (ASSET_RE.test(u.pathname)) continue;
    if (/^\/?(logout|signout|sign-out|delete|unsubscribe)\b/i.test(u.pathname)) continue;
    seen.add(key);
    (l.nav ? nav : rest).push(key);
  }
  return [...nav, ...rest].slice(0, max);
}

// ---------------------------------------------------------------------------
// Chromium
// ---------------------------------------------------------------------------

/**
 * Executable resolution: $CRAWLER_CHROMIUM_PATH, then playwright-core's own
 * expectation (works after `npx playwright-core install chromium`), then any
 * chromium-* under $PLAYWRIGHT_BROWSERS_PATH / ~/.cache/ms-playwright (so a
 * Chromium from a different playwright release still launches).
 */
export function resolveChromiumPath(): string | null {
  const env = process.env.CRAWLER_CHROMIUM_PATH;
  if (env && existsSync(env)) return env;
  try {
    const p = chromium.executablePath();
    if (p && existsSync(p)) return p;
  } catch { /* fall through */ }
  const roots = [process.env.PLAYWRIGHT_BROWSERS_PATH, join(homedir(), '.cache', 'ms-playwright'), join(homedir(), 'Library', 'Caches', 'ms-playwright'), process.env.LOCALAPPDATA ? join(process.env.LOCALAPPDATA, 'ms-playwright') : undefined].filter(Boolean) as string[];
  const rel = process.platform === 'darwin'
    ? [join('chrome-mac', 'Chromium.app', 'Contents', 'MacOS', 'Chromium'), join('chrome-mac-arm64', 'Chromium.app', 'Contents', 'MacOS', 'Chromium')]
    : process.platform === 'win32' ? [join('chrome-win', 'chrome.exe'), join('chrome-win64', 'chrome.exe')] : [join('chrome-linux', 'chrome'), join('chrome-linux64', 'chrome')];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    let dirs: string[];
    try { dirs = readdirSync(root).filter((d) => /^chromium-\d+$/.test(d)).sort((a, b) => Number(b.slice(9)) - Number(a.slice(9))); } catch { continue; }
    for (const d of dirs) for (const r of rel) {
      const p = join(root, d, r);
      if (existsSync(p) && statSync(p).isFile()) return p;
    }
    // the symlink layout used by some images: <root>/chromium -> .../chrome
    const link = join(root, 'chromium');
    if (existsSync(link) && statSync(link).isFile()) return link;
  }
  return null;
}

export interface LaunchOptions { executablePath?: string | null; fixturePort?: string | null }

export async function launchChromium(opts: LaunchOptions = {}): Promise<Browser> {
  const executablePath = opts.executablePath ?? resolveChromiumPath();
  if (!executablePath) throw new Error('no Chromium found: run `npx playwright-core install chromium` or set CRAWLER_CHROMIUM_PATH');
  const args = ['--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-extensions', '--disable-features=OptimizationHints,MediaRouter,AutofillServerCommunication,Translate,InterestFeedContentSuggestions', '--metrics-recording-only'];
  const fixturePort = opts.fixturePort ?? process.env.CRAWLER_FIXTURE_PORT;
  if (fixturePort) args.push(`--host-resolver-rules=MAP *.fixture 127.0.0.1:${fixturePort}`);
  const proxy = process.env.HTTPS_PROXY ?? process.env.https_proxy;
  return chromium.launch({
    headless: true,
    executablePath,
    args,
    chromiumSandbox: false,
    proxy: proxy ? { server: proxy, bypass: 'localhost,127.0.0.1,*.fixture' } : undefined,
  });
}

// ---------------------------------------------------------------------------
// Per-host crawl
// ---------------------------------------------------------------------------

export interface WebMCPCrawlOptions {
  pages: number; // total pages per host incl. homepage
  timeoutMs: number;
  scheme: 'https' | 'http';
  settleMs?: number; // extra wait after load for late registrations
  navGapMs?: number; // pacing between page loads on one host
}

interface PageSnapshot {
  native_navigator: boolean;
  native_document: boolean;
  registrations: Omit<WebMCPRegistration, 'page'>[];
  declarative: Omit<DeclarativeHit, 'page'>[];
  metaTokens: string[];
  links: LinkCandidate[];
}

const SNAPSHOT_FN = `(global) => {
  const S = window[global] || { native_navigator: false, native_document: false, registrations: [] };
  const hits = [];
  for (const el of document.querySelectorAll('[toolname]')) hits.push({ kind: 'declarative_form', tag: el.tagName.toLowerCase(), toolname: el.getAttribute('toolname'), tooldescription: el.getAttribute('tooldescription'), toolautosubmit: el.hasAttribute('toolautosubmit'), params: Array.from(el.querySelectorAll('[toolparamdescription]')).map((e) => e.getAttribute('name') || e.id || null).slice(0, 50) });
  for (const s of document.querySelectorAll('script[type]')) if (/webmcp|model-?context/i.test(s.type)) hits.push({ kind: 'script_type', value: s.type.slice(0, 100) });
  for (const s of document.querySelectorAll('script[src]')) if (/webmcp|model-?context/i.test(s.src)) hits.push({ kind: 'script_src', value: s.src.slice(0, 300) });
  for (const m of document.querySelectorAll('meta[name],meta[property]')) { const k = m.getAttribute('name') || m.getAttribute('property') || ''; if (/webmcp|model-?context/i.test(k)) hits.push({ kind: 'meta', name: k.slice(0, 100), content: (m.getAttribute('content') || '').slice(0, 300) }); }
  for (const l of document.querySelectorAll('link[rel]')) if (/webmcp|model-?context/i.test(l.rel)) hits.push({ kind: 'link_rel', value: l.rel.slice(0, 100), href: (l.href || '').slice(0, 300) });
  const metaTokens = Array.from(document.querySelectorAll('meta[http-equiv]')).filter((m) => (m.getAttribute('http-equiv') || '').toLowerCase() === 'origin-trial').map((m) => m.getAttribute('content') || '').filter(Boolean);
  const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 2000).map((a) => ({ href: a.href, nav: !!a.closest('nav, header, [role="navigation"]') }));
  return { native_navigator: !!S.native_navigator, native_document: !!S.native_document, registrations: S.registrations.slice(0, 500), declarative: hits.slice(0, 100), metaTokens, links };
}`;

async function newContext(browser: Browser): Promise<BrowserContext> {
  const ctx = await browser.newContext({ userAgent: userAgent(), viewport: { width: 1280, height: 800 }, serviceWorkers: 'block', ignoreHTTPSErrors: false });
  await ctx.addInitScript(WEBMCP_INIT_SCRIPT);
  await ctx.route('**/*', (route) => {
    const t = route.request().resourceType();
    if (t === 'image' || t === 'media' || t === 'font') return route.abort('blockedbyclient');
    return route.continue();
  });
  return ctx;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function visit(page: Page, url: string, opts: WebMCPCrawlOptions): Promise<{ snap: PageSnapshot; headerTokens: string[]; finalUrl: string }> {
  let res: Response | null = null;
  res = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: opts.timeoutMs });
  try { await page.waitForLoadState('networkidle', { timeout: Math.min(5000, opts.timeoutMs) }); } catch { /* busy page; take what we have */ }
  await sleep(opts.settleMs ?? 1000);
  const headerTokens: string[] = [];
  if (res) {
    try {
      for (const h of await res.headersArray()) if (h.name.toLowerCase() === 'origin-trial') for (const tok of h.value.split(',')) if (tok.trim()) headerTokens.push(tok.trim());
    } catch { /* detached */ }
  }
  const snap = (await page.evaluate(`(${SNAPSHOT_FN})(${JSON.stringify(SHIM_GLOBAL)})`)) as PageSnapshot;
  return { snap, headerTokens, finalUrl: page.url() };
}

export async function crawlHostWebMCP(browser: Browser, host: string, opts: WebMCPCrawlOptions, rank: number | null = null): Promise<WebMCPResult> {
  const start = Date.now();
  const out: WebMCPResult = {
    host, rank, registrable_domain: getDomain(host, { allowPrivateDomains: true }), ts: new Date().toISOString(), crawler_version: CRAWLER_VERSION, duration_ms: 0,
    pages_visited: [], native_modelContext: false, native_document_modelContext: false, registrations: [],
    origin_trial: { present: false, feature: null, expiry: null, tokens: [] }, declarative_hits: [],
    robots: { status: null, error: null, groups: 0, skipped: [] }, errors: [],
  };
  const robots = await fetchRobots(host, opts.scheme, opts.timeoutMs);
  out.robots.status = robots.status;
  out.robots.error = robots.error;
  out.robots.groups = robots.groups.length;
  const allowed = (u: string) => robotsAllows(robots.groups, new URL(u).pathname + new URL(u).search);

  const home = `${opts.scheme}://${host}/`;
  if (!allowed(home)) {
    out.robots.skipped.push('/');
    out.errors.push('robots_disallows_homepage');
    out.duration_ms = Date.now() - start;
    return out;
  }
  const ctx = await newContext(browser);
  try {
    const page = await ctx.newPage();
    page.setDefaultTimeout(opts.timeoutMs);
    const queue: string[] = [home];
    const visited = new Set<string>();
    while (queue.length && out.pages_visited.length < opts.pages) {
      const url = queue.shift()!;
      if (visited.has(url)) continue;
      visited.add(url);
      if (out.pages_visited.length) await sleep(opts.navGapMs ?? 1000);
      let r: Awaited<ReturnType<typeof visit>>;
      try {
        r = await visit(page, url, opts);
      } catch (e) {
        const msg = (e as Error).message.split('\n')[0].slice(0, 200);
        out.errors.push(`page:${url}: ${msg}`);
        if (!out.pages_visited.length) break; // homepage failed: nothing to crawl
        continue;
      }
      const pageUrl = r.finalUrl || url;
      out.pages_visited.push(pageUrl);
      out.native_modelContext ||= r.snap.native_navigator;
      out.native_document_modelContext ||= r.snap.native_document;
      for (const reg of r.snap.registrations) out.registrations.push({ page: pageUrl, ...reg });
      for (const d of r.snap.declarative) out.declarative_hits.push({ page: pageUrl, ...d });
      for (const tok of r.snap.metaTokens) out.origin_trial.tokens.push({ source: 'meta', page: pageUrl, ...decodeOriginTrialToken(tok) });
      for (const tok of r.headerTokens) out.origin_trial.tokens.push({ source: 'header', page: pageUrl, ...decodeOriginTrialToken(tok) });
      if (out.pages_visited.length === 1) {
        // homepage: queue links (robots-filtered; skipped ones recorded)
        const cands = pickLinks(pageUrl, r.snap.links, Math.max(0, opts.pages - 1) * 2);
        for (const c of cands) {
          if (!sameRegistrableDomain(new URL(home), new URL(c))) continue;
          if (!allowed(c)) { out.robots.skipped.push(new URL(c).pathname); continue; }
          queue.push(c);
          if (queue.length >= opts.pages - 1) break;
        }
      }
    }
  } catch (e) {
    out.errors.push(`context: ${(e as Error).message.split('\n')[0].slice(0, 200)}`);
  } finally {
    await ctx.close().catch(() => {});
  }
  const toks = out.origin_trial.tokens;
  out.origin_trial.present = toks.length > 0;
  const wm = toks.find((t) => t.feature && /webmcp|modelcontext/i.test(t.feature)) ?? toks.find((t) => t.feature) ?? toks[0];
  out.origin_trial.feature = wm?.feature ?? null;
  out.origin_trial.expiry = wm?.expiry ?? null;
  out.duration_ms = Date.now() - start;
  return out;
}
