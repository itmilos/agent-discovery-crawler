// Platform / CDN fingerprint from the homepage response (paper §4.4).
// One homepage fetch per host; evidence from headers, <meta name=generator>,
// and known asset markers in the HTML.
import { fetchUrl, bodyText, type FetchResult } from './http.js';
import type { Fingerprint } from './types.js';

interface Rule {
  label: string;
  header?: [string, RegExp | null][]; // header name, value pattern (null = presence)
  html?: RegExp[];
  generator?: RegExp;
}

// Order matters only for `primary`: generators/docs platforms first (most
// specific), then hosting layers. CDN labels are recorded in `cdn`, never in
// `platforms`/`primary`. Labels in HINT_ONLY_HTML are too common as embedded
// third-party widgets (HubSpot forms, Framer embeds, "gitbook" in prose,
// Webflow exports) to count when seen only in script/link tags: such a match
// goes to `hints[]`; a generator/header match still counts as a platform.
const RULES: Rule[] = [
  { label: 'mintlify', html: [/mintlify/i, /_mintlify\//i, /mintcdn\.com/i] },
  { label: 'gitbook', html: [/gitbook/i, /gitbook\.io/i], generator: /gitbook/i },
  { label: 'docusaurus', html: [/docusaurus/i], generator: /docusaurus/i },
  // 0.6.1: substring rules below were measured at 0% (nextra, readme.io) and 35% (squarespace) precision on the
  // blind sample (README "Fingerprint precision sample"); they now need an asset path or a bootstrap symbol.
  { label: 'readme.io', html: [/cdn\.readme\.io\//i, /readmeio\.com\//i, /\breadme-io\b/i] },
  { label: 'fern', html: [/buildwithfern|fern-docs|\bfern\b.*docs/i] },
  { label: 'nextra', html: [/[\/"'`]nextra[\/"'`-]/i, /nextra-theme/i], generator: /nextra/i },
  { label: 'mkdocs', generator: /mkdocs/i, html: [/mkdocs/i] },
  { label: 'hugo', generator: /hugo/i },
  { label: 'gatsby', generator: /gatsby/i, html: [/gatsby-/i] },
  { label: 'nextjs', html: [/\/_next\/static\//i, /__NEXT_DATA__/] },
  { label: 'nuxt', html: [/\/_nuxt\//i, /__NUXT__/] },
  { label: 'webflow', html: [/webflow/i], generator: /webflow/i },
  { label: 'wordpress', html: [/wp-content\//i, /wp-includes\//i], generator: /wordpress/i },
  { label: 'squarespace', html: [/static1?\.squarespace\.com\//i, /squarespace-cdn\.com\//i, /SQUARESPACE_ROLLUPS/], generator: /squarespace/i },
  { label: 'wix', html: [/wix\.com|wixstatic\.com|parastorage\.com/i], generator: /wix/i },
  { label: 'shopify', header: [['x-shopify-stage', null], ['x-shopid', null], ['x-sorting-hat-shopid', null]], html: [/cdn\.shopify\.com/i, /Shopify\.theme/i] },
  { label: 'ghost', generator: /ghost/i },
  { label: 'hubspot', html: [/hs-scripts\.com|hubspot/i], generator: /hubspot/i },
  { label: 'framer', html: [/framerusercontent\.com|framer\.com/i], generator: /framer/i },
  { label: 'github-pages', header: [['x-github-request-id', null], ['server', /github\.com/i]] },
  { label: 'vercel', header: [['x-vercel-id', null], ['x-vercel-cache', null], ['server', /^vercel$/i]] },
  { label: 'netlify', header: [['x-nf-request-id', null], ['server', /netlify/i]] },
  // `server: cloudflare` is the CDN in front of anything; Pages is only inferred from a pages.dev asset origin.
  // 0.6.1: a pages.dev asset on the page measured 26% precision (widgets hosted on Pages); hint only now.
  { label: 'cloudflare-pages', html: [/https?:\/\/[a-z0-9.-]+\.pages\.dev\//i] },
  { label: 'fastly', header: [['x-served-by', /cache-/i], ['via', /varnish/i], ['x-fastly-request-id', null]] },
  { label: 'akamai', header: [['server', /akamai/i], ['x-akamai-transformed', null], ['x-akamai-request-id', null]] },
  { label: 'cloudfront', header: [['via', /cloudfront/i], ['x-amz-cf-id', null]] },
  { label: 'cloudflare', header: [['cf-ray', null], ['server', /^cloudflare$/i]] },
  { label: 'google-frontend', header: [['server', /^(gws|GSE|ESF|Google Frontend|sffe)$/i]] },
  { label: 'nginx', header: [['server', /nginx/i]] },
  { label: 'apache', header: [['server', /apache/i]] },
  { label: 'iis', header: [['server', /microsoft-iis/i], ['x-powered-by', /asp\.net/i]] },
  { label: 'envoy', header: [['server', /envoy/i]] },
  { label: 'express', header: [['x-powered-by', /express/i]] },
  { label: 'php', header: [['x-powered-by', /php/i]] },
];

const CDN_LAYER = new Set(['cloudflare', 'fastly', 'akamai', 'cloudfront']);
const HOSTING_LAYER = new Set(['vercel', 'netlify', 'cloudflare-pages', 'google-frontend', 'nginx', 'apache', 'iis', 'envoy', 'express', 'php', 'github-pages']);
const HINT_ONLY_HTML = new Set(['hubspot', 'framer', 'gitbook', 'webflow', 'cloudflare-pages']);

export function extractGenerator(html: string): string | null {
  const m = html.match(/<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)["']/i) ?? html.match(/<meta[^>]+content=["']([^"']+)["'][^>]*name=["']generator["']/i);
  return m ? m[1].trim() : null;
}

export function fingerprintFromResponse(r: FetchResult): Fingerprint {
  const h = r.headers;
  const html = r.status === 200 ? bodyText(r).slice(0, 512 * 1024) : '';
  const generator = html ? extractGenerator(html) : null;
  const platforms: string[] = [];
  const cdns: string[] = [];
  const hints: string[] = [];
  const signals: string[] = [];

  for (const rule of RULES) {
    let hit: 'header' | 'generator' | 'html' | null = null;
    for (const [name, pat] of rule.header ?? []) {
      const v = h[name];
      if (v !== undefined && (pat === null || pat.test(v))) {
        hit = 'header';
        signals.push(`header:${name}${pat ? '=' + v.slice(0, 40) : ''}`);
        break;
      }
    }
    if (!hit && rule.generator && generator && rule.generator.test(generator)) {
      hit = 'generator';
      signals.push(`generator:${generator.slice(0, 40)}`);
    }
    if (!hit && html) {
      for (const re of rule.html ?? []) {
        if (re.test(html)) {
          hit = 'html';
          signals.push(`html:${rule.label}`);
          break;
        }
      }
    }
    if (!hit) continue;
    if (CDN_LAYER.has(rule.label)) cdns.push(rule.label);
    else if (hit === 'html' && HINT_ONLY_HTML.has(rule.label)) hints.push(rule.label);
    else platforms.push(rule.label);
  }

  const app = platforms.find((p) => !HOSTING_LAYER.has(p));
  const primary = app ?? platforms[0] ?? (r.status === 0 ? 'unreachable' : 'unknown');
  return {
    homepage_status: r.status,
    homepage_final_url: r.status ? r.finalUrl : null,
    homepage_error: r.error,
    server: h['server'] ?? null,
    powered_by: h['x-powered-by'] ?? null,
    generator,
    platforms,
    primary,
    cdn: cdns[0] ?? null,
    hints,
    signals,
  };
}

export async function fingerprintHost(host: string, timeoutMs = 10_000, scheme = 'https'): Promise<{ fp: Fingerprint; raw: FetchResult }> {
  const r = await fetchUrl(`${scheme}://${host}/`, { timeoutMs, accept: 'text/html,application/xhtml+xml,*/*;q=0.8' });
  return { fp: fingerprintFromResponse(r), raw: r };
}
