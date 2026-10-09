// Offline self-test: exercises validate.ts, probe.ts classification,
// fingerprint.ts, hygiene helpers, the blocked rule, the summarizer and the
// HTTP layer (against an in-process loopback server; no external network).
// `npm test`.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { Readable } from 'node:stream';
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib';
import { validateArtifact, derivedResourceFromPrmUrl, prmResourceMatches } from './validate.js';
import { classifyProbe } from './probe.js';
import { fingerprintFromResponse } from './fingerprint.js';
import { authServerMetadataUrl, extractEndpoint, prmUrlsForEndpoint, pkceFromMetadata } from './hygiene.js';
import { simhash, similarity } from './simhash.js';
import { sameRegistrableDomain, isWwwVariant, decodeBody, fetchUrl, userAgent, CRAWLER_VERSION, setGlobalRps, hostLimiter, MAX_BODY_BYTES } from './http.js';
import { computeBlocked, contactPreflight, isRedirectOnly, normalizeHost, parseHostLine, estimateDurationSec, fmtDuration, progressLine, REQUESTS_PER_HOST, parseShard, applyShard } from './run.js';
import { parseRobots, robotsAllows, pickLinks, decodeOriginTrialToken, makeFakeOriginTrialToken, resolveChromiumPath, launchChromium, crawlHostWebMCP, WEBMCP_INIT_SCRIPT, WEBMCP_METHODS } from './webmcp.js';
import { buildSubsample, readPool, weightedDraw, mulberry32, renderSampleFile } from './corpus/subsample.js';
import { startFixtureServer, FIXTURE_REQUEST_LOG, FIXTURE_SESSIONS_TERMINATED } from './fixture-server.js';
import { buildInitializeRequest, classifyHandshake, collectEndpoints, firstSseData, parseHandshakeBody, parseWwwAuthenticate, probeHandshake, MCP_PROTOCOL_VERSION, a2aLooksLikeMcp, extractAllEndpoints, type EndpointTarget } from './handshake.js';
import { handshakeGate } from './handshake-run.js';
import { buildFindings, csvEscape, hygieneFindings, isShopifyHost, isShopifyIssuer, renderCsv, renderSummary, securityTxtContact, EMAIL_TEMPLATE } from './disclosure.js';
import { originTrialKind } from './webmcp-run.js';
import { parseBand, parseBands, parseTrancoCsv, buildBands, readZip, csvFromZip, renderBandFile, writeCorpus } from './corpus/tranco.js';
import { endpointHost, extractOfficial, officialNextCursor, pageOfficial, extractGlama, glamaNext, extractSmitheryDetail, dedupeHosts, writeRegistryCorpus, loadTrancoRanks, trancoRankFor } from './corpus/registry.js';
import { compare as vCompare, renderCompare } from './vantage-compare.js';
import { plan as cPlan, renderSite as cRenderSite, writePlan as cWritePlan, parseCsv as cParseCsv, parseLogLine as cParseLogLine, readTrials as cReadTrials, scoreTrials as cScoreTrials, tabulate as cTabulate, clusteredCI as cClusteredCI, renderTable as cRenderTable, overlappingWindows as cOverlapping, TRIALS_HEADER as cTRIALS_HEADER } from './canary/kit.js';
import { parseOpenAI as rParseOpenAI, parseAnthropic as rParseAnthropic, parseGemini as rParseGemini, runTrials as rRunTrials, doneKeys as rDoneKeys, csvRow as rCsvRow, TRIALS_HEADER_V2 as rHEADER, upgradeTrialsHeader as rUpgradeHeader } from './canary/run.js';
import { extractCardTools, extractOpenApiOps, parseStructured, strictKey, looseKey, looseKeyForOp, matchPair, jaccard, llmsLinks, selectCandidates, checkHost, summarize as cSummarize, renderSampleCsv, median } from './consistency.js';
import { drawSample, extractEvidence, renderBlindCsv, parseCsv, score as fpScore, shuffle } from './fingerprint-sample.js';
import { parseIntelItem, parseIntelBody, classify, makePacer, readLabels, labelHosts, writeRadarCorpus, LABEL_SOURCE, type RadarLabel } from './corpus/radar.js';
import { mkdtempSync, readFileSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { summarizeStream, summarizeFiles, hostClass } from './summarize.js';
import type { HostResult, NxBaseline, ProbeResult } from './types.js';
import { PROBE_SPECS } from './types.js';
import type { FetchResult } from './http.js';

const spec = (path: string) => PROBE_SPECS.find((s) => s.path === path)!;

function fr(status: number, body: string, ct: string | null, headers: Record<string, string> = {}): FetchResult {
  const buf = Buffer.from(body);
  return {
    url: 'https://x.test/',
    finalUrl: 'https://x.test/',
    status,
    headers: { ...(ct ? { 'content-type': ct } : {}), ...headers },
    contentType: ct,
    contentEncoding: null,
    body: buf,
    bytes: buf.length,
    sha256: createHash('sha256').update(buf).digest('hex'),
    redirects: 0,
    cross_origin_hit: false,
    www_redirect: false,
    elapsedMs: 1,
  };
}

function nxb(status: number, body: string, ct: string | null): NxBaseline {
  const f = fr(status, body, ct);
  return { path: '/__nx_test', status, sha256: f.sha256, simhash: simhash(body), content_type: ct, bytes: f.bytes };
}

let n = 0;
async function t(name: string, fn: () => void | Promise<void>) {
  try {
    await fn();
  } catch (e) {
    console.log(`not ok - ${name}`);
    throw e;
  }
  n++;
  console.log(`ok - ${name}`);
}

// ---- llms.txt ----
await t('llms.txt valid markdown', () => {
  const v = validateArtifact('llms_txt', 'markdown', '/llms.txt', '# Acme\n\n> docs\n\n## Docs\n- [a](https://a)', 'text/plain');
  assert.equal(v.valid, true);
});
await t('llms.txt rejects html body', () => {
  const v = validateArtifact('llms_txt', 'markdown', '/llms.txt', '<!doctype html><html><head></head><body># not md</body></html>', 'text/html');
  assert.equal(v.valid, false);
  assert.ok(v.reasons.includes('body_is_html'));
});
await t('llms.txt rejects no heading', () => {
  const v = validateArtifact('llms_txt', 'markdown', '/llms.txt', 'just a sentence\nanother', 'text/plain');
  assert.equal(v.valid, false);
  assert.ok(v.reasons.includes('no_markdown_heading'));
});
await t('llms.txt: H1 must be the first line, else note:h1_not_first (not fatal)', () => {
  const v = validateArtifact('llms_txt', 'markdown', '/llms.txt', '> blurb first\n\n# Acme\n\n## Docs\n', 'text/plain');
  assert.equal(v.valid, true);
  assert.ok(v.reasons.includes('note:h1_not_first'));
  const ok = validateArtifact('llms_txt', 'markdown', '/llms.txt', '---\ntitle: x\n---\n# Acme\n', 'text/plain');
  assert.equal(ok.valid, true);
  assert.ok(!ok.reasons.includes('note:h1_not_first'));
  assert.ok(validateArtifact('llms_txt', 'markdown', '/llms.txt', '## Only h2\n', 'text/plain').reasons.includes('note:h1_not_first'));
});

// ---- JSON cards ----
await t('mcp card valid', () => {
  const v = validateArtifact('mcp_server_card', 'json', '', JSON.stringify({ name: 'x', url: 'https://mcp.x.test/mcp' }), 'application/json');
  assert.equal(v.valid, true);
});
await t('mcp card missing url/transport/tools', () => {
  const v = validateArtifact('mcp_server_card', 'json', '', JSON.stringify({ name: 'x', version: '1' }), 'application/json');
  assert.equal(v.valid, false);
  assert.ok(v.reasons.some((r) => r.startsWith('schema:')));
});
await t('protected resource RFC9728 valid', () => {
  const v = validateArtifact('oauth_protected_resource', 'json', '', JSON.stringify({ resource: 'https://mcp.x.test', authorization_servers: ['https://auth.x.test'] }), 'application/json');
  assert.equal(v.valid, true);
});
await t('protected resource: authorization_servers is OPTIONAL (RFC 9728 §2) -> valid + note', () => {
  const v = validateArtifact('oauth_protected_resource', 'json', '', JSON.stringify({ resource: 'https://mcp.x.test' }), 'application/json');
  assert.equal(v.valid, true);
  assert.ok(v.reasons.includes('note:prm_no_authorization_servers'));
  assert.equal(validateArtifact('oauth_protected_resource', 'json', '', JSON.stringify({ authorization_servers: [] }), 'application/json').valid, false);
});
await t('protected resource: resource must match the URL it was derived from (RFC 9728 §3.3)', () => {
  assert.equal(derivedResourceFromPrmUrl('https://h.test/.well-known/oauth-protected-resource'), 'https://h.test/');
  assert.equal(derivedResourceFromPrmUrl('https://h.test/.well-known/oauth-protected-resource/v1/mcp'), 'https://h.test/v1/mcp');
  assert.equal(prmResourceMatches('https://h.test', 'https://h.test/.well-known/oauth-protected-resource'), true);
  assert.equal(prmResourceMatches('https://h.test/v1/mcp', 'https://h.test/.well-known/oauth-protected-resource/v1/mcp'), true);
  assert.equal(prmResourceMatches('https://h.test/v1/mcp', 'https://h.test/.well-known/oauth-protected-resource'), false);
  const bad = validateArtifact('oauth_protected_resource', 'json', '', JSON.stringify({ resource: 'https://h.test/api', authorization_servers: ['https://as.test'] }), 'application/json', 'https://h.test/.well-known/oauth-protected-resource');
  assert.equal(bad.valid, false);
  assert.ok(bad.reasons.includes('prm_resource_mismatch'));
  const ok = validateArtifact('oauth_protected_resource', 'json', '', JSON.stringify({ resource: 'https://h.test/', authorization_servers: ['https://as.test'] }), 'application/json', 'https://h.test/.well-known/oauth-protected-resource');
  assert.equal(ok.valid, true);
});
await t('authorization server / OIDC need issuer AND response_types_supported (RFC 8414 §2)', () => {
  assert.equal(validateArtifact('oauth_authorization_server', 'json', '', '{"issuer":"https://a.test","response_types_supported":["code"]}', 'application/json').valid, true);
  const v = validateArtifact('oauth_authorization_server', 'json', '', '{"issuer":"https://a.test"}', 'application/json');
  assert.equal(v.valid, false);
  assert.ok(v.reasons.includes('schema:required:response_types_supported'));
  assert.equal(validateArtifact('openid_configuration', 'json', '', '{"token_endpoint":"x"}', 'application/json').valid, false);
});
await t('pkce_advertised requires S256', () => {
  assert.equal(pkceFromMetadata({ code_challenge_methods_supported: ['S256'] }), true);
  assert.equal(pkceFromMetadata({ code_challenge_methods_supported: ['plain', 'S256'] }), true);
  assert.equal(pkceFromMetadata({ code_challenge_methods_supported: ['plain'] }), false);
  assert.equal(pkceFromMetadata({}), false);
});
await t('a2a card', () => {
  assert.equal(validateArtifact('a2a_agent_card', 'json', '', '{"name":"bot","skills":[]}', 'application/json').valid, true);
  assert.equal(validateArtifact('a2a_agent_card', 'json', '', '{"name":"bot"}', 'application/json').valid, false);
});
await t('a2a v1.0: supportedInterfaces[].url is the endpoint (legacy url still read)', () => {
  const v1 = { name: 'bot', protocolVersion: '1.0', supportedInterfaces: [{ url: 'https://a.test/a2a', protocolBinding: 'JSONRPC' }] };
  assert.equal(validateArtifact('a2a_agent_card', 'json', '', JSON.stringify(v1), 'application/json').valid, true);
  assert.equal(extractEndpoint(v1), 'https://a.test/a2a');
  assert.equal(extractEndpoint({ name: 'bot', url: 'https://a.test/legacy' }), 'https://a.test/legacy');
});
await t('json parse error', () => {
  const v = validateArtifact('mcp_server_card', 'json', '', '{nope', 'application/json');
  assert.deepEqual(v.reasons, ['json_parse_error']);
});

// ---- OpenAPI ----
await t('openapi 3 json valid', () => {
  assert.equal(validateArtifact('openapi_json', 'openapi', '/openapi.json', '{"openapi":"3.1.0","info":{},"paths":{}}', 'application/json').valid, true);
});
await t('openapi yaml valid', () => {
  assert.equal(validateArtifact('openapi_yaml', 'openapi', '/openapi.yaml', 'openapi: "3.0.3"\ninfo:\n  title: t\npaths: {}\n', 'application/yaml').valid, true);
});
await t('swagger 2 rejected', () => {
  const v = validateArtifact('openapi_json', 'openapi', '/openapi.json', '{"swagger":"2.0"}', 'application/json');
  assert.equal(v.valid, false);
  assert.ok(v.reasons[0].startsWith('swagger_2_not_3'));
});

// ---- soft-404 classification ----
await t('soft404 by exact hash match', () => {
  const html = '<!doctype html><html><body>Not found</body></html>';
  const p = classifyProbe(spec('/ai.txt'), fr(200, html, 'text/plain'), [nxb(200, html, 'text/html')]);
  assert.equal(p.soft404, true);
  assert.equal(p.valid, false);
  assert.ok(p.reasons.includes('soft404:hash_near_dup'));
});
await t('soft404 by simhash near-dup (nonce differs)', () => {
  const page = (nonce: string) => `<html><head><script nonce="${nonce}">window.__id="${nonce}"</script><link href="/static/app.${nonce}.css"></head><body><nav>Home Products Pricing Docs Blog About Careers Contact</nav><h1>Page not found</h1><p>The page you requested could not be found on this server. It may have been moved or deleted. Try the search box or go back to the home page. Error reference ${nonce}</p><footer>Copyright Example Inc. All rights reserved. Privacy Terms Contact Status Security</footer></body></html>`;
  const p = classifyProbe(spec('/ai.txt'), fr(200, page('a1b2c3'), 'text/plain'), [nxb(200, page('zz9y8x'), 'text/html'), nxb(200, page('q0w9e8'), 'text/html')]);
  assert.ok(p.nx_similarity! >= 0.9, `similarity ${p.nx_similarity}`);
  assert.equal(p.soft404, true);
  assert.ok(p.reasons.includes('soft404:hash_near_dup'));
  assert.ok(!p.reasons.includes('soft404:html_content_type'));
});
await t('soft404 by html content-type for json path (distinct reason)', () => {
  const p = classifyProbe(spec('/.well-known/mcp-server-card'), fr(200, '<html><body>SPA</body></html>', 'text/html; charset=utf-8'), [nxb(404, '', null)]);
  assert.equal(p.soft404, true);
  assert.deepEqual(p.reasons, ['soft404:html_content_type']);
});
await t('valid llms.txt not soft404 when nx differs', () => {
  const p = classifyProbe(spec('/llms.txt'), fr(200, '# Site\n\n## Docs\n', 'text/plain; charset=utf-8'), [nxb(404, '<html>nf</html>', 'text/html')]);
  assert.equal(p.soft404, false);
  assert.equal(p.valid, true);
});
await t('404 recorded with status reason', () => {
  const p = classifyProbe(spec('/llms.txt'), fr(404, '', null), [nxb(404, '', null)]);
  assert.deepEqual(p.reasons, ['status:404']);
});
await t('simhash: identical=1, unrelated<0.9', () => {
  assert.equal(similarity(simhash('a b c d e f'), simhash('a b c d e f')), 1);
  const a = simhash('The quick brown fox jumps over the lazy dog and keeps running through the forest until night falls');
  const b = simhash('openapi 3.1.0 info title Payments API paths /charges get operationId listCharges responses 200 description ok');
  assert.ok(similarity(a, b) < 0.9);
});

// ---- new artifacts ----
await t('SEP-2127 card detected', () => {
  const v = validateArtifact('mcp_server_card', 'json', '', JSON.stringify({ name: 'com.example.search', version: '1.0.0', description: 'd', remotes: [{ type: 'streamable-http', url: 'https://mcp.example.com/mcp' }] }), 'application/json');
  assert.equal(v.valid, true);
  assert.equal(v.card_spec, 'sep-2127');
});
await t('SEP-1649 shape at legacy path', () => {
  const v = validateArtifact('mcp_server_card_legacy', 'json', '', JSON.stringify({ name: 'x', url: 'https://m/mcp', tools: [] }), 'application/json');
  assert.equal(v.valid, true);
  assert.equal(v.card_spec, 'sep-1649');
});
await t('ai-catalog: any JSON object', () => {
  assert.equal(validateArtifact('ai_catalog', 'json', '', '{"anything":1}', 'application/json').valid, true);
  assert.equal(validateArtifact('ai_catalog', 'json', '', '[1,2]', 'application/json').valid, false);
});
await t('security.txt requires Contact', () => {
  assert.equal(validateArtifact('security_txt', 'text', '', 'Contact: mailto:sec@x.test\nExpires: 2027-01-01T00:00:00z\n', 'text/plain').valid, true);
  const v = validateArtifact('security_txt', 'text', '', 'Policy: https://x.test/sec\n', 'text/plain');
  assert.equal(v.valid, false);
  assert.ok(v.reasons.includes('no_contact_field'));
});

// ---- redirects ----
await t('same registrable domain', () => {
  assert.equal(sameRegistrableDomain(new URL('https://example.com/'), new URL('https://docs.example.com/llms.txt')), true);
  assert.equal(sameRegistrableDomain(new URL('https://example.com/'), new URL('https://example.net/')), false);
  assert.equal(sameRegistrableDomain(new URL('https://a.github.io/'), new URL('https://b.github.io/')), false);
});
await t('IP literals: two different IPs are never the same domain', () => {
  assert.equal(sameRegistrableDomain(new URL('http://10.0.0.1/'), new URL('http://10.0.0.2/')), false);
  assert.equal(sameRegistrableDomain(new URL('http://10.0.0.1/'), new URL('http://10.0.0.1:8080/x')), true);
  assert.equal(sameRegistrableDomain(new URL('http://[::1]/'), new URL('http://[::2]/')), false);
  assert.equal(sameRegistrableDomain(new URL('http://1.2.3.4/'), new URL('http://3.4.example.com/')), false);
});

await t('www variant: apex <-> www is the same site; docs.* and other domains are not', () => {
  assert.equal(isWwwVariant(new URL('https://example.com/x'), new URL('https://www.example.com/x')), true);
  assert.equal(isWwwVariant(new URL('https://www.example.com/'), new URL('https://example.com/')), true);
  assert.equal(isWwwVariant(new URL('http://example.com/'), new URL('https://www.example.com/')), true); // scheme upgrade on the same hop
  assert.equal(isWwwVariant(new URL('https://example.com/'), new URL('https://example.com/')), false);
  assert.equal(isWwwVariant(new URL('https://example.com/'), new URL('https://docs.example.com/')), false);
  assert.equal(isWwwVariant(new URL('https://www.example.com/'), new URL('https://docs.example.com/')), false);
  assert.equal(isWwwVariant(new URL('https://example.com/'), new URL('https://www.example.net/')), false);
  assert.equal(isWwwVariant(new URL('https://www.a.example.com/'), new URL('https://a.example.com/')), true);
});
await t('classifyProbe: www_redirect recorded with final_url, cross_origin_hit stays false', () => {
  const r = { ...fr(200, '# Site\n\n## Docs\n', 'text/plain'), finalUrl: 'https://www.x.test/llms.txt', redirects: 1, www_redirect: true, cross_origin_hit: false };
  const p = classifyProbe(spec('/llms.txt'), r, [nxb(404, 'nf', 'text/html')]);
  assert.equal(p.valid, true);
  assert.equal(p.www_redirect, true);
  assert.equal(p.cross_origin_hit, false);
  assert.equal(p.final_url, 'https://www.x.test/llms.txt');
  assert.ok(p.reasons.includes('www_redirect:https://www.x.test'));
  assert.ok(!p.reasons.some((x) => x.startsWith('cross_origin_hit')));
  const d = { ...r, finalUrl: 'https://docs.x.test/llms.txt', www_redirect: false, cross_origin_hit: true };
  const q = classifyProbe(spec('/llms.txt'), d, [nxb(404, 'nf', 'text/html')]);
  assert.equal(q.cross_origin_hit, true);
  assert.equal(q.www_redirect, false);
  assert.ok(q.reasons.includes('cross_origin_hit:https://docs.x.test'));
});

// ---- fingerprint ----
await t('fingerprint vercel + mintlify', () => {
  const fp = fingerprintFromResponse(fr(200, '<html><head><script src="/_next/static/a.js"></script><link href="https://mintlify.b-cdn.net/x.css"></head></html>', 'text/html', { 'x-vercel-id': 'iad1::abc', server: 'Vercel' }));
  assert.ok(fp.platforms.includes('vercel'));
  assert.ok(fp.platforms.includes('mintlify'));
  assert.equal(fp.primary, 'mintlify');
});
await t('fingerprint wordpress via generator', () => {
  const fp = fingerprintFromResponse(fr(200, '<html><head><meta name="generator" content="WordPress 6.5"></head></html>', 'text/html', { server: 'nginx' }));
  assert.equal(fp.generator, 'WordPress 6.5');
  assert.equal(fp.primary, 'wordpress');
});
await t('fingerprint shopify behind cloudflare: cdn recorded separately', () => {
  const fp = fingerprintFromResponse(fr(200, '<html></html>', 'text/html', { 'x-shopify-stage': 'production', 'cf-ray': '1-IAD', server: 'cloudflare' }));
  assert.equal(fp.primary, 'shopify');
  assert.equal(fp.cdn, 'cloudflare');
  assert.ok(!fp.platforms.includes('cloudflare'));
});
await t('fingerprint: server=cloudflare alone is NOT cloudflare-pages', () => {
  const fp = fingerprintFromResponse(fr(200, '<html><body>x</body></html>', 'text/html', { server: 'cloudflare', 'cf-ray': '2-IAD' }));
  assert.ok(!fp.platforms.includes('cloudflare-pages'), JSON.stringify(fp.platforms));
  assert.equal(fp.primary, 'unknown');
  assert.equal(fp.cdn, 'cloudflare');
  const pages = fingerprintFromResponse(fr(200, '<html><script src="https://my-site.pages.dev/app.js"></script></html>', 'text/html', { server: 'cloudflare' }));
  assert.ok(!pages.platforms.includes('cloudflare-pages'), '0.6.1: a pages.dev asset is a hint, not a platform (26% precision)');
  assert.ok(pages.hints.includes('cloudflare-pages'));
});
await t('fingerprint 0.6.1: nextra / readme.io / squarespace need an asset path or bootstrap symbol, not a substring', () => {
  const font = fingerprintFromResponse(fr(200, '<html><head><style>font-family: PantonExtraBold;</style></head></html>', 'text/html'));
  assert.ok(!font.platforms.includes('nextra'), 'nExtraBold must not match nextra');
  const prose = fingerprintFromResponse(fr(200, '<html><body><p>Our docs moved from readme.io to Squarespace, see https://readme.io/pricing</p></body></html>', 'text/html'));
  assert.ok(!prose.platforms.includes('readme.io') && !prose.platforms.includes('squarespace'), JSON.stringify(prose.platforms));
  assert.equal(fingerprintFromResponse(fr(200, '<html><head><script src="/_next/static/chunks/nextra-theme-docs.js"></script></head></html>', 'text/html')).primary, 'nextra');
  assert.equal(fingerprintFromResponse(fr(200, '<html><head><link href="https://cdn.readme.io/public/x.css"></head></html>', 'text/html')).primary, 'readme.io');
  assert.equal(fingerprintFromResponse(fr(200, '<html><head><script>SQUARESPACE_ROLLUPS = {};</script></head></html>', 'text/html')).primary, 'squarespace');
  assert.equal(fingerprintFromResponse(fr(200, '<html><head><link href="https://static1.squarespace.com/static/x.css"></head></html>', 'text/html')).primary, 'squarespace');
  assert.equal(fingerprintFromResponse(fr(200, '<html><head><meta name="generator" content="Squarespace"></head></html>', 'text/html')).primary, 'squarespace');
});
await t('fingerprint: hubspot/framer/gitbook/webflow in script/link tags are hints, never primary', () => {
  const fp = fingerprintFromResponse(fr(200, '<html><head><script src="https://js.hs-scripts.com/123.js"></script><link href="https://framerusercontent.com/x.css"><a href="https://docs.gitbook.com">gitbook</a><script src="https://assets.webflow.com/x.js"></script></head></html>', 'text/html', { server: 'nginx' }));
  assert.deepEqual(fp.hints.sort(), ['framer', 'gitbook', 'hubspot', 'webflow']);
  assert.equal(fp.primary, 'nginx');
  for (const h of fp.hints) assert.ok(!fp.platforms.includes(h));
  // a generator tag is strong evidence and still counts
  const gen = fingerprintFromResponse(fr(200, '<html><head><meta name="generator" content="Webflow"></head></html>', 'text/html'));
  assert.equal(gen.primary, 'webflow');
  assert.deepEqual(gen.hints, []);
});

// ---- hygiene helpers ----
await t('rfc8414 metadata url with path issuer', () => {
  assert.equal(authServerMetadataUrl('https://auth.x.test/realm/a/'), 'https://auth.x.test/.well-known/oauth-authorization-server/realm/a');
  assert.equal(authServerMetadataUrl('https://auth.x.test'), 'https://auth.x.test/.well-known/oauth-authorization-server');
});
await t('prm urls derived from endpoint path then root', () => {
  assert.deepEqual(prmUrlsForEndpoint('https://mcp.x.test/v1/mcp'), [
    { url: 'https://mcp.x.test/.well-known/oauth-protected-resource/v1/mcp', location: 'path_suffixed' },
    { url: 'https://mcp.x.test/.well-known/oauth-protected-resource', location: 'root' },
  ]);
  assert.deepEqual(prmUrlsForEndpoint('https://mcp.x.test/'), [{ url: 'https://mcp.x.test/.well-known/oauth-protected-resource', location: 'root' }]);
});
await t('extract endpoint from remotes / transport', () => {
  assert.equal(extractEndpoint({ name: 'x', remotes: [{ type: 'sse', url: 'https://m.test/sse' }] }), 'https://m.test/sse');
  assert.equal(extractEndpoint({ name: 'x', transport: { type: 'http', url: 'https://m.test/mcp' } }), 'https://m.test/mcp');
  assert.equal(extractEndpoint({ name: 'x', servers: [{ url: 'https://m.test/a' }] }), 'https://m.test/a');
});

// ---- identity / preflight ----
await t('user-agent: version 0.6 and env-configurable contact URL / mailbox', () => {
  assert.ok(CRAWLER_VERSION.startsWith('0.6.'));
  const saved = { u: process.env.CRAWLER_CONTACT_URL, e: process.env.CRAWLER_CONTACT_EMAIL };
  process.env.CRAWLER_CONTACT_URL = 'https://lab.example/crawler';
  process.env.CRAWLER_CONTACT_EMAIL = 'crawler@lab.example';
  const ua = userAgent();
  assert.ok(ua.startsWith('AgentDiscoveryCrawler/0.6 '), ua);
  assert.ok(ua.includes('+https://lab.example/crawler') && ua.includes('mailto:crawler@lab.example'));
  assert.ok(!/example\.org|placeholder/.test(ua));
  if (saved.u === undefined) delete process.env.CRAWLER_CONTACT_URL; else process.env.CRAWLER_CONTACT_URL = saved.u;
  if (saved.e === undefined) delete process.env.CRAWLER_CONTACT_EMAIL; else process.env.CRAWLER_CONTACT_EMAIL = saved.e;
});
await t('preflight refuses a non-fixture corpus without contact env, allows fixtures', () => {
  assert.equal(contactPreflight(['good.fixture', 'spa.fixture'], {}), null);
  assert.match(contactPreflight(['example.com'], {}) ?? '', /CRAWLER_CONTACT_URL and CRAWLER_CONTACT_EMAIL/);
  assert.match(contactPreflight(['example.com'], { url: 'https://x' }) ?? '', /CRAWLER_CONTACT_EMAIL/);
  assert.equal(contactPreflight(['example.com'], { url: 'https://x', email: 'a@b' }), null);
  assert.ok(contactPreflight(['good.fixture', 'example.com'], {}) !== null); // mixed corpus counts as real
});

// ---- blocked rule ----
function mkProbe(path: string, status: number, error?: string, final_url = 'https://x.test' + path): ProbeResult {
  return { path, artifact: spec(path).artifact, status, final_url, content_type: null, bytes: 0, sha256: '', redirects: 0, cross_origin_hit: false, www_redirect: false, elapsed_ms: 1, error, simhash: '0', nx_similarity: null, soft404: false, valid: false, reasons: [] };
}
function mkHost(status: number, error?: string, final_url?: string) {
  const probes = PROBE_SPECS.map((s) => mkProbe(s.path, status, error, final_url));
  const raw = new Map<string, FetchResult>(probes.map((p) => [p.path, fr(status, '', null)]));
  const baselines: NxBaseline[] = [{ ...nxb(status, '', null), error }, { ...nxb(status, '', null), error }];
  return { probes, raw, baselines };
}
await t('computeBlocked: TLS failure is unreachable:tls, not blocked', () => {
  const h = mkHost(0, 'tls');
  const b = computeBlocked(h.probes, h.raw, h.baselines);
  assert.equal(b.blocked, false);
  assert.match(b.reason ?? '', /^unreachable:tls on 16\/16/);
  const r = mkHost(0, 'reset');
  assert.equal(computeBlocked(r.probes, r.raw, r.baselines).blocked, true);
});
await t('redirect_only: every probe left the domain -> tagged and excluded from reachable', () => {
  const h = mkHost(301, 'cross_domain_redirect', 'https://elsewhere.example/');
  assert.equal(isRedirectOnly(h.probes, h.baselines), true);
  const mixed = mkHost(301, 'cross_domain_redirect', 'https://elsewhere.example/');
  mixed.probes[0] = mkProbe(mixed.probes[0].path, 404);
  assert.equal(isRedirectOnly(mixed.probes, mixed.baselines), false);
  assert.equal(computeBlocked(h.probes, h.raw, h.baselines).blocked, false);
  const host = { blocked: { blocked: false, reason: 'redirect_only -> elsewhere.example', counts: {} }, redirect_only: true } as unknown as HostResult;
  assert.equal(hostClass(host), 'redirect_only');
  assert.equal(hostClass({ blocked: { blocked: false, reason: null, counts: {} }, redirect_only: false } as unknown as HostResult), 'reachable');
});

// ---- summarize streams ----
await t('summarize: streams JSONL line by line, skips corrupt lines, excludes redirect_only from denominator', async () => {
  const mk = (host: string, extra: Partial<HostResult>): HostResult => ({
    host, registrable_domain: host, vantage: 't', ts: '', crawler_version: CRAWLER_VERSION, duration_ms: 1,
    blocked: { blocked: false, reason: null, counts: {} }, redirect_only: false,
    fingerprint: { homepage_status: 200, homepage_final_url: null, server: null, powered_by: null, generator: null, platforms: [], primary: 'unknown', cdn: null, hints: [], signals: [] },
    nx_baselines: [], mcp_card_path: null, probe_order: [], hygiene: [],
    probes: PROBE_SPECS.map((s) => ({ ...mkProbe(s.path, 404), valid: s.path === '/llms.txt' && host === 'a.test' })),
    ...extra,
  });
  const lines = [
    JSON.stringify(mk('a.test', {})),
    '{"host": "truncated',
    JSON.stringify(mk('r.test', { redirect_only: true, blocked: { blocked: false, reason: 'redirect_only -> x', counts: {} } })),
    JSON.stringify(mk('b.test', {})),
    '',
  ].join('\n');
  const sum = await summarizeStream(Readable.from([lines]));
  assert.equal(sum.total, 3);
  assert.equal(sum.classes.get('reachable'), 2);
  assert.equal(sum.classes.get('redirect_only'), 1);
  const out = sum.render();
  assert.match(out, /reachable: 2 .*redirect-only: 1/);
  assert.match(out, /\/llms\.txt +1 \(33\.3%\) +1 \(50\.0%\)/); // all-hosts vs reachable denominators
});
await t('summarize: www column is separate from x-origin', async () => {
  const base = (host: string, patch: Partial<ProbeResult>): HostResult => ({
    host, registrable_domain: host, vantage: 't', ts: '', crawler_version: CRAWLER_VERSION, duration_ms: 1,
    blocked: { blocked: false, reason: null, counts: {} }, redirect_only: false,
    fingerprint: { homepage_status: 200, homepage_final_url: null, server: null, powered_by: null, generator: null, platforms: [], primary: 'unknown', cdn: null, hints: [], signals: [] },
    nx_baselines: [], mcp_card_path: null, probe_order: [], hygiene: [],
    probes: PROBE_SPECS.map((s) => (s.path === '/llms.txt' ? { ...mkProbe(s.path, 200), valid: true, ...patch } : mkProbe(s.path, 404))),
  });
  const sum = await summarizeStream(Readable.from([[
    JSON.stringify(base('w.test', { www_redirect: true })),
    JSON.stringify(base('x.test', { cross_origin_hit: true })),
    JSON.stringify(base('p.test', {})),
  ].join('\n')]));
  const acc = sum.paths.get('/llms.txt')!;
  assert.equal(acc.validAll, 3);
  assert.equal(acc.xo, 1);
  assert.equal(acc.www, 1);
  const out = sum.render();
  assert.match(out, /x-origin +www/);
  assert.match(out, /\/llms\.txt .*  1 +1 *\n/); // ... x-origin=1 www=1 at the end of the row
});

// ---- banner / progress ----
await t('banner estimate: hosts/concurrency x 16 requests at rps', () => {
  assert.equal(REQUESTS_PER_HOST, 16);
  assert.equal(estimateDurationSec(1000, 20, 1), 50 * 16);
  assert.equal(estimateDurationSec(1000, 20, 2), 50 * 8);
  assert.equal(estimateDurationSec(0, 20, 1), 0);
  assert.equal(fmtDuration(45), '45s');
  assert.equal(fmtDuration(800), '13m20s');
  assert.equal(fmtDuration(3700), '1h01m');
});
await t('progress line: done/total, reachable, blocked, elapsed, eta', () => {
  const line = progressLine({ done: 250, total: 1000, reachable: 200, blocked: 30, startedAt: 1_000_000 }, 1_000_000 + 600_000);
  assert.match(line, /^progress: 250\/1000 done \(25\.0%\) +reachable=200 blocked=30 +elapsed=10m00s +eta=30m00s$/);
  assert.match(progressLine({ done: 0, total: 10, reachable: 0, blocked: 0, startedAt: 0 }, 1000), /eta=\?$/);
});

// ---- Tranco corpus loader (offline, inline CSV fixture) ----
const trancoCsv = [
  '1,google.com', '2,youtube.com', '3,www.google.com', '4,mail.google.com', '5,example.co.uk',
  '6,foo.github.io', '7,bar.github.io', '8,1.2.3.4', '9,shop.example.co.uk', '10,example.net',
  '11,docs.example.net', '12,tenth.org', '13,eleventh.org', '14,twelfth.org',
].join('\r\n') + '\r\n';
await t('tranco: band parsing', () => {
  assert.deepEqual(parseBand('1-1k'), { label: '1-1k', from: 1, to: 1000 });
  assert.deepEqual(parseBand('1k-10k'), { label: '1k-10k', from: 1001, to: 10_000 });
  assert.deepEqual(parseBand('10k-100k'), { label: '10k-100k', from: 10_001, to: 100_000 });
  assert.deepEqual(parseBands(undefined).map((b) => b.label), ['1-1k', '1k-10k', '10k-100k']);
  assert.deepEqual(parseBands('1-5,5-10').map((b) => [b.from, b.to]), [[1, 5], [6, 10]]);
  assert.throws(() => parseBand('10k-1k'));
  assert.throws(() => parseBand('nope'));
});
await t('tranco: CSV parse tolerates CRLF/BOM/header; dedupe to registrable domain preserves rank order across bands', () => {
  const rows = parseTrancoCsv('\uFEFFrank,domain\n' + trancoCsv);
  assert.equal(rows.length, 14);
  assert.deepEqual(rows[0], { rank: 1, domain: 'google.com' });
  const [b1, b2] = buildBands(rows, parseBands('1-5,5-10'));
  assert.deepEqual(b1.hosts.map((h) => h.domain), ['google.com', 'youtube.com', 'example.co.uk']);
  assert.equal(b1.input_rows, 5);
  assert.equal(b1.dedupe_losses, 2); // www.google.com, mail.google.com
  assert.equal(b1.unparseable, 0);
  // github.io is public-suffix only with the private section, which is OFF here: both collapse to github.io
  assert.deepEqual(b2.hosts.map((h) => h.domain), ['github.io', 'example.net']);
  assert.equal(b2.dedupe_losses, 2); // bar.github.io, shop.example.co.uk (already seen in band 1)
  assert.equal(b2.unparseable, 1); // 1.2.3.4
  assert.deepEqual(b2.hosts.map((h) => h.rank), [6, 10]);
});
await t('tranco: minimal zip reader (stored + deflate) and csvFromZip', () => {
  const crc = (buf: Buffer) => { let c = ~0; for (const b of buf) { c ^= b; for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); } return ~c >>> 0; };
  const mkZip = (files: { name: string; data: Buffer; deflate: boolean }[]) => {
    const locals: Buffer[] = []; const centrals: Buffer[] = []; let off = 0;
    for (const f of files) {
      const comp = f.deflate ? deflateRawSync(f.data) : f.data;
      const name = Buffer.from(f.name);
      const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(f.deflate ? 8 : 0, 8);
      lh.writeUInt32LE(crc(f.data), 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(f.data.length, 22); lh.writeUInt16LE(name.length, 26);
      const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(f.deflate ? 8 : 0, 10);
      ch.writeUInt32LE(crc(f.data), 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(f.data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(off, 42);
      locals.push(lh, name, comp); centrals.push(ch, name); off += lh.length + name.length + comp.length;
    }
    const cd = Buffer.concat(centrals);
    const eocd = Buffer.alloc(22); eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10); eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(off, 16);
    return Buffer.concat([...locals, cd, eocd]);
  };
  const zip = mkZip([{ name: 'README', data: Buffer.from('ignore me'), deflate: false }, { name: 'top-1m.csv', data: Buffer.from(trancoCsv), deflate: true }]);
  const entries = readZip(zip);
  assert.deepEqual(entries.map((e) => e.name), ['README', 'top-1m.csv']);
  assert.equal(entries[1].data.toString(), trancoCsv);
  assert.equal(csvFromZip(zip), trancoCsv);
  assert.throws(() => readZip(Buffer.from('not a zip at all, definitely not')));
});
await t('tranco: writes band files, latest copies and meta sidecar', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tranco-'));
  const results = buildBands(parseTrancoCsv(trancoCsv), parseBands('1-5,5-10'));
  const now = new Date('2026-10-04T12:00:00Z');
  const { meta, metaPath } = writeCorpus(results, 14, { outDir: dir, listId: 'K25GW', source: 'inline', now, crawlerVersion: CRAWLER_VERSION });
  assert.equal(metaPath, join(dir, 'tranco-K25GW.meta.json'));
  const band1 = readFileSync(join(dir, 'tranco-K25GW-1-5.txt'), 'utf8');
  assert.equal(band1, renderBandFile(meta, results[0]));
  assert.match(band1, /^# tranco K25GW ranks 1-5/);
  assert.ok(band1.endsWith('1,google.com\n2,youtube.com\n5,example.co.uk\n'));
  assert.equal(readFileSync(join(dir, 'tranco-latest-1-5.txt'), 'utf8'), band1);
  assert.ok(existsSync(join(dir, 'tranco-latest-5-10.txt')));
  const m = JSON.parse(readFileSync(metaPath, 'utf8'));
  assert.equal(m.list_id, 'K25GW');
  assert.equal(m.csv_rows, 14);
  assert.equal(m.bands['1-5'].hosts, 3);
  assert.equal(m.bands['1-5'].dedupe_losses, 2);
  assert.equal(m.bands['5-10'].unparseable, 1);
  assert.equal(m.crawler_version, CRAWLER_VERSION);
  // the host reader accepts the rank,domain rows
  const nh = normalizeHost('5,example.co.uk');
  assert.equal(nh, 'example.co.uk');
  // without a list id the tag is the date
  const d = writeCorpus(results, 14, { outDir: dir, listId: null, source: 'inline', now, crawlerVersion: CRAWLER_VERSION });
  assert.equal(d.meta.list_tag, '2026-10-04');
  assert.ok(existsSync(join(dir, 'tranco-2026-10-04-1-5.txt')));
});

// ---- 0.6.0: MCP-registry corpus loader (offline, recorded page shapes) ----
await t('registry: endpointHost keeps hostnames, drops templates, forges, IPs, loopback, non-http', () => {
  assert.equal(endpointHost('https://mcp.example.com/mcp'), 'mcp.example.com');
  assert.equal(endpointHost('HTTPS://API.Example.COM:443/v1/sse?x=1'), 'api.example.com');
  assert.equal(endpointHost('https://{tenant}.example.com/mcp'), null);
  assert.equal(endpointHost('https://github.com/foo/bar'), null);
  assert.equal(endpointHost('https://server.smithery.ai/foo/mcp'), null);
  assert.equal(endpointHost('https://127.0.0.1:8080/mcp'), null);
  assert.equal(endpointHost('http://localhost:3000/mcp'), null);
  assert.equal(endpointHost('npx -y foo'), null);
  assert.equal(endpointHost('stdio'), null);
});
const officialPage1 = {
  servers: [
    { server: { name: 'io.github.acme/weather', remotes: [{ type: 'streamable-http', url: 'https://mcp.acme.example/mcp' }, { type: 'sse', url: 'https://mcp.acme.example/sse' }] } },
    { server: { name: 'io.github.bob/local', packages: [{ registryType: 'npm', identifier: 'bob-mcp' }] } },
    { server: { name: 'com.github/notes', remotes: [{ type: 'streamable-http', url: 'https://api.github.com/mcp' }] } },
    { server: { name: 'io.github.t/tenant', remotes: [{ type: 'streamable-http', url: 'https://{sub}.tenant.example/mcp' }] } },
  ],
  metadata: { nextCursor: 'abc', count: 4 },
};
const officialPage2 = { servers: [{ server: { name: 'io.github.c/docs', remotes: [{ type: 'streamable-http', url: 'https://docs.c.example/mcp' }] } }], metadata: { nextCursor: null, count: 1 } };
await t('registry: official pages -> endpoint rows, cursor, dedupe at hostname', () => {
  const rows = extractOfficial(officialPage1);
  assert.deepEqual(rows.map((r) => [r.host, r.transport]), [['mcp.acme.example', 'streamable-http'], ['mcp.acme.example', 'sse']]);
  assert.equal(officialNextCursor(officialPage1), 'abc');
  assert.equal(officialNextCursor(officialPage2), null);
  assert.deepEqual(dedupeHosts([...rows, ...extractOfficial(officialPage2)]), ['docs.c.example', 'mcp.acme.example']);
});
await t('registry: pageOfficial follows nextCursor with a fake fetcher', async () => {
  const seen: string[] = [];
  const fetch = async (url: string) => { seen.push(url); return url.includes('cursor=abc') ? officialPage2 : officialPage1; };
  const r = await pageOfficial(fetch, () => {});
  assert.equal(seen.length, 2);
  assert.ok(seen[1].includes('cursor=abc'));
  assert.equal(r.servers, 5);
  assert.equal(r.rows.length, 3);
});
await t('registry: glama walker picks url/endpoint-ish keys, skips repository/homepage; smithery detail -> connections', () => {
  const g = { servers: [{ slug: 'x', url: 'https://glama.ai/mcp/servers/x', repository: { url: 'https://github.com/x/y' }, homepageUrl: 'https://x.example', remotes: [{ transport: 'sse', sseUrl: 'https://mcp.x.example/sse' }] }], pageInfo: { endCursor: 'c1', hasNextPage: true } };
  const rows = extractGlama(g);
  assert.deepEqual(rows.map((r) => [r.host, r.transport]), [['mcp.x.example', 'sse']]);
  assert.equal(glamaNext(g), 'c1');
  assert.equal(glamaNext({ pageInfo: { endCursor: 'c2', hasNextPage: false } }), null);
  const s = extractSmitheryDetail('@acme/foo', { connections: [{ type: 'http', deploymentUrl: 'https://server.smithery.ai/@acme/foo/mcp' }, { type: 'http', deploymentUrl: 'https://foo.acme.example/mcp' }] });
  assert.deepEqual(s.map((r) => r.host), ['foo.acme.example']);
});
await t('registry: writeRegistryCorpus writes hosts (+ Tranco rank by host or parent), endpoints sidecar and meta', () => {
  const dir = mkdtempSync(join(tmpdir(), 'reg-'));
  const tranco = join(dir, 'tranco.txt');
  writeFileSync(tranco, '# x\n1,acme.example\n2,other.example\n');
  const rows = [...extractOfficial(officialPage1), ...extractOfficial(officialPage2)];
  const { meta } = writeRegistryCorpus(rows, { official: { servers: 5, endpoints: 3, hosts: 0 } }, { outDir: dir, trancoFiles: [tranco], now: new Date('2026-10-06T00:00:00Z') });
  assert.equal(meta.hosts, 2);
  assert.equal(meta.hosts_in_tranco, 1);
  assert.equal(meta.sources.official?.hosts, 2);
  const txt = readFileSync(join(dir, 'registry-latest.txt'), 'utf8');
  assert.ok(txt.includes('\n1,mcp.acme.example\n'));
  assert.ok(txt.includes('\ndocs.c.example\n'));
  assert.equal(readFileSync(join(dir, 'registry-2026-10-06.endpoints.jsonl'), 'utf8').trim().split('\n').length, 3);
  assert.equal(trancoRankFor('deep.sub.other.example', loadTrancoRanks([tranco])), 2);
  assert.equal(trancoRankFor('nothing.example', loadTrancoRanks([tranco])), null);
  const plat = new Map([['workers.dev', 82], ['sslip.io', 2339], ['vercel.app', 500], ['github.io', 300], ['example.com', 7]]);
  assert.equal(trancoRankFor('foo.michael.workers.dev', plat), null, 'private-suffix platform subdomains do not inherit the platform rank');
  assert.equal(trancoRankFor('1-2-3-4.sslip.io', plat), null);
  assert.equal(trancoRankFor('x.vercel.app', plat), null);
  assert.equal(trancoRankFor('mcp.api.example.com', plat), 7);
  assert.equal(trancoRankFor('workers.dev', plat), 82, 'the platform apex itself still matches');
});

// ---- 0.6.0: Cloudflare Radar commerce / fintech corpus (offline) ----
const intelShop = { domain: 'shop.example', popularity_rank: 1234, content_categories: [{ id: 32, name: 'Shopping & Auctions', super_category_id: 26 }, { id: 7, name: 'Business & Economy', super_category_id: 2 }], application: { id: 1, name: 'x' } };
await t('radar/intel: parse bulk and single bodies; missing domains are not_found; failures are errors', () => {
  const l = parseIntelItem('shop.example', 50, intelShop, new Date('2026-10-06T00:00:00Z'));
  assert.equal(l.status, 'ok'); assert.equal(l.radar_rank, 1234); assert.equal(l.source, LABEL_SOURCE);
  assert.deepEqual(l.categories, [{ id: 32, name: 'Shopping & Auctions', superCategoryId: 26 }, { id: 7, name: 'Business & Economy', superCategoryId: 2 }]);
  const hosts = [{ host: 'shop.example', rank: 2 }, { host: 'gone.example', rank: 3 }];
  const bulk = parseIntelBody(hosts, { success: true, errors: [], result: [{ domain: 'Shop.Example.', popularity_rank: 9, content_categories: [] }] });
  assert.deepEqual(bulk.map((x) => [x.host, x.status]), [['shop.example', 'ok'], ['gone.example', 'not_found']]);
  const single = parseIntelBody([hosts[0]], { success: true, result: intelShop });
  assert.equal(single[0].categories.length, 2);
  assert.equal(parseIntelBody(hosts, { success: false, errors: [{ message: 'internal' }] })[1].status, 'error');
  assert.equal(parseIntelBody(hosts, 'garbage')[0].status, 'error');
});
await t('radar: classify by category name regexes', () => {
  const mk = (names: string[]): RadarLabel => ({ host: 'h', rank: null, fetched_at: '', status: 'ok', radar_rank: null, bucket: null, source: LABEL_SOURCE, categories: names.map((name) => ({ id: null, name, superCategoryId: null })) });
  assert.deepEqual(classify(mk(['Shopping & Auctions'])), { commerce: true, fintech: false });
  assert.deepEqual(classify(mk(['Economy & Finance', 'Banking'])), { commerce: false, fintech: true });
  assert.deepEqual(classify(mk(['Cryptocurrency', 'Shopping'])), { commerce: true, fintech: true });
  assert.deepEqual(classify(mk(['Technology', 'News'])), { commerce: false, fintech: false });
  assert.deepEqual(classify(mk(['Retail'])), { commerce: true, fintech: false });
});
await t('radar: pacer spaces starts at ~rps', async () => {
  const pace = makePacer(50); // 20 ms apart
  const t0 = Date.now();
  for (let i = 0; i < 5; i++) await pace();
  const el = Date.now() - t0;
  assert.ok(el >= 70 && el < 400, `elapsed ${el}ms`);
});
await t('radar/intel: labelHosts against a loopback stand-in: skips cached hosts, ignores legacy rows, batches, retries 429, caches misses, stops on 403; then selection', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'radar-'));
  const cache = join(dir, 'labels.jsonl');
  writeFileSync(cache,
    JSON.stringify({ host: 'done.example', rank: 1, fetched_at: '2026-10-01T00:00:00Z', status: 'ok', radar_rank: 1, bucket: null, source: LABEL_SOURCE, categories: [{ id: 1, name: 'Banking', superCategoryId: null }] }) + '\n' +
    JSON.stringify({ host: 'legacy.example', rank: 4, fetched_at: '2026-10-01T00:00:00Z', status: 'ok', radar_rank: null, bucket: '1000', categories: [] }) + '\n');
  const have = await readLabels(cache);
  assert.equal(have.size, 1, 'legacy Radar-ranking rows without source are ignored');
  const hosts = [{ host: 'done.example', rank: 1 }, { host: 'shop.example', rank: 2 }, { host: 'gone.example', rank: 3 }, { host: 'legacy.example', rank: 4 }];
  const calls: string[][] = [];
  let first429 = true;
  const intel = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://x');
    const asked = u.searchParams.getAll('domain');
    calls.push(asked);
    if (req.headers.authorization !== 'Bearer tok') { res.writeHead(403, { 'content-type': 'application/json' }); res.end('{"success":false,"errors":[{"message":"auth"}]}'); return; }
    if (first429) { first429 = false; res.writeHead(429, { 'retry-after': '0' }); res.end(''); return; }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ success: true, errors: [], result: asked.filter((d) => d !== 'gone.example').map((d) => (d === 'shop.example' ? intelShop : { domain: d, content_categories: [{ id: 2, name: 'Technology', super_category_id: 1 }] })) }));
  });
  await new Promise<void>((r) => intel.listen(0, '127.0.0.1', r));
  const port = (intel.address() as { port: number }).port;
  process.env.CRAWLER_INTEL_URL = `http://127.0.0.1:${port}/bulk`;
  try {
    const r = await labelHosts(hosts, { token: 'tok', accountId: 'acc', cachePath: cache, have, rps: 100, concurrency: 2, batch: 2, timeoutMs: 5_000, log: () => {} });
    assert.deepEqual(r, { asked: 3, ok: 2, not_found: 1, errors: 0, requests: 3 }, JSON.stringify(r));
    assert.ok(!calls.flat().includes('done.example'), 'cached host must not be fetched');
    assert.deepEqual(calls[0], ['shop.example', 'gone.example'], 'batched two per call');
    assert.equal((await readLabels(cache)).size, 4, 'misses are cached too');
    await assert.rejects(labelHosts([{ host: 'new.example', rank: 9 }], { token: 'bad', accountId: 'acc', cachePath: cache, have, rps: 100, concurrency: 1, batch: 2, timeoutMs: 5_000, log: () => {} }), /token or account rejected/);
  } finally {
    delete process.env.CRAWLER_INTEL_URL;
    intel.close();
  }
  const { meta } = writeRadarCorpus(hosts, have, { outDir: dir, trancoFiles: ['t.txt'], labelsPath: cache, now: new Date('2026-10-06T00:00:00Z') });
  assert.deepEqual(meta.labelled, { ok: 3, not_found: 1, error: 0, unlabelled: 0 });
  assert.equal(meta.commerce, 1); assert.equal(meta.fintech, 1); assert.equal(meta.overlap, 0);
  assert.equal(meta.labels_window.first, '2026-10-01T00:00:00Z');
  assert.ok(readFileSync(join(dir, 'commerce-latest.txt'), 'utf8').includes('\n2,shop.example\n'));
  assert.ok(readFileSync(join(dir, 'fintech-latest.txt'), 'utf8').includes('\n1,done.example\n'));
  assert.ok(existsSync(join(dir, 'radar-2026-10-06.meta.json')));
  assert.deepEqual(meta.categories_top[0], { name: 'Banking', hosts: 1 });
});

// ---- 0.6.0: fingerprint precision sample (offline) ----
await t('fp-sample: stratified seeded draw is deterministic, caps per label, skips small labels and unreachable', () => {
  const pool: Array<{ host: string; rank: number | null; primary: string; source: string }> = [];
  const mk = (label: string, n: number) => { for (let i = 0; i < n; i++) pool.push({ host: `${label}${i}.example`, rank: i + 1, primary: label, source: 'f' }); };
  mk('wordpress', 50); mk('shopify', 25); mk('nextjs', 20); mk('ghost', 5); mk('unknown', 300); mk('unreachable', 30);
  const a = drawSample(pool, { perLabel: 20, unknownN: 40, seed: 7 });
  const b = drawSample(pool, { perLabel: 20, unknownN: 40, seed: 7 });
  assert.deepEqual(a.sample.map((s) => s.host), b.sample.map((s) => s.host));
  assert.deepEqual(a.strata.wordpress, { pool: 50, drawn: 20 });
  assert.deepEqual(a.strata.nextjs, { pool: 20, drawn: 20 });
  assert.deepEqual(a.strata.ghost, { pool: 5, drawn: 0 });
  assert.deepEqual(a.strata.unknown, { pool: 300, drawn: 40 });
  assert.deepEqual(a.strata.unreachable, { pool: 30, drawn: 0 });
  assert.equal(a.sample.length, 100);
  assert.equal(new Set(a.sample.map((s) => s.host)).size, 100, 'without replacement');
  assert.notDeepEqual(drawSample(pool, { perLabel: 20, unknownN: 40, seed: 8 }).sample.map((s) => s.host), a.sample.map((s) => s.host));
  // blind order carries no label information: first 20 are not all one stratum
  assert.ok(new Set(a.sample.slice(0, 20).map((s) => s.stratum)).size > 1);
  assert.deepEqual(shuffle([1, 2, 3], mulberry32(1)).sort(), [1, 2, 3]);
});
await t('fp-sample: evidence extraction uses generator, foreign asset domains, title and headers; self-domain assets excluded', () => {
  const html = `<html><head><title> My   Shop </title><meta name="generator" content="WordPress 6.6"><link rel="stylesheet" href="https://cdn.shopify.com/s/files/x.css"><script src="//cdn.shopify.com/s/js/a.js"></script><script src="https://static.myshop.example/app.js"></script><img src="https://www.googletagmanager.com/x.png"><script src="https://cdn.shopify.com/b.js"></script></head><body></body></html>`;
  const ev = extractEvidence('myshop.example', 42, html, { server: 'nginx', 'x-powered-by': 'PHP/8' }, 200, 'https://www.myshop.example/');
  assert.equal(ev.title, 'My Shop');
  assert.equal(ev.generator, 'WordPress 6.6');
  assert.deepEqual(ev.asset_domains, ['shopify.com', 'googletagmanager.com']);
  assert.equal(ev.asset_domain_counts['shopify.com'], 3);
  assert.equal(ev.server, 'nginx'); assert.equal(ev.powered_by, 'PHP/8'); assert.equal(ev.x_generator, null);
  assert.ok(ev.html_head.length <= 2000 && ev.html_head.includes('generator'));
});
await t('fp-sample: blind CSV has no predicted column and round-trips through the parser; score gives precision/recall/kappa', () => {
  const evs: import('./fingerprint-sample.js').Evidence[] = [
    { host: 'a.example', rank: 1, fetched_at: '', status: 200, final_url: 'https://a.example/', title: 'A, "quoted"', generator: null, server: 'nginx', powered_by: null, x_generator: null, asset_domains: ['wp.com'], asset_domain_counts: { 'wp.com': 1 }, platform_paths_200: ['/wp-login.php'], html_head: '' },
    { host: 'b.example', rank: 2, fetched_at: '', status: 200, final_url: null, title: null, generator: 'Hugo', server: null, powered_by: null, x_generator: null, asset_domains: [], asset_domain_counts: {}, platform_paths_200: [], html_head: '' },
  ];
  const csv = renderBlindCsv(evs);
  assert.ok(!/predicted|stratum/.test(csv));
  const rows = parseCsv(csv);
  assert.equal(rows.length, 2); assert.equal(rows[0].title, 'A, "quoted"'); assert.equal(rows[0].truth, ''); assert.equal(rows[1].generator, 'Hugo');
  const sample = [
    { host: 'a.example', rank: 1, predicted: 'wordpress', stratum: 'wordpress', source: 'f' },
    { host: 'b.example', rank: 2, predicted: 'hugo', stratum: 'hugo', source: 'f' },
    { host: 'c.example', rank: 3, predicted: 'wordpress', stratum: 'wordpress', source: 'f' },
    { host: 'd.example', rank: 4, predicted: 'unknown', stratum: 'unknown', source: 'f' },
    { host: 'e.example', rank: 5, predicted: 'unknown', stratum: 'unknown', source: 'f' },
    { host: 'f.example', rank: 6, predicted: 'shopify', stratum: 'shopify', source: 'f' },
  ];
  const truth = new Map([['a.example', 'wordpress'], ['b.example', 'hugo'], ['c.example', 'shopify'], ['d.example', 'none'], ['e.example', 'wordpress'], ['f.example', '?']]);
  const sc = fpScore(sample, truth);
  assert.equal(sc.rated, 5); assert.equal(sc.undecidable, 1);
  assert.equal(sc.per_label.wordpress.precision, 0.5); // a right, c wrong
  assert.equal(sc.per_label.wordpress.recall, 0.5); // a found, e missed (unknown)
  assert.equal(sc.per_label.hugo.precision, 1);
  assert.equal(sc.per_label.unknown.precision, 0.5);
  assert.ok(Math.abs(sc.accuracy - 0.6) < 1e-9);
  assert.ok(sc.kappa > 0 && sc.kappa < 1, String(sc.kappa));
  assert.deepEqual(sc.confusions.map((c) => c.host), ['c.example', 'e.example']);
});

// ---- 0.6.1: vantage comparison ----
await t('vantage-compare: class matrix, one-vantage blocks, per-path agreement, union prevalence, geo-routing', () => {
  const mk = (host: string, validPaths: string[], extra: Partial<HostResult> = {}, finalFor: Record<string, string> = {}): HostResult => ({
    host, registrable_domain: host, vantage: 't', ts: '', crawler_version: CRAWLER_VERSION, duration_ms: 1,
    blocked: { blocked: false, reason: null, counts: {} }, redirect_only: false,
    fingerprint: { homepage_status: 200, homepage_final_url: null, server: null, powered_by: null, generator: null, platforms: [], primary: 'unknown', cdn: null, hints: [], signals: [] },
    nx_baselines: [], mcp_card_path: null, probe_order: [], hygiene: [],
    probes: PROBE_SPECS.map((s) => ({ ...mkProbe(s.path, validPaths.includes(s.path) ? 200 : 404), valid: validPaths.includes(s.path), final_url: finalFor[s.path] ?? `https://${host}${s.path}` })),
    ...extra,
  });
  const blocked = (host: string): HostResult => mk(host, [], { blocked: { blocked: true, reason: 'challenge', counts: {} } });
  const A = new Map<string, HostResult>([
    ['x.test', mk('x.test', ['/llms.txt', '/openapi.json'])],
    ['y.test', mk('y.test', ['/llms.txt'])],
    ['z.test', blocked('z.test')],
    ['w.test', mk('w.test', [])],
    ['onlyA.test', mk('onlyA.test', ['/llms.txt'])],
  ]);
  const B = new Map<string, HostResult>([
    ['x.test', mk('x.test', ['/llms.txt'], {}, { '/llms.txt': 'https://eu.x.test/llms.txt' })],
    ['y.test', mk('y.test', ['/llms.txt', '/.well-known/security.txt'])],
    ['z.test', mk('z.test', ['/llms.txt'])],
    ['w.test', blocked('w.test')],
    ['onlyB.test', mk('onlyB.test', [])],
  ]);
  const c = vCompare(A, B, 'local', 'eu');
  assert.equal(c.common, 4); assert.equal(c.reachable_both, 2);
  assert.equal(c.class_matrix.reachable.reachable, 2); assert.equal(c.class_matrix.blocked.reachable, 1); assert.equal(c.class_matrix.reachable.blocked, 1);
  assert.deepEqual(c.blocked_one_vantage, { a_only: ['z.test'], b_only: ['w.test'] });
  const llms = c.paths.find((p) => p.path === '/llms.txt')!; const oapi = c.paths.find((p) => p.path === '/openapi.json')!;
  assert.deepEqual([llms.both_valid, llms.a_only, llms.b_only, llms.neither, llms.union_valid], [2, 0, 0, 0, 2]);
  assert.deepEqual([oapi.both_valid, oapi.a_only, oapi.b_only, oapi.neither, oapi.agreement], [0, 1, 0, 1, 0.5]);
  assert.deepEqual(c.any_artifact, { a: 2, b: 2, both: 2, union: 2, a_only_hosts: [], b_only_hosts: [] }); // security.txt alone does not count
  assert.equal(c.cross_origin_disagreements, 1);
  const txt = renderCompare(c);
  assert.ok(txt.includes('reachable at both: 2') && txt.includes('/openapi.json') && txt.includes('geo-routing): 1'));
});

// ---- consistency pass (§4.4): tool extraction, name normalization, Jaccard, llms.txt coverage, selection, summary ----
await t('consistency: card tools from SEP-1649 top-level, capabilities and per-remote lists; OpenAPI ops keyed by operationId else method+path', () => {
  assert.deepEqual(extractCardTools({ tools: [{ name: 'search' }, { name: 'getUser' }, 'raw_name', { nope: 1 }] }), ['search', 'getUser', 'raw_name']);
  assert.deepEqual(extractCardTools({ capabilities: { tools: [{ name: 'a' }] }, remotes: [{ url: 'x', tools: [{ name: 'b' }, { name: 'a' }] }] }), ['a', 'b']);
  assert.deepEqual(extractCardTools({ name: 'sep-2127-card', remotes: [{ type: 'streamable-http', url: 'https://x/mcp' }] }), []);
  assert.deepEqual(extractCardTools(null), []); assert.deepEqual(extractCardTools('str'), []);
  const ops = extractOpenApiOps({ openapi: '3.1.0', paths: { '/users/{id}': { get: { operationId: 'getUser' }, delete: {} }, '/search': { post: { operationId: '  ' } }, '/x': 'bad' } });
  assert.deepEqual(ops.map((o) => o.key), ['getUser', 'delete /users/{id}', 'post /search']);
  assert.deepEqual(extractOpenApiOps({ paths: null }), []);
  assert.equal(extractOpenApiOps(parseStructured('openapi: "3.0.3"\npaths:\n  /s:\n    get:\n      operationId: search\n', true))[0].key, 'search');
  assert.equal(parseStructured('{bad', false), null);
});
await t('consistency: strict key folds case/separators; loose key folds order, plurals, verb synonyms, path params and filler', () => {
  assert.equal(strictKey('listUsers'), strictKey('list_users')); assert.equal(strictKey('List-Users'), 'listusers');
  assert.equal(looseKey('listUsers'), looseKey('users_list')); // order
  assert.equal(looseKey('fetchUser'), looseKey('get_user')); // synonym
  assert.equal(looseKey('getUsers'), looseKey('get user')); // plural
  assert.equal(looseKeyForOp({ key: 'get /api/v1/users/{id}', operationId: null, method: 'get', path: '/api/v1/users/{id}' }), 'get user'); // params + filler dropped
  assert.equal(looseKey('HTTPServerStatus'), 'http server status');
  assert.notEqual(looseKey('createOrder'), looseKey('cancelOrder'));
});
await t('consistency: matchPair reports strict/loose matches, Jaccard over key sets, unmatched tools and nearest-operation candidates', () => {
  const ops = extractOpenApiOps({ paths: { '/users': { get: { operationId: 'listUsers' }, post: { operationId: 'createUser' } }, '/users/{id}': { get: {} }, '/orders': { get: { operationId: 'listOrders' } } } });
  const m = matchPair(['list_users', 'fetchUser', 'add_user', 'refund_order'], ops);
  assert.equal(m.n_tools, 4); assert.equal(m.n_ops, 4);
  assert.equal(m.matched_strict, 1); // list_users = listUsers
  assert.equal(m.matched_loose, 3); // + fetchUser = get /users/{id}, add_user = createUser
  assert.equal(m.jaccard_strict, 1 / 7); assert.equal(m.jaccard_loose, 3 / 5);
  assert.deepEqual(m.unmatched_tools, ['refund_order']);
  const c = m.candidates.find((x) => x.tool === 'refund_order')!;
  assert.equal(c.matched, false); assert.equal(c.best_op, 'listOrders'); assert.ok(c.overlap > 0 && c.overlap < 1);
  assert.equal(jaccard(new Set(), new Set()), null);
  const e = matchPair([], ops); assert.equal(e.jaccard_loose, 0); assert.equal(e.n_tools, 0);
});
await t('consistency: llms.txt links classified as OpenAPI / card / other, relative links resolved against the file URL', () => {
  const txt = '# Site\n\n- [API spec](/openapi.json)\n- [Docs](https://docs.x.test/intro.md)\n- [card](<https://x.test/.well-known/mcp/server-card.json> "t")\nSee https://x.test/swagger.yaml, and https://x.test/v2/openapi.\n';
  const l = llmsLinks(txt, 'https://x.test/llms.txt');
  assert.deepEqual(l.openapi, ['https://x.test/openapi.json', 'https://x.test/swagger.yaml', 'https://x.test/v2/openapi']);
  assert.deepEqual(l.card, ['https://x.test/.well-known/mcp/server-card.json']);
  assert.equal(l.total, 5);
  assert.deepEqual(llmsLinks('no links here', 'https://x.test/llms.txt'), { openapi: [], card: [], total: 0 });
});
await t('consistency: candidate selection from crawl rows (pair = card + OpenAPI; coverage = llms.txt + either), checkHost with an injected fetcher, summary and sample sheet', async () => {
  const mk = (host: string, validPaths: string[]): HostResult => ({
    host, registrable_domain: host, vantage: 't', ts: '', crawler_version: CRAWLER_VERSION, duration_ms: 1,
    blocked: { blocked: false, reason: null, counts: {} }, redirect_only: false,
    fingerprint: { homepage_status: 200, homepage_final_url: null, server: null, powered_by: null, generator: null, platforms: [], primary: 'unknown', cdn: null, hints: [], signals: [] },
    nx_baselines: [], mcp_card_path: null, probe_order: [], hygiene: [],
    probes: PROBE_SPECS.map((s) => ({ ...mkProbe(s.path, validPaths.includes(s.path) ? 200 : 404), valid: validPaths.includes(s.path), final_url: `https://${host}${s.path}`, card_spec: s.path.includes('mcp/server-card') ? 'sep-1649' as const : undefined })),
  });
  assert.equal(selectCandidates(mk('none.test', ['/llms.txt']), 'f'), null);
  assert.equal(selectCandidates(mk('oa.test', ['/openapi.json', '/.well-known/security.txt']), 'f'), null);
  const p = selectCandidates(mk('pair.test', ['/.well-known/mcp/server-card.json', '/openapi.yaml', '/llms.txt']), 'f')!;
  assert.deepEqual([p.pair, p.coverage, p.card_spec, p.openapi_artifact, p.llms_url], [true, true, 'sep-1649', 'openapi_yaml', 'https://pair.test/llms.txt']);
  const cov = selectCandidates(mk('cov.test', ['/llms.txt', '/openapi.json']), 'f')!;
  assert.deepEqual([cov.pair, cov.coverage, cov.card_url], [false, true, null]);
  const two = selectCandidates(mk('two.test', ['/.well-known/mcp-server-card', '/.well-known/mcp/server-card.json', '/openapi.json']), 'f')!;
  assert.deepEqual([two.card_url, two.card_alt_urls], ['https://two.test/.well-known/mcp-server-card', ['https://two.test/.well-known/mcp/server-card.json']]);
  const bodies: Record<string, [number, string]> = {
    'https://pair.test/.well-known/mcp/server-card.json': [200, JSON.stringify({ name: 'c', tools: [{ name: 'search' }, { name: 'getItem' }, { name: 'deleteItem' }] })],
    'https://pair.test/openapi.yaml': [200, 'openapi: "3.0.3"\npaths:\n  /search:\n    get:\n      operationId: search\n  /items/{id}:\n    get:\n      operationId: fetchItem\n'],
    'https://pair.test/llms.txt': [200, '# P\n\n- [spec](/openapi.yaml)\n- [gone](/.well-known/agent-card.json)\n'],
    'https://pair.test/.well-known/agent-card.json': [404, ''],
    'https://cov.test/llms.txt': [200, '# C\n\n- [docs](/docs)\n'],
    'https://two.test/.well-known/mcp-server-card': [200, JSON.stringify({ name: 'sep2127', remotes: [{ url: 'https://two.test/mcp' }] })],
    'https://two.test/.well-known/mcp/server-card.json': [200, JSON.stringify({ name: 'legacy', tools: [{ name: 'ping' }] })],
    'https://two.test/openapi.json': [200, JSON.stringify({ paths: { '/ping': { get: { operationId: 'ping' } } } })],
  };
  const fetch = async (url: string): Promise<FetchResult> => { const [status, body] = bodies[url] ?? [0, '']; return { ...fr(status, body, 'text/plain'), url, finalUrl: url, ...(status === 0 ? { error: 'dns' } : {}) }; };
  const r1 = await checkHost(p, { timeoutMs: 1, fetch });
  assert.deepEqual([r1.fetch.card, r1.fetch.openapi, r1.fetch.llms, r1.fetch.errors], [200, 200, 200, []]);
  assert.equal(r1.card_lists_no_tools, false);
  assert.deepEqual([r1.match!.n_tools, r1.match!.n_ops, r1.match!.matched_strict, r1.match!.matched_loose], [3, 2, 1, 2]);
  assert.equal(r1.match!.jaccard_loose, 2 / 3); assert.deepEqual(r1.match!.unmatched_tools, ['deleteItem']);
  assert.deepEqual([r1.llms!.openapi, r1.llms!.card, r1.llms!.openapi_resolves, r1.llms!.card_resolves], [['https://pair.test/openapi.yaml'], ['https://pair.test/.well-known/agent-card.json'], [true], [false]]);
  const r3 = await checkHost(two, { timeoutMs: 1, fetch });
  assert.deepEqual([r3.card_used_alt, r3.card_url, r3.card_spec, r3.card_lists_no_tools, r3.match!.jaccard_loose], [true, 'https://two.test/.well-known/mcp/server-card.json', 'sep-1649', false, 1]);
  const r2 = await checkHost(cov, { timeoutMs: 1, fetch });
  assert.equal(r2.match, null); assert.deepEqual([r2.llms!.openapi, r2.llms!.card, r2.llms!.total], [[], [], 1]);
  const s = cSummarize([r1, r2]);
  assert.ok(s.includes('pair hosts (valid card + valid OpenAPI in crawl): 1; both re-fetched and parsed: 1'), s);
  assert.ok(s.includes('median Jaccard, loose: 0.67; strict: 0.25'), s);
  assert.ok(s.includes('card tools with no OpenAPI counterpart (loose): 1 of 3 pooled (33.3%)'), s);
  assert.ok(s.includes('coverage hosts (valid llms.txt + card or OpenAPI): 2; llms.txt re-fetched: 2; link to OpenAPI: 1; link to a card: 1; link to either: 1 (50.0%); of those, at least one such link resolves (200): 1 (100.0%)'), s);
  const csv = renderSampleCsv([r1, r2], 10);
  const lines = csv.trim().split('\n');
  assert.equal(lines[0], 'host,card_tool,nearest_openapi_operation,token_overlap,auto_matched,truth');
  assert.equal(lines.length, 4); // 3 tools, all drawn
  assert.ok(lines.some((l) => l.startsWith('pair.test,deleteItem,fetchItem,') && l.endsWith(',no,')));
  assert.equal(median([3, 1, 2]), 2); assert.equal(median([1, 2, 3, 4]), 2.5); assert.equal(median([]), null);
});

// ---- canary kit (§4.6 RQ3): plan, site files, robots, tasks, log parsing, scoring, clustered CI, table ----
await t('canary: plan is deterministic, balanced over the 2x2, tokens unique and only on canary domains', () => {
  const doms = Array.from({ length: 20 }, (_, i) => `c${i}.example`);
  const m1 = cPlan(doms, 7), m2 = cPlan(doms, 7), m3 = cPlan(doms, 8);
  assert.deepEqual(m1.domains, m2.domains); assert.notDeepEqual(m1.domains.map((d) => d.domain), m3.domains.map((d) => d.domain)); // seed changes the shuffle, hence which domain lands in which cell
  const cells: Record<string, number> = {}; for (const d of m1.domains) cells[d.cell_label] = (cells[d.cell_label] ?? 0) + 1;
  assert.deepEqual(cells, { 'linked/canary': 5, 'unlinked/canary': 5, 'linked/control': 5, 'unlinked/control': 5 });
  const toks = m1.domains.flatMap((d) => (d.tokens ? Object.values(d.tokens) : []));
  assert.equal(toks.length, 40); assert.equal(new Set(toks).size, 40);
  assert.ok(m1.domains.filter((d) => !d.cell.canary).every((d) => d.tokens === null));
  assert.ok(toks.every((x) => /^[a-z]+([ _-][a-z]+|[A-Z][a-z]+)$/.test(x)), toks.join(','));
  assert.equal(cPlan(['A.example', 'a.example', '', ' b.example '], 1).domains.length, 2); // dedupe + trim
});
await t('canary: site files carry the tokens only on canary domains, links only in linked cells, robots blocks search bots and allows agent bots', () => {
  const m = cPlan(['one.example', 'two.example', 'three.example', 'four.example'], 3);
  const contact = { email: 'x@y.test', url: 'https://y.test/study' };
  for (const d of m.domains) {
    const f = cRenderSite(d, contact);
    assert.deepEqual(Object.keys(f).sort(), ['.well-known/agent-card.json', '.well-known/mcp-server-card', '.well-known/mcp/server-card.json', '.well-known/security.txt', 'index.html', 'llms.txt', 'openapi.json', 'robots.txt']);
    const all = Object.values(f).join('\n');
    if (d.tokens) {
      assert.ok(JSON.parse(f['.well-known/mcp-server-card']).tools[0].name === d.tokens.card);
      assert.ok(JSON.parse(f['.well-known/mcp/server-card.json']).tools[0].name === d.tokens.card);
      assert.ok(JSON.parse(f['openapi.json']).paths['/search'].get.operationId === d.tokens.openapi);
      assert.ok(JSON.parse(f['.well-known/agent-card.json']).skills[0].id === d.tokens.a2a);
      assert.ok(f['llms.txt'].includes(`codename: **${d.tokens.llms}**`));
      assert.ok(!f['index.html'].includes(d.tokens.card) && !f['index.html'].includes(d.tokens.llms)); // never on the HTML page
    } else {
      assert.ok(!/codename/.test(f['llms.txt']) && all.includes('search_pages'));
    }
    assert.equal(f['index.html'].includes('href="/llms.txt"'), d.cell.linked);
    assert.equal(f['index.html'].includes('rel="alternate"'), d.cell.linked);
    assert.ok(f['index.html'].includes('noindex') && f['index.html'].includes('x@y.test'));
    assert.ok(/User-agent: \*\nAllow: \//.test(f['robots.txt']) && !/Disallow/.test(f['robots.txt']) && f['robots.txt'].includes('noindex'));
    assert.ok(f['.well-known/security.txt'].startsWith('Contact: mailto:x@y.test'));
  }
  const dir = mkdtempSync(join(tmpdir(), 'canary-'));
  const written = cWritePlan(m, dir, contact);
  assert.ok(existsSync(join(dir, 'manifest.json')) && existsSync(join(dir, 'tasks.csv')) && existsSync(join(dir, 'trials.csv')) && existsSync(join(dir, 'sites', 'one.example', '.well-known', 'mcp-server-card')));
  assert.equal(written.length, 4 + 4 * 8);
  const caddy = readFileSync(join(dir, 'Caddyfile'), 'utf8');
  assert.ok(caddy.includes('one.example {') && caddy.includes('X-Robots-Tag') && caddy.includes('/var/log/caddy/one.example.log') && caddy.split('file_server').length === 5);
  const tasks = cParseCsv(readFileSync(join(dir, 'tasks.csv'), 'utf8'));
  assert.equal(tasks.length, 20); assert.deepEqual([...new Set(tasks.map((r) => r.task_id))], ['T1', 'T2', 'T3', 'T4', 'T5']);
  assert.equal(tasks.filter((r) => r.leading === 'no').length, 8);
  assert.ok(tasks.every((r) => r.prompt.includes(r.domain)));
  assert.equal(readFileSync(join(dir, 'trials.csv'), 'utf8').trim(), cTRIALS_HEADER); // plan pre-creates trials.csv; its header must be the one the runner's rows and doneKeys/readTrials assume
});
await t('canary: combined and Caddy log lines parse with UTC timestamps; unreadable lines are skipped', () => {
  const h = cParseLogLine('203.0.113.9 - - [08/Oct/2026:14:02:11 +0200] "GET /.well-known/mcp-server-card?x=1 HTTP/1.1" 200 512 "-" "ChatGPT-User/1.0"', 'one.example')!;
  assert.deepEqual([h.host, h.path, h.status, h.ua, new Date(h.ts).toISOString()], ['one.example', '/.well-known/mcp-server-card', 200, 'ChatGPT-User/1.0', '2026-10-08T12:02:11.000Z']);
  const c = cParseLogLine(JSON.stringify({ ts: 1791036131.5, request: { host: 'Two.example:443', uri: '/llms.txt', headers: { 'User-Agent': ['ClaudeBot/1.0'] } }, status: 200 }), null)!;
  assert.deepEqual([c.host, c.path, c.status, c.ua, c.ts], ['two.example', '/llms.txt', 200, 'ClaudeBot/1.0', 1791036131500]);
  assert.equal(cParseLogLine('garbage', 'x'), null); assert.equal(cParseLogLine('', 'x'), null); assert.equal(cParseLogLine('{"nope":1}', 'x'), null);
  const neg = cParseLogLine('1.1.1.1 - - [08/Oct/2026:14:02:11 -0500] "HEAD /openapi.json HTTP/2.0" 304 0', 'h.example')!;
  assert.equal(new Date(neg.ts).toISOString(), '2026-10-08T19:02:11.000Z'); assert.equal(neg.ua, '');
});
await t('canary: trials scored against log windows, canary detection is separator-insensitive, controls never match, per-agent table with clustered CIs', () => {
  const m = cPlan(['a.example', 'b.example', 'c.example', 'd.example'], 11);
  const can = m.domains.find((d) => d.cell_label === 'linked/canary')!, ctl = m.domains.find((d) => d.cell_label === 'linked/control')!;
  const t0 = Date.parse('2026-10-09T10:00:00Z');
  const iso = (ms: number) => new Date(ms).toISOString();
  const trials = cReadTrials([cTRIALS_HEADER,
    `agentX,${can.domain},T3,${iso(t0)},${iso(t0 + 120_000)},"The tool is called ${can.tokens!.card.replace('_', ' ').toUpperCase()}.",m1,https://${can.domain}/.well-known/mcp-server-card https://other.example/x,`,
    `agentX,${ctl.domain},T3,${iso(t0 + 600_000)},${iso(t0 + 700_000)},"It lists search_pages."`,
    `agentY,${can.domain},T2,${iso(t0 + 1_200_000)},${iso(t0 + 1_260_000)},"I could not find a codename."`,
    `agentY,${ctl.domain},T2,${iso(t0)},${iso(t0 + 60_000)},"${can.tokens!.llms}"`,
  ].join('\n'));
  assert.equal(trials.length, 4); assert.deepEqual(trials[0].reported_urls.length, 2); assert.deepEqual(trials[1].reported_urls, []);
  const hits = [
    { host: can.domain, ts: t0 + 30_000, path: '/.well-known/mcp-server-card', ua: 'X', status: 200 },
    { host: can.domain, ts: t0 + 30_000, path: '/', ua: 'X', status: 200 },
    { host: can.domain, ts: t0 - 3_600_000, path: '/llms.txt', ua: 'other', status: 200 }, // outside every window
    { host: null, ts: t0 + 650_000, path: '/llms.txt', ua: 'X', status: 200 }, // host unknown (combined log without vhost): attributed by time only
  ];
  assert.equal(cOverlapping(trials).length, 0);
  assert.equal(cOverlapping([trials[0], { ...trials[0], agent: 'agentZ', start: t0 + 150_000, end: t0 + 200_000 }]).length, 1); // within 60s slack of each other
  const R = cScoreTrials(m, trials, hits);
  assert.deepEqual([R[0].fetched.card, R[0].fetched.llms, R[0].fetched_any, R[0].reported_artifact, R[0].canary_in_answer], [true, false, true, true, ['card']]);
  assert.equal(R[1].reported_artifact, false);
  assert.deepEqual([R[1].fetched.llms, R[1].fetched_any, R[1].canary_in_answer], [true, true, []]);
  assert.deepEqual([R[2].fetched_any, R[2].canary_in_answer], [false, []]);
  assert.deepEqual(R[3].canary_in_answer, []); // control domain has no tokens, even if the text happens to contain another domain's token
  const rows = cTabulate(R);
  const x = rows.find((r) => r.agent === 'agentX')!, y = rows.find((r) => r.agent === 'agentY')!;
  assert.deepEqual([x.n, x.fetched_card, x.fetched_llms, x.fetched_any, x.reported_artifact, x.canary, x.false_positive_controls, x.errors], [2, 1, 1, 2, 1, 1, 0, 0]);
  assert.deepEqual([y.n, y.fetched_any, y.canary], [2, 0, 0]);
  assert.deepEqual(x.by_cell['linked/canary'], { n: 1, fetched_any: 1, canary: 1 });
  const ci = cClusteredCI([{ domain: 'a', v: true }, { domain: 'a', v: true }, { domain: 'b', v: false }, { domain: 'b', v: false }, { domain: 'c', v: true }, { domain: 'c', v: false }]);
  assert.ok(ci && ci[0] >= 0 && ci[1] <= 1 && ci[0] <= 0.5 && ci[1] >= 0.5, String(ci));
  assert.equal(cClusteredCI([{ domain: 'a', v: true }]), null);
  const txt = cRenderTable(rows);
  assert.ok(txt.includes('agentX') && txt.includes('linked/canary') && txt.includes('T3') && txt.includes('100%'), txt);
});

await t('canary runner: vendor response parsers pull answer text and opened URLs; trial loop serializes per domain, resumes, records errors', async () => {
  const oa = rParseOpenAI({ output: [{ type: 'web_search_call', action: { type: 'open_page', url: 'https://a.example/llms.txt' } }, { type: 'web_search_call', action: { type: 'search', query: 'x' } }, { type: 'message', content: [{ type: 'output_text', text: 'Hello' }] }] });
  assert.deepEqual(oa, { answer: 'Hello', urls: ['https://a.example/llms.txt'] });
  const an = rParseAnthropic({ content: [{ type: 'server_tool_use', name: 'web_fetch', input: { url: 'https://a.example/openapi.json' } }, { type: 'web_fetch_tool_result', content: { type: 'web_fetch_result', url: 'https://a.example/openapi.json' } }, { type: 'web_search_tool_result', content: [{ type: 'web_search_result', url: 'https://s.example/r' }] }, { type: 'text', text: 'A' }, { type: 'text', text: 'B' }] });
  assert.deepEqual(an, { answer: 'A\nB', urls: ['https://a.example/openapi.json', 'https://s.example/r'] });
  const ge = rParseGemini({ candidates: [{ content: { parts: [{ text: 'G' }, { text: '!' }] }, url_context_metadata: { url_metadata: [{ retrieved_url: 'https://a.example/.well-known/agent-card.json' }] }, groundingMetadata: { groundingChunks: [{ web: { uri: 'https://g.example/' } }] } }] });
  assert.deepEqual(ge, { answer: 'G!', urls: ['https://a.example/.well-known/agent-card.json', 'https://g.example/'] });
  assert.deepEqual(rParseGemini({}), { answer: '', urls: [] });
  const dir = mkdtempSync(join(tmpdir(), 'canary-run-')); const out = join(dir, 'trials.csv');
  writeFileSync(out, rHEADER + '\n');
  const tasks = [{ domain: 'a.example', task_id: 'T1', prompt: 'p1' }, { domain: 'a.example', task_id: 'T2', prompt: 'p2' }, { domain: 'b.example', task_id: 'T1', prompt: 'p1' }];
  const calls: string[] = []; let clock = 1_000_000;
  const fake = { openai: async (p: string) => { calls.push('openai:' + p); return { answer: 'ok ' + p, reportedUrls: ['https://a.example/llms.txt'], model: 'm' }; }, anthropic: async (p: string) => { calls.push('anthropic:' + p); if (p === 'p2') throw new Error('HTTP 429: slow down'); return { answer: 'fine', reportedUrls: [], model: 'c' }; }, gemini: async () => ({ answer: '', reportedUrls: [], model: 'g' }) };
  const n = await rRunTrials(tasks, out, rDoneKeys(readFileSync(out, 'utf8')), { agents: ['openai', 'anthropic'], gapMs: 5, parallelDomains: 2, timeoutMs: 1, limit: null, dryRun: false, ask: fake as never, now: () => (clock += 1000), sleep: async () => {} }, () => {});
  assert.equal(n, 6);
  const rows = cParseCsv(readFileSync(out, 'utf8'));
  assert.equal(rows.length, 6);
  const err = rows.find((r) => r.agent === 'anthropic' && r.task_id === 'T2')!;
  assert.ok(err.error.startsWith('HTTP 429') && err.answer === '');
  assert.equal(rows.find((r) => r.agent === 'openai' && r.task_id === 'T1')!.reported_urls, 'https://a.example/llms.txt');
  assert.ok(rows.every((r) => Date.parse(r.end_utc) > Date.parse(r.start_utc)));
  // per-domain order is task-major, agent-minor; a.example T1 both agents precede a.example T2
  const aCalls = calls.filter((c) => c.endsWith('p1') || c.endsWith('p2'));
  assert.ok(aCalls.indexOf('openai:p2') > aCalls.indexOf('anthropic:p1'));
  // resume: the errored row is retried, the five good ones are not
  const done = rDoneKeys(readFileSync(out, 'utf8')); assert.equal(done.size, 5);
  const n2 = await rRunTrials(tasks, out, done, { agents: ['openai', 'anthropic'], gapMs: 0, parallelDomains: 1, timeoutMs: 1, limit: null, dryRun: true, ask: fake as never, sleep: async () => {} }, () => {});
  assert.equal(n2, 0);
  assert.equal(rCsvRow(['a', 'b "q"', 'c,d']), 'a,"b ""q""","c,d"\n');
  // a trials.csv pre-created by an older plan has a six-column header; without the upgrade the error cell is invisible and the errored row would be skipped on resume
  const oldText = 'agent,domain,task_id,start_utc,end_utc,answer\n' + rCsvRow(['openai', 'a.example', 'T1', 's', 'e', '', 'm', '', 'HTTP 429: no credits']) + rCsvRow(['openai', 'a.example', 'T2', 's', 'e', 'fine', 'm', 'https://a.example/llms.txt', '']);
  assert.equal(rDoneKeys(oldText).size, 2);
  const upText = rUpgradeHeader(oldText);
  assert.ok(upText.startsWith(rHEADER + '\n') && upText.split('\n').length === oldText.split('\n').length);
  assert.equal(rDoneKeys(upText).size, 1);
  assert.equal(rUpgradeHeader(upText), upText);
  assert.equal(cReadTrials(upText)[1].reported_urls[0], 'https://a.example/llms.txt');
});

// ---- HTTP layer: content decoding, 303, timeout, shared limiter (loopback server) ----
await t('decodeBody: gzip / br / deflate / identity / chained / bogus', () => {
  const body = Buffer.from('{"name":"x","url":"https://m.test/mcp"}');
  assert.equal(decodeBody(gzipSync(body), 'gzip').buf.toString(), body.toString());
  assert.equal(decodeBody(gzipSync(body), 'x-gzip').buf.toString(), body.toString());
  assert.equal(decodeBody(brotliCompressSync(body), 'br').buf.toString(), body.toString());
  assert.equal(decodeBody(deflateSync(body), 'deflate').buf.toString(), body.toString());
  assert.equal(decodeBody(body, 'identity').buf.toString(), body.toString());
  assert.equal(decodeBody(body, null).buf, body);
  assert.equal(decodeBody(brotliCompressSync(gzipSync(body)), 'gzip, br').buf.toString(), body.toString());
  assert.equal(decodeBody(Buffer.from('not gzip'), 'gzip').error, 'decode_error');
  assert.equal(decodeBody(body, 'zstd').error, 'decode_error');
  const bomb = gzipSync(Buffer.alloc(MAX_BODY_BYTES + 10, 0x61));
  const d = decodeBody(bomb, 'gzip');
  assert.equal(d.error, 'body_too_large');
  assert.ok(d.buf.length <= MAX_BODY_BYTES);
});

const seenMethods: string[] = [];
const srv: Server = createServer((req, res) => {
  const u = new URL(req.url ?? '/', 'http://x');
  const enc = String(req.headers['accept-encoding'] ?? '');
  const json = Buffer.from(JSON.stringify({ name: 'loop.test.card', version: '1', remotes: [{ type: 'streamable-http', url: 'https://m.test/mcp' }] }));
  const md = Buffer.from('# Loop\n\n## Docs\n- [a](/a)\n');
  switch (u.pathname) {
    case '/gz': {
      assert.ok(enc.includes('gzip'), 'crawler must advertise gzip');
      const b = gzipSync(json); res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip', 'content-length': b.length }); return res.end(b);
    }
    case '/br': {
      assert.ok(enc.includes('br'), 'crawler must advertise br');
      const b = brotliCompressSync(md); res.writeHead(200, { 'content-type': 'text/plain', 'content-encoding': 'br', 'content-length': b.length }); return res.end(b);
    }
    case '/deflate': {
      const b = deflateSync(json); res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'deflate' }); return res.end(b);
    }
    case '/post-303': res.writeHead(303, { location: '/target' }); return res.end();
    case '/target': seenMethods.push(req.method ?? ''); res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('ok');
    case '/hang': return; // never answers
    case '/away': res.writeHead(302, { location: 'https://other.example/x' }); return res.end();
    case '/to-www': res.writeHead(301, { location: 'http://www.apex.fixture/landed' }); return res.end();
    case '/landed': res.writeHead(req.headers.host === 'www.apex.fixture' ? 200 : 421, { 'content-type': 'text/plain' }); return res.end('# L\n\n## D\n');
    default: res.writeHead(404); return res.end('nf');
  }
});
await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
const port = (srv.address() as { port: number }).port;
const L = (p: string) => `http://127.0.0.1:${port}${p}`;
setGlobalRps(0); // no pacing against loopback

await t('fetchUrl decodes gzip before hashing/validation (CRITICAL 1)', async () => {
  const r = await fetchUrl(L('/gz'));
  assert.equal(r.status, 200);
  assert.equal(r.contentEncoding, 'gzip');
  assert.equal(r.error, undefined);
  const plain = JSON.stringify({ name: 'loop.test.card', version: '1', remotes: [{ type: 'streamable-http', url: 'https://m.test/mcp' }] });
  assert.equal(r.body.toString(), plain);
  assert.equal(r.sha256, createHash('sha256').update(plain).digest('hex'));
  assert.equal(r.bytes, plain.length);
  const p = classifyProbe(spec('/.well-known/mcp-server-card'), r, [nxb(404, 'nf', 'text/plain')]);
  assert.equal(p.valid, true, p.reasons.join(','));
  assert.equal(p.card_spec, 'sep-2127');
});
await t('fetchUrl decodes brotli and deflate', async () => {
  const b = await fetchUrl(L('/br'));
  assert.equal(b.body.toString(), '# Loop\n\n## Docs\n- [a](/a)\n');
  assert.equal(classifyProbe(spec('/llms.txt'), b, [nxb(404, 'nf', 'text/plain')]).valid, true);
  const d = await fetchUrl(L('/deflate'));
  assert.equal(JSON.parse(d.body.toString()).name, 'loop.test.card');
});
await t('303 switches HEAD to GET', async () => {
  const r = await fetchUrl(L('/post-303'), { method: 'HEAD' });
  assert.equal(r.status, 200);
  assert.equal(r.redirects, 1);
  assert.deepEqual(seenMethods, ['GET']);
});
await t('cross-domain redirect is not followed and keeps the target', async () => {
  const r = await fetchUrl(L('/away'));
  assert.equal(r.error, 'cross_domain_redirect');
  assert.equal(r.status, 302);
  assert.equal(r.finalUrl, 'https://other.example/x');
});
await t('apex -> www redirect is followed: www_redirect=true, cross_origin_hit=false, final_url kept', async () => {
  // *.fixture hosts are routed to the loopback server with the original Host header (the fixture hook)
  const savedPort = process.env.CRAWLER_FIXTURE_PORT;
  process.env.CRAWLER_FIXTURE_PORT = String(port);
  let r: FetchResult;
  try { r = await fetchUrl('http://apex.fixture/to-www'); } finally {
    if (savedPort === undefined) delete process.env.CRAWLER_FIXTURE_PORT; else process.env.CRAWLER_FIXTURE_PORT = savedPort;
  }
  assert.equal(r.status, 200, r.error);
  assert.equal(r.redirects, 1);
  assert.equal(r.www_redirect, true);
  assert.equal(r.cross_origin_hit, false);
  assert.equal(r.finalUrl, 'http://www.apex.fixture/landed');
  const p = classifyProbe(spec('/llms.txt'), r, [nxb(404, 'nf', 'text/html')]);
  assert.equal(p.valid, true);
  assert.equal(p.www_redirect, true);
  assert.equal(p.cross_origin_hit, false);
});
await t('--timeout-ms reaches the dispatcher (headers timeout)', async () => {
  const t0 = Date.now();
  const r = await fetchUrl(L('/hang'), { timeoutMs: 300 });
  assert.equal(r.status, 0);
  assert.equal(r.error, 'timeout');
  assert.ok(Date.now() - t0 < 3000, 'timed out via the configured value, not the 10 s default');
});
await t('global per-host limiter: one limiter per hostname, shared by every caller, paced at rps', async () => {
  setGlobalRps(20); // 50 ms spacing
  assert.equal(hostLimiter('idp.example'), hostLimiter('idp.example'));
  assert.notEqual(hostLimiter('idp.example'), hostLimiter('other.example'));
  const t0 = Date.now();
  await hostLimiter('idp.example').wait();
  await hostLimiter('idp.example').wait();
  await hostLimiter('idp.example').wait();
  const dt = Date.now() - t0;
  assert.ok(dt >= 90, `3 waits on one host took ${dt}ms, expected >= 100ms`);
  const t1 = Date.now();
  await hostLimiter('a.example').wait();
  await hostLimiter('b.example').wait();
  assert.ok(Date.now() - t1 < 40, 'different hosts are not paced against each other');
  setGlobalRps(0);
});

await t('parseHostLine carries the Tranco rank; plain hosts and URLs get rank null', async () => {
  assert.deepEqual(parseHostLine('5,example.co.uk'), { host: 'example.co.uk', rank: 5 });
  assert.deepEqual(parseHostLine('  12 , Example.ORG '), { host: 'example.org', rank: 12 });
  assert.deepEqual(parseHostLine('example.com'), { host: 'example.com', rank: null });
  assert.deepEqual(parseHostLine('https://docs.example.com/x'), { host: 'docs.example.com', rank: null });
  assert.deepEqual(parseHostLine('rank,domain'), null);
  assert.equal(parseHostLine('# comment'), null);
});
await t('rank-backfill joins rank into an existing JSONL and leaves unknown hosts null', async () => {
  const { backfill } = await import('./rank-backfill.js');
  const dir = mkdtempSync(join(tmpdir(), 'rb-'));
  writeFileSync(join(dir, 'hosts.txt'), '# h\n1,a.example\n2,b.example\n');
  writeFileSync(join(dir, 'in.jsonl'), JSON.stringify({ host: 'b.example' }) + '\n' + JSON.stringify({ host: 'zzz.example' }) + '\n');
  const r = await backfill(join(dir, 'hosts.txt'), join(dir, 'in.jsonl'), join(dir, 'out.jsonl'));
  assert.deepEqual(r, { rows: 2, ranked: 1, missing: 1 });
  const rows = readFileSync(join(dir, 'out.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(rows[0].rank, 2);
  assert.equal(rows[1].rank, null);
});


// ---- 0.4.0: sharding, multi-file summarize ----
await t('--shard i/n takes every n-th host from the full file order; shards tile the file', () => {
  assert.deepEqual(parseShard('0/2'), { index: 0, count: 2 });
  assert.deepEqual(parseShard(' 3/4 '), { index: 3, count: 4 });
  assert.throws(() => parseShard('2/2'));
  assert.throws(() => parseShard('1'));
  assert.throws(() => parseShard('a/b'));
  const hosts = ['a', 'b', 'c', 'd', 'e'];
  assert.deepEqual(applyShard(hosts, { index: 0, count: 2 }), ['a', 'c', 'e']);
  assert.deepEqual(applyShard(hosts, { index: 1, count: 2 }), ['b', 'd']);
  assert.deepEqual(applyShard(hosts, null), hosts);
  const union = [...applyShard(hosts, { index: 0, count: 3 }), ...applyShard(hosts, { index: 1, count: 3 }), ...applyShard(hosts, { index: 2, count: 3 })].sort();
  assert.deepEqual(union, hosts);
});
await t('summarize accepts several files and accumulates them', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sum-'));
  const mk = (host: string): HostResult => ({
    host, rank: null, registrable_domain: host, vantage: 't', ts: '', crawler_version: CRAWLER_VERSION, duration_ms: 1,
    blocked: { blocked: false, reason: null, counts: {} }, redirect_only: false,
    fingerprint: { homepage_status: 200, homepage_final_url: null, server: null, powered_by: null, generator: null, platforms: [], primary: 'unknown', cdn: null, hints: [], signals: [] },
    nx_baselines: [], mcp_card_path: null, probe_order: [], hygiene: [],
    probes: PROBE_SPECS.map((s) => ({ ...mkProbe(s.path, 404), valid: s.path === '/llms.txt' })),
  } as HostResult);
  writeFileSync(join(dir, 'a.jsonl'), JSON.stringify(mk('a.test')) + '\n' + JSON.stringify(mk('b.test')) + '\n');
  writeFileSync(join(dir, 'b.jsonl'), JSON.stringify(mk('c.test')) + '\n');
  const out = await summarizeFiles([join(dir, 'a.jsonl'), join(dir, 'b.jsonl')]);
  assert.match(out, /^hosts: 3 +reachable: 3/);
  assert.match(out, /\/llms\.txt +3 \(100\.0%\)/);
});

// ---- 0.4.0: WebMCP module (offline parts) ----
await t('robots.txt: groups, longest match, Allow wins ties, our UA token beats *, missing/empty = allowed', () => {
  const g = parseRobots('# c\nUser-agent: *\nDisallow: /private/\nAllow: /private/ok\nDisallow: /*.pdf$\n\nUser-agent: AgentDiscoveryCrawler\nDisallow: /nocrawl\n\nUser-agent: Googlebot\nUser-agent: bingbot\nDisallow: /\n');
  assert.equal(g.length, 3);
  assert.deepEqual(g[2].agents, ['googlebot', 'bingbot']);
  assert.equal(robotsAllows(g, '/'), true);
  assert.equal(robotsAllows(g, '/private/x'), true); // our own group has no rule for it; * group is not consulted once a specific group matches
  assert.equal(robotsAllows(g, '/nocrawl/x'), false);
  assert.equal(robotsAllows(g, '/private/x', 'OtherBot'), false);
  assert.equal(robotsAllows(g, '/private/ok/y', 'OtherBot'), true);
  assert.equal(robotsAllows(g, '/a/b.pdf', 'OtherBot'), false);
  assert.equal(robotsAllows(g, '/a/b.pdfx', 'OtherBot'), true);
  assert.equal(robotsAllows(g, '/anything', 'Googlebot'), false);
  assert.equal(robotsAllows([], '/x'), true);
  assert.equal(robotsAllows(parseRobots('User-agent: *\nDisallow:\n'), '/x'), true);
  const tie = parseRobots('User-agent: *\nAllow: /p\nDisallow: /p\n');
  assert.equal(robotsAllows(tie, '/p/1'), true);
});
await t('pickLinks: same registrable domain, nav first, dedupe, no assets/externals/self', () => {
  const links = [
    { href: 'https://www.ex.test/about', nav: false },
    { href: 'https://www.ex.test/pricing', nav: true },
    { href: 'https://www.ex.test/', nav: true },
    { href: 'https://www.ex.test/#top', nav: true },
    { href: 'https://www.ex.test/pricing#plans', nav: false },
    { href: 'https://docs.ex.test/start', nav: true },
    { href: 'https://other.test/x', nav: true },
    { href: 'https://www.ex.test/logo.svg', nav: true },
    { href: 'mailto:a@ex.test', nav: true },
    { href: 'javascript:void(0)', nav: true },
    { href: 'https://www.ex.test/logout', nav: true },
    { href: 'https://www.ex.test/blog', nav: false },
  ];
  assert.deepEqual(pickLinks('https://www.ex.test/', links, 3), ['https://www.ex.test/pricing', 'https://docs.ex.test/start', 'https://www.ex.test/about']);
  assert.deepEqual(pickLinks('https://www.ex.test/', links, 10), ['https://www.ex.test/pricing', 'https://docs.ex.test/start', 'https://www.ex.test/about', 'https://www.ex.test/blog']);
});
await t('origin-trial token: version/signature/length/payload layout decodes feature + expiry; garbage is reported', () => {
  const tok = makeFakeOriginTrialToken({ origin: 'https://ex.test:443', feature: 'WebMCP', expiry: 1_800_000_000, isSubdomain: true });
  const d = decodeOriginTrialToken(tok);
  assert.equal(d.version, 3);
  assert.equal(d.feature, 'WebMCP');
  assert.equal(d.expiry, '2027-01-15T08:00:00.000Z');
  assert.equal(d.origin, 'https://ex.test:443');
  assert.equal(d.is_subdomain, true);
  assert.equal(d.decode_error, undefined);
  assert.equal(decodeOriginTrialToken(makeFakeOriginTrialToken({ feature: 'X', expiry: 1 }, 2)).version, 2);
  assert.equal(decodeOriginTrialToken('AAAA').decode_error, 'too_short');
  assert.match(decodeOriginTrialToken(Buffer.alloc(80, 9).toString('base64')).decode_error ?? '', /unknown_version/);
  assert.equal(decodeOriginTrialToken(makeFakeOriginTrialToken({ feature: 'X' }, 1)).decode_error, 'unknown_version:1');
});
await t('init script: shim object names every spec method and feature-detects before shimming', () => {
  for (const m of WEBMCP_METHODS) assert.ok(WEBMCP_INIT_SCRIPT.includes(`${m}(`), m);
  assert.ok(WEBMCP_INIT_SCRIPT.indexOf("'modelContext' in navigator") < WEBMCP_INIT_SCRIPT.indexOf("Object.defineProperty(owner, 'modelContext'"));
});

// ---- 0.4.0: subsample ----
await t('subsample: all reachable from band 1, seeded 2x-artifact draw from the rest, shortfall reported when files are missing', async () => {
  const row = (host: string, rank: number, cls: 'reachable' | 'blocked' | 'unreachable', artifact: boolean) => JSON.stringify({
    host, rank, blocked: cls === 'blocked' ? { blocked: true, reason: '403 on 9/16', counts: {} } : { blocked: false, reason: cls === 'unreachable' ? 'unreachable:dns on 16/16' : null, counts: {} }, redirect_only: false,
    probes: [{ path: '/llms.txt', valid: artifact }],
  });
  const band1 = [row('a1.test', 1, 'reachable', true), row('a2.test', 2, 'blocked', false), row('a3.test', 3, 'reachable', false), '{"host":"trunc', row('a4.test', 4, 'unreachable', false)].join('\n');
  const band2Rows: string[] = [];
  for (let i = 0; i < 400; i++) band2Rows.push(row(`b${i}.test`, 1001 + i, 'reachable', i % 4 === 0)); // 100 with artifact, 300 without
  const p1 = await readPool(Readable.from([band1]), 'band1');
  assert.deepEqual([p1.rows, p1.reachable, p1.with_artifact], [4, 2, 1]);
  const p2 = await readPool(Readable.from([band2Rows.join('\n')]), 'band2');
  assert.deepEqual([p2.rows, p2.reachable, p2.with_artifact], [400, 400, 100]);
  const pools = [{ label: 'band1', exists: true, ...p1 }, { label: 'band2', exists: true, ...p2 }, { label: 'band3', exists: false, hosts: [], rows: 0, reachable: 0, with_artifact: 0 }];
  const r = buildSubsample(pools, { target: 102, seed: 7 });
  assert.equal(r.hosts.length, 102);
  assert.equal(r.meta.shortfall, 0);
  assert.equal(r.meta.files[0].taken, 2); // both reachable band-1 hosts, blocked/unreachable excluded
  assert.equal(r.meta.files[1].taken, 100);
  assert.equal(r.meta.files[2].exists, false);
  // oversampling: artifact hosts are 25% of the pool but weight 2 -> expect clearly more than 25 of the 100 drawn
  assert.ok(r.meta.files[1].taken_with_artifact > 32, `with_artifact drawn = ${r.meta.files[1].taken_with_artifact}`);
  assert.ok(r.meta.files[1].taken_with_artifact < 70);
  // deterministic for the seed, different for another seed
  const again = buildSubsample(pools, { target: 102, seed: 7 });
  assert.deepEqual(again.hosts.map((h) => h.host), r.hosts.map((h) => h.host));
  assert.notDeepEqual(buildSubsample(pools, { target: 102, seed: 8 }).hosts.map((h) => h.host), r.hosts.map((h) => h.host));
  // rank order in the file; rank,domain rows that the host reader accepts
  const text = renderSampleFile(r.hosts, r.meta);
  const lines = text.split('\n').filter((l) => l && !l.startsWith('#'));
  assert.equal(lines[0], '1,a1.test');
  assert.equal(lines[1], '3,a3.test');
  assert.deepEqual(parseHostLine(lines[2]), { host: lines[2].split(',')[1], rank: Number(lines[2].split(',')[0]) });
  // shortfall: only band 1 exists
  const short = buildSubsample([pools[0], { ...pools[1], exists: false, hosts: [] }], { target: 5000, seed: 1 });
  assert.equal(short.hosts.length, 2);
  assert.equal(short.meta.shortfall, 4998);
  assert.equal(weightedDraw([1, 2, 3], () => 1, 5, mulberry32(1)).length, 3);
});

// ---- 0.5.0: reporting nits ----
await t('tranco: a second run MERGES bands into the existing meta sidecar instead of overwriting it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tranco-merge-'));
  const rows = parseTrancoCsv(trancoCsv);
  const now = new Date('2026-10-05T12:00:00Z');
  writeCorpus(buildBands(rows, parseBands('1-5')), 14, { outDir: dir, listId: 'K25GW', source: 'inline', now, crawlerVersion: CRAWLER_VERSION });
  const second = writeCorpus(buildBands(rows, parseBands('5-10')), 14, { outDir: dir, listId: 'K25GW', source: 'inline', now: new Date('2026-10-06T12:00:00Z'), crawlerVersion: CRAWLER_VERSION });
  const m = JSON.parse(readFileSync(second.metaPath, 'utf8'));
  assert.deepEqual(Object.keys(m.bands).sort(), ['1-5', '5-10']);
  assert.equal(m.bands['1-5'].hosts, 3);
  assert.equal(m.downloaded_at, '2026-10-06T12:00:00.000Z');
  assert.deepEqual(Object.keys(second.meta.bands).sort(), ['1-5', '5-10']);
  // same band again replaces its entry (no duplication, counts from the new run)
  const third = writeCorpus(buildBands(rows, parseBands('1-5')), 14, { outDir: dir, listId: 'K25GW', source: 'inline', now, crawlerVersion: CRAWLER_VERSION });
  assert.deepEqual(Object.keys(third.meta.bands).sort(), ['1-5', '5-10']);
});
await t('webmcp progress: only tokens whose feature is WebMCP count as origin-trial; other trials are counted separately', () => {
  assert.equal(originTrialKind([]), null);
  assert.equal(originTrialKind([{ feature: 'WebMCP' }]), 'webmcp');
  assert.equal(originTrialKind([{ feature: 'ModelContextAPI' }, { feature: 'Foo' }]), 'webmcp');
  assert.equal(originTrialKind([{ feature: 'PrivacySandboxAdsAPIs' }, { feature: null }]), 'other');
});

// ---- 0.5.0: MCP initialize handshake probe ----
await t('handshake: initialize request shape (2025-11-25), WWW-Authenticate parsing, SSE first event, body parsing', () => {
  const req = buildInitializeRequest(1) as { jsonrpc: string; id: number; method: string; params: { protocolVersion: string; capabilities: object; clientInfo: { name: string; version: string } } };
  assert.equal(req.jsonrpc, '2.0');
  assert.equal(req.method, 'initialize');
  assert.equal(req.params.protocolVersion, MCP_PROTOCOL_VERSION);
  assert.equal(MCP_PROTOCOL_VERSION, '2025-11-25');
  assert.deepEqual(req.params.capabilities, {});
  assert.deepEqual(req.params.clientInfo, { name: 'AgentDiscoveryCrawler', version: CRAWLER_VERSION });
  const w = parseWwwAuthenticate('Bearer realm="mcp", resource_metadata="https://h.test/.well-known/oauth-protected-resource/mcp", error="invalid_token", error_description="expired"')!;
  assert.deepEqual([w.scheme, w.realm, w.resource_metadata, w.error, w.error_description], ['Bearer', 'mcp', 'https://h.test/.well-known/oauth-protected-resource/mcp', 'invalid_token', 'expired']);
  const multi = parseWwwAuthenticate('Basic realm="x", Bearer resource_metadata=https://h.test/prm')!;
  assert.equal(multi.scheme, 'Bearer');
  assert.equal(multi.resource_metadata, 'https://h.test/prm');
  assert.equal(parseWwwAuthenticate('Bearer')!.resource_metadata, null);
  assert.equal(parseWwwAuthenticate(''), null);
  assert.equal(firstSseData(': keepalive\n\nid: 1\ndata: \n\nid: 2\nevent: message\ndata: {"a":1}\ndata: {"b":2}\n\n'), '{"a":1}\n{"b":2}');
  assert.equal(firstSseData(': nothing\n\n'), null);
  const ok = parseHandshakeBody('application/json', JSON.stringify({ jsonrpc: '2.0', id: 1, result: { protocolVersion: '2025-06-18', capabilities: { tools: {}, prompts: {} }, serverInfo: { name: 'srv', version: '1.2' } } }));
  assert.equal(ok.kind, 'json');
  assert.equal(ok.jsonrpc, true);
  assert.deepEqual(ok.result, { protocol_version: '2025-06-18', server_info: { name: 'srv', version: '1.2' }, capabilities_keys: ['tools', 'prompts'], instructions_present: false });
  const sse = parseHandshakeBody('text/event-stream', 'data: {"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"s"}}}\n\n');
  assert.equal(sse.kind, 'sse');
  assert.equal(sse.result?.server_info?.name, 's');
  const err = parseHandshakeBody('application/json', '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}');
  assert.equal(err.error?.code, -32601);
  assert.equal(parseHandshakeBody('text/html', '<!doctype html><html></html>').kind, 'html');
  assert.equal(parseHandshakeBody(null, '').kind, 'empty');
});
await t('handshake: classification table', () => {
  const none = parseHandshakeBody(null, '');
  const res = parseHandshakeBody('application/json', '{"jsonrpc":"2.0","id":1,"result":{}}');
  const err = parseHandshakeBody('application/json', '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nf"}}');
  const www = parseWwwAuthenticate('Bearer resource_metadata="https://h/prm"');
  assert.equal(classifyHandshake(0, null, none), 'unreachable');
  assert.equal(classifyHandshake(401, www, none), 'challenge_401');
  assert.equal(classifyHandshake(401, null, none), 'challenge_401_no_header');
  assert.equal(classifyHandshake(403, null, none), 'forbidden_403');
  assert.equal(classifyHandshake(200, null, res), 'no_challenge_200');
  assert.equal(classifyHandshake(200, null, err), 'jsonrpc_error_200');
  assert.equal(classifyHandshake(200, null, parseHandshakeBody('text/html', '<html>')), 'not_mcp');
  assert.equal(classifyHandshake(202, null, none), 'not_mcp');
  assert.equal(classifyHandshake(404, null, err), 'modern_no_initialize'); // 2026-07-28 server: -32601 for an unknown method
  assert.equal(classifyHandshake(400, null, err), 'modern_no_initialize');
  assert.equal(classifyHandshake(404, null, none), 'error_4xx');
  assert.equal(classifyHandshake(429, null, none), 'error_4xx');
  assert.equal(classifyHandshake(302, null, none), 'redirect_3xx');
  assert.equal(classifyHandshake(503, null, none), 'error_5xx');
});
await t('handshake: disclosure gate needs contact env AND the ethics flag; dry-run needs neither; fixtures waive contact only', () => {
  assert.match(handshakeGate(['example.com'], { ethics: true, dryRun: false }, {}) ?? '', /CRAWLER_CONTACT_URL/);
  assert.match(handshakeGate(['example.com'], { ethics: false, dryRun: false }, { url: 'https://x', email: 'a@b' }) ?? '', /--i-have-read-the-ethics-section/);
  assert.equal(handshakeGate(['example.com'], { ethics: true, dryRun: false }, { url: 'https://x', email: 'a@b' }), null);
  assert.equal(handshakeGate(['example.com'], { ethics: false, dryRun: true }, {}), null);
  assert.match(handshakeGate(['mcp-public.fixture'], { ethics: false, dryRun: false }, {}) ?? '', /ethics/);
  assert.equal(handshakeGate(['mcp-public.fixture'], { ethics: true, dryRun: false }, {}), null);
});
await t('handshake: endpoint extraction takes every SEP-2127 remote; A2A endpoints only when they look like MCP', () => {
  assert.deepEqual(extractAllEndpoints({ name: 'x', remotes: [{ type: 'streamable-http', url: 'https://a/mcp' }, { type: 'sse', url: 'https://a/sse' }] }), ['https://a/mcp', 'https://a/sse']);
  assert.deepEqual(extractAllEndpoints({ name: 'x', url: 'https://a/m' }), ['https://a/m']);
  assert.equal(a2aLooksLikeMcp('https://a/a2a', new Set(['https://a/mcp'])), null);
  assert.equal(a2aLooksLikeMcp('https://a/mcp', new Set(['https://a/mcp'])), 'same_url_as_mcp_card_endpoint');
  assert.equal(a2aLooksLikeMcp('https://a/v1/MCP/', new Set()), 'path_ends_in_mcp');
});

// end to end on the fixture vhosts: synthetic results rows -> collect -> probe
{
  const fx = await startFixtureServer(0);
  const savedFixturePort = process.env.CRAWLER_FIXTURE_PORT;
  process.env.CRAWLER_FIXTURE_PORT = String(fx.port);
  setGlobalRps(0);
  const dir = mkdtempSync(join(tmpdir(), 'hs-'));
  const hyg = (url: string, prm: string[] = []) => ({ source: 'mcp_server_card', kind: 'mcp', card_spec: 'sep-2127', endpoint: { url, https: false, status: 405, reachable: true }, endpoint_third_party_hosted: false, prm_lookups: prm.map((u) => ({ url: u, location: 'path_suffixed', status: 200, valid: true })), authorization_servers: [], has_authorization_servers: false, bearer_query_allowed: null, hsts: null, cache_control: null, mcp_unauthenticated_initialize: null, notes: [] });
  const row = (host: string, rank: number, card: string | null, hygiene: unknown[]) => JSON.stringify({ host, rank, mcp_card_path: card, hygiene, probes: [], fingerprint: { primary: 'unknown', platforms: [] }, blocked: { blocked: false, reason: null, counts: {} }, redirect_only: false });
  const a2aOnly = { ...hyg('http://mcp-public.fixture/mcp-public'), source: 'a2a_agent_card', kind: 'a2a' };
  writeFileSync(join(dir, 'a.jsonl'), [
    row('mcp-public.fixture', 10, '/.well-known/mcp-server-card', [hyg('http://mcp-public.fixture/mcp-public')]),
    row('mcp-sse.fixture', 20, '/.well-known/mcp-server-card', []), // no hygiene endpoint: must re-fetch the card
    row('mcp-protected.fixture', 30, '/.well-known/mcp-server-card', [hyg('http://mcp-protected.fixture/mcp-protected', ['http://mcp-protected.fixture/.well-known/oauth-protected-resource/mcp-protected'])]),
    '{"host":"trunc',
  ].join('\n') + '\n');
  writeFileSync(join(dir, 'b.jsonl'), [
    row('mcp-html.fixture', 40, '/.well-known/mcp-server-card', [hyg('http://mcp-html.fixture/mcp-html')]),
    row('dead.fixture', 50, '/.well-known/mcp/server-card.json', [hyg('http://127.0.0.1:1/mcp')]),
    row('a2a-only.fixture', 60, null, [a2aOnly]), // no valid MCP card: out of scope even though its A2A endpoint is an MCP URL
    row('mcp-public.fixture', 10, '/.well-known/mcp-server-card', [hyg('http://mcp-public.fixture/mcp-public')]), // duplicate row (two files): one probe only
  ].join('\n') + '\n');
  const files = [join(dir, 'a.jsonl'), join(dir, 'b.jsonl')];
  try {
    await t('handshake: dry-run lists targets and contacts nothing', async () => {
      FIXTURE_REQUEST_LOG.length = 0;
      const { targets, stats } = await collectEndpoints(files, { refetch: false, scheme: 'http' });
      assert.equal(FIXTURE_REQUEST_LOG.length, 0);
      assert.equal(stats.hosts_with_mcp_card, 6); // 5 distinct + the duplicate row
      assert.deepEqual(targets.map((x) => x.host), ['mcp-public.fixture', 'mcp-sse.fixture', 'mcp-protected.fixture', 'mcp-html.fixture', 'dead.fixture']);
      const sse = targets.find((x) => x.host === 'mcp-sse.fixture')!;
      assert.equal(sse.endpoint, null);
      assert.equal(sse.needs_card_refetch, true);
      assert.equal(stats.a2a_entries, 0); // a2a-only host has no MCP card -> never considered
    });
    let results: Awaited<ReturnType<typeof probeHandshake>>[] = [];
    await t('handshake: card re-fetch derives the missing endpoint with exactly one GET', async () => {
      FIXTURE_REQUEST_LOG.length = 0;
      const { targets, stats } = await collectEndpoints(files, { refetch: true, scheme: 'http', timeoutMs: 3000 });
      assert.equal(stats.refetched, 1);
      assert.deepEqual(FIXTURE_REQUEST_LOG.map((r) => `${r.method} ${r.host}${r.path}`), ['GET mcp-sse.fixture/.well-known/mcp-server-card']);
      assert.equal(targets.find((x) => x.host === 'mcp-sse.fixture')!.endpoint, 'http://mcp-sse.fixture/mcp-sse');
      FIXTURE_REQUEST_LOG.length = 0;
      FIXTURE_SESSIONS_TERMINATED.length = 0;
      for (const x of targets) if (x.endpoint) results.push(await probeHandshake(x as EndpointTarget & { endpoint: string }, { timeoutMs: 3000 }));
    });
    const by = (h: string) => results.find((r) => r.host === h)!;
    await t('handshake: public endpoint -> no_challenge_200 with serverInfo / protocolVersion / capability keys, session closed with DELETE', () => {
      const r = by('mcp-public.fixture');
      assert.equal(r.classification, 'no_challenge_200');
      assert.equal(r.status, 200);
      assert.equal(r.body_kind, 'json');
      assert.deepEqual(r.result?.server_info, { name: 'fixture-public-mcp', version: '9.9.9' });
      assert.equal(r.result?.protocol_version, '2025-11-25');
      assert.deepEqual(r.result?.capabilities_keys, ['tools', 'resources']);
      assert.equal(r.mcp_session_id_present, true);
      assert.deepEqual(r.session_delete, { sent: true, status: 204, error: null });
      assert.equal(r.request.authorization_sent, false);
      assert.equal(r.www_authenticate, null);
      assert.deepEqual(r.requests_made, ['POST http://mcp-public.fixture/mcp-public', 'DELETE http://mcp-public.fixture/mcp-public']);
    });
    await t('handshake: SSE endpoint -> first event parsed, stream left open by the server does not stall the probe', () => {
      const r = by('mcp-sse.fixture');
      assert.equal(r.classification, 'no_challenge_200');
      assert.equal(r.body_kind, 'sse');
      assert.equal(r.result?.server_info?.name, 'fixture-sse-mcp');
      assert.ok(r.elapsed_ms < 2500, `took ${r.elapsed_ms}ms (should stop after the first event, not at the timeout)`);
      assert.equal(r.session_delete?.sent, true);
    });
    await t('handshake: protected endpoint -> challenge_401, WWW-Authenticate parsed, resource_metadata resolves and matches the hygiene PRM', () => {
      const r = by('mcp-protected.fixture');
      assert.equal(r.classification, 'challenge_401');
      assert.equal(r.www_authenticate?.scheme, 'Bearer');
      assert.equal(r.www_authenticate?.realm, 'mcp');
      assert.equal(r.www_authenticate?.error, 'invalid_request');
      assert.equal(r.www_authenticate?.resource_metadata, 'http://mcp-protected.fixture/.well-known/oauth-protected-resource/mcp-protected');
      assert.equal(r.resource_metadata?.resolves, true);
      assert.equal(r.resource_metadata?.is_prm, true);
      assert.equal(r.resource_metadata?.matches_hygiene_prm, true);
      assert.equal(r.session_delete, null);
      assert.equal(r.result, null);
    });
    await t('handshake: HTML squatter -> not_mcp; refused connection -> unreachable', () => {
      assert.equal(by('mcp-html.fixture').classification, 'not_mcp');
      assert.equal(by('mcp-html.fixture').body_kind, 'html');
      assert.equal(by('dead.fixture').classification, 'unreachable');
      assert.equal(by('dead.fixture').error, 'refused');
      assert.equal(by('dead.fixture').requests_made.length, 1);
    });
    await t('handshake: request log — exactly one POST per endpoint, every POST is initialize, DELETE exactly once per session, never an Authorization header, nothing else', () => {
      const log = FIXTURE_REQUEST_LOG;
      const posts = log.filter((r) => r.method === 'POST');
      assert.deepEqual(posts.map((r) => `${r.host}${r.path}`).sort(), ['mcp-html.fixture/mcp-html', 'mcp-protected.fixture/mcp-protected', 'mcp-public.fixture/mcp-public', 'mcp-sse.fixture/mcp-sse']);
      for (const p of posts) {
        const j = JSON.parse(p.body);
        assert.equal(j.method, 'initialize');
        assert.equal(j.jsonrpc, '2.0');
        assert.equal(p.headers['mcp-protocol-version'], '2025-11-25');
        assert.match(p.headers.accept, /application\/json/);
        assert.match(p.headers.accept, /text\/event-stream/);
        assert.equal(p.headers['content-type'], 'application/json');
      }
      const deletes = log.filter((r) => r.method === 'DELETE');
      assert.deepEqual(deletes.map((r) => `${r.host}${r.path}`).sort(), ['mcp-public.fixture/mcp-public', 'mcp-sse.fixture/mcp-sse']);
      assert.equal(FIXTURE_SESSIONS_TERMINATED.length, 2);
      assert.ok(FIXTURE_SESSIONS_TERMINATED.every((s) => s.length > 0));
      const gets = log.filter((r) => r.method === 'GET');
      assert.deepEqual(gets.map((r) => `${r.host}${r.path}`), ['mcp-protected.fixture/.well-known/oauth-protected-resource/mcp-protected']);
      assert.equal(log.length, posts.length + deletes.length + gets.length);
      assert.ok(log.every((r) => r.headers.authorization === undefined && r.headers.cookie === undefined));
      assert.ok(log.every((r) => /^AgentDiscoveryCrawler\/0\.6 /.test(r.headers['user-agent'])));
    });
    await t('disclosure: findings.csv rows, Shopify roll-up, contact hints, email template and summary', async () => {
      const hsFile = join(dir, 'handshake.jsonl');
      writeFileSync(hsFile, results.map((r) => JSON.stringify(r)).join('\n') + '\n');
      const sec = { path: '/.well-known/security.txt', valid: true, final_url: 'http://mcp-public.fixture/.well-known/security.txt' };
      const as = (issuer: string, issuer_match: boolean, pkce: boolean) => ({ issuer, https: true, metadata_url: `${issuer}/.well-known/oauth-authorization-server`, status: 200, resolves: true, issuer_match, pkce_advertised: pkce, third_party_hosted: false });
      const rowsFile = join(dir, 'results.jsonl');
      writeFileSync(rowsFile, [
        JSON.stringify({ host: 'mcp-public.fixture', rank: 10, mcp_card_path: '/.well-known/mcp-server-card', hygiene: [hyg('http://mcp-public.fixture/mcp-public')], probes: [sec], fingerprint: { primary: 'unknown', platforms: [] } }),
        JSON.stringify({ host: 'dead.fixture', rank: 50, mcp_card_path: '/.well-known/mcp/server-card.json', hygiene: [{ ...hyg('http://127.0.0.1:1/mcp'), endpoint: { url: 'http://127.0.0.1:1/mcp', https: false, status: null, error: 'refused', reachable: false }, notes: ['endpoint_unreachable'] }], probes: [], fingerprint: { primary: 'unknown', platforms: [] } }),
        JSON.stringify({ host: 'nocard-ep.fixture', rank: 70, mcp_card_path: '/.well-known/mcp-server-card', hygiene: [{ ...hyg('x'), endpoint: undefined, notes: ['no_endpoint_url_in_card'] }], probes: [], fingerprint: { primary: 'unknown', platforms: [] } }),
        JSON.stringify({ host: 'idp.fixture', rank: 80, mcp_card_path: null, hygiene: [{ ...hyg('https://idp.fixture/mcp'), source: 'oauth_protected_resource', kind: 'protected_resource', authorization_servers: [as('https://as.fixture', false, false)], notes: ['prm_resource_mismatch', 'issuer_mismatch', 'no_pkce_advertised'] }], probes: [], fingerprint: { primary: 'unknown', platforms: [] } }),
        JSON.stringify({ host: 'shop1.fixture', rank: 90, mcp_card_path: null, hygiene: [{ ...hyg('https://shop1.fixture/'), source: 'oauth_protected_resource', kind: 'protected_resource', authorization_servers: [as('https://shopify.com/authentication/123', false, true)], notes: ['issuer_mismatch'] }], probes: [], fingerprint: { primary: 'unknown', platforms: [] } }),
        JSON.stringify({ host: 'shop2.fixture', rank: 91, mcp_card_path: null, hygiene: [{ ...hyg('https://shop2.fixture/'), source: 'oauth_protected_resource', kind: 'protected_resource', authorization_servers: [as('https://shopify.com/authentication/456', false, false)], notes: ['issuer_mismatch', 'no_pkce_advertised'] }], probes: [], fingerprint: { primary: 'shopify', platforms: ['shopify'] } }),
      ].join('\n') + '\n');
      assert.equal(isShopifyIssuer('https://shopify.com/authentication/123'), true);
      assert.equal(isShopifyIssuer('https://accounts.shopify.com/authentication/1'), true);
      assert.equal(isShopifyIssuer('https://as.fixture'), false);
      assert.equal(isShopifyHost({ fingerprint: { primary: 'shopify', platforms: [] } as never, hygiene: [] }), true);
      assert.equal(securityTxtContact('Expires: x\nContact: mailto:sec@h.test\nContact: https://h.test/r\n'), 'mailto:sec@h.test');
      assert.equal(csvEscape('a "b", c'), '"a ""b"", c"');
      const b = await buildFindings({ handshakeFile: hsFile, resultsFiles: [rowsFile], scheme: 'http' });
      const f = (host: string, finding: string) => b.findings.find((x) => x.host === host && x.finding === finding);
      // no_challenge_200 from the handshake file: public + sse (sse host has no results row -> rank from the handshake row, hint WHOIS)
      assert.equal(f('mcp-public.fixture', 'no_challenge_200')?.severity, 'medium');
      assert.match(f('mcp-public.fixture', 'no_challenge_200')!.evidence, /POST initialize http:\/\/mcp-public\.fixture\/mcp-public -> 200 .*fixture-public-mcp@9\.9\.9.*DELETE/);
      assert.equal(f('mcp-public.fixture', 'no_challenge_200')!.contact_hint, 'security.txt: http://mcp-public.fixture/.well-known/security.txt');
      assert.equal(f('mcp-sse.fixture', 'no_challenge_200')!.contact_hint, 'WHOIS/abuse');
      assert.equal(f('mcp-sse.fixture', 'no_challenge_200')!.rank, 20);
      assert.ok(!f('mcp-protected.fixture', 'no_challenge_200'));
      assert.match(f('dead.fixture', 'dead_card_endpoint')!.evidence, /127\.0\.0\.1:1\/mcp -> refused/);
      assert.equal(f('nocard-ep.fixture', 'card_without_endpoint')?.severity, 'info');
      assert.ok(f('idp.fixture', 'prm_resource_mismatch'));
      assert.match(f('idp.fixture', 'prm_issuer_mismatch')!.evidence, /as\.fixture\/\.well-known\/oauth-authorization-server -> 200/);
      assert.ok(f('idp.fixture', 'no_pkce_advertised'));
      // Shopify: no per-storefront rows, one aggregate row
      assert.ok(!b.findings.some((x) => /^shop\d\.fixture$/.test(x.host)));
      const agg = f('shopify-platform-pattern', 'shopify-platform-pattern')!;
      assert.ok(agg);
      assert.match(agg.evidence, /^2 Shopify storefront hosts; .*issuer_mismatch_two_issuer=2/);
      assert.match(agg.evidence, /no_pkce_advertised=1/);
      assert.equal(b.counts['shopify-platform-pattern'], 1);
      assert.equal(b.counts.no_challenge_200, 2);
      assert.equal(b.hosts, 5);
      const csv = renderCsv(b.findings);
      assert.equal(csv.split('\n')[0], 'host,rank,finding,evidence,severity,contact_hint,notified_on,remediated_on,notes');
      assert.equal(csv.trim().split('\n').length, b.findings.length + 1);
      assert.ok(EMAIL_TEMPLATE.includes('{{host}}') && EMAIL_TEMPLATE.includes('90 days') && EMAIL_TEMPLATE.includes('{{optout_email}}') && EMAIL_TEMPLATE.includes('DELETE'));
      const sum = renderSummary(b, { handshakeFile: hsFile, resultsFiles: [rowsFile] });
      assert.match(sum, /\| no_challenge_200 \| medium \| 2 \|/);
      assert.match(sum, /Shopify storefront hosts rolled into one row: 2/);
      // hygieneFindings on a Shopify-issuer host alone yields no issuer_mismatch row
      const shopRow = { host: 'shop1.fixture', hygiene: [{ ...hyg('https://shop1.fixture/'), source: 'oauth_protected_resource', kind: 'protected_resource', authorization_servers: [as('https://shopify.com/authentication/123', false, true)], notes: ['issuer_mismatch'] }] } as unknown as HostResult;
      assert.deepEqual(hygieneFindings(shopRow, { rank: 90, shopify: true, security_txt_valid: false, security_txt_url: null, security_txt_body_file: null }, (p) => p), []);
    });
  } finally {
    fx.server.close();
    if (savedFixturePort === undefined) delete process.env.CRAWLER_FIXTURE_PORT; else process.env.CRAWLER_FIXTURE_PORT = savedFixturePort;
    FIXTURE_REQUEST_LOG.length = 0;
  }
}

// ---- 0.4.0: WebMCP module end to end on the fixture vhosts (headless Chromium) ----
const chromiumPath = resolveChromiumPath();
if (!chromiumPath) {
  console.log('skip - WebMCP browser checks: no Chromium found (run `npx playwright-core install chromium` or set CRAWLER_CHROMIUM_PATH)');
} else {
  const fx = await startFixtureServer(0);
  const savedFixturePort = process.env.CRAWLER_FIXTURE_PORT;
  process.env.CRAWLER_FIXTURE_PORT = String(fx.port);
  const browser = await launchChromium({ executablePath: chromiumPath, fixturePort: String(fx.port) });
  const opts = { pages: 4, timeoutMs: 15_000, scheme: 'http' as const, settleMs: 200, navGapMs: 0 };
  try {
    const r = await crawlHostWebMCP(browser, 'webmcp.fixture', opts, 42);
    await t('webmcp: shim records registerTool / provideContext / unregisterTool on the fixture (name, description, input keys, page)', () => {
      assert.deepEqual(r.errors, []);
      assert.equal(r.rank, 42);
      const reg = r.registrations.find((x) => x.method === 'registerTool');
      assert.ok(reg, JSON.stringify(r.registrations));
      assert.equal(reg!.tool_name, 'search_products');
      assert.equal(reg!.description, 'Search the catalog');
      assert.deepEqual(reg!.input_keys, ['query', 'limit']);
      assert.equal(reg!.has_execute, true);
      assert.equal(reg!.page, 'http://webmcp.fixture/');
      assert.deepEqual(r.registrations.filter((x) => x.method === 'provideContext').map((x) => x.tool_name), ['add_to_cart', 'get_cart']);
      assert.equal(r.registrations.find((x) => x.method === 'unregisterTool')?.tool_name, 'get_cart');
      assert.ok(!r.registrations.some((x) => x.tool_name === 'SHOULD_NOT_BE_SEEN'));
    });
    await t('webmcp: homepage + 3 same-domain nav links, robots Disallow honored, assets/externals skipped', () => {
      assert.deepEqual(r.pages_visited, ['http://webmcp.fixture/', 'http://webmcp.fixture/tools', 'http://webmcp.fixture/trial', 'http://webmcp.fixture/about']);
      assert.deepEqual(r.robots.skipped, ['/private/secret']);
      assert.equal(r.robots.status, 200);
    });
    await t('webmcp: origin-trial token read from the Origin-Trial header and the meta tag, payload decoded', () => {
      assert.equal(r.origin_trial.present, true);
      assert.equal(r.origin_trial.feature, 'WebMCP');
      assert.equal(r.origin_trial.expiry, '2027-01-15T08:00:00.000Z');
      assert.deepEqual(r.origin_trial.tokens.map((x) => x.source), ['header', 'meta']);
    });
    await t('webmcp: declarative <form toolname> found with its toolparamdescription inputs', () => {
      assert.equal(r.declarative_hits.length, 1);
      const d = r.declarative_hits[0];
      assert.equal(d.kind, 'declarative_form');
      assert.equal(d.toolname, 'checkout');
      assert.equal(d.toolautosubmit, true);
      assert.deepEqual(d.params, ['sku', 'qty']);
      assert.equal(d.page, 'http://webmcp.fixture/tools');
    });
    await t('webmcp: feature detection reports no native modelContext in stock Chromium', () => {
      assert.equal(r.native_modelContext, false);
      assert.equal(r.native_document_modelContext, false);
    });
    const none = await crawlHostWebMCP(browser, 'webmcp-none.fixture', opts);
    await t('webmcp: a host without WebMCP yields empty registrations / no trial / no declarative hits (robots 404 = allowed)', () => {
      assert.deepEqual(none.registrations, []);
      assert.equal(none.origin_trial.present, false);
      assert.deepEqual(none.declarative_hits, []);
      assert.equal(none.robots.status, 404);
      assert.deepEqual(none.pages_visited, ['http://webmcp-none.fixture/', 'http://webmcp-none.fixture/about']);
      assert.deepEqual(none.errors, []);
    });
  } finally {
    await browser.close();
    fx.server.close();
    if (savedFixturePort === undefined) delete process.env.CRAWLER_FIXTURE_PORT; else process.env.CRAWLER_FIXTURE_PORT = savedFixturePort;
  }
}

srv.close();
console.log(`\n${n} checks passed`);
