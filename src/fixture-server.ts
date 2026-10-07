// Local fixture server for end-to-end testing without network access.
// Serves several "virtual hosts" selected by the Host header so one process
// can stand in for a small corpus:
//   good.fixture     — full discovery stack, all valid
//   spa.fixture      — SPA that returns 200 HTML for everything (soft-404s)
//   broken.fixture   — artifacts present but invalid / insecure
//   blocked.fixture  — 403 on everything (bot wall)
//   empty.fixture    — plain 404s
//   redirect.fixture — 301s every path to another registrable domain (redirect-only host)
//   apex.fixture     — 301s every path to www.apex.fixture, which serves a valid llms.txt and
//                      security.txt (www_redirect, NOT cross_origin_hit)
//   webmcp.fixture   — WebMCP module fixture: homepage calls navigator.modelContext.registerTool
//                      (feature-detected), /tools calls provideContext and carries a declarative
//                      <form toolname>, /trial has an origin-trial meta, /private/* is robots-disallowed
//   webmcp-none.fixture — plain pages, no WebMCP anything, no robots.txt
//   mcp-public.fixture    — handshake probe: card -> /mcp-public, answers initialize with a JSON-RPC
//                           result + Mcp-Session-Id and no auth; DELETE terminates the session
//   mcp-sse.fixture       — card -> /mcp-sse, same but the InitializeResult comes as an SSE stream
//                           that stays open (the probe must stop after the first event)
//   mcp-protected.fixture — card -> /mcp-protected, 401 + WWW-Authenticate Bearer resource_metadata
//                           pointing at /.well-known/oauth-protected-resource/mcp-protected
//   mcp-html.fixture      — card -> /mcp-html, 200 text/html (a web page squatting the endpoint)
// Every request is appended to FIXTURE_REQUEST_LOG (host, method, path, body) so the
// self-test can assert what the handshake probe did and did not send.
// good.fixture serves several artifacts compressed (gzip / br / deflate) when the
// client advertises it, which is how CDNs answer the crawler in the wild.
// Usage: tsx src/fixture-server.ts [port]   then
//   tsx src/run.ts --hosts hosts/fixtures.txt --out out/fixtures.jsonl --scheme http
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib';
import { makeFakeOriginTrialToken } from './webmcp.js';

type Handler = (path: string, req: IncomingMessage, res: ServerResponse, body: string) => boolean;

export interface FixtureRequest { host: string; method: string; path: string; body: string; headers: Record<string, string> }
/** Every request the fixture server saw, in order (reset with FIXTURE_REQUEST_LOG.length = 0). */
export const FIXTURE_REQUEST_LOG: FixtureRequest[] = [];

function send(res: ServerResponse, status: number, body: string, type: string, extra: Record<string, string> = {}) {
  res.writeHead(status, { 'content-type': type, 'content-length': Buffer.byteLength(body), ...extra });
  res.end(body);
}

/** Send `body` with content-encoding `enc` if the request accepts it, else identity. */
function sendEncoded(req: IncomingMessage, res: ServerResponse, status: number, body: string, type: string, enc: 'gzip' | 'br' | 'deflate', extra: Record<string, string> = {}) {
  const accepts = String(req.headers['accept-encoding'] ?? '').split(',').map((x) => x.trim().split(';')[0]);
  if (!accepts.includes(enc)) return send(res, status, body, type, extra);
  const raw = Buffer.from(body);
  const out = enc === 'gzip' ? gzipSync(raw) : enc === 'br' ? brotliCompressSync(raw) : deflateSync(raw);
  res.writeHead(status, { 'content-type': type, 'content-encoding': enc, 'content-length': out.length, vary: 'accept-encoding', ...extra });
  res.end(out);
}

// Virtual-host URLs carry no port: the crawler routes *.fixture to 127.0.0.1:$CRAWLER_FIXTURE_PORT itself.
const base = (host: string) => `http://${host}`;

const good: Handler = (path, req, res) => {
  const origin = base('good.fixture');
  const hdr = { server: 'Vercel', 'x-vercel-id': 'iad1::test' };
  switch (path) {
    case '/':
      send(res, 200, '<!doctype html><html><head><meta name="generator" content="Mintlify"><script src="/_next/static/x.js"></script></head><body>hi</body></html>', 'text/html', hdr);
      return true;
    case '/llms.txt':
      // gzip, as a CDN would serve it
      sendEncoded(req, res, 200, '# Good Fixture\n\n> A fixture site.\n\n## Docs\n- [API](/docs/api.md)\n', 'text/plain; charset=utf-8', 'gzip', hdr);
      return true;
    case '/llms-full.txt':
      sendEncoded(req, res, 200, '# Good Fixture (full)\n\nLots of text.\n', 'text/markdown', 'deflate', hdr);
      return true;
    case '/.well-known/mcp-server-card':
      // SEP-2127 shape, with HSTS + cache headers, brotli-compressed
      sendEncoded(req, res, 200, JSON.stringify({ name: 'fixture.good.search', version: '1.0.0', description: 'Good fixture MCP', remotes: [{ type: 'streamable-http', url: `${origin}/v1/mcp` }] }), 'application/json', 'br', { ...hdr, 'strict-transport-security': 'max-age=63072000', 'cache-control': 'public, max-age=300' });
      return true;
    case '/.well-known/mcp/server-card.json':
      // legacy path, SEP-1649 shape
      send(res, 200, JSON.stringify({ name: 'good-mcp', version: '1.0', transport: { type: 'streamable-http', url: `${origin}/v1/mcp` }, tools: [{ name: 'search' }] }), 'application/json', hdr);
      return true;
    case '/.well-known/oauth-protected-resource/v1/mcp':
      // RFC 9728 path-suffixed PRM for the endpoint
      send(res, 200, JSON.stringify({ resource: `${origin}/v1/mcp`, authorization_servers: [origin], bearer_methods_supported: ['header'], scopes_supported: ['read'] }), 'application/json', hdr);
      return true;
    case '/.well-known/oauth-protected-resource':
      // root PRM describes the origin itself (RFC 9728 §3.3); bearer query is the insecure bit here
      send(res, 200, JSON.stringify({ resource: `${origin}/`, authorization_servers: [origin], bearer_methods_supported: ['header', 'query'], scopes_supported: ['read'] }), 'application/json', hdr);
      return true;
    case '/.well-known/oauth-authorization-server':
      send(res, 200, JSON.stringify({ issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`, response_types_supported: ['code'], code_challenge_methods_supported: ['S256'] }), 'application/json', hdr);
      return true;
    case '/.well-known/ai-catalog.json':
      send(res, 200, JSON.stringify({ '@context': 'https://example.org/ai-card', agents: [] }), 'application/json', hdr);
      return true;
    case '/.well-known/security.txt':
      send(res, 200, 'Contact: mailto:security@good.fixture\nExpires: 2027-01-01T00:00:00.000Z\n', 'text/plain', hdr);
      return true;
    case '/.well-known/openid-configuration':
      send(res, 200, JSON.stringify({ issuer: origin, jwks_uri: `${origin}/jwks`, response_types_supported: ['code'] }), 'application/json', hdr);
      return true;
    case '/.well-known/agent-card.json':
      // A2A v1.0 shape: endpoint in supportedInterfaces[], no legacy top-level url
      send(res, 200, JSON.stringify({ name: 'good-agent', protocolVersion: '1.0', supportedInterfaces: [{ url: `${origin}/a2a`, protocolBinding: 'JSONRPC' }], skills: [{ id: 'x' }] }), 'application/json', hdr);
      return true;
    case '/.well-known/agent.json':
      // legacy A2A shape
      send(res, 200, JSON.stringify({ name: 'good-agent', url: `${origin}/a2a`, skills: [{ id: 'x' }] }), 'application/json', hdr);
      return true;
    case '/openapi.json':
      sendEncoded(req, res, 200, JSON.stringify({ openapi: '3.1.0', info: { title: 'Good' }, paths: { '/search': { get: { operationId: 'search' } } } }), 'application/json', 'br', hdr);
      return true;
    case '/openapi.yaml':
      send(res, 200, 'openapi: "3.0.3"\ninfo:\n  title: Good\npaths:\n  /search:\n    get:\n      operationId: search\n', 'application/yaml', hdr);
      return true;
    case '/ai.txt':
      send(res, 200, 'User-agent: *\nAllow: /\n', 'text/plain', hdr);
      return true;
    case '/v1/mcp':
      if (req.method === 'HEAD') { res.writeHead(405, { allow: 'POST' }); res.end(); return true; }
      send(res, 401, JSON.stringify({ error: 'unauthorized' }), 'application/json', { 'www-authenticate': `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"` });
      return true;
    case '/a2a':
      send(res, 405, '', 'text/plain');
      return true;
  }
  return false;
};

const spa: Handler = (path, _req, res) => {
  // Every path returns the same 200 HTML shell (classic SPA soft-404).
  const html = '<!doctype html><html><head><title>SPA</title><script src="/_nuxt/app.js"></script></head><body><div id="app"></div></body></html>';
  send(res, 200, html, 'text/html; charset=utf-8', { server: 'cloudflare', 'cf-ray': '0-IAD' });
  void path;
  return true;
};

const broken: Handler = (path, req, res) => {
  const hdr = { server: 'nginx/1.24', 'x-powered-by': 'PHP/8.2' };
  switch (path) {
    case '/':
      send(res, 200, '<html><head><link rel="stylesheet" href="/wp-content/themes/x/style.css"></head></html>', 'text/html', hdr);
      return true;
    case '/llms.txt':
      // a redirect to the homepage HTML — a common misconfiguration
      res.writeHead(302, { location: '/' }); res.end();
      return true;
    case '/.well-known/mcp/server-card.json':
      // valid card but http:// endpoint on a third-party host and no auth server
      send(res, 200, JSON.stringify({ name: 'broken-mcp', url: 'http://mcp.elsewhere.invalid/mcp' }), 'application/json', hdr);
      return true;
    case '/llms-full.txt':
      // redirect to a sibling host within the registrable domain (followed, flagged cross_origin_hit)
      res.writeHead(301, { location: `${base('docs.broken.fixture')}/llms-full.txt` }); res.end();
      return true;
    case '/.well-known/security.txt':
      send(res, 200, 'Policy: https://broken.fixture/security\n', 'text/plain', hdr); // no Contact
      return true;
    case '/.well-known/oauth-protected-resource':
      // no authorization_servers (allowed, noted) but `resource` names a different resource than this URL describes (RFC 9728 §3.3)
      send(res, 200, JSON.stringify({ resource: `${base('broken.fixture')}/api/mcp` }), 'application/json', hdr);
      return true;
    case '/.well-known/agent.json':
      // served as text/html but valid JSON body; issuer mismatch scenario elsewhere
      send(res, 200, JSON.stringify({ name: 'agent', url: `${base('good.fixture')}/a2a` }), 'text/html', hdr);
      return true;
    case '/openapi.json':
      send(res, 200, JSON.stringify({ swagger: '2.0', info: {} }), 'application/json', hdr);
      return true;
    case '/openapi.yaml':
      send(res, 200, 'not: [valid: yaml', 'text/plain', hdr);
      return true;
    case '/.well-known/oauth-authorization-server':
      // issuer present but response_types_supported missing -> invalid under RFC 8414 §2
      send(res, 200, JSON.stringify({ issuer: 'https://someone-else.example' }), 'application/json', hdr);
      return true;
    case '/.well-known/openid-configuration':
      // gzip-compressed valid-looking JSON that only advertises PKCE "plain"
      sendEncoded(req, res, 200, JSON.stringify({ issuer: base('broken.fixture'), response_types_supported: ['code'], code_challenge_methods_supported: ['plain'] }), 'application/json', 'gzip', hdr);
      return true;
    case '/ai.txt':
      send(res, 200, '', 'text/plain', hdr);
      return true;
  }
  return false;
};

const redirect: Handler = (_path, req, res) => {
  // Apex-style redirector: every request leaves the registrable domain.
  res.writeHead(301, { location: `https://elsewhere.example${req.url ?? '/'}` });
  res.end();
  return true;
};

const apex: Handler = (_path, req, res) => {
  // Apex -> www canonicalization, the most common redirect on the web. Same site.
  res.writeHead(301, { location: `${base('www.apex.fixture')}${req.url ?? '/'}` });
  res.end();
  return true;
};

const wwwApex: Handler = (path, _req, res) => {
  const hdr = { server: 'nginx' };
  switch (path) {
    case '/':
      send(res, 200, '<html><head><meta name="generator" content="Hugo 0.120"></head><body>www</body></html>', 'text/html', hdr);
      return true;
    case '/llms.txt':
      send(res, 200, '# Apex Fixture\n\n## Docs\n- [a](/a)\n', 'text/plain; charset=utf-8', hdr);
      return true;
    case '/.well-known/security.txt':
      send(res, 200, 'Contact: mailto:security@apex.fixture\nExpires: 2027-01-01T00:00:00.000Z\n', 'text/plain', hdr);
      return true;
  }
  return false;
};

const blocked: Handler = (_path, _req, res) => {
  send(res, 403, '<html><head><title>Just a moment...</title></head><body>cf-chl challenge-platform</body></html>', 'text/html', { server: 'cloudflare', 'cf-mitigated': 'challenge', 'cf-ray': '1-IAD' });
  return true;
};

const empty: Handler = (path, _req, res) => {
  if (path === '/') { send(res, 200, '<html><body>empty</body></html>', 'text/html', { server: 'Apache' }); return true; }
  return false;
};

const docsBroken: Handler = (path, _req, res) => {
  // valid Markdown, but the H1 is not the first line (llms.txt spec says it must be) -> note:h1_not_first
  if (path === '/llms-full.txt') { send(res, 200, '> intro blockquote first\n\n# Broken (docs host)\n\nFull text.\n', 'text/markdown'); return true; }
  return false;
};

// ---- WebMCP fixtures (src/webmcp.ts) ----
const fakeTrialToken = makeFakeOriginTrialToken({ origin: 'https://webmcp.fixture:443', feature: 'WebMCP', expiry: 1_800_000_000, isSubdomain: false, isThirdParty: false, usage: '' });
const webmcpNav = '<nav><a href="/tools">Tools</a> <a href="/trial">Trial</a> <a href="/private/secret">Private</a> <a href="/about">About</a> <a href="https://elsewhere.example/x">Elsewhere</a> <a href="/logo.png">Logo</a> <a href="/tools#top">dup</a></nav>';
const webmcp: Handler = (path, _req, res) => {
  const hdr = { server: 'nginx' };
  switch (path) {
    case '/robots.txt':
      send(res, 200, '# fixture\nUser-agent: *\nDisallow: /private/\nAllow: /\n', 'text/plain', hdr);
      return true;
    case '/':
      // Imperative API, feature-detected the way the Chrome preview docs show it; Origin-Trial also as a header here.
      send(res, 200, `<!doctype html><html><head><title>WebMCP fixture</title></head><body>${webmcpNav}<main>hello</main>
<script>
if (navigator.modelContext) {
  navigator.modelContext.registerTool({
    name: 'search_products',
    description: 'Search the catalog',
    inputSchema: { type: 'object', properties: { query: { type: 'string' }, limit: { type: 'number' } }, required: ['query'] },
    async execute({ query }) { return { content: [{ type: 'text', text: 'results for ' + query }] }; }
  });
}
</script></body></html>`, 'text/html', { ...hdr, 'origin-trial': fakeTrialToken });
      return true;
    case '/tools':
      // provideContext bulk form + the declarative form API from the declarative explainer.
      send(res, 200, `<!doctype html><html><head><title>Tools</title></head><body>${webmcpNav}
<form toolname="checkout" tooldescription="Start checkout for the current cart" toolautosubmit action="/checkout" method="post">
  <input name="sku" toolparamdescription="Product SKU"><input name="qty" toolparamdescription="Quantity"><button>Buy</button>
</form>
<script>
if ('modelContext' in navigator) {
  navigator.modelContext.provideContext({ tools: [
    { name: 'add_to_cart', description: 'Add a SKU to the cart', inputSchema: { type: 'object', properties: { sku: { type: 'string' }, qty: { type: 'integer' } } }, execute: async () => ({}) },
    { name: 'get_cart', description: 'Return the cart', inputSchema: { type: 'object', properties: {} }, execute: async () => ({}) }
  ] });
  navigator.modelContext.unregisterTool('get_cart');
}
</script></body></html>`, 'text/html', hdr);
      return true;
    case '/trial':
      send(res, 200, `<!doctype html><html><head><meta http-equiv="origin-trial" content="${fakeTrialToken}"><title>Trial</title></head><body>${webmcpNav}<p>trial page, no registrations</p></body></html>`, 'text/html', hdr);
      return true;
    case '/about':
      send(res, 200, `<!doctype html><html><head><title>About</title></head><body>${webmcpNav}<p>about</p></body></html>`, 'text/html', hdr);
      return true;
    case '/private/secret':
      // robots-disallowed: the module must never request it
      send(res, 200, `<!doctype html><html><body><script>if (navigator.modelContext) navigator.modelContext.registerTool({ name: 'SHOULD_NOT_BE_SEEN', description: 'x', inputSchema: {} });</script></body></html>`, 'text/html', hdr);
      return true;
  }
  return false;
};
const webmcpNone: Handler = (path, _req, res) => {
  switch (path) {
    case '/':
      send(res, 200, '<!doctype html><html><head><title>None</title></head><body><nav><a href="/about">About</a></nav><p>nothing here</p></body></html>', 'text/html', { server: 'Apache' });
      return true;
    case '/about':
      send(res, 200, '<!doctype html><html><body><p>about</p></body></html>', 'text/html', { server: 'Apache' });
      return true;
  }
  return false; // robots.txt -> 404
};

// ---- MCP initialize handshake fixtures (src/handshake.ts) ----
function jsonRpcBody(body: string): { id: unknown; method: string | null } {
  try { const j = JSON.parse(body); return { id: j.id ?? null, method: typeof j.method === 'string' ? j.method : null }; } catch { return { id: null, method: null }; }
}
const initializeResult = (id: unknown, name: string) => JSON.stringify({ jsonrpc: '2.0', id, result: { protocolVersion: '2025-11-25', capabilities: { tools: { listChanged: true }, resources: {} }, serverInfo: { name, version: '9.9.9' }, instructions: 'fixture' } });
/** Shared card for the mcp-*.fixture vhosts: SEP-2127, one remote at /<endpointPath>. */
function mcpCard(host: string, endpointPath: string): Handler {
  return (path, _req, res) => {
    if (path === '/.well-known/mcp-server-card') {
      send(res, 200, JSON.stringify({ name: `fixture.${host.split('.')[0]}`, version: '1.0.0', remotes: [{ type: 'streamable-http', url: `${base(host)}${endpointPath}` }] }), 'application/json');
      return true;
    }
    if (path === '/') { send(res, 200, '<html><body>mcp fixture</body></html>', 'text/html'); return true; }
    return false;
  };
}
export const FIXTURE_SESSIONS_TERMINATED: string[] = [];
const mcpPublic: Handler = (path, req, res, body) => {
  if (path !== '/mcp-public') return mcpCard('mcp-public.fixture', '/mcp-public')(path, req, res, body);
  if (req.method === 'DELETE') {
    const sid = String(req.headers['mcp-session-id'] ?? '');
    if (!sid) { send(res, 400, 'missing Mcp-Session-Id', 'text/plain'); return true; }
    FIXTURE_SESSIONS_TERMINATED.push(sid);
    res.writeHead(204); res.end(); return true;
  }
  if (req.method !== 'POST') { res.writeHead(405, { allow: 'POST, DELETE' }); res.end(); return true; }
  const { id, method } = jsonRpcBody(body);
  if (method !== 'initialize') { send(res, 400, JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32600, message: 'fixture: only initialize is answered' } }), 'application/json'); return true; }
  send(res, 200, initializeResult(id, 'fixture-public-mcp'), 'application/json', { 'mcp-session-id': 'sess-' + Math.random().toString(16).slice(2) });
  return true;
};
const mcpSse: Handler = (path, req, res, body) => {
  if (path !== '/mcp-sse') return mcpCard('mcp-sse.fixture', '/mcp-sse')(path, req, res, body);
  if (req.method === 'DELETE') { const sid = String(req.headers['mcp-session-id'] ?? ''); FIXTURE_SESSIONS_TERMINATED.push(sid); res.writeHead(200); res.end(); return true; }
  if (req.method !== 'POST') { res.writeHead(405, { allow: 'POST' }); res.end(); return true; }
  const { id } = jsonRpcBody(body);
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', 'mcp-session-id': 'sse-session-1' });
  res.write(': keepalive\n\n');
  res.write('id: 1\ndata: \n\n'); // priming event, empty data (2025-11-25 §Sending Messages item 6)
  res.write(`id: 2\nevent: message\ndata: ${initializeResult(id, 'fixture-sse-mcp')}\n\n`);
  // keep the stream open: the probe must not wait for us
  const keep = setInterval(() => { try { res.write(': ping\n\n'); } catch { clearInterval(keep); } }, 500);
  keep.unref();
  req.on('close', () => { clearInterval(keep); try { res.end(); } catch { /* closed */ } });
  return true;
};
const mcpProtected: Handler = (path, req, res, body) => {
  const origin = base('mcp-protected.fixture');
  if (path === '/.well-known/oauth-protected-resource/mcp-protected') {
    send(res, 200, JSON.stringify({ resource: `${origin}/mcp-protected`, authorization_servers: [origin], bearer_methods_supported: ['header'] }), 'application/json');
    return true;
  }
  if (path === '/.well-known/oauth-authorization-server') {
    send(res, 200, JSON.stringify({ issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`, response_types_supported: ['code'], code_challenge_methods_supported: ['S256'] }), 'application/json');
    return true;
  }
  if (path !== '/mcp-protected') return mcpCard('mcp-protected.fixture', '/mcp-protected')(path, req, res, body);
  if (req.headers.authorization) { send(res, 403, 'fixture never expects credentials', 'text/plain'); return true; }
  send(res, 401, JSON.stringify({ error: 'unauthorized' }), 'application/json', { 'www-authenticate': `Bearer realm="mcp", resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp-protected", error="invalid_request"` });
  return true;
};
const mcpHtml: Handler = (path, req, res, body) => {
  if (path !== '/mcp-html') return mcpCard('mcp-html.fixture', '/mcp-html')(path, req, res, body);
  send(res, 200, '<!doctype html><html><head><title>Welcome</title></head><body><h1>Marketing page</h1></body></html>', 'text/html; charset=utf-8');
  return true;
};

const vhosts: Record<string, Handler> = { 'mcp-public.fixture': mcpPublic, 'mcp-sse.fixture': mcpSse, 'mcp-protected.fixture': mcpProtected, 'mcp-html.fixture': mcpHtml, 'webmcp.fixture': webmcp, 'webmcp-none.fixture': webmcpNone, 'docs.broken.fixture': docsBroken, 'good.fixture': good, 'spa.fixture': spa, 'broken.fixture': broken, 'blocked.fixture': blocked, 'empty.fixture': empty, 'redirect.fixture': redirect, 'apex.fixture': apex, 'www.apex.fixture': wwwApex };

export const FIXTURE_VHOSTS = Object.keys(vhosts);

/** Start the fixture server (port 0 = ephemeral; used by the self-test). Resolves with the bound port. */
export function startFixtureServer(port: number): Promise<{ server: Server; port: number }> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const host = (req.headers.host ?? '').split(':')[0];
      const path = new URL(req.url ?? '/', 'http://x').pathname;
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) headers[k] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
      FIXTURE_REQUEST_LOG.push({ host, method: req.method ?? '', path, body, headers });
      const h = vhosts[host] ?? empty;
      if (!h(path, req, res, body)) send(res, 404, 'Not Found', 'text/plain');
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve({ server, port: (server.address() as { port: number }).port }));
  });
}

const isMain = process.argv[1] && /fixture-server\.(ts|js)$/.test(process.argv[1]);
if (isMain) {
  const port = Number(process.argv[2] ?? 8787);
  startFixtureServer(port).then(({ port: p }) => {
    console.error(`fixture server on 127.0.0.1:${p}; vhosts: ${FIXTURE_VHOSTS.join(', ')}`);
    console.error(`run the crawler with CRAWLER_FIXTURE_PORT=${p} --scheme http; see README`);
  });
}
