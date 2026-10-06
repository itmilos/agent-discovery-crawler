// Shared types for the crawler output schema (one JSONL line per host).

export type ArtifactType =
  | 'llms_txt'
  | 'llms_full_txt'
  | 'mcp_server_card' // SEP-2127 /.well-known/mcp-server-card (current)
  | 'mcp_server_card_legacy' // /.well-known/mcp/server-card.json (SEP-1649 era)
  | 'oauth_protected_resource'
  | 'oauth_authorization_server'
  | 'a2a_agent_card'
  | 'a2a_agent_json'
  | 'openid_configuration'
  | 'openapi_json'
  | 'openapi_yaml'
  | 'ai_catalog' // AI Card /.well-known/ai-catalog.json
  | 'security_txt' // RFC 9116
  | 'ai_txt';

export type ExpectedKind = 'markdown' | 'json' | 'openapi' | 'text';

export interface ProbeSpec {
  path: string;
  artifact: ArtifactType;
  kind: ExpectedKind;
  legacy?: boolean;
}

/** The fourteen canonical paths (paper §4.2, post-review). Order here is canonical; probing order is randomized per host. */
export const PROBE_SPECS: ProbeSpec[] = [
  { path: '/llms.txt', artifact: 'llms_txt', kind: 'markdown' },
  { path: '/llms-full.txt', artifact: 'llms_full_txt', kind: 'markdown' },
  { path: '/.well-known/mcp-server-card', artifact: 'mcp_server_card', kind: 'json' },
  { path: '/.well-known/mcp/server-card.json', artifact: 'mcp_server_card_legacy', kind: 'json', legacy: true },
  { path: '/.well-known/oauth-protected-resource', artifact: 'oauth_protected_resource', kind: 'json' },
  { path: '/.well-known/oauth-authorization-server', artifact: 'oauth_authorization_server', kind: 'json' },
  { path: '/.well-known/agent-card.json', artifact: 'a2a_agent_card', kind: 'json' },
  { path: '/.well-known/agent.json', artifact: 'a2a_agent_json', kind: 'json' },
  { path: '/.well-known/openid-configuration', artifact: 'openid_configuration', kind: 'json' },
  { path: '/openapi.json', artifact: 'openapi_json', kind: 'openapi' },
  { path: '/openapi.yaml', artifact: 'openapi_yaml', kind: 'openapi' },
  { path: '/.well-known/ai-catalog.json', artifact: 'ai_catalog', kind: 'json' },
  { path: '/.well-known/security.txt', artifact: 'security_txt', kind: 'text' },
  { path: '/ai.txt', artifact: 'ai_txt', kind: 'text' },
];

export const MCP_CARD_ARTIFACTS: ArtifactType[] = ['mcp_server_card', 'mcp_server_card_legacy'];
export const A2A_CARD_ARTIFACTS: ArtifactType[] = ['a2a_agent_card', 'a2a_agent_json'];

export type CardSpec = 'sep-2127' | 'sep-1649' | 'unknown';

export interface ProbeResult {
  path: string;
  artifact: ArtifactType;
  status: number; // 0 = network error (see error)
  final_url: string;
  content_type: string | null;
  bytes: number;
  sha256: string;
  redirects: number;
  /** final origin differs from probed origin (redirect within registrable domain was followed); a bare apex<->www hop does NOT set this */
  cross_origin_hit: boolean;
  /** the redirect only moved between example.com and www.example.com (same site); final_url records where it landed */
  www_redirect: boolean;
  elapsed_ms: number;
  error?: string;
  /** 64-bit simhash (hex) of the body, for soft-404 and staleness comparison */
  simhash: string;
  /** max simhash similarity to the two nonexistent-path baselines */
  nx_similarity: number | null;
  /** status 200 but body near-duplicates the nonexistent-path baseline, or HTML where structured content expected */
  soft404: boolean;
  /** which MCP card draft the body matched (MCP card artifacts only) */
  card_spec?: CardSpec;
  /** security-relevant response headers kept for hygiene */
  hsts?: string | null;
  cache_control?: string | null;
  /** path of the archived body when --store-bodies is on */
  body_file?: string;
  /** 200, non-empty, not soft-404, passes type-specific validation */
  valid: boolean;
  reasons: string[];
  /** Parsed, validated object for structured artifacts (kept for hygiene; omitted from output if large) */
  parsed?: unknown;
}

export interface Fingerprint {
  homepage_status: number;
  homepage_final_url: string | null;
  homepage_error?: string;
  server: string | null;
  powered_by: string | null;
  generator: string | null;
  /** Application/hosting platform labels detected (may be several, e.g. ["mintlify","nextjs","vercel"]); CDN labels are NOT in here */
  platforms: string[];
  /** Primary platform label used for stratification (most specific application-layer label, else first hosting label, else unknown/unreachable) */
  primary: string;
  /** Edge/CDN layer (cloudflare, fastly, akamai, cloudfront, ...) recorded separately from the platform; null if none seen */
  cdn: string | null;
  /** Weak evidence (hubspot/framer/gitbook/webflow seen only in script/link tags): never promoted to platforms/primary */
  hints: string[];
  signals: string[]; // human-readable evidence
}

export interface NxBaseline {
  path: string;
  status: number;
  sha256: string;
  simhash: string;
  content_type: string | null;
  bytes: number;
  error?: string;
}

export interface EndpointCheck {
  url: string;
  https: boolean;
  status: number | null;
  error?: string;
  reachable: boolean;
}

export interface AuthServerCheck {
  issuer: string;
  https: boolean;
  metadata_url: string;
  status: number | null;
  error?: string;
  resolves: boolean;
  issuer_match: boolean | null; // null if metadata unparseable
  /** RFC 9700/PKCE: code_challenge_methods_supported includes "S256" (null if not resolved) */
  pkce_advertised: boolean | null;
  /** issuer on a different registrable domain than the card host (informational, not a failure) */
  third_party_hosted: boolean;
}

export interface PrmCheck {
  url: string;
  location: 'root' | 'path_suffixed';
  status: number | null;
  valid: boolean;
  error?: string;
}

export interface HygieneEntry {
  source: ArtifactType;
  kind: 'mcp' | 'a2a' | 'protected_resource';
  card_spec?: CardSpec;
  endpoint?: EndpointCheck;
  /** endpoint on a different registrable domain than the card host (informational) */
  endpoint_third_party_hosted: boolean | null;
  /** RFC 9728 PRM lookups derived from the endpoint path (MCP/A2A only) */
  prm_lookups: PrmCheck[];
  authorization_servers: AuthServerCheck[];
  has_authorization_servers: boolean;
  /** RFC 9728 bearer_methods_supported includes "query" (token in URL) — bad */
  bearer_query_allowed: boolean | null;
  /** Strict-Transport-Security on the card response */
  hsts: string | null;
  cache_control: string | null;
  /** TODO: not sent in this pass (paper §4.6(e)). Always null here. */
  mcp_unauthenticated_initialize: null;
  notes: string[];
}

export interface Blocked {
  blocked: boolean;
  reason: string | null; // e.g. "403 on 10/13 probes", "challenge", "reset", "dns"
  counts: Record<string, number>;
}

export interface HostResult {
  host: string;
  /** Rank from the hosts file ("rank,domain" lines, e.g. Tranco); null when the file has none. */
  rank?: number | null;
  registrable_domain: string | null;
  vantage: string;
  ts: string;
  crawler_version: string;
  blocked: Blocked;
  /** every request (14 probes + 2 nx baselines) was a redirect out of the registrable domain; excluded from the reachable denominator */
  redirect_only: boolean;
  fingerprint: Fingerprint;
  nx_baselines: NxBaseline[];
  /** which MCP card path answered with a valid card (first in canonical order), or null */
  mcp_card_path: string | null;
  probe_order: string[];
  probes: Omit<ProbeResult, 'parsed'>[];
  hygiene: HygieneEntry[];
  duration_ms: number;
}
