// Per-artifact validation: lightweight structural checks (paper §4.2 "Hit").
// Uses Ajv for the JSON-shaped artifacts so the schemas are explicit and
// extensible; the schemas are deliberately permissive ("lightweight").
import { Ajv, type ValidateFunction } from 'ajv';
import YAML from 'yaml';
import type { ArtifactType, CardSpec, ExpectedKind } from './types.js';
import { mediaType } from './http.js';

export interface ValidationOutcome {
  valid: boolean;
  reasons: string[];
  parsed?: unknown;
  card_spec?: CardSpec;
}

const ajv = new Ajv({ allErrors: true, strict: false });

// MCP server card. Two drafts are accepted:
//  SEP-2127 (/.well-known/mcp-server-card): name (reverse-DNS), version,
//    description, remotes[] of {type|transport, url}
//  SEP-1649 era (/.well-known/mcp/server-card.json): name + url/transport/tools
const mcpCardSchema = {
  type: 'object',
  required: ['name'],
  properties: { name: { type: 'string', minLength: 1 } },
  anyOf: [
    { required: ['remotes'], properties: { remotes: { type: 'array', minItems: 1 } } },
    { required: ['url'] },
    { required: ['transport'] },
    { required: ['tools'] },
    { required: ['endpoint'] }, // seen in the wild; tolerated
  ],
};

export function detectCardSpec(doc: Record<string, unknown>): CardSpec {
  const remotes = doc.remotes;
  if (Array.isArray(remotes) && remotes.length > 0) {
    const r0 = remotes[0] as Record<string, unknown> | null;
    if (r0 && typeof r0 === 'object' && typeof r0.url === 'string' && (typeof r0.type === 'string' || typeof r0.transport === 'string')) return 'sep-2127';
    return 'sep-2127';
  }
  if (typeof doc.url === 'string' || doc.transport !== undefined || Array.isArray(doc.tools)) return 'sep-1649';
  return 'unknown';
}

// AI Card catalog (/.well-known/ai-catalog.json): JSON object check only.
const anyObjectSchema = { type: 'object' };

// RFC 9728 OAuth 2.0 Protected Resource Metadata. `resource` is REQUIRED;
// `authorization_servers` is OPTIONAL (§2) and its absence is only noted.
// §3.3: `resource` must equal the resource identifier the metadata was
// derived from; checked in validateJsonArtifact when the probe URL is known.
const protectedResourceSchema = {
  type: 'object',
  required: ['resource'],
  properties: {
    resource: { type: 'string', minLength: 1 },
    authorization_servers: { type: 'array', items: { type: 'string' } },
  },
};

// RFC 8414 §2 / OIDC Discovery §3: issuer and response_types_supported are REQUIRED
const issuerSchema = {
  type: 'object',
  required: ['issuer', 'response_types_supported'],
  properties: { issuer: { type: 'string', minLength: 1 }, response_types_supported: { type: 'array', minItems: 1 } },
};

// A2A agent card: name + (url | skills | supportedInterfaces[] (v1.0))
const a2aSchema = {
  type: 'object',
  required: ['name'],
  properties: { name: { type: 'string', minLength: 1 } },
  anyOf: [{ required: ['url'] }, { required: ['skills'] }, { required: ['supportedInterfaces'] }],
};

/**
 * RFC 9728 §3.1/§3.3: the resource identifier a PRM document at `prmUrl`
 * describes. `https://h/.well-known/oauth-protected-resource` -> `https://h/`,
 * `https://h/.well-known/oauth-protected-resource/v1/mcp` -> `https://h/v1/mcp`.
 */
export function derivedResourceFromPrmUrl(prmUrl: string): string | null {
  try {
    const u = new URL(prmUrl);
    const m = u.pathname.match(/^\/\.well-known\/oauth-protected-resource(\/.*)?$/);
    if (!m) return null;
    return `${u.origin}${m[1] ?? '/'}`;
  } catch {
    return null;
  }
}

function normResource(s: string): string | null {
  try {
    const u = new URL(s);
    return `${u.origin}${u.pathname.replace(/\/$/, '')}${u.search}`;
  } catch {
    return null;
  }
}

/** True when a PRM `resource` value identifies the same resource as the URL it was fetched from (§3.3). */
export function prmResourceMatches(resource: string, prmUrl: string): boolean | null {
  const want = derivedResourceFromPrmUrl(prmUrl);
  if (!want) return null;
  const a = normResource(resource);
  return a !== null && a === normResource(want);
}

const validators: Partial<Record<ArtifactType, ValidateFunction>> = {
  mcp_server_card: ajv.compile(mcpCardSchema),
  mcp_server_card_legacy: ajv.compile(mcpCardSchema),
  ai_catalog: ajv.compile(anyObjectSchema),
  oauth_protected_resource: ajv.compile(protectedResourceSchema),
  oauth_authorization_server: ajv.compile(issuerSchema),
  openid_configuration: ajv.compile(issuerSchema),
  a2a_agent_card: ajv.compile(a2aSchema),
  a2a_agent_json: ajv.compile(a2aSchema),
};

export function looksLikeHtml(text: string): boolean {
  const head = text.slice(0, 2048).trimStart().toLowerCase();
  return head.startsWith('<!doctype html') || head.startsWith('<html') || /<head[\s>]|<body[\s>]|<meta\s|<script[\s>]/.test(head);
}

function stripFrontmatter(text: string): string {
  if (text.startsWith('---')) {
    const end = text.indexOf('\n---', 3);
    if (end !== -1) return text.slice(end + 4);
  }
  return text;
}

export function validateMarkdown(text: string, ct: string | null): ValidationOutcome {
  const reasons: string[] = [];
  if (looksLikeHtml(text)) reasons.push('body_is_html');
  const mt = mediaType(ct);
  if (mt === 'text/html') reasons.push('content_type_html');
  const body = stripFrontmatter(text.replace(/^\uFEFF/, ''));
  // ATX headings (# .. ######) or setext (=== / --- underline)
  const hasAtx = /^\s{0,3}#{1,6}\s+\S/m.test(body);
  const hasSetext = /^\S.*\n(=+|-{3,})\s*$/m.test(body);
  if (!hasAtx && !hasSetext) reasons.push('no_markdown_heading');
  if (body.trim().length === 0) reasons.push('empty');
  // llms.txt spec: the file starts with an H1 (project name). Not fatal; noted.
  const first = body.split(/\r?\n/).find((l) => l.trim().length > 0) ?? '';
  if (!/^\s{0,3}#\s+\S/.test(first)) reasons.push('note:h1_not_first');
  const hard = reasons.filter((r) => !r.startsWith('note:'));
  return { valid: hard.length === 0, reasons };
}

export function parseJson(text: string): { ok: true; value: unknown } | { ok: false; reason: string } {
  try {
    // tolerate BOM
    const t = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
    return { ok: true, value: JSON.parse(t) };
  } catch (e) {
    return { ok: false, reason: 'json_parse_error' };
  }
}

/**
 * @param url the URL the body was fetched from (after redirects); used for the
 *            RFC 9728 §3.3 resource check. Optional for unit tests.
 */
export function validateJsonArtifact(artifact: ArtifactType, text: string, ct: string | null, url?: string): ValidationOutcome {
  const reasons: string[] = [];
  if (looksLikeHtml(text)) return { valid: false, reasons: ['body_is_html'] };
  const parsed = parseJson(text);
  if (!parsed.ok) return { valid: false, reasons: [parsed.reason] };
  const v = validators[artifact];
  if (!v) return { valid: true, reasons: [], parsed: parsed.value };
  if (typeof parsed.value !== 'object' || parsed.value === null || Array.isArray(parsed.value)) {
    return { valid: false, reasons: ['not_an_object'], parsed: parsed.value };
  }
  const ok = v(parsed.value);
  if (!ok) {
    for (const err of v.errors ?? []) {
      const path = err.instancePath || '/';
      reasons.push(`schema:${err.keyword}${path !== '/' ? ':' + path : ''}${err.params && 'missingProperty' in err.params ? ':' + err.params.missingProperty : ''}`);
    }
  }
  const mt = mediaType(ct);
  if (mt && mt !== 'application/json' && !mt.endsWith('+json') && mt !== 'text/json' && mt !== 'text/plain') {
    reasons.push(`unexpected_content_type:${mt}`);
  }
  if (artifact === 'oauth_protected_resource') {
    const rec = parsed.value as Record<string, unknown>;
    if (!Array.isArray(rec.authorization_servers)) reasons.push('note:prm_no_authorization_servers');
    if (url && typeof rec.resource === 'string' && prmResourceMatches(rec.resource, url) === false) reasons.push('prm_resource_mismatch');
  }
  // Content-type mismatch alone does not invalidate a parseable, schema-valid doc; notes never do.
  const hard = reasons.filter((r) => !r.startsWith('unexpected_content_type') && !r.startsWith('note:'));
  const out: ValidationOutcome = { valid: hard.length === 0, reasons, parsed: parsed.value };
  if (artifact === 'mcp_server_card' || artifact === 'mcp_server_card_legacy') {
    out.card_spec = detectCardSpec(parsed.value as Record<string, unknown>);
    if (out.valid && artifact === 'mcp_server_card' && out.card_spec !== 'sep-2127') reasons.push('note:legacy_shape_at_current_path');
    if (out.valid && typeof (parsed.value as Record<string, unknown>).name === 'string' && out.card_spec === 'sep-2127' && !/^[a-z0-9-]+(\.[a-z0-9-]+)+\/?/i.test((parsed.value as Record<string, unknown>).name as string)) reasons.push('note:name_not_reverse_dns');
  }
  return out;
}

/** RFC 9116: must contain at least one Contact: field. */
export function validateSecurityTxt(text: string, ct: string | null): ValidationOutcome {
  const reasons: string[] = [];
  if (looksLikeHtml(text) || mediaType(ct) === 'text/html') return { valid: false, reasons: ['body_is_html'] };
  if (text.trim().length === 0) return { valid: false, reasons: ['empty'] };
  if (!/^\s*contact\s*:\s*\S/im.test(text)) reasons.push('no_contact_field');
  if (!/^\s*expires\s*:/im.test(text)) reasons.push('note:no_expires_field');
  const hard = reasons.filter((r) => !r.startsWith('note:'));
  return { valid: hard.length === 0, reasons };
}

export function validateOpenApi(text: string, path: string, ct: string | null): ValidationOutcome {
  const reasons: string[] = [];
  if (looksLikeHtml(text)) return { valid: false, reasons: ['body_is_html'] };
  let doc: unknown;
  const preferJson = path.endsWith('.json');
  const j = parseJson(text);
  if (j.ok) doc = j.value;
  else {
    try {
      doc = YAML.parse(text, { maxAliasCount: 100 });
      if (preferJson) reasons.push('json_path_served_yaml');
    } catch {
      return { valid: false, reasons: ['unparseable_json_or_yaml'] };
    }
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return { valid: false, reasons: ['not_an_object'] };
  const o = doc as Record<string, unknown>;
  const openapi = o.openapi;
  if (typeof openapi === 'string' && openapi.startsWith('3.')) {
    if (!o.paths && !o.webhooks && !o.components) reasons.push('no_paths');
  } else if (typeof o.swagger === 'string') {
    reasons.push(`swagger_2_not_3:${o.swagger}`);
  } else {
    reasons.push('missing_openapi_3_field');
  }
  void ct;
  const hard = reasons.filter((r) => r !== 'json_path_served_yaml' && r !== 'no_paths');
  return { valid: hard.length === 0, reasons, parsed: doc };
}

export function validateText(text: string, ct: string | null): ValidationOutcome {
  const reasons: string[] = [];
  if (looksLikeHtml(text) || mediaType(ct) === 'text/html') reasons.push('body_is_html');
  if (text.trim().length === 0) reasons.push('empty');
  return { valid: reasons.length === 0, reasons };
}

export function validateArtifact(artifact: ArtifactType, kind: ExpectedKind, path: string, text: string, ct: string | null, url?: string): ValidationOutcome {
  switch (kind) {
    case 'markdown':
      return validateMarkdown(text, ct);
    case 'json':
      return validateJsonArtifact(artifact, text, ct, url);
    case 'openapi':
      return validateOpenApi(text, path, ct);
    case 'text':
      return artifact === 'security_txt' ? validateSecurityTxt(text, ct) : validateText(text, ct);
  }
}
