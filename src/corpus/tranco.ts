#!/usr/bin/env node
// Corpus builder (paper §4.1): Tranco rank bands.
//   npm run corpus:tranco                         # download latest top-1m.csv.zip + list id
//   npm run corpus:tranco -- --file top-1m.csv    # use an already-downloaded CSV
//   npm run corpus:tranco -- --bands 1-1k,1k-10k --out-dir hosts
//
// Writes hosts/tranco-<listid-or-date>-<band>.txt (rank,domain rows, rank order
// preserved, de-duplicated to registrable domain across the whole list),
// hosts/tranco-latest-<band>.txt (a copy, what the crawl:tranco* scripts read)
// and hosts/tranco-<listid-or-date>.meta.json (provenance + counts).
//
// No new dependency: the zip is a single deflated member, read with a minimal
// central-directory parser and node:zlib.
import { mkdirSync, writeFileSync, copyFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { request } from 'undici';
import { getDomain } from 'tldts';
import { CRAWLER_VERSION, getDispatcher, userAgent } from '../http.js';

export const TRANCO_ZIP_URL = 'https://tranco-list.eu/top-1m.csv.zip';
export const TRANCO_ID_URL = 'https://tranco-list.eu/top-1m-id';
export const DEFAULT_BANDS = ['1-1k', '1k-10k', '10k-100k'];
const MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Bands
// ---------------------------------------------------------------------------

export interface Band { label: string; from: number; to: number }

function parseRankToken(t: string): number {
  const m = /^(\d+(?:\.\d+)?)([km]?)$/i.exec(t.trim());
  if (!m) throw new Error(`bad rank token "${t}" (want e.g. 1, 1k, 10k, 1m)`);
  const n = Number(m[1]) * (m[2].toLowerCase() === 'k' ? 1_000 : m[2].toLowerCase() === 'm' ? 1_000_000 : 1);
  if (!Number.isInteger(n) || n < 1) throw new Error(`bad rank token "${t}"`);
  return n;
}

/**
 * "1-1k" -> ranks 1..1000, "1k-10k" -> 1001..10000, "10k-100k" -> 10001..100000.
 * A band whose lower bound is a round number is exclusive at the bottom (so the
 * three default bands tile 1..100000 without overlap); "1-1k" starts at 1.
 */
export function parseBand(label: string): Band {
  const parts = label.split('-');
  if (parts.length !== 2) throw new Error(`bad band "${label}" (want LO-HI, e.g. 1k-10k)`);
  const lo = parseRankToken(parts[0]);
  const hi = parseRankToken(parts[1]);
  if (hi <= lo) throw new Error(`bad band "${label}": upper bound must exceed lower`);
  return { label, from: lo === 1 ? 1 : lo + 1, to: hi };
}

export function parseBands(spec: string | undefined): Band[] {
  return (spec ? spec.split(',').map((s) => s.trim()).filter(Boolean) : DEFAULT_BANDS).map(parseBand);
}

// ---------------------------------------------------------------------------
// CSV -> deduped bands
// ---------------------------------------------------------------------------

export interface TrancoRow { rank: number; domain: string }

/** Parse "rank,domain" lines; tolerates a header, BOM, CRLF and blank lines. */
export function parseTrancoCsv(text: string): TrancoRow[] {
  const rows: TrancoRow[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/^﻿/, '').trim();
    if (!line || line.startsWith('#')) continue;
    const comma = line.indexOf(',');
    if (comma < 0) continue;
    const rank = Number(line.slice(0, comma));
    const domain = line.slice(comma + 1).trim().toLowerCase().replace(/\.$/, '');
    if (!Number.isInteger(rank) || rank < 1 || !domain) continue; // header or junk
    rows.push({ rank, domain });
  }
  return rows;
}

export interface BandResult {
  band: Band;
  hosts: TrancoRow[]; // rank order, deduped
  input_rows: number; // rows whose rank fell in the band
  dedupe_losses: number; // rows dropped because their registrable domain was already emitted (in this or an earlier band)
  unparseable: number; // rows tldts could not reduce to a registrable domain (IPs, bare TLDs)
}

/**
 * Reduce each row to its registrable domain (PSL, public section only:
 * `foo.github.io` collapses to `github.io` here, unlike the crawler's redirect
 * rule, because for corpus purposes one operator = one site), keep the first
 * occurrence in rank order, and slice into bands. The seen-set spans bands, so
 * a domain surfacing in 1-1k never reappears in 1k-10k.
 */
export function buildBands(rows: TrancoRow[], bands: Band[]): BandResult[] {
  const sorted = rows.slice().sort((a, b) => a.rank - b.rank);
  const seen = new Set<string>();
  const results: BandResult[] = bands.map((band) => ({ band, hosts: [], input_rows: 0, dedupe_losses: 0, unparseable: 0 }));
  for (const row of sorted) {
    const targets = results.filter((r) => row.rank >= r.band.from && row.rank <= r.band.to);
    if (!targets.length) continue;
    const reg = getDomain(row.domain, { allowPrivateDomains: false });
    for (const t of targets) {
      t.input_rows++;
      if (!reg) { t.unparseable++; continue; }
      if (seen.has(reg)) { t.dedupe_losses++; continue; }
      seen.add(reg);
      t.hosts.push({ rank: row.rank, domain: reg });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Minimal zip reader (single deflated/stored member is all Tranco ships)
// ---------------------------------------------------------------------------

export interface ZipEntry { name: string; data: Buffer }

/** Read every member of a zip via the central directory. Supports stored (0) and deflate (8). */
export function readZip(buf: Buffer): ZipEntry[] {
  const EOCD = 0x06054b50;
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65_535); i--) {
    if (buf.readUInt32LE(i) === EOCD) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('zip: end of central directory not found');
  const entries = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const out: ZipEntry[] = [];
  for (let i = 0; i < entries; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('zip: bad central directory header');
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    if (buf.readUInt32LE(localOff) !== 0x04034b50) throw new Error('zip: bad local header');
    const lNameLen = buf.readUInt16LE(localOff + 26);
    const lExtraLen = buf.readUInt16LE(localOff + 28);
    const dataStart = localOff + 30 + lNameLen + lExtraLen;
    const raw = buf.subarray(dataStart, dataStart + csize);
    let data: Buffer;
    if (method === 0) data = Buffer.from(raw);
    else if (method === 8) data = inflateRawSync(raw, { maxOutputLength: MAX_DOWNLOAD_BYTES });
    else throw new Error(`zip: unsupported compression method ${method} for ${name}`);
    out.push({ name, data });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

export function csvFromZip(buf: Buffer): string {
  const entries = readZip(buf);
  const csv = entries.find((e) => e.name.toLowerCase().endsWith('.csv')) ?? entries[0];
  if (!csv) throw new Error('zip: no members');
  return csv.data.toString('utf8');
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

async function download(url: string, timeoutMs: number): Promise<Buffer> {
  const res = await request(url, {
    method: 'GET',
    dispatcher: getDispatcher(timeoutMs),
    maxRedirections: 3,
    headers: { 'user-agent': userAgent(), accept: '*/*' },
    headersTimeout: timeoutMs,
    bodyTimeout: timeoutMs,
  });
  if (res.statusCode !== 200) {
    try { for await (const _ of res.body) { /* drain */ } } catch { /* ignore */ }
    throw new Error(`GET ${url} -> HTTP ${res.statusCode}`);
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of res.body) {
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += b.length;
    if (total > MAX_DOWNLOAD_BYTES) throw new Error(`GET ${url}: body exceeds ${MAX_DOWNLOAD_BYTES} bytes`);
    chunks.push(b);
  }
  return Buffer.concat(chunks);
}

/** Current list id (e.g. "K25GW"); null when the endpoint is unreachable or returns nonsense. */
export async function fetchListId(timeoutMs = 15_000, url = TRANCO_ID_URL): Promise<string | null> {
  try {
    const id = (await download(url, timeoutMs)).toString('utf8').trim();
    return /^[A-Za-z0-9_-]{3,32}$/.test(id) ? id : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

export interface TrancoMeta {
  list_id: string | null;
  list_tag: string; // what the file names use: list id, else YYYY-MM-DD
  source: string; // URL or local file
  downloaded_at: string;
  csv_rows: number;
  bands: Record<string, { from: number; to: number; input_rows: number; hosts: number; dedupe_losses: number; unparseable: number; file: string; latest: string }>;
  crawler_version: string;
}

export function renderBandFile(meta: Pick<TrancoMeta, 'list_id' | 'list_tag' | 'downloaded_at'>, r: BandResult): string {
  const head = [
    `# tranco ${meta.list_id ?? meta.list_tag} ranks ${r.band.from}-${r.band.to} (${r.band.label}); generated ${meta.downloaded_at}`,
    `# ${r.hosts.length} registrable domains from ${r.input_rows} rows (${r.dedupe_losses} dedupe losses, ${r.unparseable} unparseable); rank,domain`,
  ];
  return head.concat(r.hosts.map((h) => `${h.rank},${h.domain}`)).join('\n') + '\n';
}

export interface WriteOptions { outDir: string; listId: string | null; source: string; now?: Date; crawlerVersion: string }

/** Write band files, the tranco-latest-<band>.txt copies and the sidecar meta JSON (merged into an existing one for the same list id). Returns the merged meta. */
export function writeCorpus(results: BandResult[], csvRows: number, opts: WriteOptions): { meta: TrancoMeta; metaPath: string } {
  const now = opts.now ?? new Date();
  const listTag = opts.listId ?? now.toISOString().slice(0, 10);
  mkdirSync(opts.outDir, { recursive: true });
  const meta: TrancoMeta = {
    list_id: opts.listId,
    list_tag: listTag,
    source: opts.source,
    downloaded_at: now.toISOString(),
    csv_rows: csvRows,
    bands: {},
    crawler_version: opts.crawlerVersion,
  };
  for (const r of results) {
    const file = join(opts.outDir, `tranco-${listTag}-${r.band.label}.txt`);
    const latest = join(opts.outDir, `tranco-latest-${r.band.label}.txt`);
    writeFileSync(file, renderBandFile(meta, r));
    copyFileSync(file, latest); // a copy, not a symlink: survives git on Windows and tar --dereference surprises
    meta.bands[r.band.label] = { from: r.band.from, to: r.band.to, input_rows: r.input_rows, hosts: r.hosts.length, dedupe_losses: r.dedupe_losses, unparseable: r.unparseable, file, latest };
  }
  const metaPath = join(opts.outDir, `tranco-${listTag}.meta.json`);
  // MERGE into an existing sidecar for the same list: `--bands 1k-10k` run after
  // `--bands 1-1k` must not erase the 1-1k entry. Same-label bands are replaced,
  // other bands kept; top-level provenance is the latest run's.
  let merged: TrancoMeta = meta;
  if (existsSync(metaPath)) {
    try {
      const prev = JSON.parse(readFileSync(metaPath, 'utf8')) as Partial<TrancoMeta>;
      merged = { ...prev, ...meta, bands: { ...(prev.bands ?? {}), ...meta.bands } } as TrancoMeta;
    } catch { /* corrupt sidecar: overwrite */ }
  }
  writeFileSync(metaPath, JSON.stringify(merged, null, 2) + '\n');
  return { meta: merged, metaPath };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface CliArgs { file: string | null; bands: string | undefined; outDir: string; timeoutMs: number; listId: string | null | undefined }

function parseArgs(argv: string[]): CliArgs {
  const a: CliArgs = { file: null, bands: undefined, outDir: 'hosts', timeoutMs: 120_000, listId: undefined };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const v = argv[i + 1];
    switch (k) {
      case '--file': a.file = v; i++; break;
      case '--bands': a.bands = v; i++; break;
      case '--out-dir': a.outDir = v; i++; break;
      case '--timeout-ms': a.timeoutMs = Number(v); i++; break;
      case '--list-id': a.listId = v; i++; break; // override / supply the id when the id endpoint is unreachable
      case '-h': case '--help':
        console.log('usage: tranco.ts [--file top-1m.csv|top-1m.csv.zip] [--bands 1-1k,1k-10k,10k-100k] [--out-dir hosts] [--list-id ID] [--timeout-ms 120000]');
        process.exit(0);
    }
  }
  return a;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const bands = parseBands(args.bands);
  let csv: string;
  let source: string;
  if (args.file) {
    if (!existsSync(args.file)) { console.error(`error: ${args.file} not found`); process.exit(2); }
    const buf = readFileSync(args.file);
    csv = buf.readUInt32LE(0) === 0x04034b50 ? csvFromZip(buf) : buf.toString('utf8');
    source = args.file;
  } else {
    console.error(`downloading ${TRANCO_ZIP_URL} ...`);
    const buf = await download(TRANCO_ZIP_URL, args.timeoutMs);
    console.error(`  ${buf.length} bytes; extracting`);
    csv = csvFromZip(buf);
    source = TRANCO_ZIP_URL;
  }
  const listId = args.listId !== undefined ? args.listId || null : await fetchListId(Math.min(args.timeoutMs, 15_000));
  if (!listId) console.error('list id: unavailable (tranco-list.eu/top-1m-id unreachable or --list-id ""); files are tagged with today\'s date');
  else console.error(`list id: ${listId}`);
  const rows = parseTrancoCsv(csv);
  console.error(`csv rows: ${rows.length}`);
  const results = buildBands(rows, bands);
  const { meta, metaPath } = writeCorpus(results, rows.length, { outDir: args.outDir, listId, source, crawlerVersion: CRAWLER_VERSION });
  for (const [label, b] of Object.entries(meta.bands)) {
    console.error(`${label.padEnd(9)} ranks ${b.from}-${b.to}: ${b.hosts} hosts (${b.dedupe_losses} dedupe losses, ${b.unparseable} unparseable) -> ${b.file} (+ ${b.latest})`);
  }
  console.error(`meta -> ${metaPath}`);
}

const isMain = process.argv[1] && /tranco\.(ts|js)$/.test(process.argv[1]);
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
