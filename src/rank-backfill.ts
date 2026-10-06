#!/usr/bin/env node
// Backfill `rank` into an existing results JSONL from a "rank,domain" hosts file.
// Usage: tsx src/rank-backfill.ts --hosts hosts/tranco-latest-1-1k.txt --in out/x.jsonl [--out out/x.ranked.jsonl]
// Without --out the input file is rewritten in place (a .bak copy is kept).
import { createReadStream, createWriteStream, renameSync, copyFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { parseHostLine } from './run.js';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

export async function loadRanks(hostsPath: string): Promise<Map<string, number>> {
  const text = await readFile(hostsPath, 'utf8');
  const m = new Map<string, number>();
  for (const line of text.split(/\r?\n/)) {
    const e = parseHostLine(line);
    if (e && e.rank !== null && !m.has(e.host)) m.set(e.host, e.rank);
  }
  return m;
}

export async function backfill(hostsPath: string, inPath: string, outPath: string): Promise<{ rows: number; ranked: number; missing: number }> {
  const ranks = await loadRanks(hostsPath);
  const out = createWriteStream(outPath);
  const rl = createInterface({ input: createReadStream(inPath), crlfDelay: Infinity });
  let rows = 0, ranked = 0, missing = 0;
  for await (const line of rl) {
    if (!line.trim()) continue;
    const o = JSON.parse(line) as { host: string; rank?: number | null };
    rows++;
    const r = ranks.get(o.host);
    if (r !== undefined) { o.rank = r; ranked++; } else { if (o.rank === undefined) o.rank = null; missing++; }
    if (!out.write(JSON.stringify(o) + '\n')) await once(out, 'drain');
  }
  await new Promise<void>((res) => out.end(res));
  return { rows, ranked, missing };
}

async function main() {
  const hosts = arg('hosts'); const inPath = arg('in'); let outPath = arg('out');
  if (!hosts || !inPath) { console.error('usage: --hosts <hosts.txt> --in <results.jsonl> [--out <ranked.jsonl>]'); process.exit(2); }
  const inPlace = !outPath;
  if (inPlace) { outPath = inPath + '.tmp'; copyFileSync(inPath, inPath + '.bak'); }
  const r = await backfill(hosts, inPath, outPath!);
  if (inPlace) renameSync(outPath!, inPath);
  console.error(`rank backfill: ${r.rows} rows, ${r.ranked} ranked, ${r.missing} without a rank -> ${inPlace ? inPath + ' (backup: ' + inPath + '.bak)' : outPath}`);
}

if (process.argv[1] && /rank-backfill\.(ts|js)$/.test(process.argv[1])) main().catch((e) => { console.error(e); process.exit(1); });
