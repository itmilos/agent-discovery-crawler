// 64-bit SimHash over shingled tokens, for soft-404 near-duplicate detection.
// Tokens: lowercase alphanumeric runs (HTML tags stripped, so two "not found"
// pages with different per-request nonces/CSRF tokens still collide).
// Shingles: 3-token windows. Feature hash: FNV-1a 64-bit.

const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MASK64 = (1n << 64n) - 1n;

export function fnv1a64(str: string): bigint {
  let h = FNV_OFFSET;
  for (let i = 0; i < str.length; i++) {
    h ^= BigInt(str.charCodeAt(i) & 0xff);
    h = (h * FNV_PRIME) & MASK64;
  }
  return h;
}

export function tokenize(text: string): string[] {
  return text
    .replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    // drop empty tokens and nonce-like tokens (>=6 chars containing a digit: request ids, CSRF tokens, build hashes, timestamps)
    .filter((t) => t.length > 0 && !(t.length >= 6 && /\d/.test(t)));
}

export function shingles(tokens: string[], k = 3): string[] {
  if (tokens.length === 0) return [];
  if (tokens.length < k) return [tokens.join(' ')];
  const out: string[] = [];
  for (let i = 0; i + k <= tokens.length; i++) out.push(tokens.slice(i, i + k).join(' '));
  return out;
}

/** Returns the 64-bit simhash as a 16-hex-char string; empty input -> "0". */
export function simhash(text: string, k = 3): string {
  const feats = shingles(tokenize(text), k);
  if (feats.length === 0) return '0';
  const v = new Int32Array(64);
  for (const f of feats) {
    const h = fnv1a64(f);
    for (let b = 0; b < 64; b++) {
      if ((h >> BigInt(b)) & 1n) v[b]++;
      else v[b]--;
    }
  }
  let out = 0n;
  for (let b = 0; b < 64; b++) if (v[b] > 0) out |= 1n << BigInt(b);
  return out.toString(16).padStart(16, '0');
}

export function hamming(aHex: string, bHex: string): number {
  let x = BigInt('0x' + aHex) ^ BigInt('0x' + bHex);
  let n = 0;
  while (x) {
    x &= x - 1n;
    n++;
  }
  return n;
}

/** 1 - hamming/64. Two empty bodies ("0" vs "0") are similarity 1. */
export function similarity(aHex: string, bHex: string): number {
  return 1 - hamming(aHex, bHex) / 64;
}
