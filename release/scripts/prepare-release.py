#!/usr/bin/env python3
"""Build the public dataset release: strip per-host security findings (released after the
disclosure window, see paper §4.9), gzip, checksum, and write a manifest."""
import json, gzip, hashlib, os, sys, datetime
SRC = {
  "tranco-1-1k-local.jsonl":      "Tranco list 647LX ranks 1-1,000, crawled 2026-10-05 from one local vantage (crawler 0.3.x, rank backfilled)",
  "tranco-1k-10k-local.jsonl":    "Tranco list 647LX ranks 1,001-10,000, crawled 2026-10-05 from one local vantage (crawler 0.3.2)",
  "tranco-10k-100k-local.jsonl":  "Tranco list 647LX ranks 10,001-100,000, crawled 2026-10-05/06 from one local vantage (crawler 0.4.0)",
  "webmcp-sample.jsonl":          "WebMCP headless pass over the 5,000-host stratified subsample (crawler 0.4.0), 2026-10-05",
}
STRIP = {"hygiene"}            # withheld until coordinated disclosure completes
out_dir = "release/data"; os.makedirs(out_dir, exist_ok=True)
manifest = {"built_at": datetime.datetime.utcnow().isoformat()+"Z", "withheld_fields": sorted(STRIP), "files": []}
for name, desc in SRC.items():
    src = os.path.join("out", name)
    if not os.path.exists(src): print("skip (missing):", name); continue
    dst = os.path.join(out_dir, name + ".gz"); n = 0; h = hashlib.sha256()
    with open(src) as f, gzip.open(dst, "wt", compresslevel=9) as g:
        for line in f:
            if not line.strip(): continue
            o = json.loads(line)
            for k in STRIP: o.pop(k, None)
            s = json.dumps(o, separators=(",", ":")) + "\n"; g.write(s); n += 1
    with open(dst, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    manifest["files"].append({"file": os.path.basename(dst), "rows": n, "sha256": h.hexdigest(), "bytes": os.path.getsize(dst), "description": desc})
    print(f"{name}: {n} rows -> {dst} ({os.path.getsize(dst)/1e6:.1f} MB)")
for extra in ["out/tranco-bands-summary.txt", "out/webmcp-sample-summary.txt", "hosts/tranco-647LX.meta.json", "hosts/webmcp-sample.meta.json"]:
    if os.path.exists(extra):
        import shutil; shutil.copy(extra, out_dir); manifest["files"].append({"file": os.path.basename(extra), "description": "summary/metadata"})
json.dump(manifest, open(os.path.join(out_dir, "MANIFEST.json"), "w"), indent=2)
print("manifest written")
