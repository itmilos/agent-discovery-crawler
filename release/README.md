# Release notes

`scripts/prepare-release.py` builds `data/` from `out/`: strips the withheld `hygiene` field, gzips, writes `MANIFEST.json`. Re-run it whenever a crawl finishes, then attach the contents of `data/` to a GitHub Release (or upload to Zenodo) rather than committing them: the 10K-100K file is 60 MB compressed and will grow with the second vantage.

Releases so far:

- `v0.4.0-data-2026-10-05`: Tranco 1-10K complete, 10K-100K partial (first 50,515 hosts), WebMCP sample complete.
