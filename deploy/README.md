# Second vantage (paper §4.3)

The local crawl is the "non-datacenter" vantage. The paper also promises one EU
and one US cloud vantage, crawled over the same Tranco list (647LX), so that
hosts which block one network but not another are counted and the prevalence
figures can be reported as "valid at either vantage".

`vantage.sh` does the whole thing on a fresh Ubuntu 24.04 VM (2 vCPU / 4 GB is
enough; Hetzner CX22 in Falkenstein for `eu`, a Virginia box for `us`):

```
ssh root@VM 'bash -s' < deploy/vantage.sh setup
scp hosts/tranco-latest-1-1k.txt hosts/tranco-latest-1k-10k.txt hosts/tranco-latest-10k-100k.txt root@VM:agent-discovery-crawler/hosts/
ssh root@VM 'cd agent-discovery-crawler && CRAWLER_CONTACT_URL=https://github.com/itmilos/agent-discovery-crawler CRAWLER_CONTACT_EMAIL=you@example.com deploy/vantage.sh start eu'
ssh root@VM 'agent-discovery-crawler/deploy/vantage.sh status'      # any time
scp root@VM:agent-discovery-crawler/out/tranco-*-eu.jsonl out/     # when status says ALL DONE
npm run vantage:compare -- --a out/tranco-1-1k-local.jsonl --b out/tranco-1-1k-eu.jsonl --label-a local --label-b eu --out out/compare-1-1k.json
```

The hosts files are copied, never re-downloaded, so the VM crawls the same
list as the laptop. The three bands run back to back inside a tmux session
(about 30 hours at concurrency 40; the 10K–100K band is 26 of them), the log
is `out/vantage-eu.log`, and `start` is idempotent: if the VM reboots, run it
again and each band resumes from its output file. `vantage:compare` prints the
class matrix (reachable / blocked / unreachable at each vantage), the hosts
blocked at exactly one vantage, per-path agreement on `valid` among hosts
reachable at both, the union prevalence, and how many probes landed on a
different origin (geo-routed CDNs). The self-test covers the comparison.
