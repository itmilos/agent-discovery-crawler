#!/usr/bin/env bash
# Second-vantage crawl (paper §4.3): run the three Tranco bands from a cloud VM.
#
# One-time, on a fresh Ubuntu 24.04 VM (Hetzner CX22 in Falkenstein for "eu",
# or a Virginia box for "us"; 2 vCPU / 4 GB is enough):
#   ssh root@VM 'bash -s' < deploy/vantage.sh setup
#   scp hosts/tranco-latest-1-1k.txt hosts/tranco-latest-1k-10k.txt hosts/tranco-latest-10k-100k.txt root@VM:agent-discovery-crawler/hosts/
#   ssh root@VM 'cd agent-discovery-crawler && CRAWLER_CONTACT_URL=https://github.com/itmilos/agent-discovery-crawler CRAWLER_CONTACT_EMAIL=milosrujevic@gmail.com deploy/vantage.sh start eu'
# Then, any time:
#   ssh root@VM 'agent-discovery-crawler/deploy/vantage.sh status'
# When status says all three bands are done:
#   scp root@VM:agent-discovery-crawler/out/tranco-*-eu.jsonl out/
#
# The hosts files are copied from the laptop, not re-downloaded, so the VM
# crawls exactly the same Tranco list (647LX) as the local vantage. The crawl
# runs under tmux and survives the SSH session; `run.ts` resumes from the
# output file if the VM restarts (`start` is idempotent).
set -euo pipefail
cmd="${1:-}"; vantage="${2:-eu}"
REPO=https://github.com/itmilos/agent-discovery-crawler.git
DIR="$HOME/agent-discovery-crawler"

case "$cmd" in
  setup)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq git tmux curl ca-certificates >/dev/null
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null
    apt-get install -y -qq nodejs >/dev/null
    # file descriptors and ephemeral ports for 40 concurrent hosts x 14 probes
    grep -q 'nofile 65536' /etc/security/limits.conf || echo '* soft nofile 65536
* hard nofile 65536' >> /etc/security/limits.conf
    sysctl -q -w net.ipv4.ip_local_port_range="10240 65535" net.ipv4.tcp_fin_timeout=15
    [ -d "$DIR" ] || git clone -q "$REPO" "$DIR"
    cd "$DIR" && npm ci --silent --ignore-scripts
    npx tsx src/selftest.ts >/dev/null 2>&1 && echo "setup ok: $(node -v), $(git rev-parse --short HEAD), self-test passed" || { echo "self-test FAILED"; exit 1; }
    echo "now scp the three hosts/tranco-latest-*.txt files, then: deploy/vantage.sh start $vantage"
    ;;
  start)
    : "${CRAWLER_CONTACT_URL:?set CRAWLER_CONTACT_URL}" "${CRAWLER_CONTACT_EMAIL:?set CRAWLER_CONTACT_EMAIL}"
    cd "$DIR"
    for b in 1-1k 1k-10k 10k-100k; do [ -s "hosts/tranco-latest-$b.txt" ] || { echo "missing hosts/tranco-latest-$b.txt (scp it from the laptop)"; exit 1; }; done
    ulimit -n 65536 || true
    # one tmux session runs the three bands back to back; each band resumes if already partly done
    tmux has-session -t crawl 2>/dev/null && { echo "already running (tmux attach -t crawl)"; exit 0; }
    cat > "$DIR/out-$vantage.sh" <<RUN
#!/usr/bin/env bash
cd "$DIR"; mkdir -p out
export CRAWLER_CONTACT_URL="$CRAWLER_CONTACT_URL" CRAWLER_CONTACT_EMAIL="$CRAWLER_CONTACT_EMAIL" UV_THREADPOOL_SIZE=64
for b in 1-1k 1k-10k 10k-100k; do
  echo "=== band \$b start \$(date -u +%FT%TZ)" >> out/vantage-$vantage.log
  npx tsx src/run.ts --hosts hosts/tranco-latest-\$b.txt --out out/tranco-\$b-$vantage.jsonl --vantage $vantage --concurrency 40 --rps-per-host 1 --progress >> out/vantage-$vantage.log 2>&1
  echo "=== band \$b done \$(date -u +%FT%TZ)" >> out/vantage-$vantage.log
done
echo "=== ALL DONE \$(date -u +%FT%TZ)" >> out/vantage-$vantage.log
RUN
    chmod +x "$DIR/out-$vantage.sh"
    tmux new-session -d -s crawl "$DIR/out-$vantage.sh"
    echo "started vantage=$vantage in tmux session 'crawl'; log: out/vantage-$vantage.log"
    ;;
  status)
    cd "$DIR"
    for f in out/tranco-*-*.jsonl; do [ -e "$f" ] && printf '%-40s %8d rows\n' "$f" "$(wc -l < "$f")"; done
    grep -h "^===\|^progress" out/vantage-*.log 2>/dev/null | tail -4
    tmux has-session -t crawl 2>/dev/null && echo "tmux: running" || echo "tmux: not running"
    ;;
  *)
    echo "usage: deploy/vantage.sh setup | start <vantage> | status"; exit 2;;
esac
