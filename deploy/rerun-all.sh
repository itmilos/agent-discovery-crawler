#!/usr/bin/env bash
# Re-run every measurement in the paper on one VM, end to end (Nov 2026 re-run).
#
#   ssh root@VM 'bash -s' < deploy/rerun-all.sh setup            # one-time: node, repo, Tranco 647LX bands
#   ssh root@VM 'CRAWLER_CONTACT_URL=... CRAWLER_CONTACT_EMAIL=... bash -s' < deploy/rerun-all.sh start [tag]
#   ssh root@VM 'bash -s' < deploy/rerun-all.sh status
#   ssh root@VM 'bash -s' < deploy/rerun-all.sh pack             # when status says ALL DONE -> /root/rerun-<tag>.tgz
#   scp root@VM:rerun-<tag>.tgz .
#
# `start` runs, in one tmux session, in this order:
#   crawl: tranco 1-1k, 1k-10k, 10k-100k (list 647LX, same hosts as October), registry, commerce, fintech
#   then: summarize (all six), handshake (MCP endpoints, with the ethics flag), consistency (card vs OpenAPI
#   + llms.txt coverage + hand-check sample), a2a:profile, and a staleness diff against any October files found in out/.
# Every file is tagged with the vantage/tag (default "nov"), so nothing from October is overwritten; the crawl
# resumes from its own output if the VM restarts (`start` is idempotent). Expect ~30 h for the crawls.
set -euo pipefail
cmd="${1:-}"; tag="${2:-nov}"
REPO=https://github.com/itmilos/agent-discovery-crawler.git
DIR="$HOME/agent-discovery-crawler"
TRANCO_LIST="${TRANCO_LIST:-647LX}"   # the October list; set to "" to take today's list instead

case "$cmd" in
  setup)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq git tmux curl unzip ca-certificates >/dev/null
    command -v node >/dev/null || { curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null; apt-get install -y -qq nodejs >/dev/null; }
    grep -q 'nofile 65536' /etc/security/limits.conf || printf '* soft nofile 65536\n* hard nofile 65536\n' >> /etc/security/limits.conf
    sysctl -q -w net.ipv4.ip_local_port_range="10240 65535" net.ipv4.tcp_fin_timeout=15
    if [ -d "$DIR/.git" ]; then git -C "$DIR" pull -q; else git clone -q "$REPO" "$DIR"; fi
    cd "$DIR" && npm ci --silent --ignore-scripts
    npx tsx src/selftest.ts >/tmp/selftest.log 2>&1 && echo "self-test passed ($(git rev-parse --short HEAD), $(node -v))" || { tail -30 /tmp/selftest.log; echo "self-test FAILED"; exit 1; }
    mkdir -p out hosts
    if [ -n "$TRANCO_LIST" ]; then
      [ -s "hosts/tranco-$TRANCO_LIST.csv" ] || curl -fsSL "https://tranco-list.eu/download/$TRANCO_LIST/1000000" -o "hosts/tranco-$TRANCO_LIST.csv"
      npx tsx src/corpus/tranco.ts --file "hosts/tranco-$TRANCO_LIST.csv" --list-id "$TRANCO_LIST" --out-dir hosts >/dev/null
    else
      npx tsx src/corpus/tranco.ts --out-dir hosts >/dev/null
    fi
    for b in 1-1k 1k-10k 10k-100k; do printf '%-28s %6s hosts\n' "hosts/tranco-latest-$b.txt" "$(grep -c . hosts/tranco-latest-$b.txt)"; done
    for f in registry-latest commerce-latest fintech-latest; do printf '%-28s %6s hosts\n' "hosts/$f.txt" "$(grep -c . hosts/$f.txt)"; done
    ls out/*.jsonl 2>/dev/null | sed 's/^/existing: /' || true
    echo "setup ok; now: bash -s start $tag"
    ;;
  start)
    : "${CRAWLER_CONTACT_URL:?set CRAWLER_CONTACT_URL}" "${CRAWLER_CONTACT_EMAIL:?set CRAWLER_CONTACT_EMAIL}"
    cd "$DIR"; ulimit -n 65536 || true
    tmux has-session -t rerun 2>/dev/null && { echo "already running (tmux attach -t rerun)"; exit 0; }
    cat > "$DIR/rerun-$tag.sh" <<RUN
#!/usr/bin/env bash
cd "$DIR"; mkdir -p out; L=out/rerun-$tag.log
export CRAWLER_CONTACT_URL="$CRAWLER_CONTACT_URL" CRAWLER_CONTACT_EMAIL="$CRAWLER_CONTACT_EMAIL" UV_THREADPOOL_SIZE=64
say() { echo "=== \$1 \$(date -u +%FT%TZ)" >> \$L; }
crawl() { npx tsx src/run.ts --hosts hosts/\$1.txt --out out/\$2-$tag.jsonl --vantage $tag --concurrency \$3 --rps-per-host 1 --progress >> \$L 2>&1; }
say "tranco-1-1k start";      crawl tranco-latest-1-1k tranco-1-1k 20;          say "tranco-1-1k done"
say "tranco-1k-10k start";    crawl tranco-latest-1k-10k tranco-1k-10k 20;      say "tranco-1k-10k done"
say "tranco-10k-100k start";  crawl tranco-latest-10k-100k tranco-10k-100k 40;  say "tranco-10k-100k done"
say "registry start";         crawl registry-latest registry 20;                say "registry done"
say "commerce start";         crawl commerce-latest commerce 20;                say "commerce done"
say "fintech start";          crawl fintech-latest fintech 20;                  say "fintech done"
ALL="out/tranco-1-1k-$tag.jsonl out/tranco-1k-10k-$tag.jsonl out/tranco-10k-100k-$tag.jsonl out/registry-$tag.jsonl out/commerce-$tag.jsonl out/fintech-$tag.jsonl"
say "summarize start"
for f in \$ALL; do npx tsx src/summarize.ts \$f --platform-table > \${f%.jsonl}.summary.txt 2>&1 || true; done
npx tsx src/summarize.ts out/tranco-1-1k-$tag.jsonl out/tranco-1k-10k-$tag.jsonl out/tranco-10k-100k-$tag.jsonl > out/tranco-all-$tag.summary.txt 2>&1 || true
say "handshake start"
npx tsx src/handshake-run.ts --in \$ALL --out out/handshake-$tag.jsonl --rps 1 --i-have-read-the-ethics-section > out/handshake-$tag.summary.txt 2>&1 || true
say "consistency start"
npx tsx src/consistency.ts --in \$ALL --out out/consistency-$tag.jsonl --sample out/consistency-sample-$tag.csv --concurrency 20 > out/consistency-$tag.summary.txt 2>&1 || true
say "a2a-profile start"
npx tsx src/a2a-profile.ts --in \$ALL --out out/a2a-profile-$tag.jsonl --concurrency 20 > out/a2a-profile-$tag.summary.txt 2>&1 || true
say "staleness start"
for b in tranco-1-1k tranco-1k-10k tranco-10k-100k registry commerce fintech; do
  for old in out/\$b-local.jsonl out/\$b-eu.jsonl; do
    [ -s "\$old" ] && npx tsx src/vantage-compare.ts --a \$old --b out/\$b-$tag.jsonl --label-a \$(basename \${old%.jsonl} | sed 's/.*-//') --label-b $tag --out out/stale-\$b-$tag.json > out/stale-\$b-$tag.txt 2>&1 || true
  done
done
say "ALL DONE"
RUN
    chmod +x "$DIR/rerun-$tag.sh"
    tmux new-session -d -s rerun "$DIR/rerun-$tag.sh"
    echo "started tag=$tag in tmux session 'rerun'; log: out/rerun-$tag.log"
    ;;
  status)
    cd "$DIR"
    for f in out/*.jsonl; do [ -e "$f" ] && printf '%-40s %8d rows\n' "$f" "$(wc -l < "$f")"; done
    grep -h "^===" out/rerun-*.log 2>/dev/null | tail -3
    grep -h "^progress" out/rerun-*.log 2>/dev/null | tail -1
    tmux has-session -t rerun 2>/dev/null && echo "tmux: running" || echo "tmux: not running"
    ;;
  pack)
    cd "$DIR"
    tar czf "$HOME/rerun-$tag.tgz" out/*-$tag.* out/stale-*-$tag.* hosts/tranco-latest-*.txt hosts/*-latest.txt 2>/dev/null
    ls -la "$HOME/rerun-$tag.tgz"
    ;;
  *)
    echo "usage: rerun-all.sh setup | start [tag] | status | pack [tag]"; exit 2;;
esac
