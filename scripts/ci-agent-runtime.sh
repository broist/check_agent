#!/bin/sh
set -eu

agent_binary="${1:-dist/monitorozo-agent-linux-amd64}"
[ -x "$agent_binary" ] || {
  echo "Agent binary is missing or not executable: $agent_binary" >&2
  exit 1
}

work="$(mktemp -d)"
agent_pid=""
cleanup() {
  if [ -n "$agent_pid" ] && kill -0 "$agent_pid" 2>/dev/null; then
    kill -TERM "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/state" "$work/spool"
cat >"$work/agent.yaml" <<EOF
agent_id: ci-runtime
server_url: http://127.0.0.1:1
token: 0123456789abcdef0123456789abcdef
interval: 5s
request_timeout: 1s
queue_size: 2
state_file: $work/state/sequence
spool_directory: $work/spool
insecure_dev_http: true
EOF

"$agent_binary" -config "$work/agent.yaml" >"$work/agent.log" 2>&1 &
agent_pid=$!
sleep 3
if ! kill -0 "$agent_pid" 2>/dev/null; then
  cat "$work/agent.log" >&2
  echo "Agent exited during runtime check" >&2
  exit 1
fi

rss_kib="$(ps -o rss= -p "$agent_pid" 2>/dev/null | awk '{print $1}')"
if [ -z "$rss_kib" ] && [ -r "/proc/$agent_pid/status" ]; then
  rss_kib="$(awk '/^VmRSS:/ {print $2}' "/proc/$agent_pid/status")"
fi
case "$rss_kib" in
  ''|*[!0-9]*)
    echo "Could not determine agent RSS" >&2
    exit 1
    ;;
esac
if [ "$rss_kib" -ge 30720 ]; then
  echo "Agent RSS ${rss_kib} KiB exceeds the 30 MiB target" >&2
  exit 1
fi

kill -TERM "$agent_pid"
wait "$agent_pid"
agent_pid=""
grep -q '"msg":"agent stopped"' "$work/agent.log"
echo "Agent runtime check passed: RSS=${rss_kib} KiB, graceful shutdown confirmed"
