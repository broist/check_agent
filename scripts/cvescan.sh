#!/bin/sh
# Daily container image CVE scan for the Monitorozo agent.
#
# Runs as root (monitorozo-cvescan.service). Scans the images of the running
# containers with a pinned Trivy container, then writes a small summary with
# "monitorozo-agent trivy-summary" that the unprivileged agent reads. The agent
# itself never gets Docker socket access.
#
# Environment:
#   CVESCAN_MEMORY  memory limit of the Trivy container (default: 1200m)
#   CVESCAN_OUT     summary file (default: /var/lib/monitorozo-cvescan/summary.json)
#   TRIVY_IMAGE     Trivy image (default: aquasec/trivy:0.65.0)
#   CVESCAN_CACHE   Trivy cache directory (default: /var/cache/monitorozo-cvescan)
#   MONITOROZO_AGENT_BIN  agent binary (default: /usr/local/bin/monitorozo-agent)
set -eu

memory="${CVESCAN_MEMORY:-1200m}"
out="${CVESCAN_OUT:-/var/lib/monitorozo-cvescan/summary.json}"
trivy_image="${TRIVY_IMAGE:-aquasec/trivy:0.65.0}"
cache_dir="${CVESCAN_CACHE:-/var/cache/monitorozo-cvescan}"
agent_bin="${MONITOROZO_AGENT_BIN:-/usr/local/bin/monitorozo-agent}"
docker_socket=/var/run/docker.sock

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi
for command in docker sort mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Required command is missing: $command" >&2
    exit 1
  }
done
[ -x "$agent_bin" ] || {
  echo "Agent binary is missing: $agent_bin" >&2
  exit 1
}

out_dir="$(dirname "$out")"
install -d -o root -g root -m 0755 "$out_dir"
install -d -o root -g root -m 0700 "$cache_dir"

work="$(mktemp -d)"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

# Run the pinned Trivy image with bounded resources, the shared cache and a
# read-only Docker socket. Arguments are passed to "trivy".
trivy() {
  docker run --rm --pull missing \
    --cpus 1 --memory "$memory" \
    --security-opt no-new-privileges \
    -v "$docker_socket:$docker_socket:ro" \
    -v "$cache_dir:/cache" \
    "$trivy_image" --cache-dir /cache "$@"
}

# "aquasec/trivy:0.65.0" -> "trivy 0.65.0"
case "$trivy_image" in
  *:*) scanner="trivy ${trivy_image##*:}" ;;
  *) scanner="trivy" ;;
esac

scan_error=""
echo "Updating the Trivy vulnerability database"
if ! trivy image --download-db-only --quiet; then
  echo "Trivy database update failed; scanning with the cached database" >&2
  scan_error="A Trivy-adatbázis frissítése sikertelen volt; az eredmény a gyorsítótárazott adatbázison alapul."
fi

docker ps --format '{{.Image}}' | sort -u >"$work/images"

set --
index=0
while IFS= read -r image; do
  [ -n "$image" ] || continue
  index=$((index + 1))
  report="$work/image-$index.json"
  echo "Scanning $image"
  if ! trivy image --scanners vuln --severity CRITICAL,HIGH,MEDIUM \
    --format json --quiet --timeout 20m --skip-db-update \
    --image-src docker "$image" >"$report" 2>"$work/image-$index.err"; then
    echo "Scan failed for $image:" >&2
    tail -n 20 "$work/image-$index.err" >&2 || true
    rm -f "$report"
  fi
  set -- "$@" "$image=$report"
done <"$work/images"

"$agent_bin" trivy-summary -out "$out" -scanner "$scanner" \
  -error "$scan_error" "$@"
echo "Wrote $out ($index images)"
