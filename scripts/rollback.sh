#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi
if [ "$#" -ne 2 ] || [ "$2" != "--confirm" ]; then
  echo "Usage: $0 /var/lib/monitorozo-COMPONENT/releases/TIMESTAMP --confirm" >&2
  exit 2
fi
release="$(readlink -f "$1")"
parent="$(dirname "$release")"
stamp="$(basename "$release")"
case "$parent" in
  /var/lib/monitorozo-server/releases|/var/lib/monitorozo-agent/releases) ;;
  *)
    echo "Release must be inside a Monitorozo releases directory" >&2
    exit 2
    ;;
esac
printf '%s\n' "$stamp" | grep -Eq '^[0-9]{8}T[0-9]{6}Z$' || {
  echo "Release directory name must be an UTC timestamp" >&2
  exit 2
}
has_server=false
has_agent=false
if [ -x "$release/monitorozo-server" ]; then has_server=true; fi
if [ -x "$release/monitorozo-agent" ]; then has_agent=true; fi
if [ "$has_server" = false ] && [ "$has_agent" = false ]; then
  echo "No release binaries found in $release" >&2
  exit 1
fi
health_url="${MONITOROZO_HEALTH_URL:-http://127.0.0.1:8080/readyz}"
if [ "$has_server" = true ]; then
  command -v sqlite3 >/dev/null 2>&1
  command -v curl >/dev/null 2>&1
fi

if [ "$has_agent" = true ]; then systemctl stop monitorozo-agent; fi
if [ "$has_server" = true ]; then systemctl stop monitorozo-server; fi
if [ "$has_server" = true ]; then
  install -o root -g root -m 0755 "$release/monitorozo-server" \
    /usr/local/bin/monitorozo-server
  database="/var/lib/monitorozo-server/monitorozo.db"
  if [ -f "$release/monitorozo.db" ]; then
    install -o monitorozo-server -g monitorozo-server -m 0640 \
      "$release/monitorozo.db" "$database"
    rm -f "$database-wal" "$database-shm"
    sqlite3 "$database" "PRAGMA integrity_check;"
  fi
  systemctl start monitorozo-server
  curl --fail --retry 20 --retry-delay 1 --retry-connrefused \
    "$health_url" >/dev/null
fi
if [ "$has_agent" = true ]; then
  install -o root -g root -m 0755 "$release/monitorozo-agent" \
    /usr/local/bin/monitorozo-agent
  systemctl start monitorozo-agent
  systemctl is-active --quiet monitorozo-agent
fi
if [ "$has_server" = true ]; then
  systemctl --no-pager --full status monitorozo-server
fi
if [ "$has_agent" = true ]; then
  systemctl --no-pager --full status monitorozo-agent
fi
echo "Rolled back to $release"
