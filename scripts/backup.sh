#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi
destination="${1:-/var/backups/monitorozo/$(date -u +%Y%m%dT%H%M%SZ)}"
case "$destination" in
  /*) ;;
  *)
    echo "Backup destination must be an absolute path" >&2
    exit 2
    ;;
esac
[ ! -e "$destination" ] || {
  echo "Backup destination already exists: $destination" >&2
  exit 2
}
case "$destination/" in
  /etc/monitorozo/*|/var/lib/monitorozo-agent/*|/var/lib/monitorozo-server/*)
    echo "Backup destination must be outside Monitorozo configuration and state" >&2
    exit 2
    ;;
esac
umask 077
install -d -o root -g root -m 0700 "$destination"
database="/var/lib/monitorozo-server/monitorozo.db"
if [ -f "$database" ]; then
  sqlite3 "$database" ".timeout 5000" ".backup '$destination/monitorozo.db'"
  sqlite3 "$destination/monitorozo.db" "PRAGMA integrity_check;" >"$destination/integrity.txt"
fi
set --
[ -d /etc/monitorozo ] && set -- "$@" etc/monitorozo
[ -d /var/lib/monitorozo-agent ] && set -- "$@" var/lib/monitorozo-agent
[ "$#" -gt 0 ] || {
  echo "No Monitorozo configuration or agent state found" >&2
  exit 1
}
tar --exclude=var/lib/monitorozo-agent/releases -C / \
  -czf "$destination/config-and-agent-state.tar.gz" "$@"
{
  /usr/local/bin/monitorozo-server -version 2>/dev/null || true
  /usr/local/bin/monitorozo-agent -version 2>/dev/null || true
  date -u +%Y-%m-%dT%H:%M:%SZ
} >"$destination/manifest.txt"
(
  cd "$destination"
  sha256sum monitorozo.db config-and-agent-state.tar.gz manifest.txt 2>/dev/null >SHA256SUMS ||
    sha256sum config-and-agent-state.tar.gz manifest.txt >SHA256SUMS
)
echo "Backup completed: $destination"
