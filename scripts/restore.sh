#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi
if [ "$#" -ne 2 ] || [ "$2" != "--confirm" ]; then
  echo "Usage: $0 /absolute/path/to/backup --confirm" >&2
  exit 2
fi
backup="${1%/}"
case "$backup" in
  /*) ;;
  *)
    echo "Backup path must be absolute" >&2
    exit 2
    ;;
esac
[ -f "$backup/config-and-agent-state.tar.gz" ] || {
  echo "Configuration/state archive is missing" >&2
  exit 1
}
(
  cd "$backup"
  sha256sum -c SHA256SUMS
)

has_server=false
has_agent=false
if [ -f /etc/systemd/system/monitorozo-server.service ]; then has_server=true; fi
if [ -f /etc/systemd/system/monitorozo-agent.service ]; then has_agent=true; fi
[ "$has_server" = true ] || [ "$has_agent" = true ] || {
  echo "Install the server or agent component before restoring it" >&2
  exit 1
}
health_url="${MONITOROZO_HEALTH_URL:-http://127.0.0.1:8080/readyz}"
if [ "$has_server" = true ]; then
  command -v sqlite3 >/dev/null 2>&1
  command -v curl >/dev/null 2>&1
fi
if [ "$has_agent" = true ]; then systemctl stop monitorozo-agent; fi
if [ "$has_server" = true ]; then systemctl stop monitorozo-server; fi
tar -C / -xzf "$backup/config-and-agent-state.tar.gz"
if [ "$has_server" = true ] && [ -f "$backup/monitorozo.db" ]; then
  install -o monitorozo-server -g monitorozo-server -m 0640 \
    "$backup/monitorozo.db" /var/lib/monitorozo-server/monitorozo.db
  rm -f /var/lib/monitorozo-server/monitorozo.db-wal \
    /var/lib/monitorozo-server/monitorozo.db-shm
  sqlite3 /var/lib/monitorozo-server/monitorozo.db \
    "PRAGMA integrity_check;"
fi
if [ "$has_agent" = true ] && [ -d /var/lib/monitorozo-agent ]; then
  chown -R monitorozo-agent:monitorozo-agent /var/lib/monitorozo-agent
  chmod 0750 /var/lib/monitorozo-agent
fi
if [ "$has_server" = true ]; then
  systemctl start monitorozo-server
  curl --fail --retry 20 --retry-delay 1 --retry-connrefused \
    "$health_url" >/dev/null
fi
if [ "$has_agent" = true ]; then systemctl start monitorozo-agent; fi
if [ "$has_server" = true ]; then
  systemctl --no-pager --full status monitorozo-server
fi
if [ "$has_agent" = true ]; then
  systemctl --no-pager --full status monitorozo-agent
fi
echo "Restore completed from $backup"
