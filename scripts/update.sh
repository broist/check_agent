#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi
component="${1:-all}"
case "$component" in
  server|agent|all) ;;
  *)
    echo "Usage: $0 [server|agent|all]" >&2
    exit 2
    ;;
esac
for command in install cp date systemctl tar; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Required command is missing: $command" >&2
    exit 1
  }
done
if [ "$component" = server ] || [ "$component" = all ]; then
  command -v sqlite3 >/dev/null 2>&1
  command -v curl >/dev/null 2>&1
fi
health_url="${MONITOROZO_HEALTH_URL:-http://127.0.0.1:8080/readyz}"

root="/var/lib/monitorozo-$component"
if [ "$component" = all ]; then
  root="/var/lib/monitorozo-server"
fi
umask 077
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="$root/releases/$stamp"
install -d -o root -g root -m 0700 "$backup"

has_server=false
has_agent=false
if [ "$component" = server ] || [ "$component" = all ]; then
  has_server=true
  if [ ! -x bin/monitorozo-server ] ||
    [ ! -x /usr/local/bin/monitorozo-server ]; then
    echo "Server release/installed binary is missing" >&2
    exit 1
  fi
  bin/monitorozo-server -version
  cp -a /usr/local/bin/monitorozo-server "$backup/"
fi
if [ "$component" = agent ] || [ "$component" = all ]; then
  has_agent=true
  if [ ! -x bin/monitorozo-agent ] ||
    [ ! -x /usr/local/bin/monitorozo-agent ]; then
    echo "Agent release/installed binary is missing" >&2
    exit 1
  fi
  bin/monitorozo-agent -version
  cp -a /usr/local/bin/monitorozo-agent "$backup/"
fi
tar -C / -czf "$backup/config.tar.gz" etc/monitorozo
database="/var/lib/monitorozo-server/monitorozo.db"
database_saved=false
if [ "$has_server" = true ] && [ -f "$database" ]; then
  sqlite3 "$database" ".timeout 5000" ".backup '$backup/monitorozo.db'"
  database_saved=true
fi

completed=false
rollback_on_failure() {
  code=$?
  if [ "$completed" = false ]; then
    echo "Update failed; restoring $backup" >&2
    set +e
    if [ "$has_agent" = true ]; then systemctl stop monitorozo-agent; fi
    if [ "$has_server" = true ]; then systemctl stop monitorozo-server; fi
    if [ "$has_agent" = true ]; then
      install -o root -g root -m 0755 "$backup/monitorozo-agent" \
        /usr/local/bin/monitorozo-agent
    fi
    if [ "$has_server" = true ]; then
      install -o root -g root -m 0755 "$backup/monitorozo-server" \
        /usr/local/bin/monitorozo-server
      if [ "$database_saved" = true ]; then
        install -o monitorozo-server -g monitorozo-server -m 0640 \
          "$backup/monitorozo.db" "$database"
        rm -f "$database-wal" "$database-shm"
      fi
      systemctl start monitorozo-server
    fi
    if [ "$has_agent" = true ]; then systemctl start monitorozo-agent; fi
    set -e
  fi
  exit "$code"
}
trap rollback_on_failure EXIT HUP INT TERM

if [ "$has_agent" = true ]; then systemctl stop monitorozo-agent; fi
if [ "$has_server" = true ]; then systemctl stop monitorozo-server; fi
if [ "$has_server" = true ]; then
  install -o root -g root -m 0755 bin/monitorozo-server \
    /usr/local/bin/monitorozo-server
  systemctl start monitorozo-server
  healthy=false
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if curl --fail --silent --show-error \
      "$health_url" >/dev/null; then
      healthy=true
      break
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  [ "$healthy" = true ] ||
    { echo "Server readiness check failed" >&2; exit 1; }
fi
if [ "$has_agent" = true ]; then
  install -o root -g root -m 0755 bin/monitorozo-agent \
    /usr/local/bin/monitorozo-agent
  systemctl start monitorozo-agent
  systemctl is-active --quiet monitorozo-agent
fi
completed=true
trap - EXIT HUP INT TERM
if [ "$has_server" = true ]; then
  systemctl --no-pager --full status monitorozo-server
fi
if [ "$has_agent" = true ]; then
  systemctl --no-pager --full status monitorozo-agent
fi
echo "Update completed. Previous release: $backup"
