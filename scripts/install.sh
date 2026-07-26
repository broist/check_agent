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

install -d -o root -g root -m 0755 /etc/monitorozo
if [ "$component" = server ] || [ "$component" = all ]; then
  [ -x bin/monitorozo-server ] || {
    echo "Missing executable: bin/monitorozo-server" >&2
    exit 1
  }
  getent group monitorozo-server >/dev/null ||
    groupadd --system monitorozo-server
  id monitorozo-server >/dev/null 2>&1 ||
    useradd --system --gid monitorozo-server \
      --home-dir /var/lib/monitorozo-server --shell /usr/sbin/nologin \
      monitorozo-server
  install -d -o monitorozo-server -g monitorozo-server -m 0750 \
    /var/lib/monitorozo-server
  install -o root -g root -m 0755 bin/monitorozo-server \
    /usr/local/bin/monitorozo-server
  install -o root -g root -m 0644 deploy/systemd/monitorozo-server.service \
    /etc/systemd/system/monitorozo-server.service
fi
if [ "$component" = agent ] || [ "$component" = all ]; then
  [ -x bin/monitorozo-agent ] || {
    echo "Missing executable: bin/monitorozo-agent" >&2
    exit 1
  }
  getent group monitorozo-agent >/dev/null ||
    groupadd --system monitorozo-agent
  id monitorozo-agent >/dev/null 2>&1 ||
    useradd --system --gid monitorozo-agent \
      --home-dir /var/lib/monitorozo-agent --shell /usr/sbin/nologin \
      monitorozo-agent
  install -d -o monitorozo-agent -g monitorozo-agent -m 0750 \
    /var/lib/monitorozo-agent
  install -o root -g root -m 0755 bin/monitorozo-agent \
    /usr/local/bin/monitorozo-agent
  install -o root -g root -m 0644 deploy/systemd/monitorozo-agent.service \
    /etc/systemd/system/monitorozo-agent.service
fi
systemctl daemon-reload
echo "Installed component: $component. Install its protected configuration, then enable the service."
