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
if [ "$component" = agent ] || [ "$component" = all ]; then
  systemctl disable --now monitorozo-agent 2>/dev/null || true
  rm -f /etc/systemd/system/monitorozo-agent.service
  rm -f /usr/local/bin/monitorozo-agent
fi
if [ "$component" = server ] || [ "$component" = all ]; then
  systemctl disable --now monitorozo-server 2>/dev/null || true
  rm -f /etc/systemd/system/monitorozo-server.service
  rm -f /usr/local/bin/monitorozo-server
fi
systemctl daemon-reload
echo "Removed component: $component. Configuration and state were retained."
