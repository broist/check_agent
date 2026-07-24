#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi
systemctl disable --now monitorozo-agent monitorozo-server 2>/dev/null || true
rm -f /etc/systemd/system/monitorozo-agent.service /etc/systemd/system/monitorozo-server.service
rm -f /usr/local/bin/monitorozo-agent /usr/local/bin/monitorozo-server
systemctl daemon-reload
echo "Configuration and data were retained in /etc/monitorozo and /var/lib/monitorozo-*."

