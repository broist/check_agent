#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/var/lib/monitorozo-server/releases/$stamp"
install -d -o root -g root -m 0750 "$backup"
cp -a /usr/local/bin/monitorozo-agent /usr/local/bin/monitorozo-server "$backup/"
install -o root -g root -m 0755 bin/monitorozo-agent /usr/local/bin/monitorozo-agent
install -o root -g root -m 0755 bin/monitorozo-server /usr/local/bin/monitorozo-server
systemctl restart monitorozo-server monitorozo-agent
systemctl --no-pager --full status monitorozo-server monitorozo-agent
echo "Previous binaries: $backup"

