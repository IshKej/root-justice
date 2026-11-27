#!/usr/bin/env bash
# Remove the Root Justice service and program files. Keeps the evidence ledger
# (chain-of-custody) unless you pass --purge-evidence.
set -euo pipefail
PURGE=0
[[ "${1:-}" == "--purge-evidence" ]] && PURGE=1

if [[ $EUID -ne 0 ]]; then echo "run as root: sudo $0" >&2; exit 1; fi

systemctl disable --now root-justice.service 2>/dev/null || true
rm -f /etc/systemd/system/root-justice.service
systemctl daemon-reload
rm -rf /opt/root-justice /etc/root-justice
if [[ $PURGE -eq 1 ]]; then
  rm -rf /var/lib/root-justice
  echo "[root-justice] removed, including evidence ledger."
else
  echo "[root-justice] removed. Evidence ledger kept at /var/lib/root-justice (use --purge-evidence to delete)."
fi
