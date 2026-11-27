#!/usr/bin/env bash
# Root Justice installer (Linux/systemd). Installs into an isolated venv and
# registers a hardened, least-privilege service. SAFE BY DEFAULT: the service
# starts in log-only mode, bound to loopback, until you edit the env file.
#
# Usage:  sudo ./deploy/install.sh
# Deliberate root use: installing a system service requires it. The service
# itself runs UNPRIVILEGED (systemd DynamicUser); root is only for setup.
set -euo pipefail

PREFIX=/opt/root-justice
ETC=/etc/root-justice
UNIT=/etc/systemd/system/root-justice.service
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "This installer must run as root (installs a system service): sudo $0" >&2
  exit 1
fi

echo "[root-justice] installing from ${SRC_DIR}"
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

install -d -m 0755 "$PREFIX" "$ETC"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --upgrade pip >/dev/null
"$PREFIX/venv/bin/pip" install "$SRC_DIR" >/dev/null

# Config: never overwrite an existing operator-edited env file.
if [[ ! -f "$ETC/root-justice.env" ]]; then
  install -m 0640 "$SRC_DIR/deploy/root-justice.env.example" "$ETC/root-justice.env"
  echo "[root-justice] wrote default config -> $ETC/root-justice.env (log-only, loopback)"
else
  echo "[root-justice] keeping existing config $ETC/root-justice.env"
fi

install -m 0644 "$SRC_DIR/deploy/systemd/root-justice.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now root-justice.service

echo
echo "[root-justice] installed and started in LOG-ONLY mode."
echo "  status : systemctl status root-justice"
echo "  logs   : journalctl -u root-justice -f"
echo "  enforce: edit $ETC/root-justice.env (set RJ_EXTRA_ARGS=--enforce ...), then"
echo "           systemctl restart root-justice"
echo "  report : sudo -u root /opt/root-justice/venv/bin/root-justice export-report \\"
echo "             --evidence /var/lib/root-justice/evidence_ledger.jsonl --reviewed-by \"<your name>\""
