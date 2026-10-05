#!/usr/bin/env bash
# Run from project root. Copies app to server and runs deploy.sh there.
# Needs: sshpass (brew install hudochenkov/sshpass/sshpass) OR SSH key for root@server.
# Usage: REMOTE_SSH_PASS='yourpass' ./install-remote.sh
#   Or set: REMOTE_HOST, REMOTE_USER, REMOTE_PORT, REMOTE_SSH_PASS, ADMIN_PASSWORD

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_PORT="${REMOTE_PORT:-22}"
REMOTE_SSH_PASS="${REMOTE_SSH_PASS:-}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
SECRET_KEY="${SECRET_KEY:-$(openssl rand -hex 24)}"
SSH_PORT="${SSH_PORT:-22}"
INSTALL_DIR="${INSTALL_DIR:-/opt/ssh-panel}"
REMOTE_STAGING="/tmp/ssh-panel-install-$$"

if [ -z "$REMOTE_HOST" ]; then
  echo "Set REMOTE_HOST (e.g. REMOTE_HOST=1.2.3.4 ./install-remote.sh)"
  exit 1
fi

run_ssh() {
  if [ -n "$REMOTE_SSH_PASS" ] && command -v sshpass &>/dev/null; then
    sshpass -e ssh "${SSH_OPTS[@]}" "$@"
  else
    ssh "${SSH_OPTS[@]}" "$@"
  fi
}

run_rsync() {
  local dest="$REMOTE_USER@$REMOTE_HOST:$REMOTE_STAGING"
  if [ -n "$REMOTE_SSH_PASS" ] && command -v sshpass &>/dev/null; then
    rsync -e "sshpass -e ssh -o StrictHostKeyChecking=accept-new -p $REMOTE_PORT" "${RSYNC_OPTS[@]}" ./ "$dest/"
  else
    rsync -e "ssh -o StrictHostKeyChecking=accept-new -p $REMOTE_PORT" "${RSYNC_OPTS[@]}" ./ "$dest/"
  fi
}

echo "=== Target: $REMOTE_USER@$REMOTE_HOST:$REMOTE_PORT ==="
if [ -z "$REMOTE_SSH_PASS" ]; then
  echo "REMOTE_SSH_PASS not set; using SSH key if configured."
else
  if ! command -v sshpass &>/dev/null; then
    echo "Warning: sshpass not found. Install with: brew install hudochenkov/sshpass/sshpass"
    echo "Falling back to SSH key auth."
  fi
  export SSHPASS="$REMOTE_SSH_PASS"
fi
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -p "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST")
RSYNC_OPTS=(-a -z --exclude 'venv' --exclude '__pycache__' --exclude '.git' --exclude '*.pyc' --exclude '.DS_Store')

echo "=== Creating staging dir on server ==="
run_ssh "mkdir -p $REMOTE_STAGING"

echo "=== Syncing project to staging ==="
run_rsync

echo "=== Running deploy (from staging into $INSTALL_DIR) ==="
run_ssh "cd $REMOTE_STAGING && chmod +x deploy.sh && INSTALL_DIR='$INSTALL_DIR' ADMIN_PASSWORD=\"$ADMIN_PASSWORD\" SECRET_KEY='$SECRET_KEY' SSH_PORT='$SSH_PORT' PORT=5000 ./deploy.sh; rm -rf $REMOTE_STAGING"

echo ""
echo "=== Done. Panel: http://$REMOTE_HOST:5000 — Login: admin / (password you set) ==="
