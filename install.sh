#!/usr/bin/env bash
# One-line install from GitHub. Run on server as root.
#   curl -sSL https://raw.githubusercontent.com/OWNER/REPO/main/install.sh | sudo bash -s -- https://github.com/OWNER/REPO.git
# Optional second arg: branch (default main).

set -e
REPO="${1:-$GITHUB_REPO}"
BRANCH="${2:-main}"

if [ -z "$REPO" ]; then
  echo "Usage: curl -sSL https://raw.githubusercontent.com/OWNER/REPO/main/install.sh | sudo bash -s -- https://github.com/OWNER/REPO.git"
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (e.g. sudo bash -s -- $REPO)"
  exit 1
fi

if [[ "$REPO" != *://* ]]; then
  REPO="https://github.com/${REPO}.git"
fi

STAGING="/tmp/ssh-panel-install-$$"
apt-get update -qq
apt-get install -y -qq git

git clone --depth 1 --branch "$BRANCH" "$REPO" "$STAGING"
cd "$STAGING"
chmod +x deploy.sh
./deploy.sh
rm -rf "$STAGING"
