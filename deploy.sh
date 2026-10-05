#!/bin/bash
# Run on Ubuntu server as root. Usage: ADMIN_PASSWORD=yourpass SECRET_KEY=randomkey ./deploy.sh

set -e
SECRET_KEY="${SECRET_KEY:-$(openssl rand -hex 24)}"
PORT="${PORT:-5000}"
INSTALL_DIR="${INSTALL_DIR:-/opt/ssh-panel}"

if [ ! -f "app.py" ] || [ ! -f "templates/login.html" ] || [ ! -f "static/style.css" ]; then
  echo "Error: Run deploy.sh from project root. Clone must contain app.py, templates/, and static/."
  exit 1
fi

if [ -f "$INSTALL_DIR/app.py" ]; then
  if command -v ufw &>/dev/null; then
    ufw disable 2>/dev/null || true
  fi
  apt-get update -qq
  apt-get install -y -qq rsync 2>/dev/null || true
  rsync -a --exclude='user_limits.json' --exclude='panel_settings.json' --exclude='user_traffic.json' --exclude='ssh_sessions.json' --exclude='venv' --exclude='.git' ./ "$INSTALL_DIR/"
  cd "$INSTALL_DIR"
  if [ ! -f "templates/login.html" ]; then
    echo "Error: templates missing after sync. Check repo has templates/."
    exit 1
  fi
  if [ -d "venv" ]; then
    ./venv/bin/pip install -q -r requirements.txt
  else
    python3 -m venv venv
    ./venv/bin/pip install -q -r requirements.txt
  fi
  systemctl daemon-reload
  systemctl restart ssh-panel
  echo "Update finished. Panel restarted."
  exit 0
fi

if [ -z "${ADMIN_PASSWORD}" ]; then
  if [ -t 0 ]; then
    while true; do
      echo -n "Panel admin password: "
      read -rs PASS1
      echo
      echo -n "Confirm password: "
      read -rs PASS2
      echo
      if [ -z "$PASS1" ]; then
        echo "Password cannot be empty. Try again."
        continue
      fi
      if [ "$PASS1" != "$PASS2" ]; then
        echo "Passwords do not match. Try again."
        continue
      fi
      ADMIN_PASSWORD="$PASS1"
      break
    done
  else
    echo "Set ADMIN_PASSWORD in the environment (no TTY for password prompt)."
    exit 1
  fi
fi

apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip

mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
cd "$INSTALL_DIR"
if [ ! -f "templates/login.html" ]; then
  echo "Error: templates not found. Ensure the repo includes the templates/ folder."
  exit 1
fi

python3 -m venv venv
./venv/bin/pip install -q -r requirements.txt

cat > /etc/systemd/system/ssh-panel.service << EOF
[Unit]
Description=SSH User Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=ADMIN_USER=admin
Environment=ADMIN_PASSWORD=$ADMIN_PASSWORD
Environment=SECRET_KEY=$SECRET_KEY
Environment=FLASK_APP=app.py
ExecStart=$INSTALL_DIR/venv/bin/gunicorn -w 1 -b 0.0.0.0:$PORT app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ssh-panel
systemctl restart ssh-panel

if command -v ufw &>/dev/null; then
  ufw disable 2>/dev/null || true
fi

PANEL_HOST=""
if command -v hostname &>/dev/null; then
  PANEL_HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
[ -z "$PANEL_HOST" ] && PANEL_HOST="YOUR_SERVER_IP"
echo ""
echo "=== Install finished ==="
echo "Panel:  http://${PANEL_HOST}:${PORT}"
echo "Login:  admin / (password you set)"
echo "Set SECRET_KEY in env if not already set."
echo ""
