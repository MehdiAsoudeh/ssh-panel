# SSH Panel – Install & troubleshooting

## Requirements

- Ubuntu or Debian (root)
- Python 3, iptables, getent, chpasswd, useradd/userdel/usermod, systemd
- SSH: `/etc/ssh/sshd_config`; service name is `ssh` (Debian) or `sshd` (RHEL)

## Deploy

```bash
cd /opt/ssh-panel   # or wherever you copied the app
chmod +x deploy.sh
ADMIN_PASSWORD='your_admin_pass' SECRET_KEY="$(openssl rand -hex 24)" ./deploy.sh
```

Optional env: `PORT=5000`, `SSH_PORT=22`, `INSTALL_DIR=/opt/ssh-panel`.  
If `SSH_PORT` or `SSH_PORT_INPUT` is set, no prompt; if not set and stdin is not a TTY, default 22 is used.

## Known issues

1. **Non-interactive install** – If there is no TTY (e.g. `curl | bash`), the script does not prompt for SSH port; set `SSH_PORT=22` (or desired port) in the environment.
2. **SSH service name** – Debian uses `ssh`, RHEL/CentOS use `sshd`. Deploy and panel try both on restart.
3. **Auth log** – Traffic/session tracking reads `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL). If neither exists, traffic is still polled from iptables every 15s but new SSH logins are not detected until next poll.
4. **Panel runs as root** – Needed for iptables, useradd, chpasswd, sshd_config. Run only on a dedicated/trusted server.
5. **Copy deploy** – `cp -r . $INSTALL_DIR` copies everything in the current dir (e.g. `venv`, `__pycache__`). Prefer a clean copy or run deploy from a clean clone.

## Troubleshooting

- **Panel not reachable** – Open panel port (e.g. 5000): `ufw allow 5000 && ufw reload`. Check: `systemctl status ssh-panel` and `journalctl -u ssh-panel -f`.
- **SSH port change did nothing** – Confirm service: `systemctl status ssh` or `systemctl status sshd`. Restart the one that is active. Ensure no duplicate `Port` in `sshd_config`.
- **Traffic always zero** – iptables accounting must run as root; ensure no errors in `journalctl -u ssh-panel`. If auth.log is missing, session-based tracking is disabled but total traffic can still be synced from chains every 15s.
- **Login loop / 500** – Set `SECRET_KEY` and `ADMIN_PASSWORD` in the systemd unit; restart: `systemctl restart ssh-panel`.

## Cron (optional)

- **Check limits**: `curl -s "http://127.0.0.1:5000/internal/check-limits?key=CRON_KEY"`
- **Migrate traffic rules**: `curl -s "http://127.0.0.1:5000/internal/migrate-traffic-rules?key=CRON_KEY"`

Set `CRON_KEY` in the service environment if you use these.
