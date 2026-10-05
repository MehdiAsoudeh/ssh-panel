# SSH Panel

Panel to manage SSH users (add/edit/delete, traffic limits, lock/unlock). Ubuntu/Debian, root.

---

**Install or update** (run on server as root; safe to run multiple times):

```bash
apt-get update -qq && apt-get install -y -qq git && cd /tmp && rm -rf ssh-panel && git clone https://github.com/MahdiAsoudeh/ssh-panel.git ssh-panel && cd ssh-panel && chmod +x deploy.sh && ./deploy.sh
```

- First run: full install (you set panel password). Later runs: update only (code refreshed, users/settings kept).
- Then open the panel in browser (port 5000) — login **admin** / (password you set).
