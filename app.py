import base64
import json
import os
import re
import subprocess
import threading
import time
from functools import wraps
from flask import Flask, Response, jsonify, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
ADMIN_PASS = os.environ.get("ADMIN_PASSWORD", "change-me")
LIMITS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "user_limits.json")
PANEL_SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel_settings.json")
USER_TRAFFIC_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "user_traffic.json")
SESSIONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_sessions.json")
AUTH_LOG = "/var/log/auth.log" if os.path.isfile("/var/log/auth.log") else "/var/log/secure"
IPTABLES_CHAIN = "SSH_PANEL_TRAFFIC"
IPTABLES_CHAIN_IN = "SSH_PANEL_TRAFFIC_IN"
SSH_ACCT_IN = "SSH_PANEL_ACCT_IN"
SSH_ACCT_OUT = "SSH_PANEL_ACCT_OUT"

_traffic_lock = threading.Lock()
_ssh_tracker_started = False


def ensure_traffic_chain():
    ok, _, _ = run("iptables -L " + IPTABLES_CHAIN + " -n 2>/dev/null")
    if ok:
        return
    run("iptables -N " + IPTABLES_CHAIN)
    run("iptables -A OUTPUT -j " + IPTABLES_CHAIN)
    run("iptables -A " + IPTABLES_CHAIN + " -j ACCEPT")


def ensure_traffic_chain_in():
    ok, _, _ = run("iptables -L " + IPTABLES_CHAIN_IN + " -n 2>/dev/null")
    if ok:
        return
    run("iptables -N " + IPTABLES_CHAIN_IN)
    run("iptables -A INPUT -j " + IPTABLES_CHAIN_IN)
    run("iptables -A " + IPTABLES_CHAIN_IN + " -j ACCEPT")


def ensure_user_traffic_rule(uid):
    ensure_traffic_chain()
    ok, out, _ = run("iptables -L " + IPTABLES_CHAIN + " -n -v -x 2>/dev/null")
    if not ok:
        return
    for line in out.splitlines():
        if "owner" in line and "match" in line and str(uid) in line.split():
            return
    run("iptables -I " + IPTABLES_CHAIN + " 1 -m owner --uid-owner " + str(uid) + " ! -o lo -j ACCEPT")


def ensure_user_traffic_rule_in(uid):
    ensure_traffic_chain_in()
    ok, out, _ = run("iptables -L " + IPTABLES_CHAIN_IN + " -n -v -x 2>/dev/null")
    if not ok:
        return
    for line in out.splitlines():
        if "owner" in line and "match" in line and str(uid) in line.split():
            return
    run("iptables -I " + IPTABLES_CHAIN_IN + " 1 -m owner --uid-owner " + str(uid) + " ! -i lo -j ACCEPT")


def remove_user_traffic_rule(uid):
    run("iptables -D " + IPTABLES_CHAIN + " -m owner --uid-owner " + str(uid) + " ! -o lo -j ACCEPT 2>/dev/null")
    run("iptables -D " + IPTABLES_CHAIN + " -m owner --uid-owner " + str(uid) + " -j ACCEPT 2>/dev/null")
    run("iptables -D " + IPTABLES_CHAIN_IN + " -m owner --uid-owner " + str(uid) + " ! -i lo -j ACCEPT 2>/dev/null")
    run("iptables -D " + IPTABLES_CHAIN_IN + " -m owner --uid-owner " + str(uid) + " -j ACCEPT 2>/dev/null")


def ensure_ssh_acct_chains():
    for chain, hook in [(SSH_ACCT_IN, "INPUT"), (SSH_ACCT_OUT, "OUTPUT")]:
        ok, _, _ = run("iptables -L " + chain + " -n 2>/dev/null")
        if not ok:
            run("iptables -N " + chain)
        run("iptables -D " + hook + " -j " + chain + " 2>/dev/null")
        run("iptables -I " + hook + " 1 -j " + chain)


def add_session_rules(user, ip, port, pid):
    comment = "ssh_u:" + user + " ssh_p:" + str(pid)
    run("iptables -I " + SSH_ACCT_IN + " 1 -s " + ip + " -p tcp --sport " + str(port) + " -m comment --comment " + repr(comment) + " -j ACCEPT")
    run("iptables -I " + SSH_ACCT_OUT + " 1 -d " + ip + " -p tcp --dport " + str(port) + " -m comment --comment " + repr(comment) + " -j ACCEPT")


def remove_session_rules(ip, port):
    run("iptables -D " + SSH_ACCT_IN + " -s " + ip + " -p tcp --sport " + str(port) + " -j ACCEPT 2>/dev/null")
    run("iptables -D " + SSH_ACCT_OUT + " -d " + ip + " -p tcp --dport " + str(port) + " -j ACCEPT 2>/dev/null")


def _parse_acct_chain(chain, direction, with_rule_num=False):
    out = []
    cmd = "iptables -L " + chain + " -n -v -x"
    if with_rule_num:
        cmd += " --line-numbers"
    ok, raw, _ = run(cmd + " 2>/dev/null")
    if not ok:
        return out
    for line in raw.splitlines():
        parts = line.split()
        if with_rule_num:
            if len(parts) < 3:
                continue
            try:
                rulenum = int(parts[0])
                b = int(parts[2])
            except ValueError:
                continue
        else:
            if len(parts) < 2:
                continue
            try:
                b = int(parts[1])
            except ValueError:
                continue
            rulenum = 0
        comment = re.search(r'/\*\s*(.*?)\s*\*/', line)
        if not comment:
            continue
        c = comment.group(1)
        u = re.search(r'ssh_u:(\S+)', c)
        if not u:
            continue
        user = u.group(1)
        idx = 8 if with_rule_num else 7
        if "spt:" in line:
            m = re.search(r'spt:(\d+)', line)
            ip = parts[idx] if len(parts) > idx else ""
            port = int(m.group(1)) if m else 0
        else:
            m = re.search(r'dpt:(\d+)', line)
            ip = parts[idx + 1] if len(parts) > idx + 1 else ""
            port = int(m.group(1)) if m else 0
        if ip and port:
            out.append((rulenum, b, user, ip, port, direction))
    return out


def _poll_acct_and_update():
    ensure_ssh_acct_chains()
    traffic = load_user_traffic()
    for chain, direction in [(SSH_ACCT_IN, "in"), (SSH_ACCT_OUT, "out")]:
        for _rulenum, b, user, _ip, _port, _ in _parse_acct_chain(chain, direction):
            if b > 0:
                traffic[user] = traffic.get(user, 0) + b
    save_user_traffic(traffic)
    run("iptables -Z " + SSH_ACCT_IN + " 2>/dev/null")
    run("iptables -Z " + SSH_ACCT_OUT + " 2>/dev/null")
    _enforce_all_limits_after_traffic_update(traffic)


def sync_traffic_now():
    with _traffic_lock:
        _poll_acct_and_update()


def load_user_traffic():
    if not os.path.isfile(USER_TRAFFIC_FILE):
        return {}
    try:
        with open(USER_TRAFFIC_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_user_traffic(traffic):
    try:
        with open(USER_TRAFFIC_FILE, "w") as f:
            json.dump(traffic, f, indent=0)
    except Exception:
        pass


def reset_user_traffic(username):
    with _traffic_lock:
        traffic = load_user_traffic()
        traffic[username] = 0
        save_user_traffic(traffic)
        for chain, direction in [(SSH_ACCT_IN, "in"), (SSH_ACCT_OUT, "out")]:
            for rulenum, _b, u, _ip, _port, _ in _parse_acct_chain(chain, direction, with_rule_num=True):
                if u == username:
                    run("iptables -Z " + chain + " " + str(rulenum) + " 2>/dev/null")


def load_sessions():
    if not os.path.isfile(SESSIONS_FILE):
        return {}
    try:
        with open(SESSIONS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_sessions(sessions):
    try:
        with open(SESSIONS_FILE, "w") as f:
            json.dump(sessions, f, indent=0)
    except Exception:
        pass


def _enforce_user_limit(username):
    limits = load_limits()
    raw_limit = limits.get(username)
    limit_gb = _limit_raw_to_gb(raw_limit)
    if limit_gb is None or limit_gb <= 0:
        return
    limit_bytes = limit_gb * (1024 ** 3)
    traffic = load_user_traffic()
    traffic_bytes = int(traffic.get(username, 0))
    if traffic_bytes >= limit_bytes:
        run(f"usermod -L '{username}'")
        run(f"pkill -9 -u '{username}' 2>/dev/null")


def _enforce_all_limits_after_traffic_update(traffic_dict):
    limits = load_limits()
    for username, traffic_bytes in (traffic_dict or {}).items():
        raw_limit = limits.get(username)
        limit_gb = _limit_raw_to_gb(raw_limit)
        if limit_gb is None or limit_gb <= 0:
            continue
        if int(traffic_bytes) >= limit_gb * (1024 ** 3):
            _enforce_user_limit(username)


def _ssh_tracker_loop():
    global _ssh_tracker_started
    ensure_ssh_acct_chains()
    sessions = load_sessions()
    re_accepted = re.compile(r'sshd\[(\d+)\].*Accepted\s+(?:password|publickey|keyboard-interactive)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)', re.I)
    re_closed = re.compile(r'sshd\[(\d+)\].*session\s+closed\s+for\s+user\s+(\S+)', re.I)
    log_path = AUTH_LOG
    last_poll = time.time()
    if not os.path.isfile(log_path):
        _ssh_tracker_started = True
        while True:
            time.sleep(15)
            with _traffic_lock:
                _poll_acct_and_update()
        return
    try:
        f = open(log_path, "r")
        f.seek(0, 2)
    except Exception:
        _ssh_tracker_started = True
        while True:
            time.sleep(15)
            with _traffic_lock:
                _poll_acct_and_update()
        return
    _ssh_tracker_started = True
    while True:
        line = f.readline()
        if line:
            line = line.strip()
            m = re_accepted.search(line)
            if m:
                pid, user, ip, port = m.group(1), m.group(2), m.group(3), m.group(4)
                port = int(port)
                add_session_rules(user, ip, port, pid)
                sessions[pid] = {"user": user, "ip": ip, "port": port}
                save_sessions(sessions)
                continue
            m = re_closed.search(line)
            if m:
                pid = m.group(1)
                if pid in sessions:
                    s = sessions[pid]
                    user, ip, port = s["user"], s["ip"], s["port"]
                    with _traffic_lock:
                        total = 0
                        for rulenum, b, _, sip, sport, _ in _parse_acct_chain(SSH_ACCT_IN, "in", with_rule_num=True):
                            if sip == ip and sport == port:
                                total += b
                                if rulenum > 0:
                                    run("iptables -Z " + SSH_ACCT_IN + " " + str(rulenum) + " 2>/dev/null")
                                break
                        for rulenum, b, _, dip, dport, _ in _parse_acct_chain(SSH_ACCT_OUT, "out", with_rule_num=True):
                            if dip == ip and dport == port:
                                total += b
                                if rulenum > 0:
                                    run("iptables -Z " + SSH_ACCT_OUT + " " + str(rulenum) + " 2>/dev/null")
                                break
                        if total > 0:
                            traffic = load_user_traffic()
                            traffic[user] = traffic.get(user, 0) + total
                            save_user_traffic(traffic)
                    remove_session_rules(ip, port)
                    del sessions[pid]
                    save_sessions(sessions)
                    _enforce_user_limit(user)
        else:
            time.sleep(0.5)
        if time.time() - last_poll >= 15:
            with _traffic_lock:
                _poll_acct_and_update()
            last_poll = time.time()


def start_ssh_tracker():
    global _ssh_tracker_started
    if _ssh_tracker_started:
        return
    t = threading.Thread(target=_ssh_tracker_loop, daemon=True)
    t.start()


def load_limits():
    if not os.path.isfile(LIMITS_FILE):
        return {}
    try:
        with open(LIMITS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_limits(limits):
    with open(LIMITS_FILE, "w") as f:
        json.dump(limits, f, indent=0)


def _limit_raw_to_gb(raw):
    if raw is None:
        return None
    try:
        n = int(float(raw))
        return n if n >= 1 else None
    except (TypeError, ValueError):
        return None


def run(cmd, input_text=None):
    """Run shell command; inputs must be validated by caller."""
    try:
        r = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            input=input_text,
        )
        return r.returncode == 0, (r.stdout or "").strip(), (r.stderr or "").strip()
    except Exception as e:
        return False, "", str(e)


def get_online_users():
    s = set()
    for cmd in [
        "users 2>/dev/null",
        "who /run/utmp 2>/dev/null",
        "who /var/run/utmp 2>/dev/null",
        "who 2>/dev/null",
        "w -h 2>/dev/null",
    ]:
        ok, out, _ = run(cmd)
        if not ok or not out:
            continue
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            name = parts[0]
            if name and not name.startswith("USER") and name != "NAME" and len(name) < 64:
                s.add(name)
    return s


def get_ssh_users():
    start_ssh_tracker()
    online_set = get_online_users()
    limits = load_limits()
    traffic_by_user = load_user_traffic()
    ok, out, _ = run("getent passwd")
    if not ok:
        return []
    uids = []
    user_info = {}
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _, uid, gid, gecos, home, shell = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
        try:
            uid = int(uid)
        except ValueError:
            continue
        if uid < 1000:
            continue
        if "/nologin" in shell or "/false" in shell:
            continue
        if username not in limits:
            continue
        uids.append(uid)
        user_info[uid] = {"username": username, "uid": uid, "home": home, "shell": shell}
    users = []
    for uid in sorted(uids):
        info = user_info[uid]
        username = info["username"]
        traffic_bytes = int(traffic_by_user.get(username, 0))
        raw_limit = limits.get(username)
        limit_gb = _limit_raw_to_gb(raw_limit)
        limit_bytes = (limit_gb * (1024 ** 3)) if limit_gb is not None and limit_gb > 0 else None
        over_limit = limit_bytes is not None and traffic_bytes >= limit_bytes
        if over_limit:
            run(f"usermod -L '{username}'")
            run(f"pkill -9 -u '{username}'")
        ok2, passwd_s, _ = run(f"passwd -S '{username}' 2>/dev/null")
        locked = ok2 and " L " in passwd_s
        remainder = traffic_bytes
        usage_gb = int(remainder // (1024 ** 3))
        remainder = remainder % (1024 ** 3)
        usage_mb = int(remainder // (1024 ** 2))
        remainder = remainder % (1024 ** 2)
        usage_kb = int(remainder // 1024)
        usage_b = int(remainder % 1024)
        users.append({
            "username": username,
            "uid": uid,
            "home": info["home"],
            "shell": info["shell"],
            "usage_bytes": traffic_bytes,
            "usage_gb": usage_gb,
            "usage_mb": usage_mb,
            "usage_kb": usage_kb,
            "usage_b": usage_b,
            "limit_gb": limit_gb,
            "over_limit": over_limit,
            "locked": locked,
            "online": username in online_set,
        })
    return users


def enforce_traffic_limits():
    traffic_by_user = load_user_traffic()
    limits = load_limits()
    ok, out, _ = run("getent passwd")
    if not ok:
        return
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _, uid, gid, gecos, home, shell = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
        try:
            uid = int(uid)
        except ValueError:
            continue
        if uid < 1000:
            continue
        if "/nologin" in shell or "/false" in shell:
            continue
        raw_limit = limits.get(username)
        limit_gb = _limit_raw_to_gb(raw_limit)
        if limit_gb is None or limit_gb <= 0:
            continue
        limit_bytes = limit_gb * (1024 ** 3)
        traffic_bytes = int(traffic_by_user.get(username, 0))
        if traffic_bytes >= limit_bytes:
            run(f"usermod -L '{username}'")
            run(f"pkill -9 -u '{username}'")


def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return inner


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        p = request.form.get("password", "")
        if p == get_admin_password():
            session["admin_logged_in"] = True
            return redirect(url_for("index"))
        flash("Invalid password.")
    return render_template("login.html")


# Internal routes: localhost + CRON_KEY only
@app.route("/internal/check-limits")
def internal_check_limits():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "Forbidden", 403
    if request.args.get("key") != os.environ.get("CRON_KEY", "changeme"):
        return "Forbidden", 403
    enforce_traffic_limits()
    return "OK", 200


@app.route("/internal/migrate-traffic-rules")
def internal_migrate_traffic_rules():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "Forbidden", 403
    if request.args.get("key") != os.environ.get("CRON_KEY", "changeme"):
        return "Forbidden", 403
    ok, out, _ = run("getent passwd")
    if not ok:
        return "getent failed", 500
    uids = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 3:
            continue
        try:
            uid = int(parts[2])
            if uid >= 1000 and "/nologin" not in (parts[6] or "") and "/false" not in (parts[6] or ""):
                uids.append(uid)
        except ValueError:
            continue
    for uid in uids:
        remove_user_traffic_rule(uid)
    for uid in uids:
        ensure_user_traffic_rule(uid)
        ensure_user_traffic_rule_in(uid)
    return "OK (rules migrated, counters reset)", 200


@app.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("login"))


REBOOT_CRON_MARKER = "SSH_PANEL_AUTO_REBOOT"
REBOOT_CRON_LINE = "0 5,17 * * * /sbin/reboot # " + REBOOT_CRON_MARKER


def get_ssh_port():
    ok, out, _ = run("grep -E '^Port |^#Port ' /etc/ssh/sshd_config 2>/dev/null | tail -1")
    if not ok or not out.strip():
        return 22
    line = out.strip()
    if line.startswith("#"):
        return 22
    try:
        return int(line.split()[1])
    except (IndexError, ValueError):
        return 22


def set_ssh_port(port):
    try:
        p = int(port)
        if p < 1 or p > 65535:
            return False, "Invalid port"
    except (TypeError, ValueError):
        return False, "Invalid port"
    ok, out, _ = run("sed -i 's/^#*Port .*/Port " + str(p) + "/' /etc/ssh/sshd_config")
    if not ok:
        return False, out or "Failed"
    run("ufw allow " + str(p) + "/tcp 2>/dev/null; ufw reload 2>/dev/null")
    run("firewall-cmd --permanent --add-port=" + str(p) + "/tcp 2>/dev/null; firewall-cmd --reload 2>/dev/null")
    run("systemctl restart ssh 2>/dev/null")
    run("systemctl restart sshd 2>/dev/null")
    return True, None


def get_auto_restart_enabled():
    ok, out, _ = run("crontab -l 2>/dev/null")
    return ok and REBOOT_CRON_MARKER in out


def set_auto_restart_enabled(enable):
    ok, out, _ = run("crontab -l 2>/dev/null")
    lines = []
    if ok and out:
        for line in out.splitlines():
            if REBOOT_CRON_MARKER not in line:
                lines.append(line)
    if enable:
        lines.append(REBOOT_CRON_LINE)
    path = "/tmp/ssh_panel_cron_%s" % os.getpid()
    try:
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        ok, _, err = run("crontab " + path)
        return ok, err
    finally:
        if os.path.isfile(path):
            os.unlink(path)


def load_panel_settings():
    if not os.path.isfile(PANEL_SETTINGS_FILE):
        return {}
    try:
        with open(PANEL_SETTINGS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def get_admin_password():
    s = load_panel_settings()
    p = s.get("admin_password")
    if p is not None and p != "":
        return str(p)
    return os.environ.get("ADMIN_PASSWORD", ADMIN_PASS)


def save_panel_settings(settings):
    try:
        with open(PANEL_SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=0)
        return True, None
    except Exception as e:
        return False, str(e)


def get_panel_domain():
    return (load_panel_settings().get("domain") or "").strip()


def get_panel_port():
    s = load_panel_settings()
    port = s.get("port")
    if port is not None:
        try:
            p = int(port)
            if 1 <= p <= 65535:
                return p
        except (TypeError, ValueError):
            pass
    return get_ssh_port()


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "ssh_port":
            port = request.form.get("ssh_port", "").strip()
            ok, err = set_ssh_port(port)
            if ok:
                try:
                    p = int(port)
                    if 1 <= p <= 65535:
                        s = load_panel_settings()
                        s["port"] = p
                        save_panel_settings(s)
                except (TypeError, ValueError):
                    pass
                flash("SSH port updated. Reconnect using the new port.")
            else:
                flash("SSH port failed: " + (err or "unknown"))
        elif action == "auto_restart_enable":
            ok, err = set_auto_restart_enabled(True)
            if ok:
                flash("Auto restart enabled (5 AM and 5 PM).")
            else:
                flash("Failed: " + (err or "unknown"))
        elif action == "auto_restart_disable":
            ok, err = set_auto_restart_enabled(False)
            if ok:
                flash("Auto restart disabled.")
            else:
                flash("Failed: " + (err or "unknown"))
        elif action == "save_domain":
            domain = (request.form.get("panel_domain") or "").strip()
            s = load_panel_settings()
            s["domain"] = domain
            ok, err = save_panel_settings(s)
            if ok:
                flash("Domain saved." if domain else "Domain cleared.")
            else:
                flash("Domain save failed: " + (err or "unknown"))
        elif action == "panel_password":
            current = request.form.get("current_password", "")
            new_pass = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if current != get_admin_password():
                flash("Current password is wrong.")
            elif not new_pass or len(new_pass) < 1:
                flash("New password cannot be empty.")
            elif new_pass != confirm:
                flash("New password and confirmation do not match.")
            else:
                s = load_panel_settings()
                s["admin_password"] = new_pass
                ok, err = save_panel_settings(s)
                if ok:
                    flash("Panel password updated.")
                else:
                    flash("Failed to save: " + (err or "unknown"))
        return redirect(url_for("settings"))
    ssh_port = get_ssh_port()
    auto_restart = get_auto_restart_enabled()
    panel_domain = get_panel_domain()
    return render_template("settings.html", ssh_port=ssh_port, auto_restart=auto_restart, panel_domain=panel_domain)


def _total_usage(users):
    total_bytes = sum(u["usage_bytes"] for u in users)
    gb = int(total_bytes // (1024 ** 3))
    r = total_bytes % (1024 ** 3)
    mb = int(r // (1024 ** 2))
    r = r % (1024 ** 2)
    kb = int(r // 1024)
    b = int(r % 1024)
    return {"usage_gb": gb, "usage_mb": mb, "usage_kb": kb, "usage_b": b}


@app.route("/")
@login_required
def index():
    users = get_ssh_users()
    total = _total_usage(users)
    panel_domain = get_panel_domain()
    ssh_port = get_ssh_port()
    return render_template("index.html", users=users, total=total, panel_domain=panel_domain, ssh_port=ssh_port)


def _build_npvt_payload(username):
    domain = get_panel_domain()
    if not domain:
        return None, "domain not set"
    port = get_panel_port()
    payload = {
        "sshConfigType": "SSH-Direct",
        "remarks": username,
        "sshHost": domain,
        "sshPort": port,
        "sshUsername": username,
        "sshPassword": "",
        "sni": "",
        "tlsVersion": "DEFAULT",
        "httpProxy": "",
        "authenticateProxy": False,
        "proxyUsername": "",
        "proxyPassword": "",
        "payload": "",
        "dnsTTMode": "UDP",
        "dnsServer": "",
        "nameserver": "",
        "publicKey": "",
        "udpgwPort": 7300,
        "udpgwTransparentDNS": True,
    }
    raw = json.dumps(payload, separators=(",", ":"))
    encoded = base64.b64encode(raw.encode()).decode("ascii")
    return "npvt-ssh://" + encoded, None


@app.route("/api/user/<username>/npvt-config")
@login_required
def api_npvt_config(username):
    users = {u["username"]: u for u in get_ssh_users()}
    if username not in users:
        return "not found", 404
    full_link, err = _build_npvt_payload(username)
    if err:
        return err, 400
    return Response(full_link, mimetype="text/plain")


@app.route("/api/traffic")
@login_required
def api_traffic():
    users = get_ssh_users()
    total = _total_usage(users)
    return jsonify({
        "users": [{
            "username": u["username"],
            "usage_gb": u["usage_gb"],
            "usage_mb": u["usage_mb"],
            "usage_kb": u["usage_kb"],
            "usage_b": u.get("usage_b", 0),
            "limit_gb": u["limit_gb"],
            "over_limit": u["over_limit"],
        } for u in users],
        "total": total,
    })


def format_size(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.1f} GB"


app.jinja_env.filters["format_size"] = format_size


def parse_traffic_gb(raw):
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    try:
        n = int(float(raw))
        return n if n >= 1 else None
    except (TypeError, ValueError):
        return None


@app.route("/user/add", methods=["GET", "POST"])
@login_required
def user_add():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        traffic_gb = parse_traffic_gb(request.form.get("traffic_gb"))
        if not username or not password:
            flash("Username and password required.")
            return render_template("user_add.html")
        if traffic_gb is None:
            flash("Traffic limit must be at least 1 GB (integer).")
            return render_template("user_add.html")
        if not username.isalnum() or len(username) > 32:
            flash("Username must be alphanumeric and up to 32 chars.")
            return render_template("user_add.html")
        ok, out, err = run(f"id -u '{username}' 2>/dev/null")
        if ok:
            flash("User already exists.")
            return render_template("user_add.html")
        ok, out, err = run(f"useradd -m -s /bin/bash '{username}'")
        if not ok:
            flash(f"useradd failed: {err or out}")
            return render_template("user_add.html")
        escaped = password.replace("'", "'\"'\"'")
        ok, out, err = run(f"echo '{username}:{escaped}' | chpasswd")
        if not ok:
            flash(f"Setting password failed: {err or out}")
            run(f"userdel -r '{username}' 2>/dev/null")
            return render_template("user_add.html")
        limits = load_limits()
        limits[username] = traffic_gb
        save_limits(limits)
        ok, uid_out, _ = run(f"id -u '{username}' 2>/dev/null")
        if ok and uid_out.isdigit():
            ensure_user_traffic_rule(int(uid_out))
        flash("User created.")
        return redirect(url_for("index"))
    return render_template("user_add.html")


@app.route("/user/<username>/edit", methods=["GET", "POST"])
@login_required
def user_edit(username):
    users = {u["username"]: u for u in get_ssh_users()}
    if username not in users:
        flash("User not found.")
        return redirect(url_for("index"))
    if request.method == "POST":
        new_username = request.form.get("new_username", "").strip()
        new_password = request.form.get("password", "")
        lock = request.form.get("lock") == "1"
        unlock = request.form.get("unlock") == "1"
        traffic_gb = parse_traffic_gb(request.form.get("traffic_gb"))
        if new_username and new_username != username:
            if not new_username.isalnum() or len(new_username) > 32:
                flash("New username must be alphanumeric, 1-32 chars.")
                return redirect(url_for("user_edit", username=username))
            ok, _, _ = run(f"id -u '{new_username}' 2>/dev/null")
            if ok:
                flash("New username already exists.")
                return redirect(url_for("user_edit", username=username))
            ok, out, err = run(f"usermod -l '{new_username}' -d /home/{new_username} -m '{username}'")
            if not ok:
                flash(f"Rename failed: {err or out}")
                return redirect(url_for("user_edit", username=username))
            limits = load_limits()
            limits[new_username] = limits.pop(username, limits.get(username))
            save_limits(limits)
            username = new_username
            flash("Username updated.")
        if lock:
            run(f"usermod -L '{username}'")
            flash("User locked.")
            return redirect(url_for("index"))
        if unlock:
            run(f"usermod -U '{username}'")
            flash("User unlocked.")
            return redirect(url_for("index"))
        if traffic_gb is not None:
            limits = load_limits()
            limits[username] = traffic_gb
            save_limits(limits)
            traffic_bytes = int(load_user_traffic().get(username, 0))
            limit_bytes = (traffic_gb * (1024 ** 3)) if traffic_gb > 0 else 0
            if traffic_gb > 0 and traffic_bytes < limit_bytes:
                run(f"usermod -U '{username}'")
                flash("Traffic limit updated; user unlocked.")
            else:
                flash("Traffic limit updated.")
        if new_password:
            escaped = new_password.replace("'", "'\"'\"'")
            ok, out, err = run(f"echo '{username}:{escaped}' | chpasswd")
            if ok:
                flash("Password updated.")
            else:
                flash(f"Failed: {err or out}")
        return redirect(url_for("index"))
    return render_template("user_edit.html", user=users[username])


@app.route("/user/<username>/reset-traffic", methods=["POST"])
@login_required
def user_reset_traffic(username):
    users = {u["username"]: u for u in get_ssh_users()}
    if username not in users:
        flash("User not found.")
        return redirect(url_for("index"))
    reset_user_traffic(username)
    flash("Traffic reset for %s." % username)
    return redirect(url_for("index"))


@app.route("/user/<username>/delete", methods=["POST"])
@login_required
def user_delete(username):
    users = {u["username"]: u for u in get_ssh_users()}
    if username not in users:
        flash("User not found.")
        return redirect(url_for("index"))
    uid = users[username]["uid"]
    run(f"pkill -9 -u '{username}' 2>/dev/null")
    ok, out, err = run(f"userdel -r -f '{username}'")
    if ok:
        remove_user_traffic_rule(uid)
        limits = load_limits()
        limits.pop(username, None)
        save_limits(limits)
        flash("User deleted.")
    else:
        flash(f"Delete failed: {err or out}")
    return redirect(url_for("index"))


start_ssh_tracker()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
