from flask import (
    Flask, request, jsonify, render_template_string,
    Response, send_from_directory, session, redirect, url_for
)
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
import sqlite3
import csv
import io
import os
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get(
    "INSIDERWATCH_SECRET_KEY", secrets.token_hex(32)
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "insiderwatch_fixed.db")
PROTECTED_DIR = os.path.join(BASE_DIR, "protected_files")

# ---------------------------------------------------------
# EMPLOYEES, FILES AND PERMISSIONS
# ---------------------------------------------------------

USERS = {"A": 3, "B": 2, "C": 1}

FILES = {
    "basic.txt": 1,
    "company_policies.txt": 1,
    "employee_handbook.txt": 1,
    "medium.txt": 2,
    "project_status.txt": 2,
    "it_guidelines.txt": 2,
    "confidential.txt": 3,
    "security_audit.txt": 3,
    "financial_summary.txt": 3
}

EMPLOYEE_DEMO_ACCOUNTS = {
    "EMP001": ("A", "A@12345"),
    "EMP002": ("B", "B@12345"),
    "EMP003": ("C", "C@12345"),
}

# All employees see all files in the portal.
# These permissions control what they can actually do.
FILE_PERMISSIONS = {
    filename: (
        {"A": ["read", "write", "modify"], "B": ["read", "write", "modify"], "C": ["read"]}
        if level == 1 else
        {"A": ["read", "write", "modify"], "B": ["read"], "C": []}
        if level == 2 else
        {"A": ["read", "write", "modify"], "B": [], "C": []}
    )
    for filename, level in FILES.items()
}

DEVICE_TOKENS = {
    "A": os.environ.get("INSIDERWATCH_TOKEN_A", ""),
    "B": os.environ.get("INSIDERWATCH_TOKEN_B", ""),
    "C": os.environ.get("INSIDERWATCH_TOKEN_C", "")
}

DEVICE_LAST_SEEN = {}


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

def connect_db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    os.makedirs(PROTECTED_DIR, exist_ok=True)

    # Create example files if they don't exist.
    sample_files = {
        "basic.txt": "NEXORA TECHNOLOGIES\nCompany overview and general information.\nOur mission is to build reliable digital solutions and support secure collaboration.\n",
        "company_policies.txt": "NEXORA TECHNOLOGIES - COMPANY POLICIES\n\n1. Treat colleagues respectfully.\n2. Use company systems for authorized work.\n3. Protect company information.\n4. Report suspected security issues promptly.\n",
        "employee_handbook.txt": "NEXORA TECHNOLOGIES - EMPLOYEE HANDBOOK\n\nThis handbook introduces workplace expectations, communication practices, and employee support resources. Contact Human Resources for official policy questions.\n",
        "medium.txt": "INTERNAL COMPANY INFORMATION\nThis document is intended for internal business use. Share information only with colleagues who need it for their work.\n",
        "project_status.txt": "INTERNAL PROJECT STATUS REPORT\n\nProject Orion: Planning and requirements review.\nProject Nova: Development activities in progress.\nNext step: Review milestones with the project lead.\n",
        "it_guidelines.txt": "INTERNAL IT GUIDELINES\n\nUse strong unique passwords. Lock your screen when away. Install approved updates. Do not open unexpected attachments. Report suspicious activity to IT.\n",
        "confidential.txt": "CONFIDENTIAL COMPANY INFORMATION\nAccess is restricted to employees with appropriate authorization. Do not distribute externally.\n",
        "security_audit.txt": "CONFIDENTIAL SECURITY REVIEW\n\nThis demonstration document represents an internal security review record. Detailed findings should be shared only with authorized personnel.\n",
        "financial_summary.txt": "CONFIDENTIAL FINANCIAL SUMMARY\n\nDemonstration-only financial record. Values are illustrative and are not real company financial data. Distribution is restricted.\n"
    }

    for filename, content in sample_files.items():
        path = os.path.join(PROTECTED_DIR, filename)
        if not os.path.isfile(path):
            with open(path, "w", encoding="utf-8") as file:
                file.write(content)

    with connect_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                resource TEXT NOT NULL,
                result TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        con.execute("""
            CREATE TABLE IF NOT EXISTS employee_accounts (
                employee_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        con.execute("""
            CREATE TABLE IF NOT EXISTS login_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_token TEXT UNIQUE NOT NULL,
                employee_id TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                requested_at TEXT NOT NULL,
                reviewed_at TEXT
            )
        """)

        for employee_id, (batch, password) in EMPLOYEE_DEMO_ACCOUNTS.items():
            account = con.execute(
                "SELECT employee_id FROM employee_accounts WHERE employee_id=?",
                (employee_id,)
            ).fetchone()

            if not account:
                con.execute("""
                    INSERT INTO employee_accounts
                    (employee_id, batch_id, password_hash)
                    VALUES (?, ?, ?)
                """, (
                    employee_id,
                    batch,
                    generate_password_hash(password)
                ))


def log_event(user, resource, result, reason):
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")

    with connect_db() as con:
        con.execute("""
            INSERT INTO events
            (user_id, resource, result, reason, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (str(user), str(resource), str(result), str(reason), stamp))


def log_denial(user, resource, reason, prefix=""):
    log_event(
        user,
        str(resource)[:120] or "(empty)",
        "DENIED",
        (prefix + reason)[:500]
    )


def fetch_events(limit=500):
    limit = max(1, min(int(limit), 1000))

    with connect_db() as con:
        rows = con.execute("""
            SELECT * FROM events
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


# ---------------------------------------------------------
# ACCESS CONTROL
# ---------------------------------------------------------

def evaluate(user, resource):
    user = str(user).strip().upper()
    resource = os.path.basename(str(resource)).strip().lower()

    if user not in USERS:
        return user, resource, False, "Unknown batch"

    if resource not in FILES:
        return user, resource, False, "Unknown file"

    if USERS[user] < FILES[resource]:
        return user, resource, False, (
            f"Insufficient clearance: required level {FILES[resource]}, "
            f"employee level {USERS[user]}"
        )

    return user, resource, True, "Access allowed"


def check_file_permission(batch, filename, action):
    batch = str(batch).strip().upper()
    filename = os.path.basename(str(filename)).strip().lower()
    action = str(action).strip().lower()

    if batch not in USERS or filename not in FILES:
        return False

    return action in FILE_PERMISSIONS[filename].get(batch, [])


# ---------------------------------------------------------
# INSIDERWATCH MONITORING DASHBOARD
# ---------------------------------------------------------

@app.route("/")
def home():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/health")
def health():
    return jsonify({
        "status": "online",
        "database": "connected"
    })


@app.route("/api/access", methods=["POST"])
def access():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "result": "DENIED",
            "reason": "Send valid JSON"
        }), 400

    user, resource, allowed, reason = evaluate(
        data.get("user", ""),
        data.get("file", "")
    )

    result = "ALLOWED" if allowed else "DENIED"

    if user in USERS:
        if allowed:
            log_event(user, resource, result, "[DASHBOARD TEST] " + reason)
        else:
            log_denial(user, resource, reason, "[DASHBOARD TEST] ")

    status = 200 if allowed else (
        403 if user in USERS and resource in FILES else 400
    )

    return jsonify({
        "user": user,
        "file": resource,
        "result": result,
        "reason": reason
    }), status


@app.route("/api/logs")
def logs():
    try:
        limit = request.args.get("limit", default=100, type=int)
        return jsonify(fetch_events(limit or 100))
    except (sqlite3.Error, ValueError):
        app.logger.exception("Could not fetch logs")
        return jsonify({"error": "Could not fetch logs"}), 500


@app.route("/api/summary")
def summary():
    try:
        events = fetch_events(1000)
        since = datetime.now().astimezone() - timedelta(hours=24)
        recent = []

        for event in events:
            try:
                when = datetime.fromisoformat(event["timestamp"])
                if when >= since:
                    recent.append(event)
            except (ValueError, TypeError):
                continue

        denied = sum(e["result"] == "DENIED" for e in recent)
        allowed = sum(e["result"] == "ALLOWED" for e in recent)

        denied_by_user = {}
        for event in recent:
            if event["result"] == "DENIED":
                user = event["user_id"]
                denied_by_user[user] = denied_by_user.get(user, 0) + 1

        alerts = []
        for user, count in denied_by_user.items():
            alerts.append({
                "user": user,
                "count": count,
                "severity": "HIGH" if count >= 5 else "MEDIUM",
                "message": (
                    "Repeated denied access attempts"
                    if count >= 5
                    else "Denied access attempt detected"
                )
            })

        hourly = []
        for hour in range(24):
            hour_events = []

            for event in recent:
                try:
                    event_hour = datetime.fromisoformat(
                        event["timestamp"]
                    ).hour
                    if event_hour == hour:
                        hour_events.append(event)
                except (ValueError, TypeError):
                    continue

            hourly.append({
                "hour": f"{hour:02d}:00",
                "denied": sum(e["result"] == "DENIED" for e in hour_events),
                "allowed": sum(e["result"] == "ALLOWED" for e in hour_events)
            })

        users = []
        for user in USERS:
            user_events = [e for e in recent if e["user_id"] == user]
            users.append({
                "user": user,
                "total": len(user_events),
                "denied": sum(e["result"] == "DENIED" for e in user_events)
            })

        return jsonify({
            "total": len(events),
            "events24": len(recent),
            "denied": denied,
            "allowed": allowed,
            "alerts": alerts,
            "users": users,
            "hourly": hourly
        })

    except sqlite3.Error:
        app.logger.exception("Could not calculate summary")
        return jsonify({"error": "Could not calculate summary"}), 500


@app.route("/api/demo", methods=["POST"])
def demo():
    scenarios = [
        ("A", "confidential.txt"),
        ("A", "medium.txt"),
        ("B", "medium.txt"),
        ("B", "confidential.txt"),
        ("C", "basic.txt"),
        ("C", "medium.txt"),
        ("C", "confidential.txt"),
        ("C", "confidential.txt")
    ]

    for user, resource in scenarios:
        _, _, allowed, reason = evaluate(user, resource)

        if allowed:
            log_event(user, resource, "ALLOWED", "[DEMO] " + reason)
        else:
            log_denial(user, resource, reason, "[DEMO] ")

    return jsonify({
        "message": "Demo activity generated",
        "count": len(scenarios)
    })


@app.route("/api/export")
def export_csv():
    output = io.StringIO()

    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id", "user_id", "resource", "result", "reason", "timestamp"
        ]
    )

    writer.writeheader()
    writer.writerows(fetch_events())

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=insiderwatch_events.csv"
        }
    )


# ---------------------------------------------------------
# COMPANY HOMEPAGE - SEPARATE FROM MONITORING DASHBOARD
# ---------------------------------------------------------

@app.route("/company")
def company_home():
    return render_template_string(COMPANY_HTML, file_count=len(FILES))


COMPANY_HTML = r"""
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Nexora Technologies | Company Profile</title>
<style>
:root{--ink:#f6f7ff;--muted:#b5bdd5;--dark:#0b1020;--panel:#151b31;--line:#ffffff20;--pink:#ff4d9d;--cyan:#48e5e1;--violet:#8668ff;--lime:#c5ff6a}*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:90px}body{margin:0;background:#0b1020;color:var(--ink);font-family:Inter,Segoe UI,Arial,sans-serif;line-height:1.65}a{text-decoration:none;color:inherit}.wrap{width:min(1180px,88%);margin:auto}.topline{background:linear-gradient(90deg,var(--pink),var(--violet),var(--cyan));height:4px}header{position:sticky;top:0;z-index:20;background:#0b1020eF;backdrop-filter:blur(18px);border-bottom:1px solid var(--line);padding:14px 6%;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}.brand{display:flex;align-items:center;gap:12px}.logo{width:44px;height:44px;border-radius:14px;background:linear-gradient(135deg,var(--pink),var(--violet) 55%,var(--cyan));display:grid;place-items:center;font-weight:900;font-size:22px;box-shadow:0 8px 30px #8668ff55}.brand b{font-size:15px;letter-spacing:1.2px}.brand small{display:block;color:#9da8c7;font-size:10px;letter-spacing:2px}nav{display:flex;align-items:center;gap:20px;flex-wrap:wrap}nav a{font-size:12px;color:#d4daee}nav a:hover{color:var(--cyan)}.login{padding:10px 16px;border-radius:10px;background:linear-gradient(100deg,var(--pink),var(--violet));color:white;font-weight:800;box-shadow:0 8px 24px #8668ff35}.hero{position:relative;overflow:hidden;padding:92px 6% 105px;background:radial-gradient(ellipse at 78% 15%,#6f3cb855,transparent 30%),radial-gradient(ellipse at 90% 85%,#00b8b455,transparent 32%),linear-gradient(130deg,#11172d,#18112f 56%,#102b3a)}.hero:after{content:"";position:absolute;width:440px;height:440px;border:1px solid #ffffff18;border-radius:50%;right:-100px;top:30px;box-shadow:0 0 0 45px #ffffff05,0 0 0 90px #ffffff04}.hero-inner{width:min(1180px,100%);margin:auto;position:relative;z-index:1;display:grid;grid-template-columns:1.2fr .8fr;gap:55px;align-items:center}.pill{display:inline-flex;align-items:center;gap:8px;padding:7px 12px;border:1px solid #ffffff2b;border-radius:30px;background:#ffffff0c;color:var(--cyan);font-size:10px;letter-spacing:1.6px;font-weight:800}.hero h1{font-size:clamp(39px,5.2vw,67px);line-height:1.05;letter-spacing:-2px;margin:22px 0}.gradient{background:linear-gradient(95deg,var(--pink),#b49aff,var(--cyan));-webkit-background-clip:text;background-clip:text;color:transparent}.hero p{color:#c0c8df;max-width:650px;font-size:15px;line-height:1.9}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:28px}.btn{display:inline-block;border-radius:10px;padding:13px 18px;font-size:12px;font-weight:800;background:linear-gradient(100deg,var(--pink),var(--violet));color:#fff;border:1px solid transparent;transition:.2s}.btn:hover{transform:translateY(-3px);box-shadow:0 12px 30px #8668ff3b}.btn.ghost{background:#ffffff0b;border-color:#ffffff35}.hero-card{padding:25px;border-radius:24px;border:1px solid #ffffff24;background:linear-gradient(145deg,#ffffff18,#ffffff05);box-shadow:0 25px 90px #0005;backdrop-filter:blur(12px);transform:rotate(1deg)}.hero-card-top{display:flex;justify-content:space-between;align-items:center;color:#aeb8d3;font-size:11px}.live-dot{width:8px;height:8px;background:var(--lime);display:inline-block;border-radius:50%;box-shadow:0 0 15px var(--lime)}.orbit{height:180px;display:grid;place-items:center;position:relative}.orb{width:128px;height:128px;border-radius:40px;transform:rotate(45deg);background:linear-gradient(135deg,var(--pink),var(--violet) 50%,var(--cyan));box-shadow:0 0 65px #8668ff66;display:grid;place-items:center}.orb span{transform:rotate(-45deg);font-size:48px;font-weight:900}.orbit:before,.orbit:after{content:"";position:absolute;border:1px solid #ffffff28;border-radius:50%;width:165px;height:165px}.orbit:after{width:205px;height:205px;border-style:dashed}.mini-stats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.mini{padding:13px;background:#ffffff0b;border:1px solid #ffffff12;border-radius:12px}.mini strong{font-size:22px;display:block}.mini span{font-size:10px;color:#aab5d0}.stats{width:min(1180px,88%);margin:-30px auto 0;position:relative;z-index:2;display:grid;grid-template-columns:repeat(4,1fr);gap:13px}.stat{border:1px solid #ffffff18;border-radius:16px;padding:22px;background:linear-gradient(145deg,#1c2440,#12182b);box-shadow:0 18px 45px #0003}.stat strong{font-size:29px;display:block;background:linear-gradient(90deg,var(--pink),var(--cyan));color:transparent;background-clip:text}.stat span{font-size:11px;color:#aeb8d3}.section{padding:82px 6%}.section.alt{background:linear-gradient(180deg,#10162a,#0d1324)}.head{max-width:730px;text-align:center;margin:0 auto 38px}.kicker{font-size:10px;letter-spacing:2.5px;color:var(--cyan);font-weight:900}.head h2,.about h2{font-size:clamp(28px,3.3vw,42px);line-height:1.2;letter-spacing:-1px;margin:12px 0}.head p,.muted{color:var(--muted);font-size:13px}.about{width:min(1180px,100%);margin:auto;display:grid;grid-template-columns:1fr 1fr;gap:45px;align-items:center}.about p{color:var(--muted);font-size:13px}.values{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:24px}.value{padding:16px;border-radius:13px;background:#ffffff08;border:1px solid var(--line)}.value b{display:block;font-size:13px}.value span{color:var(--muted);font-size:11px}.visual-panel{padding:26px;border-radius:22px;background:linear-gradient(135deg,#ff4d9d1b,#8668ff1b,#48e5e11b);border:1px solid #ffffff20}.visual-panel h3{margin-top:0}.timeline{display:grid;gap:14px}.timeitem{display:flex;gap:13px;align-items:flex-start;padding:14px;border-radius:12px;background:#0b102088}.num{min-width:32px;height:32px;border-radius:10px;display:grid;place-items:center;background:linear-gradient(135deg,var(--pink),var(--violet));font-weight:900}.timeitem b{font-size:13px}.timeitem p{margin:4px 0 0;font-size:11px}.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:17px;width:min(1180px,100%);margin:auto}.card{padding:24px;border:1px solid #ffffff18;border-radius:17px;background:linear-gradient(145deg,#1a2139,#11172a);transition:.25s}.card:hover{transform:translateY(-5px);border-color:#8668ff88;box-shadow:0 20px 40px #0003}.icon{width:47px;height:47px;border-radius:14px;display:grid;place-items:center;font-size:21px;background:linear-gradient(135deg,#ff4d9d2d,#8668ff35,#48e5e126);border:1px solid #ffffff18;margin-bottom:18px}.card h3{font-size:16px;margin:0 0 9px}.card p{font-size:12px;color:var(--muted);margin:0}.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}.chip{font-size:10px;color:#d9def0;background:#ffffff0a;border:1px solid #ffffff17;border-radius:30px;padding:6px 9px}.client-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;width:min(1180px,100%);margin:auto}.client{border:1px solid #ffffff19;border-radius:14px;padding:20px;background:#ffffff06}.client-logo{height:43px;width:43px;border-radius:12px;display:grid;place-items:center;font-size:16px;font-weight:900;background:linear-gradient(135deg,#ff4d9d33,#48e5e133);margin-bottom:12px}.client b{font-size:13px;display:block}.client span{font-size:10px;color:var(--muted)}.client-note{font-size:10px;color:#8d9ab9;text-align:center;margin:18px auto 0}.departments{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px;width:min(1180px,100%);margin:auto}.dept{padding:19px;border-radius:13px;background:#ffffff06;border:1px solid #ffffff17}.dept b{font-size:13px}.dept p{font-size:11px;color:var(--muted);margin:5px 0 0}.docgrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;width:min(1180px,100%);margin:auto}.doc{padding:19px;border:1px solid #ffffff19;border-radius:14px;background:#ffffff07}.dochead{display:flex;justify-content:space-between;align-items:center;gap:10px}.docicon{width:37px;height:37px;display:grid;place-items:center;border-radius:10px;background:#48e5e11a;color:var(--cyan)}.level{font-size:9px;letter-spacing:1px;padding:5px 8px;border-radius:20px;background:#8668ff25;color:#c6baff}.doc h3{font-size:13px;margin:14px 0 3px;overflow-wrap:anywhere}.doc small{font-size:10px;color:var(--cyan)}.doc p{font-size:11px;color:var(--muted)}.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;width:min(1180px,100%);margin:auto}.step{border-top:2px solid transparent;border-image:linear-gradient(90deg,var(--pink),var(--cyan)) 1;padding:20px;background:#ffffff07}.step b{font-size:13px}.step p{font-size:11px;color:var(--muted)}.cta{width:min(1180px,88%);margin:65px auto;padding:38px;border:1px solid #ffffff25;border-radius:20px;background:radial-gradient(circle at 80% 10%,#8668ff44,transparent 35%),linear-gradient(120deg,#211733,#142d3a);display:flex;align-items:center;justify-content:space-between;gap:22px;flex-wrap:wrap}.cta h2{margin:0 0 8px;font-size:27px}.cta p{color:#bdc6dd;font-size:12px;margin:0;max-width:650px}footer{border-top:1px solid var(--line);padding:32px 6%;background:#080c18}.foot{width:min(1180px,100%);margin:auto;display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap}.foot p{color:#8490ae;font-size:11px}.footlinks{display:flex;gap:17px;flex-wrap:wrap}.footlinks a{font-size:11px;color:#b8c2d9}.copyright{text-align:center;border-top:1px solid #ffffff12;padding-top:18px;margin-top:24px;font-size:10px;color:#73809f}
@media(max-width:900px){.hero-inner{grid-template-columns:1fr}.hero-card{max-width:520px}.client-grid{grid-template-columns:repeat(2,1fr)}.grid3,.docgrid,.departments{grid-template-columns:repeat(2,1fr)}.about{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}}@media(max-width:580px){header{padding:12px 5%}nav{gap:11px}nav a{font-size:11px}.hero{padding:60px 6% 75px}.hero h1{letter-spacing:-1px}.section{padding:55px 6%}.grid3,.docgrid,.departments,.steps,.client-grid{grid-template-columns:1fr}.stats{width:90%;gap:8px}.stat{padding:16px}.stat strong{font-size:24px}.values{grid-template-columns:1fr}.cta{padding:25px}.brand b{font-size:12px}}
</style></head><body><div class="topline"></div>
<header><a class="brand" href="#home"><span class="logo">N</span><span><b>NEXORA / TECHNOLOGIES</b><small>BUILD WHAT'S NEXT</small></span></a><nav><a href="#home">Home</a><a href="#about">Company</a><a href="#services">Services</a><a href="#clients">Clients</a><a href="#teams">Teams</a><a href="#resources">Resources</a><a class="login" href="/employee">Employee Login ↗</a></nav></header>
<section class="hero" id="home"><div class="hero-inner"><div><span class="pill"><span class="live-dot"></span> DIGITAL WORKPLACE · COMPANY PROFILE</span><h1>Technology with purpose. <span class="gradient">People at the centre.</span></h1><p>Nexora Technologies is a modern technology-company demonstration profile focused on digital delivery, secure collaboration and practical business solutions. Explore our capabilities, teams, sample client portfolio and employee resources.</p><div class="actions"><a class="btn" href="#services">Explore capabilities ↗</a><a class="btn ghost" href="/employee">Employee sign in</a></div><div class="chips"><span class="chip">Digital engineering</span><span class="chip">Cloud & operations</span><span class="chip">Security-first mindset</span></div></div><div class="hero-card"><div class="hero-card-top"><span>NEXORA / COMPANY SNAPSHOT</span><span><i class="live-dot"></i> PORTAL ACTIVE</span></div><div class="orbit"><div class="orb"><span>N</span></div></div><div class="mini-stats"><div class="mini"><strong>06</strong><span>Business functions</span></div><div class="mini"><strong>{{ file_count }}</strong><span>Demo documents</span></div><div class="mini"><strong>03</strong><span>Employee batches</span></div><div class="mini"><strong>360°</strong><span>Connected workplace</span></div></div></div></div></section>
<div class="stats"><div class="stat"><strong>01</strong><span>Purpose-led technology</span></div><div class="stat"><strong>06</strong><span>Cross-functional teams</span></div><div class="stat"><strong>{{ file_count }}</strong><span>Sample company documents</span></div><div class="stat"><strong>24/7</strong><span>Portal availability goal</span></div></div>
<section class="section" id="about"><div class="about"><div><span class="kicker">01 / COMPANY PROFILE</span><h2>We connect business needs with thoughtful technology.</h2><p>Nexora Technologies is presented here as a sample organization for the InsiderWatch project. The company profile illustrates how a professional business website can connect external-facing company information with a secure internal employee workspace.</p><p>Our approach centres on clear communication, dependable systems, responsible information handling and continuous improvement. Teams work together to turn requirements into useful digital experiences and maintainable solutions.</p><div class="values"><div class="value"><b>✦ Purposeful innovation</b><span>Build around real user and business needs.</span></div><div class="value"><b>⬡ Responsible security</b><span>Apply access controls and sound practices.</span></div><div class="value"><b>↗ Collaborative delivery</b><span>Keep stakeholders aligned throughout work.</span></div><div class="value"><b>◎ Continuous learning</b><span>Review, improve and share knowledge.</span></div></div></div><div class="visual-panel"><span class="kicker">OUR OPERATING MODEL</span><h3>From discovery to dependable delivery</h3><div class="timeline"><div class="timeitem"><span class="num">01</span><div><b>Understand</b><p>Clarify goals, users, requirements and risks.</p></div></div><div class="timeitem"><span class="num">02</span><div><b>Design & build</b><p>Create usable systems with quality and security in mind.</p></div></div><div class="timeitem"><span class="num">03</span><div><b>Support & improve</b><p>Monitor outcomes, gather feedback and refine solutions.</p></div></div></div></div></div></section>
<section class="section alt" id="services"><div class="head"><span class="kicker">02 / WHAT WE DO</span><h2>Capabilities built for modern teams.</h2><p>Representative service areas for this demonstration company profile.</p></div><div class="grid3"><article class="card"><div class="icon">⌘</div><h3>Digital Product Engineering</h3><p>Plan and build web applications, internal tools and customer-facing digital products with maintainability in mind.</p><div class="chips"><span class="chip">Web apps</span><span class="chip">APIs</span></div></article><article class="card"><div class="icon">☁</div><h3>Cloud & Platform Operations</h3><p>Support reliable application environments, deployment workflows, system visibility and operational readiness.</p><div class="chips"><span class="chip">Cloud</span><span class="chip">Automation</span></div></article><article class="card"><div class="icon">⬡</div><h3>Cybersecurity & Governance</h3><p>Promote access governance, security awareness, controlled information sharing and incident visibility.</p><div class="chips"><span class="chip">Access control</span><span class="chip">Monitoring</span></div></article><article class="card"><div class="icon">◈</div><h3>Data & Business Intelligence</h3><p>Organize business information into useful reports, operational views and decision-support experiences.</p><div class="chips"><span class="chip">Reporting</span><span class="chip">Analytics</span></div></article><article class="card"><div class="icon">✳</div><h3>Experience & Service Design</h3><p>Improve digital journeys through clear navigation, accessible layouts and user-centred workflows.</p><div class="chips"><span class="chip">UX</span><span class="chip">Research</span></div></article><article class="card"><div class="icon">↗</div><h3>Technology Consulting</h3><p>Help teams frame problems, prioritize improvements and plan practical implementation roadmaps.</p><div class="chips"><span class="chip">Strategy</span><span class="chip">Delivery</span></div></article></div></section>
<section class="section" id="clients"><div class="head"><span class="kicker">03 / CLIENT ECOSYSTEM</span><h2>Built around different industries.</h2><p>The following are illustrative portfolio entries for the demo website, not claims of real customers or partnerships.</p></div><div class="client-grid"><div class="client"><div class="client-logo">NF</div><b>Northstar Finance</b><span>Financial services · Sample profile</span></div><div class="client"><div class="client-logo">HM</div><b>HelioMed Systems</b><span>Healthcare technology · Sample profile</span></div><div class="client"><div class="client-logo">OV</div><b>Orbit Ventures</b><span>Business services · Sample profile</span></div><div class="client"><div class="client-logo">GS</div><b>Greenfield Supply</b><span>Logistics & operations · Sample profile</span></div><div class="client"><div class="client-logo">AP</div><b>Atlas Properties</b><span>Real estate · Sample profile</span></div><div class="client"><div class="client-logo">SP</div><b>Summit Learning</b><span>Education · Sample profile</span></div><div class="client"><div class="client-logo">BL</div><b>BluePeak Retail</b><span>Retail technology · Sample profile</span></div><div class="client"><div class="client-logo">CW</div><b>Clearwater Energy</b><span>Energy & sustainability · Sample profile</span></div></div><p class="client-note">Sample names are included for visual demonstration. Replace them with approved client names and logos before public deployment.</p></section>
<section class="section alt" id="teams"><div class="head"><span class="kicker">04 / OUR TEAMS</span><h2>Specialists working as one.</h2><p>These functions represent the people and responsibilities that support delivery.</p></div><div class="departments"><div class="dept"><b>01 · Engineering & Development</b><p>Application architecture, development, testing and technical problem-solving.</p></div><div class="dept"><b>02 · Security & Risk</b><p>Security awareness, access governance and responsible information handling.</p></div><div class="dept"><b>03 · People & Culture</b><p>Onboarding, employee experience, learning and workplace policies.</p></div><div class="dept"><b>04 · IT Operations</b><p>System availability, device support and operational readiness.</p></div><div class="dept"><b>05 · Project Delivery</b><p>Planning, milestones, stakeholder communication and delivery coordination.</p></div><div class="dept"><b>06 · Business Operations</b><p>Administration, internal processes, reporting and business support.</p></div></div></section>
<section class="section" id="resources"><div class="head"><span class="kicker">05 / EMPLOYEE RESOURCES</span><h2>Information, organized by access level.</h2><p>{{ file_count }} sample files are configured in the document library. Sign in to see the library; server-side permissions still control every file action.</p></div><div class="docgrid"><div class="doc"><div class="dochead"><span class="docicon">▤</span><span class="level">LEVEL 1</span></div><h3>Basic company information</h3><small>basic.txt</small><p>General company overview and introductory information.</p></div><div class="doc"><div class="dochead"><span class="docicon">▤</span><span class="level">LEVEL 1</span></div><h3>Company policies</h3><small>company_policies.txt</small><p>Workplace expectations and responsible system use.</p></div><div class="doc"><div class="dochead"><span class="docicon">▤</span><span class="level">LEVEL 1</span></div><h3>Employee handbook</h3><small>employee_handbook.txt</small><p>Employee guidance and internal support resources.</p></div><div class="doc"><div class="dochead"><span class="docicon">▤</span><span class="level">LEVEL 2</span></div><h3>Internal information</h3><small>medium.txt</small><p>Information intended for appropriate internal business use.</p></div><div class="doc"><div class="dochead"><span class="docicon">▤</span><span class="level">LEVEL 2</span></div><h3>Project status report</h3><small>project_status.txt</small><p>Illustrative project milestones and progress notes.</p></div><div class="doc"><div class="dochead"><span class="docicon">▤</span><span class="level">LEVEL 2</span></div><h3>IT guidelines</h3><small>it_guidelines.txt</small><p>Practical system-use guidance and security awareness.</p></div><div class="doc"><div class="dochead"><span class="docicon">▣</span><span class="level">LEVEL 3</span></div><h3>Confidential information</h3><small>confidential.txt</small><p>Restricted demonstration information for authorized employees.</p></div><div class="doc"><div class="dochead"><span class="docicon">▣</span><span class="level">LEVEL 3</span></div><h3>Security review</h3><small>security_audit.txt</small><p>Illustrative internal security review record.</p></div><div class="doc"><div class="dochead"><span class="docicon">▣</span><span class="level">LEVEL 3</span></div><h3>Financial summary</h3><small>financial_summary.txt</small><p>Demonstration-only financial record with restricted distribution.</p></div></div><div class="actions" style="justify-content:center;margin-top:28px"><a class="btn" href="/employee">Sign in to employee workspace ↗</a></div></section>
<section class="section alt" id="access"><div class="head"><span class="kicker">06 / TRUST & ACCESS</span><h2>Easy to navigate. Controlled where it matters.</h2><p>The InsiderWatch demonstration enforces permissions on the server, not just in the page design.</p></div><div class="steps"><div class="step"><b>01 · Sign in</b><p>Use an employee account to request access to the internal workspace.</p></div><div class="step"><b>02 · Find resources</b><p>Browse the file library and internal workspace sections.</p></div><div class="step"><b>03 · Verify permissions</b><p>The server checks authorization when files are read or modified and records relevant attempts.</p></div></div></section>
<div class="cta"><div><h2>Let’s build what’s next.</h2><p>Employees can sign in to the workspace to access the resources available to their account. Public visitors can continue exploring the company profile and capabilities.</p></div><a class="btn" href="/employee">Employee login ↗</a></div>
<footer><div class="foot"><div><b>NEXORA / TECHNOLOGIES</b><p>A demonstration company profile for the InsiderWatch project.</p></div><div class="footlinks"><a href="#home">Home</a><a href="#about">Company</a><a href="#services">Services</a><a href="#clients">Clients</a><a href="#teams">Teams</a><a href="/employee">Employee Login</a></div></div><div class="copyright">© 2026 Nexora Technologies · Sample company profile and illustrative client directory</div></footer>
</body></html>
"""

# ---------------------------------------------------------
# EMPLOYEE LOGIN AND ADMIN APPROVAL
# ---------------------------------------------------------

@app.route("/employee")
def employee_login_page():
    return render_template_string(EMPLOYEE_LOGIN_HTML)


@app.route("/api/employee/login", methods=["POST"])
def employee_login_request():
    data = request.get_json(silent=True) or {}

    employee_id = str(data.get("employee_id", "")).strip().upper()
    password = str(data.get("password", ""))

    with connect_db() as con:
        account = con.execute("""
            SELECT employee_id, batch_id, password_hash
            FROM employee_accounts
            WHERE employee_id = ?
        """, (employee_id,)).fetchone()

    if not account or not check_password_hash(
        account["password_hash"], password
    ):
        return jsonify({
            "error": "Invalid employee ID or password."
        }), 401

    token = secrets.token_urlsafe(32)
    now = datetime.now().astimezone().isoformat(timespec="seconds")

    with connect_db() as con:
        cursor = con.execute("""
            INSERT INTO login_requests
            (request_token, employee_id, batch_id, status, requested_at)
            VALUES (?, ?, ?, 'PENDING', ?)
        """, (token, employee_id, account["batch_id"], now))

        request_id = cursor.lastrowid

    session["login_request_id"] = request_id
    session["login_request_token"] = token

    session.pop("employee_id", None)
    session.pop("employee_batch", None)

    log_event(
        account["batch_id"],
        "employee_login",
        "PENDING",
        f"Login approval requested by {employee_id}"
    )

    return jsonify({
        "message": "Login request submitted.",
        "status": "PENDING"
    })


@app.route("/api/employee/status")
def employee_login_status():
    request_id = session.get("login_request_id")
    token = session.get("login_request_token")

    if not request_id or not token:
        return jsonify({"status": "NONE"}), 401

    with connect_db() as con:
        item = con.execute("""
            SELECT * FROM login_requests
            WHERE id = ? AND request_token = ?
        """, (request_id, token)).fetchone()

    if not item:
        return jsonify({"status": "NONE"}), 404

    if item["status"] == "APPROVED":
        session["employee_id"] = item["employee_id"]
        session["employee_batch"] = item["batch_id"]

    return jsonify({"status": item["status"]})


@app.route("/api/admin/login-requests")
def get_login_requests():
    with connect_db() as con:
        rows = con.execute("""
            SELECT id, employee_id, batch_id, status, requested_at
            FROM login_requests
            WHERE status = 'PENDING'
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

    return jsonify([dict(row) for row in rows])


@app.route("/api/admin/login-requests/<int:request_id>", methods=["POST"])
def review_login_request(request_id):
    data = request.get_json(silent=True) or {}
    decision = str(data.get("decision", "")).upper()

    if decision not in ("APPROVE", "REJECT"):
        return jsonify({
            "error": "Decision must be APPROVE or REJECT."
        }), 400

    new_status = "APPROVED" if decision == "APPROVE" else "REJECTED"
    reviewed_at = datetime.now().astimezone().isoformat(timespec="seconds")

    with connect_db() as con:
        item = con.execute("""
            SELECT employee_id, batch_id, status
            FROM login_requests
            WHERE id = ?
        """, (request_id,)).fetchone()

        if not item:
            return jsonify({"error": "Request not found."}), 404

        if item["status"] != "PENDING":
            return jsonify({"error": "Request already reviewed."}), 409

        con.execute("""
            UPDATE login_requests
            SET status = ?, reviewed_at = ?
            WHERE id = ? AND status = 'PENDING'
        """, (new_status, reviewed_at, request_id))

    log_event(
        item["batch_id"],
        "employee_login",
        new_status,
        f"Login {new_status.lower()} for {item['employee_id']}"
    )

    return jsonify({"status": new_status})


# ---------------------------------------------------------
# EMPLOYEE FILE PORTAL
# All files are displayed; actions are permission-checked.
# ---------------------------------------------------------

@app.route("/portal")
def employee_portal():
    employee_id = session.get("employee_id")
    batch = session.get("employee_batch")

    if not employee_id or batch not in USERS:
        return redirect(url_for("employee_login_page"))

    all_files = []

    for filename, level in FILES.items():
        actions = FILE_PERMISSIONS[filename].get(batch, [])

        all_files.append({
            "name": filename,
            "level": level,
            "can_read": "read" in actions,
            "can_write": "write" in actions,
            "can_modify": "modify" in actions
        })

    return render_template_string(
        EMPLOYEE_PORTAL_HTML,
        employee_id=employee_id,
        batch=batch,
        files=all_files
    )


@app.route("/employee/file/<path:filename>", methods=["GET"])
def employee_read_file(filename):
    employee_id = session.get("employee_id")
    batch = session.get("employee_batch")

    if not employee_id or batch not in USERS:
        return jsonify({"error": "Login approval required"}), 401

    filename = os.path.basename(filename).lower()

    if filename not in FILES:
        log_denial(batch, filename, "Unknown file", "[PORTAL] ")
        return "File not found", 404

    if not check_file_permission(batch, filename, "read"):
        log_denial(
            batch, filename,
            "Unauthorized read attempt",
            "[PORTAL SECURITY ALERT] "
        )

        return render_template_string("""
            <html><body style="font-family:Arial;padding:40px">
            <h2 style="color:#c62828">Access Denied</h2>
            <p>You do not have permission to read {{ filename }}.</p>
            <p>Your attempt has been recorded by InsiderWatch.</p>
            <a href="/portal">Return to File Library</a>
            </body></html>
        """, filename=filename), 403

    path = os.path.join(PROTECTED_DIR, filename)

    if not os.path.isfile(path):
        return "File not found on server", 404

    log_event(
        batch, filename, "ALLOWED",
        f"File read by {employee_id}"
    )

    return send_from_directory(
        PROTECTED_DIR, filename, as_attachment=False
    )


@app.route("/api/company/file/<path:filename>", methods=["PUT"])
def modify_company_file(filename):
    employee_id = session.get("employee_id")
    batch = session.get("employee_batch")

    if not employee_id or batch not in USERS:
        return jsonify({"error": "Login approval required"}), 401

    filename = os.path.basename(filename).lower()

    if filename not in FILES:
        return jsonify({"error": "Unknown file"}), 404

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not isinstance(
        data.get("content"), str
    ):
        return jsonify({
            "error": "Send JSON with a content field."
        }), 400

    path = os.path.join(PROTECTED_DIR, filename)

    # Existing files need modify permission.
    # Creating a missing file requires write permission.
    action = "modify" if os.path.isfile(path) else "write"

    if not check_file_permission(batch, filename, action):
        log_denial(
            batch, filename,
            f"Unauthorized {action} attempt",
            "[PORTAL SECURITY ALERT] "
        )

        return jsonify({
            "result": "DENIED",
            "message": f"You do not have {action} permission."
        }), 403

    with open(path, "w", encoding="utf-8") as file:
        file.write(data["content"])

    log_event(
        batch, filename, "ALLOWED",
        f"File {action} by {employee_id}"
    )

    return jsonify({
        "result": "ALLOWED",
        "message": "File saved successfully."
    })


@app.route("/employee/logout")
def employee_logout():
    session.clear()
    return redirect(url_for("employee_login_page"))


# ---------------------------------------------------------
# DEVICE APIs
# ---------------------------------------------------------

def authenticated_device():
    supplied = request.headers.get("X-Device-Token", "")

    if not supplied:
        return None

    for device, expected in DEVICE_TOKENS.items():
        if expected and secrets.compare_digest(supplied, expected):
            return device

    return None


@app.route("/api/device/heartbeat", methods=["POST"])
def device_heartbeat():
    device = authenticated_device()

    if device is None:
        return jsonify({"error": "Invalid or missing device token"}), 401

    now = datetime.now().astimezone().isoformat(timespec="seconds")
    DEVICE_LAST_SEEN[device] = now

    return jsonify({
        "status": "online",
        "device": device,
        "last_seen": now
    })


@app.route("/api/devices")
def connected_devices():
    now = datetime.now().astimezone()
    result = []

    for device in USERS:
        seen = DEVICE_LAST_SEEN.get(device)
        online = False

        if seen:
            try:
                online = (
                    now - datetime.fromisoformat(seen)
                ).total_seconds() <= 30
            except ValueError:
                online = False

        result.append({
            "device": device,
            "online": online,
            "last_seen": seen
        })

    return jsonify(result)


@app.route("/api/device/access", methods=["POST"])
def device_access():
    device = authenticated_device()

    if device is None:
        return jsonify({"error": "Invalid or missing device token"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Send JSON with a file field"}), 400

    resource = str(data.get("file", "")).strip().lower()
    user, resource, allowed, reason = evaluate(device, resource)

    if not allowed:
        log_denial(device, resource, reason, "[REMOTE] ")
        status = 403 if resource in FILES else 400

        return jsonify({
            "user": user,
            "file": resource,
            "result": "DENIED",
            "reason": reason
        }), status

    path = os.path.join(PROTECTED_DIR, resource)

    if not os.path.isfile(path):
        return jsonify({"error": "File missing"}), 404

    log_event(device, resource, "ALLOWED", "[REMOTE] " + reason)

    return send_from_directory(
        PROTECTED_DIR, resource, as_attachment=True
    )


# ---------------------------------------------------------
# EMPLOYEE LOGIN HTML
# ---------------------------------------------------------

EMPLOYEE_LOGIN_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nexora Technologies | Employee Access</title>
<style>
:root{--bg:#090b18;--panel:#15152b;--line:#ffffff20;--text:#f7f5ff;--muted:#b6bad3;--pink:#ff4d9d;--violet:#9065ff;--cyan:#43e6df;--lime:#c8ff6a}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:90px}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;line-height:1.6}a{text-decoration:none;color:inherit}.topline{height:4px;background:linear-gradient(90deg,var(--pink),var(--violet),var(--cyan),var(--lime))}
header{position:sticky;top:0;z-index:10;padding:13px 6%;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;background:#090b18ed;backdrop-filter:blur(16px);border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:12px}.logo{width:44px;height:44px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,var(--pink),var(--violet),var(--cyan));font-weight:900;font-size:23px;box-shadow:0 8px 28px #9065ff55}.brand b{font-size:14px;letter-spacing:1.2px}.brand small{display:block;color:#9da8c7;font-size:10px;letter-spacing:1.7px}nav{display:flex;align-items:center;gap:20px;flex-wrap:wrap}nav a{font-size:12px;color:#d4daee}nav a:hover{color:var(--cyan)}.login-top{background:linear-gradient(100deg,var(--pink),var(--violet));padding:10px 17px;border-radius:10px;color:white;font-weight:800;box-shadow:0 8px 25px #9065ff38}
.hero{padding:68px 6% 75px;background:radial-gradient(ellipse at 75% 12%,#9b42e944,transparent 32%),radial-gradient(ellipse at 90% 85%,#00c8bd33,transparent 33%),linear-gradient(125deg,#11152a,#21132e 55%,#102b38);overflow:hidden}.hero-inner{max-width:1180px;margin:auto;display:grid;grid-template-columns:1.1fr .9fr;gap:40px;align-items:center}.eyebrow{display:inline-block;padding:7px 12px;border:1px solid #ffffff2a;border-radius:30px;background:#ffffff0b;color:var(--cyan);font-size:10px;letter-spacing:1.7px;font-weight:800}.hero h1{font-size:clamp(36px,5vw,61px);line-height:1.08;letter-spacing:-1.8px;margin:20px 0}.gradient{background:linear-gradient(95deg,var(--pink),#bda3ff,var(--cyan));color:transparent;background-clip:text}.hero p{max-width:640px;color:#c3c9df;font-size:14px;line-height:1.9}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:25px}.btn{display:inline-block;padding:12px 17px;border-radius:10px;font-size:12px;font-weight:800;background:linear-gradient(100deg,var(--pink),var(--violet));color:white}.btn.secondary{background:#ffffff0b;border:1px solid #ffffff35}.showcase{padding:24px;border-radius:22px;border:1px solid #ffffff24;background:linear-gradient(145deg,#ffffff19,#ffffff05);box-shadow:0 25px 75px #0005}.showcase-top{display:flex;justify-content:space-between;color:#c1c8df;font-size:11px}.online{color:var(--lime)}.showcase h3{font-size:20px;margin:24px 0 5px}.showcase>p{font-size:12px;color:var(--muted);margin-top:0}.feature-list{display:grid;gap:10px;margin-top:18px}.feature{display:flex;align-items:center;gap:12px;padding:12px;border-radius:12px;background:#ffffff09;border:1px solid #ffffff12}.feature-icon{width:36px;height:36px;display:grid;place-items:center;border-radius:10px;background:linear-gradient(135deg,#ff4d9d35,#43e6df28);font-size:17px}.feature b{display:block;font-size:12px}.feature span{display:block;font-size:10px;color:var(--muted)}
.stats{max-width:1180px;width:88%;margin:-25px auto 0;position:relative;display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.stat{padding:18px;border:1px solid #ffffff1c;border-radius:14px;background:linear-gradient(145deg,#20213b,#13172b);box-shadow:0 15px 35px #0003}.stat strong{display:block;font-size:25px;background:linear-gradient(90deg,var(--pink),var(--cyan));color:transparent;background-clip:text}.stat span{font-size:10px;color:var(--muted)}section.content{padding:65px 6%}.heading{text-align:center;max-width:720px;margin:0 auto 30px}.heading small{color:var(--cyan);font-size:10px;font-weight:900;letter-spacing:2px}.heading h2{font-size:clamp(26px,3vw,38px);margin:8px 0}.heading p{font-size:13px;color:var(--muted)}.about-grid{max-width:1180px;margin:auto;display:grid;grid-template-columns:1fr 1fr;gap:28px;align-items:stretch}.panel{padding:26px;border:1px solid var(--line);border-radius:17px;background:linear-gradient(145deg,#1b2038,#111629)}.panel h3{margin-top:0}.panel p,.panel li{color:var(--muted);font-size:12px}.panel ul{padding-left:19px}.grid3{max-width:1180px;margin:auto;display:grid;grid-template-columns:repeat(3,1fr);gap:15px}.service{padding:22px;border:1px solid var(--line);border-radius:15px;background:#ffffff07}.service .ico{width:42px;height:42px;display:grid;place-items:center;border-radius:12px;background:linear-gradient(135deg,#ff4d9d35,#9065ff35,#43e6df2b);font-size:20px}.service h3{font-size:14px;margin:15px 0 7px}.service p{font-size:11px;color:var(--muted)}.clients{max-width:1180px;margin:auto;display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.client{padding:17px;border:1px solid var(--line);border-radius:13px;background:#ffffff06}.client-mark{width:37px;height:37px;display:grid;place-items:center;border-radius:11px;background:linear-gradient(135deg,#ff4d9d35,#43e6df35);font-weight:900;margin-bottom:9px}.client b{display:block;font-size:12px}.client span{font-size:10px;color:var(--muted)}.demo-note{text-align:center;color:#8d97b5;font-size:10px;margin-top:16px}.login-area{background:radial-gradient(ellipse at 20% 50%,#5b2b7d2b,transparent 45%),#0d1122}.login-grid{max-width:1180px;margin:auto;display:grid;grid-template-columns:1fr 430px;gap:35px;align-items:center}.login-copy h2{font-size:clamp(28px,4vw,43px);line-height:1.2;margin:12px 0}.login-copy p{color:var(--muted);font-size:13px;max-width:620px}.login-bullets{display:grid;gap:12px;margin-top:22px}.bullet{display:flex;gap:10px;font-size:12px;color:#d7d9eb}.tick{color:var(--lime);font-weight:900}.login-card{padding:29px;border-radius:20px;background:linear-gradient(145deg,#1c2038,#111627);border:1px solid #ffffff28;box-shadow:0 25px 70px #0005;scroll-margin-top:105px}.login-card .mini-label{color:var(--cyan);font-size:10px;font-weight:900;letter-spacing:2px}.login-card h2{font-size:25px;margin:7px 0}.login-card>p{color:var(--muted);font-size:12px}.field{margin-top:16px}.field label{display:block;font-size:11px;color:#dce0f1;margin-bottom:7px}.field input{width:100%;padding:13px 14px;border:1px solid #ffffff27;border-radius:9px;background:#090d19;color:white;font-size:14px;outline:none}.field input:focus{border-color:var(--cyan);box-shadow:0 0 0 3px #43e6df1c}.submit{width:100%;padding:13px;margin-top:18px;border:0;border-radius:9px;background:linear-gradient(100deg,var(--pink),var(--violet));color:white;font-size:13px;font-weight:900;cursor:pointer}.submit:hover{filter:brightness(1.1)}#message{font-size:12px;line-height:1.6;margin-top:14px;color:var(--cyan);overflow-wrap:anywhere}.hint{font-size:10px!important;color:#8994b4!important;margin-top:13px}.hint a{color:var(--cyan);text-decoration:underline}.login-back{display:inline-block;margin-top:15px;color:var(--cyan);font-size:11px}.steps{max-width:1180px;margin:auto;display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.step{padding:20px;border-top:2px solid var(--violet);border-radius:0 0 13px 13px;background:#ffffff07}.step strong{font-size:13px}.step p{font-size:11px;color:var(--muted)}footer{padding:28px 6%;border-top:1px solid var(--line);background:#080a14}.foot{max-width:1180px;margin:auto;display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap}.foot b{font-size:13px;letter-spacing:1px}.foot p{font-size:10px;color:#8d97b5}.footlinks{display:flex;gap:16px;flex-wrap:wrap}.footlinks a{font-size:11px;color:#c4cbe0}.copyright{text-align:center;border-top:1px solid #ffffff12;padding-top:16px;margin-top:18px;color:#737e9e;font-size:10px}
@media(max-width:850px){.hero-inner,.about-grid,.login-grid{grid-template-columns:1fr}.showcase{max-width:600px}.grid3{grid-template-columns:repeat(2,1fr)}.clients{grid-template-columns:repeat(2,1fr)}.login-grid{gap:25px}.login-card{max-width:520px;width:100%}}@media(max-width:580px){header{padding:12px 4%}nav{gap:12px}.hero{padding:48px 5% 60px}.stats{grid-template-columns:repeat(2,1fr);width:90%}section.content{padding:48px 5%}.grid3,.steps{grid-template-columns:1fr}.clients{grid-template-columns:repeat(2,1fr)}.login-card{padding:22px}.brand b{font-size:12px}}
</style>
</head>
<body>
<div class="topline"></div>
<header>
 <a class="brand" href="/company"><span class="logo">N</span><span><b>NEXORA TECHNOLOGIES</b><small>INNOVATION · TRUST · SECURITY</small></span></a>
 <nav><a href="/company">Company Home</a><a href="#about">About</a><a href="#services">Services</a><a href="#clients">Clients</a><a href="#how">How it works</a><a class="login-top" href="#login">Employee Login ↗</a></nav>
</header>
<section class="hero"><div class="hero-inner"><div><span class="eyebrow">WELCOME TO NEXORA TECHNOLOGIES</span><h1>People, technology<br>and trust — <span class="gradient">working together.</span></h1><p>Nexora Technologies brings teams, business resources and company information together in one connected workplace. Our InsiderWatch-protected employee portal helps staff access work documents while respecting each account's assigned permissions.</p><div class="actions"><a class="btn" href="#login">Sign in to your workspace ↗</a><a class="btn secondary" href="#about">Explore our company</a></div></div><div class="showcase"><div class="showcase-top"><span>THE NEXORA WORKPLACE</span><span class="online">● PORTAL OVERVIEW</span></div><h3>Your work, organized.</h3><p>A single place for essential employee resources.</p><div class="feature-list"><div class="feature"><div class="feature-icon">▤</div><div><b>Company documents</b><span>Policies, project files and team resources</span></div></div><div class="feature"><div class="feature-icon">◎</div><div><b>Employee workspace</b><span>Personal batch details and quick navigation</span></div></div><div class="feature"><div class="feature-icon">⬡</div><div><b>Monitored access</b><span>Permission checks and security event logging</span></div></div><div class="feature"><div class="feature-icon">◇</div><div><b>Business directory</b><span>Illustrative client and department listings</span></div></div></div></div></div></section>
<div class="stats"><div class="stat"><strong>9</strong><span>Sample work documents</span></div><div class="stat"><strong>3</strong><span>Employee access batches</span></div><div class="stat"><strong>6</strong><span>Business functions</span></div><div class="stat"><strong>24/7</strong><span>Digital access goal</span></div></div>
<section class="content" id="about"><div class="heading"><small>WHO WE ARE</small><h2>A connected company, built for modern work</h2><p>Company profile, workplace principles and the tools that help our teams work responsibly.</p></div><div class="about-grid"><div class="panel"><h3>About Nexora Technologies</h3><p>Nexora Technologies is presented here as a modern technology company profile for the InsiderWatch demonstration project. This portal brings together general company information, work resources and employee access in one navigable experience.</p><p>InsiderWatch is the security-monitoring component of this demonstration. It records relevant access events and applies file permissions on the server so that showing a filename does not automatically grant permission to open or change it.</p><h3>Our mission</h3><p>Make work information easier to find while supporting thoughtful, accountable handling of company data.</p></div><div class="panel"><h3>Our workplace principles</h3><ul><li>Protect internal documents with account-based permissions.</li><li>Make employee resources easy to navigate.</li><li>Keep access decisions on the server, not only in the interface.</li><li>Encourage responsible handling of business information.</li><li>Record security-relevant actions for monitoring and review.</li></ul></div></div></section>
<section class="content" id="services" style="background:#101326"><div class="heading"><small>WHAT WE DO</small><h2>Services and capabilities</h2><p>Example service areas for the company profile. These descriptions are demo content, not a claim of real-world contracts.</p></div><div class="grid3"><article class="service"><div class="ico">✦</div><h3>Software & Digital Solutions</h3><p>Digital workflows, application development and tools designed around everyday business needs.</p></article><article class="service"><div class="ico">⬡</div><h3>Security Monitoring</h3><p>Access-event visibility, activity monitoring and permission-based document handling through InsiderWatch.</p></article><article class="service"><div class="ico">▤</div><h3>Document Management</h3><p>Organized work files, company policies, project updates and employee reference materials.</p></article><article class="service"><div class="ico">◎</div><h3>IT Operations</h3><p>Technical support practices, system guidance and structured handling of access requests.</p></article><article class="service"><div class="ico">◇</div><h3>Business Analytics</h3><p>Example reporting workflows for organizing business information and reviewing operational activity.</p></article><article class="service"><div class="ico">↗</div><h3>Employee Experience</h3><p>A central employee hub with clear navigation between documents, directory information and policies.</p></article></div></section>
<section class="content" id="clients"><div class="heading"><small>CLIENT DIRECTORY</small><h2>Client industries and relationships</h2><p>Sample client cards for demonstrating the directory layout and navigation.</p></div><div class="clients"><div class="client"><div class="client-mark">NF</div><b>Northstar Finance</b><span>Financial services · Sample profile</span></div><div class="client"><div class="client-mark">HM</div><b>HelioMed Systems</b><span>Healthcare technology · Sample profile</span></div><div class="client"><div class="client-mark">OV</div><b>Orbit Ventures</b><span>Business services · Sample profile</span></div><div class="client"><div class="client-mark">GS</div><b>Greenfield Supply</b><span>Logistics · Sample profile</span></div><div class="client"><div class="client-mark">AP</div><b>Atlas Properties</b><span>Real estate · Sample profile</span></div><div class="client"><div class="client-mark">SL</div><b>Summit Learning</b><span>Education · Sample profile</span></div><div class="client"><div class="client-mark">BP</div><b>BluePeak Retail</b><span>Retail technology · Sample profile</span></div><div class="client"><div class="client-mark">CE</div><b>Clearwater Energy</b><span>Energy · Sample profile</span></div></div><p class="demo-note">These client names are fictional examples for a project demonstration, not verified customers.</p></section>
<section class="content" style="background:#101326"><div class="heading"><small>TEAMS & DEPARTMENTS</small><h2>People behind the work</h2><p>A sample organization structure for navigating common business functions.</p></div><div class="grid3"><article class="service"><div class="ico">⌘</div><h3>Technology & Development</h3><p>Applications, internal tools and technical delivery.</p></article><article class="service"><div class="ico">⬡</div><h3>Information Security</h3><p>Access controls, security awareness and incident review.</p></article><article class="service"><div class="ico">♡</div><h3>People & Culture</h3><p>Employee support, onboarding and workplace resources.</p></article><article class="service"><div class="ico">▦</div><h3>Business Operations</h3><p>Project coordination and operational documentation.</p></article><article class="service"><div class="ico">▤</div><h3>Finance & Administration</h3><p>Administrative resources and controlled financial documents.</p></article><article class="service"><div class="ico">◉</div><h3>Client Services</h3><p>Client directory information and relationship coordination.</p></article></div></section>
<section class="content" id="how"><div class="heading"><small>EMPLOYEE ACCESS</small><h2>How the employee portal works</h2><p>Access follows a simple request, approval and permission-checking process.</p></div><div class="steps"><div class="step"><strong>01 · Request access</strong><p>Enter your assigned employee ID and password in the sign-in panel below.</p></div><div class="step"><strong>02 · Monitoring approval</strong><p>Your login request waits for approval through the monitoring workflow.</p></div><div class="step"><strong>03 · Open your workspace</strong><p>After approval, use the employee hub to browse documents and available resources. Server-side permissions still apply.</p></div></div></section>
<section class="content login-area" id="login"><div class="login-grid"><div class="login-copy"><span class="eyebrow">EMPLOYEE ACCESS PORTAL</span><h2>Your next task starts in <span class="gradient">your workspace.</span></h2><p>Sign in with your employee credentials to request access. Once approved, your workspace includes employee details, document sections, client directory, announcements and policies.</p><div class="login-bullets"><div class="bullet"><span class="tick">✓</span><span>Browse the company document library and project resources.</span></div><div class="bullet"><span class="tick">✓</span><span>View your employee ID and assigned batch in the workspace.</span></div><div class="bullet"><span class="tick">✓</span><span>Access is checked by the server for each protected file action.</span></div><div class="bullet"><span class="tick">✓</span><span>Login requests are subject to monitoring approval.</span></div></div></div><div class="login-card"><span class="mini-label">NEXORA · SECURE SIGN IN</span><h2>Employee login</h2><p>Use the credentials assigned to your employee account.</p><form id="loginForm"><div class="field"><label for="employeeId">Employee ID</label><input id="employeeId" name="employeeId" placeholder="e.g. EMP001" autocomplete="username" required></div><div class="field"><label for="password">Password</label><input id="password" name="password" type="password" placeholder="Enter your password" autocomplete="current-password" required></div><button class="submit" type="submit">Request login access ↗</button></form><div id="message" role="status" aria-live="polite"></div><p class="hint">Demo accounts, if enabled in your local project: EMP001 / A@12345 · EMP002 / B@12345 · EMP003 / C@12345. Login still requires monitoring approval.</p><a class="login-back" href="/company">← Return to public company profile</a></div></div></section>
<footer><div class="foot"><div><b>NEXORA TECHNOLOGIES</b><p>Innovation · Trust · Security</p><p>Company information and employee resources portal.</p></div><div class="footlinks"><a href="/company">Company Home</a><a href="#about">About</a><a href="#services">Services</a><a href="#clients">Client Directory</a><a href="#login">Employee Login</a><a href="/">Security Dashboard</a></div></div><div class="copyright">© 2026 Nexora Technologies · InsiderWatch security-monitoring demonstration. Company, service and client details on this page are illustrative.</div></footer>
<script>
const form=document.getElementById("loginForm");
const message=document.getElementById("message");
let poller=null;
form.addEventListener("submit",async function(event){
 event.preventDefault();
 if(poller)clearInterval(poller);
 message.textContent="Sending login request...";
 try{
  const response=await fetch("/api/employee/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({employee_id:document.getElementById("employeeId").value,password:document.getElementById("password").value})});
  const data=await response.json();
  if(!response.ok){message.textContent=data.error||"Login failed. Check your credentials.";return;}
  message.textContent="Request sent. Waiting for monitoring approval...";
  poller=setInterval(async()=>{try{const r=await fetch("/api/employee/status");const s=await r.json();if(s.status==="APPROVED"){clearInterval(poller);window.location.href="/portal";}else if(s.status==="REJECTED"){clearInterval(poller);message.textContent="Your login request was rejected. Contact your administrator.";}}catch(error){message.textContent="Unable to check approval status. Please keep this page open.";}},2000);
 }catch(error){message.textContent="Cannot connect to the server. Please try again.";}
});
</script>
</body>
</html>
"""


# ---------------------------------------------------------
# EMPLOYEE FILE PORTAL HTML
# All files are visible; restricted files remain inaccessible.
# ---------------------------------------------------------

EMPLOYEE_PORTAL_HTML = r"""
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Nexora Workspace | Employee Hub</title>
<style>
:root{--bg:#0a0d1a;--panel:#141a2d;--line:#ffffff18;--text:#f4f5ff;--muted:#a6afca;--pink:#ff4d9d;--violet:#8668ff;--cyan:#48e5e1;--lime:#c5ff6a}*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:90px}body{margin:0;background:radial-gradient(ellipse at 90% 0,#42245c55,transparent 28%),var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif}a{color:inherit;text-decoration:none}header{position:sticky;top:0;z-index:10;padding:15px 5%;display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap;background:#0a0d1aeF;backdrop-filter:blur(15px);border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:10px}.logo{height:39px;width:39px;display:grid;place-items:center;border-radius:12px;background:linear-gradient(135deg,var(--pink),var(--violet),var(--cyan));font-weight:900}.brand b{font-size:14px;letter-spacing:1px}.brand small{display:block;color:var(--muted);font-size:10px}.user{font-size:12px;color:var(--muted)}.user b{color:var(--cyan)}.logout{color:#fff;background:linear-gradient(100deg,var(--pink),var(--violet));padding:9px 13px;border-radius:8px;margin-left:10px;font-weight:700}.nav{display:flex;gap:8px;padding:12px 5%;overflow-x:auto;border-bottom:1px solid var(--line);background:#101529}.nav a{white-space:nowrap;padding:9px 13px;border-radius:8px;font-size:12px;color:#c4cce1}.nav a:hover{background:#ffffff12;color:var(--cyan)}main{max-width:1300px;margin:auto;padding:30px 5% 60px}.welcome{padding:29px;border-radius:20px;background:radial-gradient(circle at 85% 10%,#8668ff55,transparent 35%),linear-gradient(120deg,#211731,#142d3a);border:1px solid #ffffff1c;display:flex;justify-content:space-between;align-items:center;gap:25px;flex-wrap:wrap}.eyebrow{color:var(--cyan);font-size:10px;font-weight:800;letter-spacing:2px}.welcome h1{font-size:clamp(26px,4vw,38px);margin:8px 0}.welcome p{color:#bdc6df;font-size:13px;margin:0;max-width:650px}.pill{padding:8px 12px;border-radius:30px;background:#ffffff12;border:1px solid #ffffff25;font-size:11px}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:18px 0 32px}.metric{padding:18px;border:1px solid var(--line);border-radius:13px;background:linear-gradient(145deg,#191f36,#111628)}.metric strong{display:block;font-size:25px;background:linear-gradient(90deg,var(--pink),var(--cyan));color:transparent;background-clip:text}.metric span{font-size:11px;color:var(--muted)}.section{margin-top:34px;scroll-margin-top:130px}.section-title{display:flex;align-items:end;justify-content:space-between;gap:15px;flex-wrap:wrap;margin-bottom:16px}.section-title h2{margin:0;font-size:22px}.section-title p{margin:5px 0 0;color:var(--muted);font-size:12px}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.card{background:linear-gradient(145deg,#171e33,#111626);border:1px solid var(--line);border-radius:14px;padding:19px;min-width:0}.card h3{font-size:14px;margin:0 0 7px}.card p{font-size:12px;color:var(--muted);line-height:1.7}.badge{display:inline-block;border-radius:30px;background:#8668ff26;color:#cfc4ff;padding:5px 8px;font-size:10px;margin-bottom:10px}.files{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.file-name{overflow-wrap:anywhere;font-size:14px}.level{font-size:10px;color:var(--cyan)}.open,button{display:inline-block;padding:9px 12px;border:1px solid #48e5e155;background:#48e5e114;color:#76f0ec;border-radius:8px;cursor:pointer;font-size:11px;font-weight:700;margin:4px 5px 0 0}.open:hover,button:hover{background:#48e5e126}.editor{display:none;margin-top:13px}.editor textarea{width:100%;min-height:120px;background:#080d17;color:white;border:1px solid #ffffff25;border-radius:8px;padding:10px;margin:8px 0;font-family:inherit}.denied{color:#ff83b4}.clients{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.client{padding:17px;border:1px solid var(--line);border-radius:12px;background:#ffffff06}.client-mark{height:36px;width:36px;display:grid;place-items:center;border-radius:11px;background:linear-gradient(135deg,#ff4d9d33,#48e5e133);font-weight:900;margin-bottom:10px}.client b{font-size:12px;display:block}.client span{font-size:10px;color:var(--muted)}.notice{padding:16px;border-radius:12px;border:1px solid #8668ff55;background:#8668ff12;color:#cbd0e9;font-size:12px}.resource-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.resource{padding:16px;border:1px solid var(--line);border-radius:12px;background:#ffffff06}.resource b{font-size:12px}.resource p{font-size:11px;color:var(--muted);margin:5px 0 0}footer{text-align:center;padding:25px;color:#7f8baa;border-top:1px solid var(--line);font-size:11px}
@media(max-width:900px){.metrics{grid-template-columns:repeat(2,1fr)}.cards,.files{grid-template-columns:repeat(2,minmax(0,1fr))}.clients{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){.cards,.files,.clients,.resource-list{grid-template-columns:1fr}.welcome{padding:22px}.metrics{gap:8px}.metric{padding:13px}main{padding-left:4%;padding-right:4%}}
</style></head><body>
<header><a class="brand" href="/company"><span class="logo">N</span><span><b>NEXORA WORKSPACE</b><small>EMPLOYEE HUB · INSIDERWATCH PROTECTED</small></span></a><div class="user">Signed in as <b>{{ employee_id }}</b> · Batch {{ batch }} <a class="logout" href="/employee/logout">Sign out ↗</a></div></header>
<nav class="nav"><a href="#overview">Overview</a><a href="#documents">Document library</a><a href="#clients">Client directory</a><a href="#announcements">Announcements</a><a href="#policies">Policies & support</a><a href="/company">Public company site ↗</a></nav>
<main><section class="welcome" id="overview"><div><span class="eyebrow">YOUR DIGITAL WORKPLACE</span><h1>Welcome back, {{ employee_id }}.</h1><p>Your workspace brings company documents, business information and internal resources together. Choose a section below to get started.</p></div><span class="pill">● Session authenticated</span></section>
<div class="metrics"><div class="metric"><strong>{{ files|length }}</strong><span>Documents in library</span></div><div class="metric"><strong>{{ batch }}</strong><span>Your employee batch</span></div><div class="metric"><strong>06</strong><span>Business functions</span></div><div class="metric"><strong>24/7</strong><span>Workspace availability goal</span></div></div>
<section class="section"><div class="section-title"><div><h2>Quick access</h2><p>Jump to a common workspace area.</p></div></div><div class="cards"><a class="card" href="#documents"><span class="badge">DOCUMENTS</span><h3>Company document library →</h3><p>Browse all listed files. Read and edit actions are checked by the server.</p></a><a class="card" href="#clients"><span class="badge">DIRECTORY</span><h3>Client directory →</h3><p>View illustrative client profiles and the industries represented in this demo workspace.</p></a><a class="card" href="#policies"><span class="badge">SUPPORT</span><h3>Policies & help →</h3><p>Review basic workplace and IT guidance and find the appropriate support team.</p></a></div></section>
<section class="section" id="documents"><div class="section-title"><div><h2>Document library</h2><p>All filenames remain visible; access to each file is enforced when you open or change it.</p></div><span class="pill">{{ files|length }} documents</span></div><div class="files">{% for file in files %}<article class="card"><span class="badge">LEVEL {{ file.level }}</span><h3 class="file-name">{{ file.name }}</h3><p class="level">Company document · InsiderWatch monitored</p><a class="open" href="/employee/file/{{ file.name }}">Open document ↗</a>{% if file.can_modify %}<button onclick="showEditor('{{ file.name }}')">Edit file</button><div class="editor" id="editor-{{ file.name }}"><textarea id="content-{{ file.name }}" placeholder="Enter updated file content"></textarea><button onclick="saveFile('{{ file.name }}')">Save changes</button><p id="message-{{ file.name }}"></p></div>{% endif %}</article>{% endfor %}</div></section>
<section class="section" id="clients"><div class="section-title"><div><h2>Client directory</h2><p>Illustrative sample profiles for the project demo — not real client relationships.</p></div></div><div class="clients"><div class="client"><div class="client-mark">NF</div><b>Northstar Finance</b><span>Financial services</span></div><div class="client"><div class="client-mark">HM</div><b>HelioMed Systems</b><span>Healthcare technology</span></div><div class="client"><div class="client-mark">OV</div><b>Orbit Ventures</b><span>Business services</span></div><div class="client"><div class="client-mark">GS</div><b>Greenfield Supply</b><span>Logistics & operations</span></div><div class="client"><div class="client-mark">AP</div><b>Atlas Properties</b><span>Real estate</span></div><div class="client"><div class="client-mark">SL</div><b>Summit Learning</b><span>Education</span></div><div class="client"><div class="client-mark">BP</div><b>BluePeak Retail</b><span>Retail technology</span></div><div class="client"><div class="client-mark">CE</div><b>Clearwater Energy</b><span>Energy & sustainability</span></div></div></section>
<section class="section" id="announcements"><div class="section-title"><div><h2>Announcements & updates</h2><p>General demo notices for the employee workspace.</p></div></div><div class="cards"><article class="card"><span class="badge">SECURITY</span><h3>Keep your account secure</h3><p>Use a strong password, avoid sharing credentials and sign out when using a shared computer.</p></article><article class="card"><span class="badge">IT OPERATIONS</span><h3>Report unusual activity</h3><p>Report unexpected prompts, suspicious attachments or unusual access behaviour to the IT/security team.</p></article><article class="card"><span class="badge">DOCUMENTS</span><h3>Check document permissions</h3><p>A file appearing in the directory does not mean your account is allowed to read or edit it.</p></article></div></section>
<section class="section" id="policies"><div class="section-title"><div><h2>Policies & support</h2><p>Quick guidance for common employee questions.</p></div></div><div class="resource-list"><div class="resource"><b>IT support</b><p>For access problems or system issues, contact your organization’s designated IT support contact.</p></div><div class="resource"><b>Information security</b><p>Follow approved access procedures and report suspected unauthorized access promptly.</p></div><div class="resource"><b>Document handling</b><p>Use company documents only for authorized work and do not share restricted material externally.</p></div><div class="resource"><b>Employee policies</b><p>Refer to employee_handbook.txt and company_policies.txt where your account has permission to open them.</p></div></div><div class="notice" style="margin-top:15px">This is a demonstration workspace. Client entries and announcements are illustrative sample content. Actual document access is determined by your assigned permissions.</div></section>
</main><footer>Nexora Technologies Employee Hub · Powered by InsiderWatch Security Monitoring</footer>
<script>
function showEditor(name){const editor=document.getElementById("editor-"+name);editor.style.display=editor.style.display==="block"?"none":"block";}
async function saveFile(name){const content=document.getElementById("content-"+name).value;const message=document.getElementById("message-"+name);message.textContent="Saving...";try{const response=await fetch("/api/company/file/"+encodeURIComponent(name),{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({content:content})});const data=await response.json();message.textContent=data.message||data.error||"Finished.";if(!response.ok)message.className="denied";}catch(error){message.textContent="Could not connect to the server.";}}
</script></body></html>
"""

# ---------------------------------------------------------
# EXISTING MONITORING DASHBOARD HTML
# ---------------------------------------------------------

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>InsiderWatch | Security Operations Center</title>
<style>
:root{--bg:#080b16;--side:#0d1222;--panel:#121a2d;--panel2:#171f35;--line:#29334e;--text:#f3f5ff;--muted:#9aa7c3;--cyan:#45e6e0;--pink:#ff4f9a;--purple:#9c7bff;--green:#6cf0b5;--red:#ff627e;--amber:#ffc66d}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:90px}body{margin:0;background:radial-gradient(ellipse at 80% 0%,#30205244,transparent 32%),var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif}button,input,select{font:inherit}a{color:var(--cyan);text-decoration:none}.layout{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}aside{position:sticky;top:0;height:100vh;overflow:auto;padding:25px 17px;background:#0b1020;border-right:1px solid var(--line)}.brand{display:flex;gap:11px;align-items:center;padding:0 8px}.brandmark{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;font-weight:900;font-size:20px;background:linear-gradient(135deg,var(--pink),var(--purple),var(--cyan));box-shadow:0 8px 25px #9c7bff33}.brand strong{font-size:17px;letter-spacing:.6px}.brand strong span{color:var(--cyan)}.sub{font-size:10px;letter-spacing:1.6px;color:var(--muted);margin:6px 8px 28px}.navlabel{font-size:10px;letter-spacing:2px;color:#657493;margin:24px 10px 9px}.nav{display:flex;align-items:center;gap:11px;width:100%;text-align:left;padding:12px 13px;border-radius:10px;margin:4px 0;background:transparent;border:1px solid transparent;color:#aab5ce;cursor:pointer;font-size:12px}.nav:hover{background:#ffffff08;color:white}.nav.active{background:linear-gradient(100deg,#ff4f9a20,#9c7bff22,#45e6e015);color:white;border-color:#9c7bff55}.nav .ico{width:22px;text-align:center;font-size:16px;color:var(--cyan)}.sidebottom{margin-top:32px;border:1px solid var(--line);border-radius:12px;padding:14px;background:#ffffff04;font-size:11px;color:var(--muted);line-height:1.8}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 10px #6cf0b5;margin-right:6px}main{min-width:0}header{position:sticky;top:0;z-index:10;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;padding:18px 28px;background:#080b16eF;backdrop-filter:blur(16px);border-bottom:1px solid var(--line)}header b{font-size:12px;letter-spacing:1.2px}header .muted{font-size:11px;color:var(--muted);margin-top:4px}.headright{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.statuspill{border:1px solid #6cf0b544;color:var(--green);padding:8px 11px;border-radius:30px;font-size:10px;background:#6cf0b50b}.content{padding:25px;max-width:1800px;margin:auto}.page{display:none;animation:fade .22s ease}.page.active{display:block}@keyframes fade{from{opacity:.45;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}.pagetitle{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:19px}.eyebrow{font-size:10px;letter-spacing:2px;color:var(--cyan);font-weight:800}.pagetitle h1{font-size:26px;letter-spacing:-.6px;margin:7px 0}.pagetitle p{font-size:12px;color:var(--muted);margin:0}.actions,.formrow{display:flex;gap:9px;flex-wrap:wrap}button,select,input{background:#171f35;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:10px 12px;outline:none}button{cursor:pointer;font-size:11px}button:hover{border-color:var(--cyan)}button:disabled{opacity:.5;cursor:wait}.primary{background:linear-gradient(100deg,#ff4f9a,#9c7bff);border:0;color:white;font-weight:800}.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:16px 0}.metric,.panel{min-width:0;border:1px solid var(--line);border-radius:15px;background:linear-gradient(145deg,#151d32,#101727);padding:18px;box-shadow:0 12px 35px #00000012}.metric{position:relative;overflow:hidden}.metric:after{content:"";position:absolute;width:90px;height:90px;border-radius:50%;right:-35px;top:-35px;background:var(--glow,#45e6e0);opacity:.08;filter:blur(2px)}.metric .label{font-size:10px;color:var(--muted);letter-spacing:1.1px}.value{font-size:30px;font-weight:800;margin:12px 0 4px}.metric small{font-size:10px;color:var(--muted)}.cyan{color:var(--cyan)}.green{color:var(--green)}.red{color:var(--red)}.amber{color:var(--amber)}.purple{color:var(--purple)}.grid2{display:grid;grid-template-columns:1.3fr 1fr;gap:14px;margin:14px 0}.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:14px 0}.panel h2{font-size:13px;margin:0 0 14px}.panel .desc{font-size:11px;color:var(--muted);margin:-6px 0 14px;line-height:1.6}.tablewrap{width:100%;overflow:auto}table{width:100%;border-collapse:collapse;font-size:11px;min-width:650px}th,td{text-align:left;padding:12px 9px;border-bottom:1px solid #29334eaa;vertical-align:top;overflow-wrap:anywhere}th{font-size:9px;letter-spacing:.9px;color:#8291b0;font-weight:700}tbody tr:hover{background:#ffffff05}.badge{display:inline-block;padding:5px 8px;border-radius:6px;font-size:9px;font-weight:800;letter-spacing:.4px}.ALLOWED{color:var(--green);background:#6cf0b514;border:1px solid #6cf0b526}.DENIED{color:var(--red);background:#ff627e14;border:1px solid #ff627e26}.PENDING{color:var(--amber);background:#ffc66d14}.empty{color:var(--muted);padding:18px 0;font-size:11px}.barrow{margin:14px 0}.barlabel{display:flex;justify-content:space-between;gap:10px;font-size:11px}.bar{height:7px;background:#222d45;border-radius:10px;overflow:hidden;margin-top:7px}.bar span{display:block;height:100%;border-radius:10px;background:linear-gradient(90deg,var(--purple),var(--cyan))}.alert{padding:13px;border:1px solid #ff627e38;background:#ff627e0b;border-radius:11px;margin:9px 0;font-size:11px;line-height:1.7}.alert.med{border-color:#ffc66d38;background:#ffc66d08}.callout{padding:13px;border:1px solid #45e6e033;background:#45e6e008;border-radius:10px;color:var(--muted);font-size:11px;line-height:1.7}.quickgrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.quick{padding:14px;border-radius:11px;background:#ffffff05;border:1px solid var(--line)}.quick b{display:block;font-size:12px;margin-bottom:5px}.quick span{font-size:10px;color:var(--muted)}.eventtop{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px}.search{min-width:190px}.sectionhint{font-size:10px;color:var(--muted);margin-top:10px}.policygrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.policy{padding:17px;border-radius:12px;border:1px solid var(--line);background:#ffffff04}.policy h3{font-size:12px;margin:0 0 8px}.policy p{font-size:11px;color:var(--muted);line-height:1.8}.employee-card{display:flex;gap:13px;align-items:center;padding:15px;border:1px solid var(--line);border-radius:12px;background:#ffffff04}.avatar{width:43px;height:43px;display:grid;place-items:center;border-radius:13px;background:linear-gradient(135deg,#ff4f9a,#9c7bff);font-weight:900}.employee-card b{font-size:12px}.employee-card p{margin:4px 0 0;font-size:10px;color:var(--muted)}footer{padding:20px 0 0;text-align:center;color:#63718e;font-size:10px}
.navbadge{margin-left:auto;min-width:22px;height:22px;padding:0 6px;border-radius:999px;display:inline-flex;align-items:center;justify-content:center;font-size:10px;font-weight:900;line-height:1;color:#fff;box-shadow:0 0 0 2px #0b1020;animation:badgeIn .2s ease}.navbadge[hidden]{display:none!important}.navbadge.danger{background:linear-gradient(135deg,#ff405f,#ff1744);box-shadow:0 0 12px #ff174455,0 0 0 2px #0b1020}.navbadge.pending{background:linear-gradient(135deg,#ffbd52,#ff8a28);color:#251200;box-shadow:0 0 12px #ffad4244,0 0 0 2px #0b1020}.nav{gap:11px}.navtext{flex:1;text-align:left}@keyframes badgeIn{from{transform:scale(.65);opacity:.4}to{transform:scale(1);opacity:1}}@media(max-width:1050px){.layout{grid-template-columns:210px minmax(0,1fr)}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.grid3{grid-template-columns:1fr 1fr}.quickgrid{grid-template-columns:1fr 1fr}}
@media(max-width:760px){.layout{grid-template-columns:1fr}aside{position:relative;height:auto;padding:14px}.navlabel,.sidebottom,.sub{display:none}.navlist{display:flex;overflow:auto;gap:5px;margin-top:14px}.nav{min-width:max-content;width:auto;margin:0;padding:10px}.navtitle{display:none}header{position:relative;padding:15px}.content{padding:14px}.grid2,.grid3{grid-template-columns:1fr}.policygrid{grid-template-columns:1fr}.cards{gap:9px}.metric{padding:14px}.value{font-size:24px}.pagetitle h1{font-size:22px}}
</style></head><body>
<div class="layout"><aside><div class="brand"><div class="brandmark">IW</div><div><strong>INSIDER<span>WATCH</span></strong></div></div><div class="sub">SECURITY OPERATIONS CENTER</div>
<div class="navtitle">MONITORING</div><div class="navlist">
<button class="nav active" data-page="overview"><span class="ico">◈</span>Overview</button>
<button class="nav" data-page="fileaccess"><span class="ico">▤</span><span class="navtext">File access</span><span class="navbadge danger" id="fileDeniedBadge" hidden>0</span></button>
<button class="nav" data-page="behavior"><span class="ico">⌁</span>Behaviour analysis</button>
<button class="nav" data-page="employees"><span class="ico">♙</span>Employees & devices</button>
<button class="nav" data-page="approvals"><span class="ico">✓</span><span class="navtext">Login approvals</span><span class="navbadge pending" id="loginPendingBadge" hidden>0</span></button>
<button class="nav" data-page="policy"><span class="ico">⬡</span>Policies & testing</button>
</div><div class="navtitle">QUICK LINKS</div><div class="sidebottom"><span class="dot"></span>Local monitoring engine<br>SQLite event storage<br><a href="/company">↗ Company website</a><br><a href="/employee">↗ Employee portal</a><br><br><span id="sideHealth">Checking service…</span></div></aside>
<main><header><div><b>SECURITY OPERATIONS / <span id="headerSection">OVERVIEW</span></b><div class="muted">Employee file activity · access governance · behavioural signals</div></div><div class="headright"><span class="statuspill"><span class="dot"></span>ENGINE ONLINE</span><span class="muted" id="clock"></span><button onclick="refreshAll()">↻ Refresh</button></div></header>
<div class="content">
<section class="page active" id="page-overview"><div class="pagetitle"><div><span class="eyebrow">LIVE SECURITY SNAPSHOT</span><h1>Threat intelligence overview</h1><p>Monitor document access, policy enforcement and activity patterns from one workspace.</p></div><div class="actions"><button class="primary" onclick="demo()">＋ Generate demo activity</button><button onclick="location.href='/api/export'">↓ Export CSV</button></div></div>
<div class="cards"><div class="metric" style="--glow:var(--cyan)"><div class="label">TOTAL RECORDED EVENTS</div><div class="value cyan" id="total">0</div><small>Latest 1,000 records available to summary</small></div><div class="metric" style="--glow:var(--purple)"><div class="label">ACTIVITY · LAST 24 HOURS</div><div class="value purple" id="events24">0</div><small>Allowed and denied events</small></div><div class="metric" style="--glow:var(--red)"><div class="label">DENIED ACCESS · 24H</div><div class="value red" id="denied">0</div><small>Policy blocks and rejected requests</small></div><div class="metric" style="--glow:var(--green)"><div class="label">ALLOWED ACCESS · 24H</div><div class="value green" id="allowed">0</div><small>Successful logged access checks</small></div></div>
<div class="grid2"><div class="panel"><h2>Access activity by hour</h2><p class="desc">Events from the last 24 hours, grouped by local hour.</p><div id="hourChart"></div></div><div class="panel"><h2>Activity by employee batch</h2><p class="desc">Volume and denied requests by batch label.</p><div id="userChart"></div></div></div>
<div class="panel"><div class="eventtop"><div><h2 style="margin-bottom:5px">Latest file access events</h2><p class="desc" style="margin:0">Newest records first. Select File access for the full event table.</p></div><button onclick="showPage('fileaccess')">View all file events →</button></div><div class="tablewrap"><table><thead><tr><th>TIME</th><th>EMPLOYEE / BATCH</th><th>FILE</th><th>RESULT</th><th>REASON / CONTEXT</th></tr></thead><tbody id="topEvents"><tr><td colspan="5">Loading events…</td></tr></tbody></table></div></div>
<div class="grid2"><div class="panel"><h2>Priority behaviour signals</h2><div id="overviewAlerts" class="empty">Analysing events…</div></div><div class="panel"><h2>System shortcuts</h2><div class="quickgrid"><div class="quick"><b>File access</b><span>Review every recorded file event.</span><p><a href="#" onclick="showPage('fileaccess');return false">Open section ↗</a></p></div><div class="quick"><b>Behaviour</b><span>See repeated denials and unusual patterns.</span><p><a href="#" onclick="showPage('behavior');return false">Open section ↗</a></p></div><div class="quick"><b>Approvals</b><span>Review employee login requests.</span><p><a href="#" onclick="showPage('approvals');return false">Open section ↗</a></p></div></div></div></div>
</section>
<section class="page" id="page-fileaccess"><div class="pagetitle"><div><span class="eyebrow">AUDIT TRAIL</span><h1>Employee file access</h1><p>Review file name, timestamp, employee/batch, outcome, and recorded reason for each event.</p></div><div class="actions"><button onclick="loadEvents()">↻ Refresh events</button><button onclick="location.href='/api/export'">↓ Export CSV</button></div></div>
<div class="cards"><div class="metric"><div class="label">EVENTS SHOWN</div><div class="value cyan" id="shownEvents">0</div></div><div class="metric"><div class="label">UNIQUE FILES</div><div class="value purple" id="uniqueFiles">0</div></div><div class="metric"><div class="label">USERS / BATCHES</div><div class="value" id="uniqueUsers">0</div></div><div class="metric"><div class="label">DENIED IN CURRENT VIEW</div><div class="value red" id="viewDenied">0</div></div></div>
<div class="panel"><div class="eventtop"><div><h2>Complete recent access log</h2><p class="desc" style="margin:0">The database records batch ID rather than a person's full name. Reasons may include [REMOTE], [DEMO], or [DASHBOARD TEST].</p></div><div class="formrow"><input class="search" id="eventSearch" placeholder="Search user, file, reason…" oninput="renderEvents()"><select id="resultFilter" onchange="renderEvents()"><option value="ALL">All outcomes</option><option value="ALLOWED">Allowed</option><option value="DENIED">Denied</option></select></div></div><div class="tablewrap"><table><thead><tr><th>EVENT ID</th><th>TIMESTAMP</th><th>EMPLOYEE / BATCH</th><th>FILE / RESOURCE</th><th>RESULT</th><th>REASON / ACTION CONTEXT</th></tr></thead><tbody id="allEvents"><tr><td colspan="6">Loading…</td></tr></tbody></table></div><div class="sectionhint">This table shows recorded events returned by the existing /api/logs endpoint (up to 500 rows).</div></div></section>
<section class="page" id="page-behavior"><div class="pagetitle"><div><span class="eyebrow">PATTERN REVIEW</span><h1>Behaviour analysis</h1><p>Rule-based indicators derived from logged events. Indicators are for review and are not proof of malicious intent.</p></div><button onclick="refreshAll()">↻ Recalculate</button></div><div class="cards"><div class="metric"><div class="label">REPEATED DENIAL GROUPS</div><div class="value red" id="repeatDenials">0</div><small>Batch with 3+ denied events in visible log</small></div><div class="metric"><div class="label">MOST REQUESTED FILE</div><div class="value cyan" id="topFile" style="font-size:18px">—</div><small id="topFileCount">No events yet</small></div><div class="metric"><div class="label">DENIAL RATE</div><div class="value amber" id="denialRate">0%</div><small>Within returned event history</small></div><div class="metric"><div class="label">AFTER-HOURS EVENTS</div><div class="value purple" id="afterHours">0</div><small>Local time before 08:00 or from 20:00</small></div></div>
<div class="grid2"><div class="panel"><h2>Indicators requiring review</h2><p class="desc">Generated from event counts and timestamps; verify context with the employee or system owner.</p><div id="behaviorAlerts" class="empty">Analysing…</div></div><div class="panel"><h2>File request concentration</h2><p class="desc">Which resources appear most often in the returned event log.</p><div id="fileRanking"></div></div></div>
<div class="grid2"><div class="panel"><h2>Per-batch activity profile</h2><div class="tablewrap"><table><thead><tr><th>BATCH</th><th>EVENTS</th><th>DENIED</th><th>DENIAL RATE</th><th>UNIQUE FILES</th></tr></thead><tbody id="batchAnalysis"></tbody></table></div></div><div class="panel"><h2>How to interpret the signals</h2><div class="callout"><b>Repeated denials:</b> may indicate a permissions mismatch, testing, or attempted access beyond clearance.<br><br><b>After-hours activity:</b> is only a time-based indicator; shifts, timezone settings and remote work can explain it.<br><br><b>High-volume file access:</b> may reflect normal assigned work. Correlate with approved duties and additional logs before taking action.<br><br><b>Data limits:</b> current event schema stores batch labels (A/B/C), file/resource, result, reason and timestamp—not verified employee names, IP addresses, download counts or file contents.</div></div></div></section>
<section class="page" id="page-employees"><div class="pagetitle"><div><span class="eyebrow">IDENTITY & ENDPOINTS</span><h1>Employees & devices</h1><p>Review demo employee batches, clearance levels, recent activity, and heartbeat status.</p></div><button onclick="loadDevices()">↻ Refresh devices</button></div><div class="grid3"><div class="employee-card"><div class="avatar">A</div><div><b>Batch A · EMP001</b><p>Level 3 · Top clearance · Read / write / modify across configured files</p></div></div><div class="employee-card"><div class="avatar">B</div><div><b>Batch B · EMP002</b><p>Level 2 · Medium clearance · Basic modify, medium read</p></div></div><div class="employee-card"><div class="avatar">C</div><div><b>Batch C · EMP003</b><p>Level 1 · Basic clearance · Basic read-only access</p></div></div></div><div class="grid2"><div class="panel"><h2>Connected device heartbeat</h2><p class="desc">A device is online when a valid configured token has sent a heartbeat in the last 30 seconds.</p><div class="tablewrap"><table><thead><tr><th>BATCH</th><th>STATUS</th><th>LAST SEEN</th></tr></thead><tbody id="deviceRows"><tr><td colspan="3">Loading…</td></tr></tbody></table></div><p class="sectionhint">No heartbeat means unknown/offline, not necessarily a failed employee login.</p></div><div class="panel"><h2>Recent activity by batch</h2><div class="tablewrap"><table><thead><tr><th>BATCH</th><th>RECENT EVENTS</th><th>DENIED</th><th>LAST EVENT</th></tr></thead><tbody id="employeeActivity"></tbody></table></div></div></div></section>
<section class="page" id="page-approvals"><div class="pagetitle"><div><span class="eyebrow">ACCESS GOVERNANCE</span><h1>Employee login approvals</h1><p>Review pending employee requests and approve or reject access to the employee portal.</p></div><button onclick="loadLoginRequests()">↻ Refresh requests</button></div><div class="panel"><h2>Pending and recent requests</h2><p class="desc">Approval decisions are handled by the existing login request API.</p><div id="loginRequests" class="empty">Loading requests…</div></div></section>
<section class="page" id="page-policy"><div class="pagetitle"><div><span class="eyebrow">CONTROL CENTER</span><h1>Policies & access testing</h1><p>Check the configured clearance rules and create a logged test event.</p></div></div><div class="panel"><h2>Access test console</h2><p class="desc">Tests use the existing server-side access evaluation and are logged as dashboard test events.</p><div class="formrow"><select id="testUser"><option value="A">Batch A · Level 3</option><option value="B">Batch B · Level 2</option><option value="C">Batch C · Level 1</option></select><select id="testFile"><option>confidential.txt</option><option>security_audit.txt</option><option>financial_summary.txt</option><option>medium.txt</option><option>project_status.txt</option><option>it_guidelines.txt</option><option>basic.txt</option><option>company_policies.txt</option><option>employee_handbook.txt</option></select><button id="testButton" class="primary" onclick="testAccess()">Run access test</button></div><div id="testResult" class="sectionhint">No test run in this session.</div></div><div class="panel" style="margin-top:14px"><h2>Configured clearance policy</h2><div class="policygrid"><div class="policy"><h3 class="cyan">BATCH A · LEVEL 3</h3><p>Basic files: read / write / modify<br>Medium files: read / write / modify<br>Confidential files: read / write / modify</p></div><div class="policy"><h3 class="purple">BATCH B · LEVEL 2</h3><p>Basic files: read / write / modify<br>Medium files: read only<br>Confidential files: no access</p></div><div class="policy"><h3 class="amber">BATCH C · LEVEL 1</h3><p>Basic files: read only<br>Medium files: no access<br>Confidential files: no access</p></div></div><p class="sectionhint">Policy values reflect the FILE_PERMISSIONS configuration in app.py. The server remains responsible for enforcing access.</p></div><div class="panel" style="margin-top:14px"><h2>Monitoring data notes</h2><div class="callout">The dashboard can only display information the application records. To track real person's name, device IP, session ID, bytes downloaded, or exact read/write/modify actions, those fields must be added to the backend event schema and logging calls. This dashboard does not invent those details.</div></div></section>
<footer>InsiderWatch Security Operations Center · Rule-based indicators are decision support, not a determination of intent.</footer>
</div></main></div>
<script>
const $=id=>document.getElementById(id);let cachedEvents=[];let summaryData={};
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function getJSON(url,options){const r=await fetch(url,options);const d=await r.json();if(!r.ok)throw new Error(d.error||d.reason||('HTTP '+r.status));return d;}
function showPage(name){document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+name));document.querySelectorAll('.nav[data-page]').forEach(n=>n.classList.toggle('active',n.dataset.page===name));const label={overview:'OVERVIEW',fileaccess:'FILE ACCESS AUDIT',behavior:'BEHAVIOUR ANALYSIS',employees:'EMPLOYEES & DEVICES',approvals:'LOGIN APPROVALS',policy:'POLICIES & TESTING'};$('headerSection').textContent=label[name]||name.toUpperCase();if(name==='fileaccess')renderEvents();if(name==='behavior')renderBehavior();if(name==='employees')loadDevices();if(name==='approvals')loadLoginRequests();}
document.querySelectorAll('.nav[data-page]').forEach(n=>n.addEventListener('click',()=>showPage(n.dataset.page)));
function fmtTime(s){return esc(String(s||'').replace('T',' ').slice(0,19))}
function eventRow(e,detail=false){return `<tr>${detail?`<td>${esc(e.id)}</td>`:''}<td>${fmtTime(e.timestamp)}</td><td><b>${esc(e.user_id)}</b><div class="sectionhint">Batch / clearance label</div></td><td><b>${esc(e.resource)}</b></td><td><span class="badge ${esc(e.result)}">${esc(e.result)}</span></td><td>${esc(e.reason||'No reason recorded')}</td></tr>`}
async function refreshAll(){try{const [sum,events]=await Promise.all([getJSON('/api/summary'),getJSON('/api/logs?limit=500')]);summaryData=sum;cachedEvents=Array.isArray(events)?events:[];$('total').textContent=sum.total??cachedEvents.length;$('events24').textContent=sum.events24??0;$('denied').textContent=sum.denied??0;$('allowed').textContent=sum.allowed??0;$('hourChart').innerHTML=(sum.hourly||[]).map(h=>`<div class="barrow"><div class="barlabel"><span>${esc(h.hour)}</span><span>Denied ${h.denied} · Allowed ${h.allowed}</span></div><div class="bar"><span style="width:${Math.min(100,(h.denied+h.allowed)*8)}%"></span></div></div>`).join('')||'<div class="empty">No activity recorded yet.</div>';$('userChart').innerHTML=(sum.users||[]).map(u=>`<div class="barrow"><div class="barlabel"><span>Batch ${esc(u.user)}</span><span>${u.total} events · ${u.denied} denied</span></div><div class="bar"><span style="width:${Math.min(100,u.total*10)}%"></span></div></div>`).join('');$('topEvents').innerHTML=cachedEvents.length?cachedEvents.slice(0,12).map(e=>eventRow(e)).join(''):'<tr><td colspan="5" class="empty">No file access events recorded yet. Use the access test or employee portal to generate activity.</td></tr>';renderEvents();renderBehavior();renderEmployeeActivity();renderOverviewAlerts();$('sideHealth').textContent='API connected · '+cachedEvents.length+' events loaded';}catch(e){console.error(e);$('sideHealth').textContent='API error: '+e.message;}}
async function loadEvents(){await refreshAll();}
function renderEvents(){const q=($('eventSearch')?.value||'').toLowerCase();const f=$('resultFilter')?.value||'ALL';const arr=cachedEvents.filter(e=>(f==='ALL'||e.result===f)&&[e.user_id,e.resource,e.result,e.reason,e.timestamp,e.id].join(' ').toLowerCase().includes(q));$('shownEvents').textContent=arr.length;$('uniqueFiles').textContent=new Set(arr.map(e=>e.resource)).size;$('uniqueUsers').textContent=new Set(arr.map(e=>e.user_id)).size;$('viewDenied').textContent=arr.filter(e=>e.result==='DENIED').length;$('allEvents').innerHTML=arr.length?arr.map(e=>eventRow(e,true)).join(''):'<tr><td colspan="6" class="empty">No matching events.</td></tr>';}
function analyze(){const byUser={},byFile={},after=[];cachedEvents.forEach(e=>{const u=e.user_id||'Unknown',f=e.resource||'Unknown';byUser[u]??={total:0,denied:0,files:new Set(),last:'',after:0};byUser[u].total++;if(e.result==='DENIED')byUser[u].denied++;byUser[u].files.add(f);if(!byUser[u].last||String(e.timestamp)>byUser[u].last)byUser[u].last=e.timestamp;byFile[f]=(byFile[f]||0)+1;const d=new Date(e.timestamp);if(!isNaN(d)&& (d.getHours()<8||d.getHours()>=20)){after.push(e);byUser[u].after++;}});return {byUser,byFile,after};}
function renderBehavior(){const {byUser,byFile,after}=analyze();const users=Object.entries(byUser);const deniedTotal=cachedEvents.filter(e=>e.result==='DENIED').length;$('repeatDenials').textContent=users.filter(([u,x])=>x.denied>=3).length;$('denialRate').textContent=(cachedEvents.length?Math.round(deniedTotal/cachedEvents.length*100):0)+'%';$('afterHours').textContent=after.length;const top=Object.entries(byFile).sort((a,b)=>b[1]-a[1])[0];$('topFile').textContent=top?top[0]:'—';$('topFileCount').textContent=top?top[1]+' events in returned log':'No events yet';$('fileRanking').innerHTML=Object.entries(byFile).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([f,n])=>`<div class="barrow"><div class="barlabel"><span>${esc(f)}</span><b>${n}</b></div><div class="bar"><span style="width:${Math.min(100,n/Math.max(1,...Object.values(byFile))*100)}%"></span></div></div>`).join('')||'<div class="empty">No file activity to rank.</div>';$('batchAnalysis').innerHTML=users.map(([u,x])=>`<tr><td><b>${esc(u)}</b></td><td>${x.total}</td><td class="${x.denied?'red':'green'}">${x.denied}</td><td>${Math.round(x.denied/Math.max(1,x.total)*100)}%</td><td>${x.files.size}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">No events yet.</td></tr>';const alerts=[];users.forEach(([u,x])=>{if(x.denied>=3)alerts.push({level:x.denied>=5?'HIGH':'REVIEW',user:u,msg:`${x.denied} denied attempts across ${x.files.size} distinct file(s). Check whether this reflects normal work or a permission mismatch.`});if(x.after>=3)alerts.push({level:'REVIEW',user:u,msg:`${x.after} events occurred outside the dashboard's local 08:00–20:00 reference window. Confirm timezone and shift context.`});});$('behaviorAlerts').innerHTML=alerts.length?alerts.map(a=>`<div class="alert ${a.level==='REVIEW'?'med':''}"><b class="${a.level==='HIGH'?'red':'amber'}">${esc(a.level)} · ${esc(a.user)}</b><div>${esc(a.msg)}</div></div>`).join(''):'<div class="callout">No repeated-denial or repeated after-hours indicator met the current rule thresholds in the returned log. This does not guarantee that activity is risk-free.</div>';}
function renderOverviewAlerts(){const s=summaryData||{};const alerts=s.alerts||[];$('overviewAlerts').innerHTML=alerts.length?alerts.slice(0,5).map(a=>`<div class="alert ${a.severity==='HIGH'?'':'med'}"><b class="${a.severity==='HIGH'?'red':'amber'}">${esc(a.severity)} · Batch ${esc(a.user)}</b><div>${esc(a.message)} · ${a.count} denied event(s) in 24 hours.</div></div>`).join(''):'<div class="empty">No repeated-denial alert currently reported by the summary API.</div>';}
function renderEmployeeActivity(){const {byUser}=analyze();$('employeeActivity').innerHTML=Object.entries(byUser).map(([u,x])=>`<tr><td><b>${esc(u)}</b></td><td>${x.total}</td><td class="${x.denied?'red':'green'}">${x.denied}</td><td>${fmtTime(x.last)}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">No activity recorded.</td></tr>';}
async function loadDevices(){try{const d=await getJSON('/api/devices');$('deviceRows').innerHTML=d.map(x=>`<tr><td><b>Batch ${esc(x.device)}</b></td><td><span class="badge ${x.online?'ALLOWED':'DENIED'}">${x.online?'ONLINE':'OFFLINE / UNKNOWN'}</span></td><td>${x.last_seen?fmtTime(x.last_seen):'No heartbeat recorded'}</td></tr>`).join('');}catch(e){$('deviceRows').innerHTML=`<tr><td colspan="3">${esc(e.message)}</td></tr>`;}}
async function testAccess(){const b=$('testButton');b.disabled=true;try{const d=await getJSON('/api/access',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:$('testUser').value,file:$('testFile').value})});$('testResult').innerHTML=`<span class="badge ${esc(d.result)}">${esc(d.result)}</span> ${esc(d.user)} → ${esc(d.file)} · ${esc(d.reason)}`;await refreshAll();}catch(e){$('testResult').textContent='Test result: '+e.message;await refreshAll();}finally{b.disabled=false;}}
async function demo(){try{const d=await getJSON('/api/demo',{method:'POST'});await refreshAll();alert(d.message+' ('+d.count+' events).');}catch(e){alert('Demo failed: '+e.message);}}
async function loadLoginRequests(){const host=$('loginRequests');try{const items=await getJSON('/api/admin/login-requests');if(!items.length){host.innerHTML='<div class="empty">No pending login requests.</div>';return;}host.innerHTML=items.map(item=>`<div class="employee-card" style="margin:10px 0"><div class="avatar">${esc(item.batch_id)}</div><div style="flex:1"><b>Employee ${esc(item.employee_id)} · Batch ${esc(item.batch_id)}</b><p>Requested: ${esc(item.requested_at)} · Status: ${esc(item.status||'PENDING')}</p></div><div class="actions"><button class="primary" onclick="reviewEmployeeRequest(${Number(item.id)},'APPROVE')">Approve</button><button onclick="reviewEmployeeRequest(${Number(item.id)},'REJECT')">Reject</button></div></div>`).join('');}catch(e){host.innerHTML='<div class="empty">Unable to load requests. '+esc(e.message)+'</div>';}}
async function reviewEmployeeRequest(id,decision){try{const d=await getJSON('/api/admin/login-requests/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision})});alert('Login request '+String(d.status||decision).toLowerCase()+'.');await loadLoginRequests();await refreshAll();}catch(e){alert('Could not review request: '+e.message);}}
async function updateNotificationBadges(){
  const fileBadge=$('fileDeniedBadge');
  const loginBadge=$('loginPendingBadge');
  try{
    const [events,requests]=await Promise.all([
      getJSON('/api/logs?limit=1000'),
      getJSON('/api/admin/login-requests')
    ]);
    const deniedCount=(Array.isArray(events)?events:[]).filter(e=>
      String(e.result||'').toUpperCase()==='DENIED'
    ).length;
    const pendingCount=(Array.isArray(requests)?requests:[]).filter(r=>
      String(r.status||'PENDING').toUpperCase()==='PENDING'
    ).length;
    fileBadge.textContent=deniedCount>99?'99+':String(deniedCount);
    fileBadge.hidden=deniedCount===0;
    fileBadge.title=deniedCount+' denied file-access events in the latest 1000 recorded events';
    loginBadge.textContent=pendingCount>99?'99+':String(pendingCount);
    loginBadge.hidden=pendingCount===0;
    loginBadge.title=pendingCount+' login request(s) awaiting approval';
    fileBadge.setAttribute('aria-label',deniedCount+' denied file access events');
    loginBadge.setAttribute('aria-label',pendingCount+' pending login approvals');
  }catch(error){
    console.error('Notification badge refresh failed:',error);
    // Keep last known counts visible if an API request temporarily fails.
  }
}

function tick(){ $('clock').textContent=new Date().toLocaleString(); }
tick();setInterval(tick,1000);refreshAll();loadDevices();loadLoginRequests();updateNotificationBadges();setInterval(refreshAll,7000);setInterval(loadLoginRequests,10000);setInterval(updateNotificationBadges,7000);setInterval(loadDevices,15000);
</script></body></html>
"""

# ---------------------------------------------------------
# ERROR HANDLING AND STARTUP
# ---------------------------------------------------------

@app.errorhandler(Exception)
def handle_error(exc):
    if isinstance(exc, HTTPException):
        return exc

    app.logger.exception("Unhandled application error")

    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error"}), 500

    return "Internal server error. Check the Flask terminal.", 500


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)