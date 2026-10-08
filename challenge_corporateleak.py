#!/usr/bin/env python3
"""
Challenge: Corporate Leak — NexaCorp Internal Portal

Vulnerability: The server assigns admin role based solely on the email domain.
Register with any @nexacorp.com email to get admin access and see financials.

Run standalone:  python challenge_corporateleak.py [port]
Default port: 8002
"""

import sys
import json
from flask import Flask, request, render_template_string, redirect, session, jsonify

app = Flask(__name__)
app.secret_key = "nexacorp-internal-portal-key-2026"

COMPANY_DOMAIN = "nexacorp.com"
FLAG = "$4,817,263"

# in-memory user store
users_db = {}

PAGE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexaCorp — Internal Portal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0b0e1a;--surface:rgba(15,20,35,.85);--border:rgba(59,130,246,.18);
  --border-h:rgba(59,130,246,.4);--text:#e2e8f0;--text2:#64748b;
  --blue:#3b82f6;--blue2:#2563eb;--blue-glow:rgba(59,130,246,.12);
  --green:#22c55e;--red:#ef4444;--gold:#eab308;
  --font:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:15px/1.6 var(--font);min-height:100vh}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:linear-gradient(rgba(59,130,246,.02) 1px,transparent 1px),
  linear-gradient(90deg,rgba(59,130,246,.02) 1px,transparent 1px);background-size:50px 50px}
body::after{content:'';position:fixed;top:-150px;left:50%;transform:translateX(-50%);
  width:600px;height:400px;pointer-events:none;z-index:0;
  background:radial-gradient(ellipse,rgba(59,130,246,.07),transparent 70%)}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}

.topbar{
  position:sticky;top:0;z-index:10;
  background:rgba(11,14,26,.85);backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);padding:12px 24px;
  display:flex;align-items:center;justify-content:space-between;
}
.topbar .brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:16px}
.topbar .brand .nx{color:var(--blue)}
.topbar .brand .corp{color:var(--text2);font-weight:500;font-size:12px}
.topbar nav a{color:var(--text2);font-weight:600;font-size:14px;padding:6px 14px;border-radius:8px;transition:all .2s}
.topbar nav a:hover{color:var(--text);background:rgba(59,130,246,.1);text-decoration:none}

.wrap{max-width:600px;margin:0 auto;padding:40px 20px 60px;position:relative;z-index:1}

.card{background:var(--surface);backdrop-filter:blur(12px);border:1px solid var(--border);
  border-radius:16px;padding:32px;margin-bottom:20px}

h1{font-size:28px;font-weight:900;margin-bottom:4px}
h2{font-size:20px;font-weight:800}
.sub{color:var(--text2);font-size:14px;margin-bottom:24px}

label{color:var(--text2);font-size:13px;font-weight:600;display:block;margin-bottom:6px}
input{width:100%;padding:12px 14px;margin-bottom:16px;
  background:rgba(11,14,26,.7);border:1px solid var(--border);border-radius:10px;
  color:var(--text);font:15px var(--font);outline:none;transition:all .2s}
input:focus{border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-glow)}
input::placeholder{color:var(--text2);opacity:.4}

.btn{display:block;width:100%;padding:13px;border:0;border-radius:10px;
  background:linear-gradient(135deg,var(--blue2),var(--blue));
  color:#fff;font:700 15px var(--font);cursor:pointer;transition:all .2s}
.btn:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(59,130,246,.3)}

.err{color:var(--red);font-weight:600;font-size:14px;margin-bottom:12px;
  padding:10px 14px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:8px}
.muted{color:var(--text2)}
.mono{font-family:var(--mono)}
.link{color:var(--blue);font-weight:600}

/* dashboard */
.dash-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:12px}
.role-badge{font-size:12px;font-weight:700;padding:4px 12px;border-radius:6px;text-transform:uppercase;letter-spacing:1px}
.role-user{background:rgba(100,116,139,.15);color:var(--text2);border:1px solid rgba(100,116,139,.2)}
.role-admin{background:rgba(59,130,246,.12);color:var(--blue);border:1px solid rgba(59,130,246,.25)}

.metric{background:rgba(59,130,246,.04);border:1px solid var(--border);border-radius:12px;
  padding:16px 20px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
.metric .label{color:var(--text2);font-size:13px;font-weight:600}
.metric .val{font-family:var(--mono);font-weight:700;font-size:18px}
.metric .val.green{color:var(--green)}

.locked{text-align:center;padding:40px 20px;color:var(--text2)}
.locked .icon{font-size:48px;margin-bottom:12px}
.locked p{font-size:14px;max-width:300px;margin:0 auto}

.flag-box{
  background:linear-gradient(135deg,rgba(34,197,94,.08),rgba(34,197,94,.02));
  border:1px solid rgba(34,197,94,.25);border-radius:12px;
  padding:20px;text-align:center;margin-top:16px;
}
.flag-box .label{color:var(--green);font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.flag-box .flag{font-family:var(--mono);font-size:16px;font-weight:700;color:var(--green);
  background:rgba(34,197,94,.08);padding:10px 20px;border-radius:8px;display:inline-block;word-break:break-all}

footer{text-align:center;color:var(--text2);font-size:11px;padding:20px;position:relative;z-index:1;
  border-top:1px solid var(--border);margin-top:30px}
</style></head><body>

<div class="topbar">
  <div class="brand">
    <span class="nx">NexaCorp</span>
    <span class="corp">Internal Portal</span>
  </div>
  <nav id="topnav"></nav>
</div>

<div class="wrap" id="app"></div>

<!--
  TODO: remove before production
  Role assignment logic:
    - If email domain == "nexacorp.com" → role = admin (full access)
    - Otherwise → role = user (restricted)
  Ticket: SEC-2041 — "domain-based role assignment is insecure, anyone can register with @nexacorp.com"
  Status: won't fix (management says it's fine)
-->
<footer>
  &copy; 2026 NexaCorp Inc. All rights reserved.<br>
  <span style="opacity:.6">For support contact: <a href="mailto:support@nexacorp.com" style="color:var(--text2)">support@nexacorp.com</a></span>
</footer>

<script>
var API='';

function showNav(loggedIn){
  var nav=document.getElementById('topnav');
  if(loggedIn) nav.innerHTML='<a href="#" onclick="logout();return false">Logout</a>';
  else nav.innerHTML='<a href="#" onclick="showLogin();return false">Login</a> <a href="#" onclick="showRegister();return false">Register</a>';
}

function showRegister(){
  showNav(false);
  document.getElementById('app').innerHTML=`
    <div class="card">
      <h1>Create Account</h1>
      <p class="sub">Register to access the NexaCorp portal</p>
      <div id="err"></div>
      <form onsubmit="doRegister(event)">
        <label>Email</label>
        <input type="email" id="reg_email" placeholder="you@example.com" required>
        <label>Password</label>
        <input type="password" id="reg_pass" placeholder="Choose a password" required>
        <button class="btn" type="submit">Create Account</button>
      </form>
      <p class="muted" style="margin-top:16px;text-align:center;font-size:14px">
        Already have an account? <a class="link" href="#" onclick="showLogin();return false">Login</a>
      </p>
    </div>`;
}

function showLogin(){
  showNav(false);
  document.getElementById('app').innerHTML=`
    <div class="card">
      <h1>Welcome Back</h1>
      <p class="sub">Sign in to access the portal</p>
      <div id="err"></div>
      <form onsubmit="doLogin(event)">
        <label>Email</label>
        <input type="email" id="log_email" placeholder="you@example.com" required>
        <label>Password</label>
        <input type="password" id="log_pass" placeholder="Your password" required>
        <button class="btn" type="submit">Login</button>
      </form>
      <p class="muted" style="margin-top:16px;text-align:center;font-size:14px">
        New here? <a class="link" href="#" onclick="showRegister();return false">Create account</a>
      </p>
    </div>`;
}

async function doRegister(e){
  e.preventDefault();
  // NOTE: backend assigns role based on email domain
  // employees (@nexacorp.com) get admin, everyone else gets user
  var email=document.getElementById('reg_email').value;
  var pass=document.getElementById('reg_pass').value;
  var r=await fetch(API+'/api/register',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:email,password:pass})});
  var d=await r.json();
  if(!r.ok){document.getElementById('err').innerHTML='<div class="err">'+d.error+'</div>';return}
  showDashboard(d);
}

async function doLogin(e){
  e.preventDefault();
  var email=document.getElementById('log_email').value;
  var pass=document.getElementById('log_pass').value;
  var r=await fetch(API+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:email,password:pass})});
  var d=await r.json();
  if(!r.ok){document.getElementById('err').innerHTML='<div class="err">'+d.error+'</div>';return}
  showDashboard(d);
}

function showDashboard(data){
  showNav(true);
  var isAdmin=data.role==='admin';
  var badge=isAdmin?'<span class="role-badge role-admin">Admin</span>':'<span class="role-badge role-user">User</span>';

  var content='<div class="card">';
  content+='<div class="dash-header"><div><h2>Dashboard</h2><p class="muted" style="font-size:13px">'+data.email+'</p></div>'+badge+'</div>';

  content+='<div class="metric"><span class="label">Employees</span><span class="val">2,847</span></div>';
  content+='<div class="metric"><span class="label">Active Projects</span><span class="val">156</span></div>';

  if(isAdmin){
    content+='<hr style="border:0;border-top:1px solid rgba(59,130,246,.15);margin:20px 0">';
    content+='<h3 style="font-size:16px;margin-bottom:14px;color:var(--blue)">📊 Financial Reports (Confidential)</h3>';
    content+='<div class="metric"><span class="label">Q1 Revenue</span><span class="val green">$1,394,520</span></div>';
    content+='<div class="metric"><span class="label">Q2 Revenue</span><span class="val green">$1,287,340</span></div>';
    content+='<div class="metric"><span class="label">Q3 Revenue</span><span class="val green">$1,052,891</span></div>';
    content+='<div class="metric"><span class="label">Q4 Revenue</span><span class="val green">$1,082,512</span></div>';
    content+='<div class="metric" style="border-color:rgba(34,197,94,.3);background:rgba(34,197,94,.04)"><span class="label" style="font-weight:700;color:var(--green)">Annual Profit (2025)</span><span class="val green" style="font-size:22px">$4,817,263</span></div>';
    content+='<div class="flag-box"><div class="label">Flag</div><div class="flag">'+data.flag+'</div></div>';
  } else {
    content+='<hr style="border:0;border-top:1px solid rgba(59,130,246,.15);margin:20px 0">';
    content+='<div class="locked"><div class="icon">🔒</div>';
    content+='<h3 style="margin-bottom:8px">Financial Reports</h3>';
    content+='<p>You don\'t have permission to view financial reports. This section is restricted to authorized personnel only.</p></div>';
  }

  content+='</div>';
  document.getElementById('app').innerHTML=content;
}

function logout(){showRegister()}

showRegister();
</script>
</body></html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify(error="Email and password required."), 400
    if "@" not in email:
        return jsonify(error="Invalid email format."), 400
    if len(password) < 4:
        return jsonify(error="Password too short."), 400
    if email in users_db:
        return jsonify(error="Email already registered."), 400

    domain = email.split("@")[1]
    role = "admin" if domain == COMPANY_DOMAIN else "user"

    users_db[email] = {"password": password, "role": role}

    resp = {"email": email, "role": role}
    if role == "admin":
        resp["flag"] = FLAG
    return jsonify(resp)


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = users_db.get(email)
    if not user or user["password"] != password:
        return jsonify(error="Invalid credentials."), 401

    resp = {"email": email, "role": user["role"]}
    if user["role"] == "admin":
        resp["flag"] = FLAG
    return jsonify(resp)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8002
    print(f"\n  NexaCorp Internal Portal (Corporate Leak challenge)")
    print(f"  http://127.0.0.1:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
