#!/usr/bin/env python3
"""
Challenge instance: "Role Up" (Broken Access Control).

A STANDALONE vulnerable web app with its own URL, separate from the CTF
platform. Players open this app, exploit it to reveal the flag, then submit
that flag back on the platform.

    Flag button  ->  POST /flag {"role":"user"}  ->  403
    tamper body  ->  {"role":"admin"}            ->  200 + flag

Run (own port, so it can have its own URL / tunnel):
    pip install flask
    python3 challenge_roleup.py            # port 8001
    python3 challenge_roleup.py 9000       # custom port

Deliberately insecure — that's the challenge. Host only for the CTF.
"""

import sys
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
FLAG = "FLAG{r0le_1n_body_gu3st_t0_4dm1n}"

PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Role Up</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@700;800&family=DM+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
  :root{--paper:#f3efe6;--card:#fffdf8;--ink:#16231b;--green:#1b5e3a;--green-d:#123d28;
        --muted:#6d7570;--line:#ddd6c6;--gold:#a9792a;--danger:#a5362f}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--paper);
       color:var(--ink);font:15px/1.65 'DM Sans',system-ui,Segoe UI,Tahoma,sans-serif}
  .mono{font-family:'IBM Plex Mono',monospace}
  h1{font-family:'Archivo';margin:.1em 0 .3em;font-size:24px}
  .card{background:var(--card);border:1px solid var(--line);border-top:4px solid var(--green);
        border-radius:12px;padding:34px;width:min(92vw,440px);text-align:center;
        box-shadow:0 2px 14px rgba(18,61,40,.08)}
  .tag{display:inline-block;font-family:'IBM Plex Mono';font-size:11px;letter-spacing:1px;
       text-transform:uppercase;color:var(--green);border:1px solid var(--line);border-radius:5px;padding:3px 10px}
  p.mut{color:var(--muted)}
  button{margin-top:18px;background:var(--green);color:#f4f1e8;border:0;padding:13px 34px;
         border-radius:8px;cursor:pointer;font-weight:700;font-size:16px;font-family:'DM Sans'}
  button:hover{background:var(--green-d)} button:active{transform:translateY(1px)}
  #out{margin-top:20px;min-height:48px;font-family:'IBM Plex Mono',monospace;font-size:14px;
       padding:13px;border-radius:8px;display:none;word-break:break-all;border:1px solid}
  #out .flag{font-weight:700;font-size:15px}
  .win{background:#e8f3ec;color:#14532b;border-color:#bcdcc7!important;display:block!important}
  .bad{background:#f7e9e7;color:#8f2d26;border-color:#e3c3bf!important;display:block!important}
</style></head><body>
  <div class="card">
    <span class="tag">Web · Role Up</span>
    <h1>Members Area</h1>
    <p class="mut">Only administrators can reveal the flag. You are signed in as a regular user — press the button and see.</p>
    <button id="btn">Flag</button>
    <div id="out"></div>
  </div>
<script>
  const out=document.getElementById('out');
  document.getElementById('btn').onclick=async()=>{
    out.className='';out.style.display='none';out.innerHTML='';
    const r=await fetch('flag',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({role:'user'})});   // <-- the interesting part
    const d=await r.json();
    if(r.status===200){out.className='win';
      out.innerHTML='<div class="flag">'+d.flag+'</div>'+
        '<div style="margin-top:8px;font-size:12px">Submit this flag on the CTF platform.</div>';}
    else{out.className='bad';out.textContent=r.status+' '+(d.error||'Forbidden');}
  };
</script>
</body></html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/flag", methods=["POST"])
def flag():
    # Deliberately vulnerable: trusts the role sent by the client.
    data = request.get_json(silent=True) or {}
    if data.get("role") == "admin":
        return jsonify(flag=FLAG), 200
    return jsonify(error="Forbidden — admins only."), 403


if __name__ == "__main__":
    import socket
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8001
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); lan_ip = s.getsockname()[0]; s.close()
    except Exception:
        lan_ip = "0.0.0.0"
    print("\n  Challenge: Role Up")
    print(f"  Local    ->  http://127.0.0.1:{PORT}")
    print(f"  Network  ->  http://{lan_ip}:{PORT}")
    print("  Give this URL to players. Flag is revealed by tampering role -> admin.\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
