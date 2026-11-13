#!/usr/bin/env python3
# app.py — статус и API приложения vpn-az (VPN-клиент своего AZ-узла для Umbrel).
# Только stdlib. Слушает 0.0.0.0:8666, сеть хоста (network_mode: host).
import json
import os
import re
import secrets
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DATA = os.environ.get("DATA", "/data")
PORT = int(os.environ.get("APP_PORT", "8666"))
OVPN_CONF = os.path.join(DATA, "client.ovpn")
WG_CONF = os.path.join(DATA, "wg0.conf")
NET_SH = os.path.join(DATA, "net.sh")
DNS_PORT = os.environ.get("DNS_PORT", "5399")
OVPN_DEV = "azvpn"

EGRESS = {"direct": None, "tunnel": None, "at": 0}
TOKEN = (os.environ.get("APP_PASSWORD") or "").strip()


def data_path(name):
    return os.path.join(DATA, name)


def token():
    global TOKEN
    if TOKEN:
        return TOKEN
    p = data_path("api_token")
    try:
        TOKEN = open(p).read().strip()
    except OSError:
        TOKEN = ""
    if not TOKEN:
        TOKEN = secrets.token_hex(24)
        with open(p, "w") as f:
            f.write(TOKEN)
        os.chmod(p, 0o600)
    return TOKEN


def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           shell=isinstance(cmd, str))
        return (r.stdout or "").strip()
    except Exception:
        return ""


def sh(script, timeout=60):
    try:
        r = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return "err: %s" % e


def iface_exists(n):
    return os.path.exists("/sys/class/net/%s" % n)


def tun_ip():
    out = run(["ip", "-4", "-o", "addr", "show", "dev", OVPN_DEV])
    m = re.search(r"inet ([0-9.]+)/", out)
    return m.group(1) if m else ""


def ovpn_alive():
    try:
        pid = int(open(data_path("ovpn.pid")).read().strip())
        os.kill(pid, 0)
        return True
    except Exception:
        return bool(run("pgrep -f 'openvpn --config %s'" % OVPN_CONF))


def mode():
    if os.path.exists(OVPN_CONF):
        return "openvpn"
    if os.path.exists(WG_CONF):
        return "wireguard"
    return "none"


def dns_ok():
    return run("ss -lnuH | grep -c ':%s '" % DNS_PORT) not in ("", "0")


def ip_forward():
    return run(["cat", "/proc/sys/net/ipv4/ip_forward"]) == "1"


def egress_loop():
    global EGRESS
    while True:
        direct = None
        out = run(["curl", "-s", "--max-time", "5", "https://ifconfig.me"])
        if re.fullmatch(r"[0-9.]{7,15}", out or ""):
            direct = out
        tunnel = None
        dev = OVPN_DEV if iface_exists(OVPN_DEV) else ("wg0" if iface_exists("wg0") else None)
        if dev:
            out = run(["curl", "-s", "--max-time", "6", "--interface", dev, "https://ifconfig.me"])
            if re.fullmatch(r"[0-9.]{7,15}", out or ""):
                tunnel = out
        EGRESS = {"direct": direct or EGRESS.get("direct"), "tunnel": tunnel or EGRESS.get("tunnel"),
                  "at": int(time.time())}
        time.sleep(120)


def dns_a(name):
    import socket
    import struct
    import random
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in name.rstrip(".").split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(q, ("127.0.0.1", int(DNS_PORT)))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    ancount = struct.unpack(">H", data[6:8])[0]
    i = 12
    while data[i] != 0:
        i += 1 + data[i]
    i += 5
    out = []
    for _ in range(ancount):
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while data[i] != 0:
                i += 1 + data[i]
            i += 1
        rtype, _c, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            out.append(".".join(str(b) for b in data[i:i + 4]))
        i += rdlen
    return out


def ovpn_meta():
    """Что видно в профиле, без секретов."""
    if not os.path.exists(OVPN_CONF):
        return {}
    meta: dict = {"remotes": []}
    try:
        with open(OVPN_CONF, errors="ignore") as f:
            for line in f:
                m = re.match(r"\s*remote\s+(\S+)\s+(\d+)", line)
                if m:
                    meta["remotes"].append("%s:%s" % (m.group(1), m.group(2)))
                if "redirect-gateway" in line or re.match(r"\s*route\s+0\.0\.0\.0\s+0\.0\.0\.0", line):
                    meta["full_tunnel"] = True
    except OSError:
        pass
    return meta


def status():
    m = mode()
    st = {
        "time": int(time.time()),
        "mode": m,
        "lan_access": os.path.exists(data_path("lan_access")),
        "forwarding": ip_forward(),
        "dns": {"port": DNS_PORT, "listening": dns_ok(),
                "override": os.path.exists(data_path("dns_on")),
                "upstream": os.environ.get("AZ_DNS_UPSTREAM", "1.1.1.1")},
        "egress": EGRESS,
    }
    if m == "openvpn":
        st["tunnel"] = {
            "dev": OVPN_DEV,
            "alive": ovpn_alive(),
            "ip": tun_ip(),
            "routes": len(run(["ip", "-4", "route", "show", "dev", OVPN_DEV]).splitlines()),
            "default_via_tunnel": bool(re.search(r"^(0\.0\.0\.0/1|128\.0\.0\.0/1)\b",
                                                run(["ip", "-4", "route", "show", "dev", OVPN_DEV]), re.M)),
            "meta": ovpn_meta(),
        }
    elif m == "wireguard":
        peers = []
        for line in run(["wg", "show", "wg0", "dump"]).splitlines()[1:]:
            f = line.split("\t")
            if len(f) >= 8:
                hs = int(f[4] or 0)
                peers.append({"endpoint": f[2], "allowed": f[3],
                              "handshake_age": (int(time.time()) - hs) if hs else None,
                              "rx": int(f[5] or 0), "tx": int(f[6] or 0)})
        st["tunnel"] = {"dev": "wg0", "alive": iface_exists("wg0"), "peers": peers,
                        "routes": len(run(["ip", "-4", "route", "show", "dev", "wg0"]).splitlines())}
    return st


def apply_net(arg="apply"):
    sh("sh %s %s >> %s/net.log 2>&1" % (NET_SH, arg, DATA))


PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN AZ — Umbrel</title>
<style>
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px;background:#0f1115;color:#e6e6e6}
h1{font-size:19px;margin:0 0 4px}
.sub{color:#8b93a1;font-size:13px;margin-bottom:18px}
.card{background:#171a21;border:1px solid #232735;border-radius:12px;padding:16px;margin-bottom:14px;max-width:760px}
.row{display:flex;justify-content:space-between;gap:12px;padding:5px 0;border-bottom:1px solid #1e222d}
.row:last-child{border-bottom:0}
.k{color:#8b93a1}.v{font-variant-numeric:tabular-nums;text-align:right;word-break:break-all}
.ok{color:#3ddc84}.bad{color:#ff6b6b}
button{background:#2a3040;color:#e6e6e6;border:1px solid #39415a;border-radius:8px;padding:7px 12px;cursor:pointer;font-size:13px}
button:hover{background:#333b4e}
textarea{width:100%;height:120px;background:#0f1115;color:#cfd4e0;border:1px solid #2b3143;border-radius:8px;padding:10px;font:12px/1.4 ui-monospace,monospace;box-sizing:border-box}
.tools{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
pre{white-space:pre-wrap;font:12px/1.45 ui-monospace,monospace;color:#b9c0cf;margin:8px 0 0}
</style></head><body>
<h1>VPN AZ — Umbrel</h1>
<div class="sub">Туннель к своему AZ-узлу, без зависимости от роутера</div>
<div class="card" id="st">загрузка…</div>
<div class="card">
  <div class="k" style="margin-bottom:8px">Профиль .ovpn из панели AZ (client.sh) — вставь целиком</div>
  <textarea id="conf" placeholder="client&#10;dev tun&#10;remote 5.39.253.63 50080 udp4&#10;..."></textarea>
  <div class="tools">
    <button onclick="post('/api/config', document.getElementById('conf').value)">Загрузить профиль</button>
    <button onclick="post('/api/dns_on?on=' + (S.dns.override?0:1))">Перехват DNS</button>
    <button onclick="post('/api/lan?on=' + (S.lan_access?0:1))">NAT в домашнюю сеть</button>
    <button onclick="post('/api/restart')">Перезапустить туннель</button>
    <button onclick="load()">Обновить</button>
  </div>
  <pre id="out"></pre>
</div>
<script>
let S={};
const T=new URLSearchParams(location.search).get('token')||'';
async function load(){
  const r=await fetch('/status.json',{headers:{'X-Auth-Token':T}});
  S=await r.json(); render();
}
function render(){
  const t=S.tunnel||{}; const rows=[];
  rows.push(['Режим', S.mode]);
  if(S.mode==='openvpn'){
    rows.push(['Туннель', t.alive?'поднят':'нет']);
    rows.push(['Адрес в туннеле', t.ip||'—']);
    rows.push(['Маршрутов через туннель', t.routes]);
    rows.push(['Весь трафик через VPN', t.default_via_tunnel?'да':'нет']);
    rows.push(['Сервер', (t.meta&&t.meta.remotes||[]).join(', ')||'—']);
  }
  rows.push(['DNS :'+S.dns.port, (S.dns.listening?'слушает':'нет')+(S.dns.override?' · перехват вкл':' · перехват выкл')]);
  rows.push(['Выход напрямую', S.egress.direct||'—']);
  rows.push(['Выход через туннель', S.egress.tunnel||'—']);
  rows.push(['NAT в домашнюю сеть', S.lan_access?('вкл'+(S.forwarding?'':' (forwarding off!)')):'выкл']);
  document.getElementById('st').innerHTML=rows.map(function(r){
    const k=r[0], v=String(r[1]);
    const cls=(v==='да'||v==='поднят'||v==='слушает'||v==='openvpn')?'ok':(v==='нет'||v==='—'||v==='none')?'bad':'';
    return '<div class="row"><span class="k">'+k+'</span><span class="v '+cls+'">'+v+'</span></div>';
  }).join('');
}
async function post(u,body){
  const o={method:'POST',headers:{'X-Auth-Token':T}};
  if(body!==undefined){o.body=body;}
  const r=await fetch(u,o); const j=await r.json().catch(function(){return {};});
  document.getElementById('out').textContent=JSON.stringify(j,null,1);
  setTimeout(load,1500);
}
load(); setInterval(load,10000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "vpn-az"
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _auth(self, u):
        tok = self.headers.get("X-Auth-Token") or (parse_qs(u.query).get("token") or [""])[0]
        return tok == token()

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if not self._auth(u):
            return self._send(403, json.dumps({"error": "auth"}))
        if u.path == "/status.json":
            return self._send(200, json.dumps(status()))
        if u.path == "/api/dns":
            name = (parse_qs(u.query).get("name") or [""])[0]
            if not name:
                return self._send(400, json.dumps({"error": "name?"}))
            try:
                return self._send(200, json.dumps({"name": name, "a": dns_a(name)}))
            except Exception as e:
                return self._send(200, json.dumps({"name": name, "error": str(e)}))
        if u.path == "/api/diag":
            script = ("sh %s status 2>&1; echo '--- tun ---'; ls -l /dev/net/tun 2>&1; "
                      "echo '--- ovpn.log ---'; tail -14 %s/ovpn.log 2>&1; "
                      "echo '--- net.log ---'; tail -8 %s/net.log 2>&1" % (NET_SH, DATA, DATA))
            return self._send(200, json.dumps({"diag": sh(script, timeout=30)}))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        u = urlparse(self.path)
        if not self._auth(u):
            return self._send(403, json.dumps({"error": "auth"}))
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        raw = body
        if body.startswith("conf=") or "conf=" in body[:10]:
            body = parse_qs(body).get("conf", [""])[0]
        q = parse_qs(u.query)

        if u.path == "/api/config":
            if not body.strip():
                return self._send(400, json.dumps({"error": "пустой профиль"}))
            is_ovpn = ("<ca>" in body or "-----BEGIN CERTIFICATE-----" in body) and "remote " in body
            if not is_ovpn and ("[Interface]" not in body or "PrivateKey" not in body):
                return self._send(400, json.dumps({"error": "не похоже ни на .ovpn, ни на wg-конфиг"}))
            path = OVPN_CONF if is_ovpn else WG_CONF
            other = WG_CONF if is_ovpn else OVPN_CONF
            with open(path, "w") as f:
                f.write(body if body.endswith("\n") else body + "\n")
            os.chmod(path, 0o600)
            if os.path.exists(other):
                os.remove(other)
            apply_net("apply")
            return self._send(200, json.dumps({"ok": True, "mode": mode()}))

        if u.path in ("/api/dns_on", "/api/lan"):
            on = (q.get("on") or parse_qs(raw).get("on") or ["1"])[0] not in ("0", "off", "false")
            flag = data_path("dns_on" if u.path == "/api/dns_on" else "lan_access")
            if on:
                with open(flag, "w") as f:
                    f.write("1\n")
            elif os.path.exists(flag):
                os.remove(flag)
            apply_net("lan" if u.path == "/api/lan" else "up")
            return self._send(200, json.dumps({"ok": True, "on": on}))

        if u.path == "/api/restart":
            apply_net("apply")
            return self._send(200, json.dumps({"ok": True, "status": status()}))
        return self._send(404, json.dumps({"error": "not found"}))


def boot():
    threading.Thread(target=egress_loop, daemon=True).start()
    time.sleep(2)
    apply_net("up")
    while True:
        time.sleep(45)
        sh("sh %s watch >> %s/net.log 2>&1" % (NET_SH, DATA), timeout=120)


if __name__ == "__main__":
    token()
    threading.Thread(target=boot, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
