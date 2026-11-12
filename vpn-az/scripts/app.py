#!/usr/bin/env python3
# app.py — статус и API приложения vpn-az (AntiZapret Client для Umbrel).
# Только stdlib. Слушает 0.0.0.0:8666, сеть хоста (network_mode: host).
import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DATA = os.environ.get("DATA", "/data")
PORT = int(os.environ.get("APP_PORT", "8666"))
TOKEN = os.environ.get("APP_PASSWORD", "")
RELAY = os.environ.get("AZ_RELAY_ENDPOINT", "deha.mediaconf.tech:51920")
DNS_PORT = os.environ.get("DNS_PORT", "5399")
WG_CONF = os.path.join(DATA, "wg0.conf")
PHONE_DIR = os.path.join(DATA, "wgphone")
PHONE_CONF = os.path.join(PHONE_DIR, "server.conf")
CLIENTS_DIR = os.path.join(PHONE_DIR, "clients")

EGRESS = {"direct": None, "tunnel": None, "at": 0}


def run(cmd, timeout=8, stdin=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              input=stdin, shell=isinstance(cmd, str)).stdout.strip()
    except Exception:
        return ""


def conf_get(path, key):
    try:
        with open(path) as f:
            for line in f:
                m = re.match(r"\s*%s\s*=\s*(.+)" % re.escape(key), line)
                if m:
                    return m.group(1).strip()
    except OSError:
        pass
    return ""


def iface_exists(name):
    return os.path.exists("/sys/class/net/%s" % name)


def wg_dump(name):
    out = run(["wg", "show", name, "dump"])
    return out.splitlines() if out else []


def wg_stats(name):
    peers = []
    lines = wg_dump(name)
    if len(lines) < 2:
        return {"up": iface_exists(name), "peers": peers}
    for line in lines[1:]:
        f = line.split("\t")
        if len(f) < 8:
            continue
        hs = int(f[4] or 0)
        peers.append({
            "pubkey": f[0][:12],
            "endpoint": f[2],
            "allowed": f[3],
            "handshake_age": (int(time.time()) - hs) if hs else None,
            "rx": int(f[5] or 0),
            "tx": int(f[6] or 0),
        })
    return {"up": True, "peers": peers}


def dns_ok():
    try:
        out = run("ss -lnuH | grep -c ':%s '" % DNS_PORT, timeout=5)
        return int(out or 0) > 0
    except Exception:
        return False


def egress_loop():
    global EGRESS
    while True:
        direct = None
        try:
            out = subprocess.run(
                ["curl", "-s", "--max-time", "5", "https://ifconfig.me"],
                capture_output=True, text=True, timeout=8).stdout.strip()
            if re.fullmatch(r"[0-9.]{7,15}", out):
                direct = out
        except Exception:
            pass
        tunnel = None
        try:
            out = subprocess.run(
                ["curl", "-s", "--max-time", "6", "--interface", "wg0",
                 "https://ifconfig.me"],
                capture_output=True, text=True, timeout=9).stdout.strip()
            if re.fullmatch(r"[0-9.]{7,15}", out):
                tunnel = out
        except Exception:
            pass
        EGRESS = {"direct": EGRESS.get("direct") if EGRESS else direct,
                  "tunnel": tunnel or (EGRESS.get("tunnel") if EGRESS else None),
                  "at": int(time.time())}
        time.sleep(120)


def dns_a(name, port=None, server="127.0.0.1"):
    """Минимальный DNS-запрос A-записи напрямую на локальный резолвер."""
    import socket
    import struct
    import random
    port = int(port or DNS_PORT)
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in name.rstrip(".").split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(q, (server, port))
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
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            out.append(".".join(str(b) for b in data[i:i + 4]))
        i += rdlen
    return out


def status():
    st = {
        "time": int(time.time()),
        "config_present": os.path.exists(WG_CONF),
        "az_address": conf_get(WG_CONF, "Address"),
        "az_endpoint": conf_get(WG_CONF, "Endpoint"),
        "routes": len(run("ip -4 route show dev wg0").splitlines()),
        "dns": {"listening": dns_ok(), "port": DNS_PORT, "override": os.path.exists(os.path.join(DATA, "dns_on")),
                "upstream": os.environ.get("AZ_DNS_UPSTREAM", "")},
        "wg0": wg_stats("wg0"),
        "wgphone": wg_stats("wgphone"),
        "relay": RELAY,
        "egress": EGRESS,
        "forwarding": run(["cat", "/proc/sys/net/ipv4/ip_forward"]) == "1",
    }
    if os.path.exists(PHONE_CONF):
        st["wgphone"]["port"] = conf_get(PHONE_CONF, "ListenPort")
        st["wgphone"]["address"] = conf_get(PHONE_CONF, "Address")
    return st


def peers_list():
    out = []
    if not os.path.isdir(CLIENTS_DIR):
        return out
    for name in sorted(os.listdir(CLIENTS_DIR)):
        if name.endswith(".conf"):
            out.append(name[:-5])
    return out


def genkey():
    return run(["wg", "genkey"])


def pubkey(priv):
    return run(["wg", "pubkey"], stdin=priv + "\n")


def genpsk():
    return run(["wg", "genpsk"])


def ensure_server():
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    if os.path.exists(PHONE_CONF) and conf_get(PHONE_CONF, "PrivateKey"):
        # миграция порта: 51820 занят приложением WireGuard на этом же хосте
        txt = open(PHONE_CONF).read()
        new = re.sub(r"ListenPort\s*=\s*\d+", "ListenPort = 51920", txt)
        if new != txt:
            with open(PHONE_CONF, "w") as f:
                f.write(new)
            os.chmod(PHONE_CONF, 0o600)
        return
    priv = genkey()
    conf = ("[Interface]\nAddress = 10.77.0.1/24\nListenPort = 51920\nMTU = 1280\n"
            "PrivateKey = %s\n" % priv)
    with open(PHONE_CONF, "w") as f:
        f.write(conf)
    os.chmod(PHONE_CONF, 0o600)


def add_peer(name):
    name = re.sub(r"[^A-Za-z0-9_-]", "", name)[:32]
    if not name:
        return None, "пустое имя"
    ensure_server()
    conf = open(PHONE_CONF).read()
    if "# Client = %s\n" % name in conf:
        return None, "такой профиль уже есть"
    used = set(re.findall(r"AllowedIPs = 10\.77\.0\.(\d+)", conf))
    ip = next((i for i in range(2, 250) if str(i) not in used), None)
    if ip is None:
        return None, "кончились адреса"
    cli_priv = genkey()
    cli_pub = pubkey(cli_priv)
    srv_pub = pubkey(conf_get(PHONE_CONF, "PrivateKey"))
    psk = genpsk()
    with open(PHONE_CONF, "a") as f:
        f.write("\n# Client = %s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\n"
                "AllowedIPs = 10.77.0.%d/32\n" % (name, cli_pub, psk, ip))
    # порт в профиле всегда равен фактическому ListenPort сервера
    host = RELAY.rsplit(":", 1)[0] if ":" in RELAY else RELAY
    port = conf_get(PHONE_CONF, "ListenPort") or "51920"
    client = ("[Interface]\nPrivateKey = %s\nAddress = 10.77.0.%d/32\n"
              "DNS = 10.77.0.1\nMTU = 1280\n\n[Peer]\nPublicKey = %s\n"
              "PresharedKey = %s\nEndpoint = %s:%s\nAllowedIPs = 0.0.0.0/0\n"
              "PersistentKeepalive = 25\n" % (cli_priv, ip, srv_pub, psk, host, port))
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    with open(os.path.join(CLIENTS_DIR, name + ".conf"), "w") as f:
        f.write(client)
    os.chmod(os.path.join(CLIENTS_DIR, name + ".conf"), 0o600)
    subprocess.Popen(["/bin/sh", "-c", "sh %s/net.sh up >> %s/net.log 2>&1" % (DATA, DATA)])
    return client, None


PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>AntiZapret Client</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{background:#0f1216;color:#dfe6ee;font:15px/1.5 system-ui,sans-serif;margin:0;padding:24px}
h1{font-size:19px;margin:0 0 4px} .m{color:#8b97a5;font-size:13px;margin-bottom:18px}
table{border-collapse:collapse;width:100%;max-width:760px;margin-bottom:22px}
td{padding:6px 10px;border-bottom:1px solid #1d232b} td:first-child{color:#8b97a5;width:44%}
.ok{color:#4ade80} .bad{color:#f87171} .warn{color:#fbbf24}
textarea,button,input{font:inherit;background:#151a21;color:#dfe6ee;border:1px solid #26303b;border-radius:8px;padding:8px}
textarea{width:100%;max-width:760px;height:170px} button{cursor:pointer;background:#1d2733}
pre{background:#151a21;border:1px solid #26303b;border-radius:8px;padding:12px;overflow:auto;max-width:760px}
</style></head><body>
<h1>AntiZapret Client</h1>
<div class="m">Umbrel &rarr; деха · обновлено <span id="t">__TS__</span></div>
<table id="s"></table>
<details><summary>Загрузить wg0.conf (сплит-профиль AZ)</summary>
<form method="post" action="/api/config">
<input type="hidden" name="token" value="__TOKEN__">
<textarea name="conf" placeholder="[Interface]&#10;PrivateKey = ...&#10;Address = 10.29.8.7/32&#10;..."></textarea>
<p><button type="submit">Сохранить и применить</button></p></form></details>
<details><summary>Профили для телефона</summary>
<form method="post" action="/api/peer">
<input type="hidden" name="token" value="__TOKEN__">
<input name="name" placeholder="имя устройства"><button type="submit">Создать профиль</button></form>
<pre id="peers">—</pre></details>
<script>
async function upd(){
 const j = await (await fetch('/status.json')).json();
 const rows = [
  ['wg0', j.wg0.up ? '<span class=ok>поднят</span>' : '<span class=bad>нет</span>'],
  ['AZ-адрес', j.az_address || '—'],
  ['эндпоинт', j.az_endpoint || '—'],
  ['маршрутов в туннель', j.routes],
  ['рукопожатие', j.wg0.peers.length ? (j.wg0.peers[0].handshake_age === null ? '<span class=bad>никогда</span>' :
      (j.wg0.peers[0].handshake_age < 180 ? '<span class=ok>'+j.wg0.peers[0].handshake_age+' c</span>' :
       '<span class=warn>'+j.wg0.peers[0].handshake_age+' c</span>')) : '—'],
  ['DNS-резолвер', j.dns.listening ? '<span class=ok>:'+j.dns.port+' → '+j.dns.upstream+'</span>' : '<span class=bad>не слушает</span>'],
  ['выход напрямую', j.egress.direct || '—'],
  ['выход через туннель', j.egress.tunnel || '—'],
  ['WG-сервер (телефон)', (j.wgphone.up ? '<span class=ok>10.77.0.1:'+(j.wgphone.port||'')+'</span>' : '<span class=bad>не поднят</span>')],
  ['релей снаружи', j.relay],
 ];
 document.getElementById('s').innerHTML = rows.map(r=>'<tr><td>'+r[0]+'</td><td>'+r[1]+'</td></tr>').join('');
 document.getElementById('t').textContent = new Date(j.time*1000).toLocaleTimeString();
 const p = await (await fetch('/api/peers')).json();
 document.getElementById('peers').textContent = p.peers.length ? p.peers.join('\\n') : '—';
}
upd(); setInterval(upd, 15000);
</script></body></html>"""

API_TOKEN = ""


def page():
    return (PAGE.replace("__TS__", time.strftime("%H:%M:%S"))
                .replace("__TOKEN__", API_TOKEN))


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

    def _auth(self, raw):
        if TOKEN and self.headers.get("X-Auth-Token") == TOKEN:
            return True
        if raw and API_TOKEN:
            if parse_qs(raw).get("token", [""])[0] == API_TOKEN:
                return True
        return False

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, page(), "text/html; charset=utf-8")
        if u.path == "/status.json":
            return self._send(200, json.dumps(status()))
        if u.path == "/api/peers":
            return self._send(200, json.dumps({"peers": peers_list()}))
        if u.path == "/api/diag":
            script = ("sh %s/net.sh status 2>&1; echo '--- addr ---'; ip -4 addr show dev wg0 2>&1; "
                      "echo '--- wg ---'; wg show wg0 2>&1; echo '--- routes ---'; "
                      "ip -4 route show dev wg0 2>&1 | head -5; echo '--- net.log ---'; "
                      "tail -15 %s/net.log 2>&1; echo '--- app.log ---'; tail -5 %s/app.log 2>&1; "
                      "echo '--- dnsmasq ---'; tail -5 %s/dnsmasq.log 2>&1" % (DATA, DATA, DATA, DATA))
            out = run(["/bin/sh", "-c", script], timeout=20)
            return self._send(200, json.dumps({"diag": out}))
        if u.path == "/api/dns":
            name = (parse_qs(u.query).get("name") or [""])[0]
            if not name:
                return self._send(400, json.dumps({"error": "name?"}))
            try:
                return self._send(200, json.dumps({"name": name, "a": dns_a(name)}))
            except Exception as e:
                return self._send(200, json.dumps({"name": name, "error": str(e)}))
        if u.path.startswith("/peers/") and u.path.endswith(".conf"):
            name = os.path.basename(u.path)[:-5]
            path = os.path.join(CLIENTS_DIR, name + ".conf")
            if os.path.exists(path):
                return self._send(200, open(path).read(), "text/plain; charset=utf-8")
            return self._send(404, json.dumps({"error": "not found"}))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        if not self._auth(raw):
            return self._send(403, json.dumps({"error": "forbidden"}))
        if u.path == "/api/config":
            conf = raw
            if raw.startswith("conf=") or "conf=" in raw[:10]:
                conf = parse_qs(raw).get("conf", [""])[0]
            if "[Interface]" not in conf or "PrivateKey" not in conf or "[Peer]" not in conf:
                return self._send(400, json.dumps({"error": "это не похоже на wg-конфиг"}))
            with open(WG_CONF, "w") as f:
                f.write(conf if conf.endswith("\n") else conf + "\n")
            os.chmod(WG_CONF, 0o600)
            subprocess.Popen(["/bin/sh", "-c", "sh %s/net.sh apply >> %s/net.log 2>&1" % (DATA, DATA)])
            return self._send(200, json.dumps({"ok": True}))
        if u.path == "/api/dns_on":
            on = (parse_qs(raw).get("on", ["1"])[0] or "1")
            flag = os.path.join(DATA, "dns_on")
            if on in ("0", "off", "false"):
                if os.path.exists(flag):
                    os.remove(flag)
            else:
                with open(flag, "w") as f:
                    f.write("1\n")
            subprocess.Popen(["/bin/sh", "-c", "sh %s/net.sh up >> %s/net.log 2>&1" % (DATA, DATA)])
            return self._send(200, json.dumps({"ok": True, "override": os.path.exists(flag)}))
        if u.path == "/api/peer":
            name = parse_qs(raw).get("name", ["phone"])[0]
            client, err = add_peer(name)
            if err:
                return self._send(400, json.dumps({"error": err}))
            return self._send(200, json.dumps({"name": name, "config": client}))
        return self._send(404, json.dumps({"error": "not found"}))


def main():
    global API_TOKEN
    os.makedirs(DATA, exist_ok=True)
    token_file = os.path.join(DATA, "api_token")
    if os.path.exists(token_file):
        API_TOKEN = open(token_file).read().strip()
    if not API_TOKEN:
        API_TOKEN = os.urandom(16).hex()
        with open(token_file, "w") as f:
            f.write(API_TOKEN)
        os.chmod(token_file, 0o600)
    ensure_server()
    threading.Thread(target=egress_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.serve_forever()


if __name__ == "__main__":
    main()
