#!/usr/bin/env python3
# app.py — VPN AZ для Umbrel, v3: библиотека профилей (.ovpn/.wg), connect/disconnect,
# автооткат при потере связи, статус, PWA. Только stdlib.
import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import threading
import time
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "3.1.0"
DATA = os.environ.get("DATA", "/data")
PORT = int(os.environ.get("APP_PORT", "8666"))
NET_SH = os.path.join(DATA, "net.sh")
PROFILES = os.path.join(DATA, "profiles")
STATE = os.path.join(DATA, "state")
DNS_PORT = os.environ.get("DNS_PORT", "5399")
PASSWORD = (os.environ.get("APP_PASSWORD") or "").strip()
MAX_BODY = 8 * 1024 * 1024

EGRESS = {"direct": None, "tunnel": None, "at": 0}
CONN_LOCK = threading.Lock()
TOKEN = ""
COOKIE = "vpnaz"


# ----------------------------------------------------------------- утилиты
def run(cmd, timeout=12):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           shell=isinstance(cmd, str))
        return (r.stdout or "").strip()
    except Exception:
        return ""


def sh(script, timeout=120):
    try:
        r = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:  # noqa: BLE001
        return "err: %s" % e


def net(*args, timeout=180):
    return sh("sh %s %s >> %s/net.log 2>&1" % (NET_SH, " ".join(args), DATA), timeout=timeout)


def read(p, default=""):
    try:
        with open(p, errors="ignore") as f:
            return f.read().strip()
    except OSError:
        return default


def write(p, s):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(s)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def api_token():
    global TOKEN
    if TOKEN:
        return TOKEN
    p = os.path.join(DATA, "api_token")
    TOKEN = read(p)
    if not TOKEN:
        TOKEN = secrets.token_hex(24)
        write(p, TOKEN)
    return TOKEN


def session_value():
    return hmac.new(api_token().encode(), b"vpnaz-session-v1", hashlib.sha256).hexdigest()


def state(name, default=""):
    return read(os.path.join(STATE, name), default)


def phase():
    return state("phase") or "off"


# ----------------------------------------------------------------- профили
def slugify(name):
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", (name or "").lower()).strip("-.")
    s = re.sub(r"-+", "-", s)[:40]
    return s or "profile"


def new_id(name):
    base = slugify(name)
    pid = base
    i = 2
    while os.path.isdir(os.path.join(PROFILES, pid)):
        pid = "%s-%d" % (base, i)
        i += 1
    return pid


def profile_dir(pid):
    return os.path.join(PROFILES, pid)


def find_conf(pid):
    d = profile_dir(pid)
    if not os.path.isdir(d):
        return ""
    names = sorted(os.listdir(d))
    for ext in (".ovpn", ".conf"):
        for n in names:
            if n.lower().endswith(ext):
                return os.path.join(d, n)
    return ""


def conf_type(path):
    return "openvpn" if path.lower().endswith(".ovpn") else ("wireguard" if path.endswith(".conf") else "none")


def conf_meta(path):
    meta = {"remotes": [], "full_tunnel": False, "auth_user_pass": False, "external_files": []}
    if not path or not os.path.exists(path):
        return meta
    txt = read(path)
    for line in txt.splitlines():
        s = line.strip()
        m = re.match(r"remote\s+(\S+)\s+(\d+)", s)
        if m:
            meta["remotes"].append("%s:%s" % (m.group(1), m.group(2)))
        if re.search(r"redirect-gateway|^route\s+0\.0\.0\.0\s+0\.0\.0\.0", s):
            meta["full_tunnel"] = True
        if s.startswith("auth-user-pass"):
            meta["auth_user_pass"] = True
        m = re.match(r"(ca|cert|key|tls-auth|tls-crypt|pkcs12|auth-user-pass)\s+(\S+)$", s)
        if m and not m.group(2).startswith("<") and "/" not in m.group(2) and not m.group(2).startswith("["):
            meta["external_files"].append(m.group(2))
    if path.endswith(".conf"):
        if re.search(r"AllowedIPs\s*=.*0\.0\.0\.0/0", txt):
            meta["full_tunnel"] = True
        m = re.search(r"Endpoint\s*=\s*(\S+)", txt)
        if m:
            meta["remotes"].append(m.group(1))
    return meta


def profile(pid):
    d = profile_dir(pid)
    if not os.path.isdir(d):
        return None
    pj = {}
    try:
        pj = json.loads(read(os.path.join(d, "profile.json"), "{}") or "{}")
    except Exception:  # noqa: BLE001
        pj = {}
    conf = find_conf(pid)
    meta = conf_meta(conf)
    files = sorted(os.listdir(d))
    return {
        "id": pid,
        "name": pj.get("name") or pid,
        "type": "openvpn" if pj.get("type") == "openvpn" or conf.endswith(".ovpn") else
                ("wireguard" if conf else "none"),
        "created": pj.get("created") or int(os.path.getmtime(d)),
        "config": os.path.basename(conf) if conf else "",
        "remotes": meta["remotes"],
        "full_tunnel": meta["full_tunnel"],
        "has_creds": os.path.exists(os.path.join(d, "cred.txt")),
        "files": [f for f in files if f != "profile.json"],
        "missing": [f for f in meta["external_files"] if not os.path.exists(os.path.join(d, f))],
    }


def profiles():
    if not os.path.isdir(PROFILES):
        return []
    out = [profile(p) for p in sorted(os.listdir(PROFILES)) if os.path.isdir(os.path.join(PROFILES, p))]
    return [p for p in out if p and p["config"]]


def save_profile(pid, name, ptype):
    write(os.path.join(profile_dir(pid), "profile.json"),
          json.dumps({"name": name, "type": ptype, "created": int(time.time())}, ensure_ascii=False))


def import_files(files, name="", user="", password=""):
    """files: список (filename, bytes). Возвращает (id, warnings)."""
    cfg = None
    extras = []
    warnings = []
    for fn, blob in files:
        low = fn.lower()
        if low.endswith(".ovpn") or low.endswith(".conf"):
            if cfg is None or low.endswith(".ovpn"):
                cfg = (fn, blob)
        elif low.endswith(".zip"):
            warnings.extend(("zip внутри загрузки пропущен: %s" % fn,))
        else:
            extras.append((fn, blob))
    if cfg is None:
        raise ValueError("в загрузке нет файла .ovpn или .conf")
    fname, blob = cfg
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        text = blob.decode("latin-1")
    if not text.strip():
        raise ValueError("пустой конфиг")
    is_ovpn = fname.lower().endswith(".ovpn")
    if is_ovpn and "remote " not in text and "remote " not in text.replace("\r", ""):
        raise ValueError("в .ovpn нет строки remote — это не профиль подключения")
    if not is_ovpn and ("[Interface]" not in text or "PrivateKey" not in text):
        raise ValueError("в .conf нет [Interface]/PrivateKey — это не WireGuard-конфиг")

    base_name = name or re.sub(r"\.(ovpn|conf)$", "", os.path.basename(fname))
    pid = new_id(base_name)
    d = profile_dir(pid)
    os.makedirs(d, exist_ok=True)

    with open(os.path.join(d, os.path.basename(fname)), "w") as f:
        f.write(text if text.endswith("\n") else text + "\n")
    for fn, blob in extras:
        target = os.path.join(d, os.path.splitext(os.path.basename(fn))[0] + os.path.splitext(fn)[1])
        with open(target, "wb") as f:
            f.write(blob)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass

    pj = {"name": base_name, "type": "openvpn" if is_ovpn else "wireguard", "created": int(time.time())}
    write(os.path.join(d, "profile.json"), json.dumps(pj, ensure_ascii=False))

    meta = profile(pid) or {}
    if is_ovpn and user:
        write(os.path.join(d, "cred.txt"), "%s\n%s\n" % (user, password))
        meta = profile(pid) or {}
        warnings.append("логин/пароль сохранены в cred.txt")
    if meta.get("missing"):
        warnings.append("в профиле упомянуты файлы, которых нет: " + ", ".join(meta["missing"]))
    return pid, warnings


def import_any(body, ctype, query):
    """Разбирает multipart / zip / сырой текст. Возвращает (id, warnings)."""
    name = (query.get("name") or [""])[0]
    user = (query.get("user") or [""])[0]
    pwd = (query.get("pass") or [""])[0]

    if body[:2] == b"PK":
        zf = zipfile.ZipFile(io.BytesIO(body))
        files = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            inner = os.path.basename(info.filename)
            if not inner or inner.startswith("."):
                continue
            files.append((inner, zf.read(info)))
        return import_files(files, name, user, pwd)

    if "multipart/form-data" in (ctype or ""):
        m = re.search(r"boundary=([^;]+)", ctype)
        if not m:
            raise ValueError("нет boundary в multipart")
        boundary = ("--" + m.group(1).strip('"')).encode()
        files, fields = [], {}
        for part in body.split(boundary):
            part = part.strip(b"\r\n")
            if not part or part in (b"--", b"--\r\n"):
                continue
            if b"\r\n\r\n" not in part:
                continue
            head, data = part.split(b"\r\n\r\n", 1)
            head_s = head.decode("utf-8", "replace")
            fm = re.search(r'name="([^"]*)"(?:;\s*filename="([^"]*)")?', head_s)
            if not fm:
                continue
            fname = fm.group(2)
            data = data.rstrip(b"\r\n")
            if fname:
                files.append((fname, data))
            else:
                fields[fm.group(1)] = data.decode("utf-8", "replace")
        name = name or fields.get("name", "")
        user = user or fields.get("user", "")
        pwd = pwd or fields.get("pass", "")
        return import_files(files, name, user, pwd)

    text = body.decode("utf-8", "replace")
    if text.startswith("conf="):
        text = parse_qs(text).get("conf", [""])[0]
    if not text.strip():
        raise ValueError("пустой профиль")
    ext = ".conf" if "[Interface]" in text and "PrivateKey" in text else ".ovpn"
    return import_files([("profile" + ext, text.encode())], name, user, pwd)


# ----------------------------------------------------------------- сеть/статус
def iface_exists(n):
    return os.path.exists("/sys/class/net/%s" % n)


def tun_dev():
    if iface_exists("azvpn"):
        return "azvpn"
    if iface_exists("wg0"):
        return "wg0"
    return ""


def tun_ip():
    out = run(["ip", "-4", "-o", "addr", "show", "dev", tun_dev() or "azvpn"])
    m = re.search(r"inet ([0-9.]+)/", out)
    return m.group(1) if m else ""


def wg_peers():
    peers = []
    for line in run(["wg", "show", "wg0", "dump"]).splitlines()[1:]:
        f = line.split("\t")
        if len(f) >= 8:
            hs = int(f[4] or 0)
            peers.append({"endpoint": f[2], "allowed": f[3],
                          "handshake_age": (int(time.time()) - hs) if hs else None,
                          "rx": int(f[5] or 0), "tx": int(f[6] or 0)})
    return peers


def routes_count():
    dev = tun_dev()
    return len(run(["ip", "-4", "route", "show", "dev", dev]).splitlines()) if dev else 0


def default_via_tunnel():
    dev = tun_dev()
    if not dev:
        return False
    return bool(re.search(r"^(0\.0\.0\.0/1|128\.0\.0\.0/1|default)", run(["ip", "-4", "route", "show", "dev", dev]), re.M))


def dns_listening():
    out = run("ss -lnuH 2>/dev/null | grep -c ':%s '" % DNS_PORT)
    try:
        return int((out or "0").strip() or 0) > 0
    except ValueError:
        return False


def egress_loop():
    global EGRESS
    while True:
        direct = run(["curl", "-s", "--max-time", "6", "https://ifconfig.me"])
        if not re.fullmatch(r"[0-9.]{7,15}", direct or ""):
            direct = None
        tunnel = None
        dev = tun_dev()
        if dev:
            out = run(["curl", "-s", "--max-time", "8", "--interface", dev, "https://ifconfig.me"])
            if re.fullmatch(r"[0-9.]{7,15}", out or ""):
                tunnel = out
        EGRESS = {"direct": direct or EGRESS.get("direct"), "tunnel": tunnel or EGRESS.get("tunnel"),
                  "at": int(time.time())}
        time.sleep(90)


def status():
    ph = phase()
    aid = state("active")
    prof = profile(aid) if aid else None
    dev = tun_dev()
    st = {
        "version": VERSION,
        "time": int(time.time()),
        "phase": ph,
        "error": state("error"),
        "since": int(state("since") or 0),
        "active_id": aid,
        "active": prof,
        "profiles": profiles(),
        "tunnel": {
            "dev": dev,
            "ip": tun_ip() if dev else "",
            "routes": routes_count(),
            "default_via_tunnel": default_via_tunnel(),
            "alive": bool(dev),
            "peers": wg_peers() if dev == "wg0" else [],
        },
        "dns": {"port": DNS_PORT, "listening": dns_listening(),
                "override": os.path.exists(os.path.join(STATE, "dns_on"))},
        "autostart": os.path.exists(os.path.join(STATE, "autostart")),
        "lan": {"nat": os.path.exists(os.path.join(STATE, "lan_access"))},
        "egress": EGRESS,
        "direct_ok": probe_direct(),
    }
    return st


def probe_direct():
    for url in ("http://1.1.1.1/", "https://1.1.1.1/"):
        code = run(["curl", "-s", "-o", "/dev/null", "-m", "5", "-w", "%{http_code}", url])
        if code in ("200", "301", "302", "403", "404"):
            return True
    return False


def check_url(url, via=""):
    """Проверка сайта с сервера: via=tunnel — принудительно через интерфейс туннеля."""
    if not re.match(r"^https?://[^\s]+$", url or ""):
        return {"ok": False, "error": "нужен адрес вида https://site"}
    # -4: туннель IPv4-only, иначе curl уходит в AAAA и падает мгновенно
    cmd = ["curl", "-sS", "-4", "-o", "/dev/null", "-m", "15", "-k",
           "-w", "%{http_code} %{time_total} %{remote_ip}"]
    if via == "tunnel":
        dev = tun_dev()
        if not dev:
            return {"ok": False, "error": "туннель не поднят"}
        cmd += ["--interface", dev]
    out = run(cmd + [url], timeout=25)
    parts = (out or "").split()
    if len(parts) < 3 or not parts[0].isdigit():
        return {"ok": False, "via": via or "direct", "error": (out or "нет ответа")[:200]}
    code = int(parts[0])
    return {"ok": code < 400, "via": via or "direct", "code": code,
            "time": round(float(parts[1]), 2), "ip": parts[2]}


def do_connect(pid):
    if not CONN_LOCK.acquire(blocking=False):
        return False
    try:
        write(os.path.join(STATE, "phase"), "connecting")
        if os.path.exists(os.path.join(STATE, "error")):
            os.remove(os.path.join(STATE, "error"))
        net("disconnect", timeout=60)
        write(os.path.join(STATE, "active"), pid)
        write(os.path.join(STATE, "phase"), "connecting")
        net("connect", pid, timeout=240)
        return phase() == "on"
    finally:
        CONN_LOCK.release()


def do_disconnect():
    net("disconnect", timeout=90)


def watch_loop():
    while True:
        time.sleep(30)
        try:
            net("watch", timeout=120)
        except Exception:  # noqa: BLE001
            pass


def boot():
    os.makedirs(PROFILES, exist_ok=True)
    os.makedirs(STATE, exist_ok=True)
    threading.Thread(target=egress_loop, daemon=True).start()
    threading.Thread(target=watch_loop, daemon=True).start()
    time.sleep(2)
    ph = phase()
    auto = os.path.exists(os.path.join(STATE, "autostart")) and bool(state("active"))
    if ph == "connecting":
        # контейнер упал посреди подключения — не оставляем полутуннель
        net("disconnect", timeout=60)
        write(os.path.join(STATE, "phase"), "failed")
        write(os.path.join(STATE, "error"), "подключение было прервано перезапуском — включи заново")
    elif auto:
        # автостарт: поднимаем последний профиль, даже если штатная остановка сняла туннель
        threading.Thread(target=lambda: do_connect(state("active")), daemon=True).start()
    elif ph == "on" and state("active"):
        threading.Thread(target=lambda: do_connect(state("active")), daemon=True).start()


# ----------------------------------------------------------------- иконки PWA
def _png(size, pixels):
    raw = b"".join(b"\x00" + bytes(v for px in pixels[y] for v in px) for y in range(size))

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def _icon(size):
    bg = (14, 17, 22)
    accent = (61, 220, 132)
    white = (245, 248, 250)
    px: list = [[bg for _ in range(size)] for _ in range(size)]
    c = size / 2.0
    r_outer = size * 0.40
    r_inner = size * 0.34
    # круг-подложка
    for y in range(size):
        for x in range(size):
            d = ((x - c) ** 2 + (y - c) ** 2) ** 0.5
            if d <= r_outer:
                px[y][x] = accent if d <= r_inner else (30, 60, 45)
    # щит внутри
    top = size * 0.32
    bot = size * 0.70
    half = size * 0.11
    for y in range(int(top), int(bot * 1.02)):
        t = (y - top) / (bot - top)
        w = half * (1.0 - t * 0.55)
        if y > bot:
            w = half * 0.45 * max(0.0, 1 - (y - bot) / (size * 0.08))
        for x in range(int(c - w), int(c + w)):
            if 0 <= x < size and 0 <= y < size:
                px[y][x] = white
    # замок: дужка и тело
    lw = size * 0.045
    ring = size * 0.13
    for y in range(size):
        for x in range(size):
            dx, dy = x - c, y - (c - size * 0.03)
            d = (dx * dx + dy * dy) ** 0.5
            if y < c - size * 0.03 and abs(d - ring) <= lw * 0.55:
                px[y][x] = bg
    body_top = int(c - size * 0.01)
    body_bot = int(c + size * 0.09)
    body_l = int(c - size * 0.075)
    body_r = int(c + size * 0.075)
    for y in range(body_top, body_bot):
        for x in range(body_l, body_r):
            px[y][x] = bg
    return _png(size, px)


ICONS = {}


def icon(size):
    if size not in ICONS:
        ICONS[size] = _icon(size)
    return ICONS[size]


MANIFEST = {
    "name": "VPN AZ",
    "short_name": "VPN AZ",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0e1116",
    "theme_color": "#0e1116",
    "icons": [
        {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
        {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
    ],
}


# ----------------------------------------------------------------- UI
LOGIN_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0e1116">
<title>VPN AZ</title><style>
body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#0e1116;
color:#e8ecf1;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
form{background:#161a21;border:1px solid #232936;border-radius:16px;padding:26px;width:min(340px,86vw)}
h1{font-size:18px;margin:0 0 4px}p{color:#8b93a1;font-size:13px;margin:0 0 18px}
input{width:100%;box-sizing:border-box;background:#0e1116;border:1px solid #2b3143;color:#e8ecf1;
border-radius:10px;padding:11px 12px;font-size:15px;margin-bottom:12px}
button{width:100%;background:#3ddc84;color:#08110c;border:0;border-radius:10px;padding:12px;
font-size:15px;font-weight:600;cursor:pointer}
</style></head><body>
<form method="post" action="/api/login">
  <h1>VPN AZ</h1><p>Пароль приложения — в карточке приложения в Umbrel</p>
  <input type="password" name="password" placeholder="пароль" autofocus autocomplete="current-password">
  <button type="submit">Войти</button>
</form></body></html>"""

PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0e1116"><link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/icon-192.png">
<title>VPN AZ</title><style>
*{box-sizing:border-box}
body{margin:0;background:#0e1116;color:#e8ecf1;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
padding:18px 16px calc(28px + env(safe-area-inset-bottom));max-width:680px;margin:0 auto}
h1{font-size:17px;margin:0;letter-spacing:.2px}
.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.pill{font-size:12px;padding:4px 10px;border-radius:999px;background:#1b2029;color:#8b93a1;border:1px solid #262c38}
.pill.on{background:#0f2a1e;color:#3ddc84;border-color:#1d4a34}
.pill.bad{background:#2a1414;color:#ff6b6b;border-color:#4a2020}
.power-wrap{display:flex;flex-direction:column;align-items:center;gap:12px;margin:6px 0 22px}
.power{width:150px;height:150px;border-radius:50%;border:0;cursor:pointer;position:relative;
background:radial-gradient(circle at 50% 40%,#1d2330,#141821);box-shadow:inset 0 0 0 1px #262d3b,0 8px 30px #0006;
transition:transform .12s ease,box-shadow .2s ease;display:flex;align-items:center;justify-content:center}
.power:active{transform:scale(.97)}
.power svg{width:54px;height:54px;fill:#8b93a1;transition:fill .2s}
.power.on{background:radial-gradient(circle at 50% 40%,#1e5f3f,#0e2a1c);box-shadow:inset 0 0 0 1px #2e7d52,0 0 40px #3ddc8440}
.power.on svg{fill:#3ddc84}
.power.busy svg{fill:#f0b429}
.power.err{background:radial-gradient(circle at 50% 40%,#4a2020,#221414);box-shadow:inset 0 0 0 1px #7d2e2e}
.power.err svg{fill:#ff6b6b}
.ptitle{font-size:16px;font-weight:600}
.psub{font-size:13px;color:#8b93a1;text-align:center;max-width:300px}
.psub.bad{color:#ff8080}
.card{background:#161a21;border:1px solid #232936;border-radius:14px;padding:14px;margin-bottom:12px}
.sec{font-size:12px;letter-spacing:.6px;text-transform:uppercase;color:#6b7385;margin:18px 0 8px}
.prof{display:flex;align-items:center;gap:12px;padding:12px;border-radius:12px;border:1px solid #232936;
background:#161a21;margin-bottom:8px;cursor:pointer;transition:border-color .15s}
.prof:hover{border-color:#33405a}
.prof.sel{border-color:#3ddc84;background:#132219}
.dot{width:9px;height:9px;border-radius:50%;background:#2f3746;flex:0 0 9px}
.prof.sel .dot{background:#3ddc84;box-shadow:0 0 8px #3ddc84}
.pname{font-weight:600;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pmeta{font-size:12px;color:#7d8698;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.acts{margin-left:auto;display:flex;gap:6px;flex:0 0 auto}
.ico{background:#1e2431;border:1px solid #2b3344;color:#9aa4b6;border-radius:9px;padding:6px 9px;
font-size:12px;cursor:pointer}
.ico:hover{background:#262e3d;color:#e8ecf1}
.row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #1e222d}
.row:last-child{border-bottom:0;padding-bottom:0}
.k{color:#8b93a1;font-size:13px}.v{font-variant-numeric:tabular-nums;font-size:13px;text-align:right;word-break:break-all}
.ok{color:#3ddc84}.bad{color:#ff6b6b}
.sw{width:44px;height:26px;border-radius:999px;background:#2a3242;position:relative;cursor:pointer;flex:0 0 44px;transition:background .18s}
.sw:after{content:"";position:absolute;top:3px;left:3px;width:20px;height:20px;border-radius:50%;background:#8b93a1;transition:.18s}
.sw.on{background:#1e5f3f}.sw.on:after{left:21px;background:#3ddc84}
button.primary{width:100%;background:#3ddc84;color:#08110c;border:0;border-radius:12px;padding:13px;
font-size:15px;font-weight:600;cursor:pointer;margin-top:4px}
button.ghost{width:100%;background:#1a1f29;color:#c7cede;border:1px solid #2b3344;border-radius:12px;
padding:12px;font-size:14px;cursor:pointer}
dialog{border:0;border-radius:16px;background:#141821;color:#e8ecf1;padding:18px;width:min(560px,94vw)}
dialog::backdrop{background:#000a}
dialog h2{font-size:16px;margin:0 0 12px}
input[type=text],input[type=password],textarea{width:100%;background:#0e1116;border:1px solid #2b3143;
color:#e8ecf1;border-radius:10px;padding:10px 11px;font:14px/1.4 ui-monospace,monospace;margin-bottom:9px}
textarea{height:130px;resize:vertical}
label{font-size:12px;color:#8b93a1;display:block;margin:10px 0 4px}
pre{white-space:pre-wrap;font:11px/1.45 ui-monospace,monospace;color:#b9c0cf;max-height:280px;overflow:auto;
background:#0e1116;border-radius:10px;padding:10px;margin:8px 0 0}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #3ddc8440;border-top-color:#3ddc84;
border-radius:50%;animation:r 1s linear infinite;vertical-align:-2px;margin-right:6px}
@keyframes r{to{transform:rotate(360deg)}}
.hint{font-size:12px;color:#7d8698;margin-top:8px}
</style></head><body>
<div class="top"><h1>VPN AZ</h1><span class="pill" id="pill">…</span></div>

<div class="power-wrap">
  <button class="power" id="power" onclick="toggle()" aria-label="Включить или выключить">
    <svg viewBox="0 0 24 24"><path d="M13 3h-2v10h2V3zm4.83 2.17-1.42 1.42A6.92 6.92 0 0 1 19 12a7 7 0 1 1-14 0c0-2.14.96-4.05 2.59-5.41L6.17 5.17A8.93 8.93 0 0 0 3 12a9 9 0 1 0 14.83-6.83z"/></svg>
  </button>
  <div class="ptitle" id="ptitle">Выключено</div>
  <div class="psub" id="psub">Выбери профиль и нажми кнопку</div>
</div>

<div class="card">
  <div class="row"><span class="k">Внешний IP напрямую</span><span class="v" id="e1">—</span></div>
  <div class="row"><span class="k">Внешний IP через туннель</span><span class="v ok" id="e2">—</span></div>
  <div class="row"><span class="k">Адрес в туннеле</span><span class="v" id="tip">—</span></div>
  <div class="row"><span class="k">Весь трафик через VPN</span><span class="v" id="full">—</span></div>
</div>

<div class="sec">Профили</div>
<div id="profiles"></div>
<button class="ghost" onclick="openImport()">+ Добавить профиль</button>

<div class="sec">Сервис</div>
<div class="card">
  <div class="row"><span class="k">Перехват DNS всех приложений</span><div class="sw" id="swdns" onclick="setOpt('dns')"></div></div>
  <div class="row"><span class="k">Включать туннель при запуске</span><div class="sw" id="swauto" onclick="setOpt('auto')"></div></div>
  <div class="row"><span class="k">NAT в домашнюю сеть</span><div class="sw" id="swlan" onclick="setOpt('lan')"></div></div>
</div>
<button class="ghost" onclick="diag()">Диагностика и журнал</button>

<dialog id="imp">
  <h2>Новый профиль</h2>
  <label>Файлы: .ovpn / .conf (+ ca.crt, ключи — можно пакетом)</label>
  <input type="file" id="files" multiple style="margin-bottom:10px">
  <label>…или вставь текст конфига</label>
  <textarea id="conftext" placeholder="client&#10;dev tun&#10;remote 1.2.3.4 1194&#10;..."></textarea>
  <label>Логин/пароль, если провайдер их требует</label>
  <input type="text" id="u" placeholder="логин (необязательно)" autocomplete="off">
  <input type="password" id="p" placeholder="пароль (необязательно)" autocomplete="new-password">
  <label>Название профиля</label>
  <input type="text" id="nm" placeholder="например: KZ полный туннель">
  <button class="primary" onclick="doImport()">Добавить</button>
  <button class="ghost" style="margin-top:8px" onclick="document.getElementById('imp').close()">Отмена</button>
  <pre id="impout"></pre>
</dialog>

<dialog id="dlg"><h2 id="dlgt">Журнал</h2><pre id="diagout">загрузка…</pre>
<button class="ghost" onclick="document.getElementById('dlg').close()">Закрыть</button></dialog>

<script>
let S={}, busy=false;
async function api(path,opt){
  const r=await fetch(path,Object.assign({credentials:'same-origin'},opt||{}));
  if(r.status===401){location.href='/';return {};}
  return r.json().catch(function(){return {};});
}
async function load(){
  try{ S=await api('/api/status'); }catch(e){ return; }
  render();
}
function fmt(n){ n=+n||0; if(n>1073741824)return (n/1073741824).toFixed(1)+' ГБ';
  if(n>1048576)return (n/1048576).toFixed(1)+' МБ'; if(n>1024)return (n/1024).toFixed(0)+' КБ'; return n+' Б'; }
function dur(s){ if(!s||s<1)return '—'; s=Math.floor(s); const h=Math.floor(s/3600),m=Math.floor(s%3600/60);
  return (h?h+' ч ':'')+(m?m+' мин ':'')+(s%60)+' с'; }
function render(){
  const ph=S.phase||'off', p=document.getElementById('power'), pill=document.getElementById('pill');
  p.className='power'+(ph==='on'?' on':(ph==='connecting'?' busy':(ph==='failed'?' err':'')));
  const nm=(S.active&&S.active.name)||'профиль не выбран';
  const titles={off:'Выключено',on:'Подключено',connecting:'Подключаюсь…',failed:'Не подключилось'};
  document.getElementById('ptitle').textContent=titles[ph]||ph;
  let sub='';
  if(ph==='on'){ sub=nm+' · '+dur(S.time-(S.since||S.time)); }
  else if(ph==='connecting'){ sub='Идёт проверка туннеля, до 90 секунд'; }
  else if(ph==='failed'){ sub=S.error||'не удалось поднять туннель'; }
  else { sub=nm==='профиль не выбран'?'Выбери профиль и нажми кнопку':'Нажми, чтобы подключиться: '+nm; }
  const ps=document.getElementById('psub'); ps.textContent=sub;
  ps.className='psub'+(ph==='failed'?' bad':'');
  pill.textContent=ph==='on'?'ВКЛ':(ph==='connecting'?'ПОДКЛЮЧЕНИЕ':(ph==='failed'?'ОШИБКА':'ВЫКЛ'));
  pill.className='pill'+(ph==='on'?' on':(ph==='failed'?' bad':''));
  const eg=S.egress||{}, t=S.tunnel||{};
  document.getElementById('e1').textContent=eg.direct||'—';
  document.getElementById('e2').textContent=eg.tunnel||'—';
  document.getElementById('tip').textContent=t.ip||'—';
  const fld=document.getElementById('full');
  fld.textContent=t.default_via_tunnel?'да':'нет';
  fld.className='v '+(t.default_via_tunnel?'ok':'');
  document.getElementById('swdns').className='sw'+(S.dns&&S.dns.override?' on':'');
  document.getElementById('swauto').className='sw'+(S.autostart?' on':'');
  document.getElementById('swlan').className='sw'+(S.lan&&S.lan.nat?' on':'');
  const box=document.getElementById('profiles'); const list=S.profiles||[];
  if(!list.length){ box.innerHTML='<div class="card" style="color:#7d8698;font-size:13px">Профилей нет. Добавь .ovpn или .conf.</div>'; return; }
  box.innerHTML=list.map(function(x){
    const sel=x.id===S.active_id;
    const meta=(x.type==='openvpn'?'OpenVPN':'WireGuard')+(x.full_tunnel?' · весь трафик':'' )+
      (x.remotes&&x.remotes.length?' · '+x.remotes[0]:'')+(x.missing&&x.missing.length?' · нет файлов: '+x.missing.join(','):'');
    return '<div class="prof'+(sel?' sel':'')+'" onclick="pick(\\''+x.id+'\\')">'+
      '<span class="dot"></span><div style="min-width:0"><div class="pname">'+esc(x.name)+'</div>'+
      '<div class="pmeta">'+esc(meta)+'</div></div>'+
      '<div class="acts"><button class="ico" onclick="event.stopPropagation();askRename(\\''+x.id+'\\',\\''+esc(x.name).replace(/'/g,'')+'\\')">✎</button>'+
      '<button class="ico" onclick="event.stopPropagation();del(\\''+x.id+'\\')">✕</button></div></div>';
  }).join('');
}
function esc(s){ return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
async function toggle(){
  if(busy)return; busy=true;
  if(S.phase==='on'){ await api('/api/disconnect',{method:'POST'}); }
  else if(S.active_id){ await api('/api/connect?id='+encodeURIComponent(S.active_id),{method:'POST'}); }
  else { busy=false; openImport(); return; }
  await load(); busy=false;
}
async function pick(id){
  if(id===S.active_id && S.phase==='on') return;
  await api('/api/connect?id='+encodeURIComponent(id),{method:'POST'});
  load();
}
async function setOpt(what){
  let on;
  if(what==='dns') on=!(S.dns&&S.dns.override);
  else if(what==='auto') on=!S.autostart;
  else on=!(S.lan&&S.lan.nat);
  await api('/api/'+what+(on?'_on':'_off'),{method:'POST'});
  load();
}
async function del(id){
  if(!confirm('Удалить профиль?'))return;
  await api('/api/delete?id='+encodeURIComponent(id),{method:'POST'}); load();
}
async function askRename(id,cur){
  const n=prompt('Название профиля',cur); if(!n)return;
  await api('/api/rename?id='+encodeURIComponent(id)+'&name='+encodeURIComponent(n),{method:'POST'}); load();
}
function openImport(){ document.getElementById('impout').textContent=''; document.getElementById('imp').showModal(); }
async function doImport(){
  const out=document.getElementById('impout'); out.textContent='загрузка…';
  const fd=new FormData();
  const fs=document.getElementById('files').files;
  for(let i=0;i<fs.length;i++) fd.append('file'+i,fs[i],fs[i].name);
  const txt=document.getElementById('conftext').value.trim();
  if(txt) fd.append('config',new Blob([txt],{type:'text/plain'}), txt.indexOf('[Interface]')>=0?'profile.conf':'profile.ovpn');
  fd.append('name',document.getElementById('nm').value.trim());
  fd.append('user',document.getElementById('u').value);
  fd.append('pass',document.getElementById('p').value);
  const r=await fetch('/api/import',{method:'POST',body:fd,credentials:'same-origin'});
  const j=await r.json().catch(function(){return{}});
  out.textContent=j.ok?('добавлено: '+(j.profile&&j.profile.name||'')+(j.warnings&&j.warnings.length?'\\n'+j.warnings.join('\\n'):'')):('ошибка: '+(j.error||r.status));
  if(j.ok){ setTimeout(function(){document.getElementById('imp').close(); load();},900); }
}
async function diag(){
  document.getElementById('dlg').showModal();
  const o=document.getElementById('diagout'); o.textContent='…';
  const j=await api('/api/diag'); o.textContent=j.diag||'нет данных';
}
load(); setInterval(load,3000);
document.addEventListener('visibilitychange',function(){ if(!document.hidden) load(); });
</script></body></html>"""


# ----------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "vpn-az/3"
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _cookie_ok(self):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == COOKIE and hmac.compare_digest(v, session_value()):
                    return True
        return False

    def _auth(self, u):
        if self._cookie_ok():
            return True
        tok = self.headers.get("X-Auth-Token") or (parse_qs(u.query).get("token") or [""])[0]
        return bool(tok) and hmac.compare_digest(tok, api_token())

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            if self._auth(u):
                return self._send(200, PAGE, "text/html; charset=utf-8")
            return self._send(200, LOGIN_PAGE, "text/html; charset=utf-8")
        if u.path == "/manifest.webmanifest":
            return self._send(200, json.dumps(MANIFEST), "application/manifest+json")
        if u.path in ("/icon-192.png", "/icon-512.png"):
            return self._send(200, icon(192 if "192" in u.path else 512), "image/png")
        if u.path == "/favicon.ico":
            return self._send(200, icon(192), "image/png")
        if not self._auth(u):
            return self._send(401, json.dumps({"error": "auth"}))
        if u.path == "/api/status":
            return self._send(200, json.dumps(status(), ensure_ascii=False))
        if u.path == "/api/diag":
            script = ("sh %s status 2>&1; echo '--- tun ---'; ls -l /dev/net/tun 2>&1; "
                      "echo '--- ovpn.log ---'; tail -16 %s/ovpn.log 2>&1; "
                      "echo '--- net.log ---'; tail -10 %s/net.log 2>&1; "
                      "echo '--- ip route ---'; ip -4 route 2>&1 | head -80" % (NET_SH, DATA, DATA))
            return self._send(200, json.dumps({"diag": sh(script, timeout=40)}, ensure_ascii=False))
        if u.path == "/api/check":
            q = parse_qs(u.query)
            url = (q.get("url") or [""])[0]
            via = (q.get("via") or [""])[0]
            return self._send(200, json.dumps(check_url(url, via), ensure_ascii=False))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return self._send(413, json.dumps({"error": "слишком большой файл"}))
        body = self.rfile.read(n) if n else b""

        if u.path == "/api/login":
            form = parse_qs(body.decode("utf-8", "replace"))
            pwd = (form.get("password") or [""])[0]
            if PASSWORD and hmac.compare_digest(pwd, PASSWORD):
                return self._send(302, "", "text/plain", [("Location", "/"),
                                   ("Set-Cookie", "%s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000"
                                    % (COOKIE, session_value()))])
            return self._send(401, LOGIN_PAGE, "text/html; charset=utf-8")

        if not self._auth(u):
            return self._send(401, json.dumps({"error": "auth"}))

        if u.path == "/api/import":
            try:
                pid, warnings = import_any(body, self.headers.get("Content-Type", ""), q)
            except Exception as e:  # noqa: BLE001
                return self._send(400, json.dumps({"error": str(e)}, ensure_ascii=False))
            return self._send(200, json.dumps({"ok": True, "profile": profile(pid),
                                               "warnings": warnings}, ensure_ascii=False))

        if u.path == "/api/connect":
            pid = (q.get("id") or [""])[0]
            if not pid and body:
                try:
                    pid = (json.loads(body.decode()) or {}).get("id", "")
                except Exception:  # noqa: BLE001
                    pid = ""
            if not profile(pid):
                return self._send(404, json.dumps({"error": "нет такого профиля"}))
            threading.Thread(target=do_connect, args=(pid,), daemon=True).start()
            return self._send(200, json.dumps({"ok": True, "phase": "connecting"}))

        if u.path == "/api/disconnect":
            threading.Thread(target=do_disconnect, daemon=True).start()
            return self._send(200, json.dumps({"ok": True, "phase": "off"}))

        if u.path in ("/api/auto_on", "/api/auto_off"):
            flag = os.path.join(STATE, "autostart")
            on = u.path.endswith("_on")
            if on:
                write(flag, "1\n")
            elif os.path.exists(flag):
                os.remove(flag)
            return self._send(200, json.dumps({"ok": True, "on": on}))

        if u.path in ("/api/dns_on", "/api/dns_off", "/api/lan_on", "/api/lan_off"):
            what = "dns" if "dns" in u.path else "lan"
            on = u.path.endswith("_on")
            flag = os.path.join(STATE, "dns_on" if what == "dns" else "lan_access")
            if on:
                write(flag, "1\n")
            elif os.path.exists(flag):
                os.remove(flag)
            net(what, "on" if on else "off", timeout=60)
            return self._send(200, json.dumps({"ok": True, "on": on}))

        if u.path == "/api/delete":
            pid = (q.get("id") or [""])[0]
            if pid and os.path.isdir(profile_dir(pid)):
                if state("active") == pid:
                    net("disconnect", timeout=90)
                    for f in ("active", "since"):
                        p = os.path.join(STATE, f)
                        if os.path.exists(p):
                            os.remove(p)
                    write(os.path.join(STATE, "phase"), "off")
                shutil.rmtree(profile_dir(pid), ignore_errors=True)
                return self._send(200, json.dumps({"ok": True}))
            return self._send(404, json.dumps({"error": "нет такого профиля"}))

        if u.path == "/api/rename":
            pid = (q.get("id") or [""])[0]
            name = ((q.get("name") or [""])[0]).strip()
            p = profile(pid)
            if not p or not name:
                return self._send(400, json.dumps({"error": "id и name обязательны"}))
            pj = {}
            try:
                pj = json.loads(read(os.path.join(profile_dir(pid), "profile.json"), "{}") or "{}")
            except Exception:  # noqa: BLE001
                pass
            pj.update({"name": name})
            write(os.path.join(profile_dir(pid), "profile.json"), json.dumps(pj, ensure_ascii=False))
            return self._send(200, json.dumps({"ok": True}))

        return self._send(404, json.dumps({"error": "not found"}))


def main():
    os.makedirs(PROFILES, exist_ok=True)
    os.makedirs(STATE, exist_ok=True)
    api_token()
    threading.Thread(target=boot, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
