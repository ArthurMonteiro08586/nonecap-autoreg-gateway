#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NoneCap Gateway v1.0 — hCaptcha solve API поверх пула NoneCap-ключей.

Стандартный только stdlib (http.server). Порт :9997.

Эндпоинты:
  POST /v1/solve          {"sitekey": "...", "url": "...", "wait": 30}
                          -> {"token": "P1_...", "key_used": "nc_live_ab...", "credits_left": N}
                          Ротация ключей, фолбэк прокси, retry на мёртвых ключах.
  GET  /v1/keys           пул: маскированные ключи + баланс каждого (через прокси)
  GET  /health            статус: живые/мёртвые ключи, аптайм
  GET  /dashboard         HTML-дашборд (авто-обновление 15с)
  POST /pool/reload       перечитать пул с диска

Auth: заголовок X-Gateway-Key (GATEWAY_API_KEY из .env / env). Без ключа — 401.

Запуск:  python nonecap_gateway.py [--port 9997]
"""
import json
import os
import re
import sys
import time
import threading
import urllib.request
import urllib.parse
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(os.environ.get("NONECAP_GATEWAY_PORT", "9997"))
ACCOUNTS_FILE = Path.home() / "Desktop" / "nonecap_accounts.txt"
PROXY_FILE = Path.home() / "tmp" / "live_http_proxies.txt"
API_BASE = "https://api.nonecap.com"

# gateway auth key — из env или файла рядом (НЕ хардкодить)
GW_KEY_FILE = Path(__file__).parent / "gateway_key.txt"
GATEWAY_API_KEY = os.environ.get("NONECAP_GATEWAY_KEY", "")
if not GATEWAY_API_KEY and GW_KEY_FILE.exists():
    GATEWAY_API_KEY = GW_KEY_FILE.read_text().strip()

_lock = threading.Lock()
_state = {
    "keys": [],          # [{key, alive, credits, locked, last_used}]
    "proxies": [],
    "started_at": time.time(),
    "requests": 0,
    "solved": 0,
    "failed": 0,
}


def load_pool():
    keys = []
    try:
        for line in open(str(ACCOUNTS_FILE), encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            parts = line.split(":")
            email = parts[0]
            key = None
            for p in parts:
                m = re.search(r"nc_live_[A-Za-z0-9_\-]+", p)
                if m:
                    key = m.group(0)
            if key:
                keys.append({"email": email, "key": key, "alive": True,
                             "credits": None, "locked": False, "last_used": 0})
    except Exception as e:
        print("[pool] load err:", e)
    return keys


def load_proxies():
    px = []
    try:
        for line in open(str(PROXY_FILE), encoding="utf-8", errors="ignore"):
            line = line.strip()
            if not line:
                continue
            p = line.split()[0]
            if not p.startswith("http"):
                p = "http://" + p
            px.append(p)
    except Exception:
        pass
    return px


def reload_pool():
    with _lock:
        _state["keys"] = load_pool()
        _state["proxies"] = load_proxies()
    print("[pool] reloaded:", len(_state["keys"]), "keys,", len(_state["proxies"]), "proxies")


def api_call(key, method, path, payload=None, proxy=None, timeout=95):
    """Один вызов api.nonecap.com. Возвращает (status, json_or_text). Бросает на сетевой ошибке."""
    url = API_BASE + path
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json",
               "User-Agent": "nonecap-gateway/1.0"}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    op = urllib.request.build_opener(*handlers)
    try:
        with op.open(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            try:
                return r.status, json.loads(body)
            except Exception:
                return r.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body


def pick_key():
    with _lock:
        cands = [k for k in _state["keys"] if k["alive"] and not k["locked"]]
        if not cands:
            return None
        cands.sort(key=lambda k: k["last_used"])
        k = cands[0]
        k["last_used"] = time.time()
        return k


def mark_key(entry, alive=None, locked=None, credits=None):
    if entry is None:
        return
    with _lock:
        for k in _state["keys"]:
            if k["key"] == entry["key"]:
                if alive is not None:
                    k["alive"] = alive
                if locked is not None:
                    k["locked"] = locked
                if credits is not None:
                    k["credits"] = credits


def solve(sitekey, url, wait=30):
    """Ротация ключей + прокси. Возвращает dict результата или бросает."""
    tried_keys = 0
    proxies = list(_state["proxies"]) or [None]
    last_err = None
    while tried_keys < 6:
        entry = pick_key()
        if entry is None:
            break
        tried_keys += 1
        key = entry["key"]
        px = proxies[tried_keys % len(proxies)]
        try:
            st, resp = api_call(key, "POST", "/v1/solves?wait=" + str(wait),
                                {"type": "hcaptcha", "sitekey": sitekey, "url": url},
                                proxy=px, timeout=wait + 30)
            if st == 200 and isinstance(resp, dict) and resp.get("token"):
                with _lock:
                    _state["solved"] += 1
                return {"token": resp["token"], "solve_id": resp.get("id"),
                        "key_used": key[:14] + "...", "user_agent": resp.get("user_agent")}
            if st == 202 and isinstance(resp, dict):
                # in-flight -> poll
                sid = resp.get("id")
                for _ in range(18):
                    time.sleep(5)
                    st2, r2 = api_call(key, "GET", "/v1/solves/" + str(sid), proxy=px, timeout=30)
                    if st2 == 200 and isinstance(r2, dict) and r2.get("token"):
                        with _lock:
                            _state["solved"] += 1
                        return {"token": r2["token"], "solve_id": sid,
                                "key_used": key[:14] + "...", "user_agent": r2.get("user_agent")}
                    if st2 == 200 and isinstance(r2, dict) and r2.get("status") in ("failed", "cancelled"):
                        last_err = "solve " + str(r2.get("status"))
                        break
                else:
                    last_err = "solve timeout (poll)"
                    continue
            if st in (401, 403):
                code = resp.get("error", {}).get("code", "") if isinstance(resp, dict) else ""
                if "lock" in str(code):
                    mark_key(entry, locked=True, alive=False)
                    last_err = "key locked"
                    continue
                if "credit" in str(code).lower() or "insufficient" in str(resp).lower():
                    mark_key(entry, alive=False)
                    last_err = "no credits"
                    continue
                mark_key(entry, alive=False)
                last_err = str(resp)[:100]
                continue
            last_err = "HTTP " + str(st) + " " + str(resp)[:120]
        except Exception as e:
            last_err = str(e)[:120]
            continue
    with _lock:
        _state["failed"] += 1
    raise RuntimeError("solve failed after " + str(tried_keys) + " keys: " + str(last_err))


def balance_all():
    out = []
    proxies = list(_state["proxies"]) or [None]
    with _lock:
        snapshot = [dict(k) for k in _state["keys"]]
    for i, k in enumerate(snapshot):
        px = proxies[i % len(proxies)]
        try:
            st, resp = api_call(k["key"], "GET", "/v1/me", proxy=px, timeout=20)
            credits = None
            if isinstance(resp, dict):
                credits = resp.get("credits") or resp.get("balance") or resp
            out.append({"email": k["email"], "key": k["key"][:14] + "...",
                        "http": st, "credits": credits})
            mark_key(k, alive=(st == 200), locked=(st == 403), credits=credits)
        except Exception as e:
            out.append({"email": k["email"], "key": k["key"][:14] + "...", "err": str(e)[:60]})
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        if not GATEWAY_API_KEY:
            return True
        got = self.headers.get("X-Gateway-Key") or ""
        if not got:
            m = re.match(r"Bearer\s+(.+)", self.headers.get("Authorization") or "")
            got = m.group(1) if m else ""
        return got == GATEWAY_API_KEY

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/dashboard":
            return self._dashboard()
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        if path == "/health":
            with _lock:
                alive = sum(1 for k in _state["keys"] if k["alive"] and not k["locked"])
                total = len(_state["keys"])
            return self._send(200, {"status": "ok", "keys_alive": alive, "keys_total": total,
                                    "proxies": len(_state["proxies"]),
                                    "uptime_s": int(time.time() - _state["started_at"]),
                                    "requests": _state["requests"], "solved": _state["solved"],
                                    "failed": _state["failed"]})
        if path == "/v1/keys":
            return self._send(200, {"pool": balance_all()})
        if path == "/files":
            return self._files_api()
        return self._send(404, {"error": "not found"})

    def _files_api(self):
        """File browser для агентов: ?path=DIR — листинг; ?path=FILE — содержимое.
        Whitelist корней: Desktop, tmp, SESSION-BASE (read-only)."""
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        rel = (qs.get("path") or [""])[0]
        roots = [Path.home() / "Desktop", Path.home() / "tmp", Path.home() / "SESSION-BASE"]
        target = (Path.home() / rel) if rel else Path.home() / "Desktop"
        try:
            target = target.resolve()
        except Exception:
            return self._send(400, {"error": "bad path"})
        if not any(str(target).startswith(str(r.resolve())) for r in roots):
            return self._send(403, {"error": "path outside whitelist (Desktop/tmp/SESSION-BASE)"})
        if target.is_dir():
            items = []
            try:
                for e in sorted(target.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))[:500]:
                    try:
                        items.append({"name": e.name, "dir": e.is_dir(),
                                      "size": e.stat().st_size if e.is_file() else None})
                    except Exception:
                        items.append({"name": e.name, "dir": e.is_dir(), "size": None})
            except Exception as ex:
                return self._send(500, {"error": str(ex)[:100]})
            return self._send(200, {"path": str(target), "items": items})
        if target.is_file():
            if target.stat().st_size > 2_000_000:
                return self._send(413, {"error": "file > 2MB, use range/read locally"})
            try:
                content = target.read_text(encoding="utf-8", errors="replace")
            except Exception as ex:
                return self._send(500, {"error": str(ex)[:100]})
            return self._send(200, {"path": str(target), "size": target.stat().st_size,
                                    "content": content})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            payload = {}
        with _lock:
            _state["requests"] += 1
        if path == "/pool/reload":
            reload_pool()
            return self._send(200, {"ok": True, "keys": len(_state["keys"])})
        if path == "/v1/solve":
            sitekey = payload.get("sitekey")
            url = payload.get("url")
            if not sitekey or not url:
                return self._send(400, {"error": "sitekey and url required"})
            stream = bool(payload.get("stream"))
            if stream:
                return self._solve_stream(sitekey, url, int(payload.get("wait", 30)))
            try:
                res = solve(sitekey, url, int(payload.get("wait", 30)))
                return self._send(200, res)
            except Exception as e:
                return self._send(502, {"error": str(e)[:300]})
        return self._send(404, {"error": "not found"})

    def _solve_stream(self, sitekey, url, wait):
        """SSE-стриминг прогресса solve: события pick/solving/result/error."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        def emit(ev, data):
            try:
                self.wfile.write(("event: " + ev + "\ndata: " + json.dumps(data, ensure_ascii=False) + "\n\n").encode())
                self.wfile.flush()
                return True
            except Exception:
                return False

        tried = 0
        proxies = list(_state["proxies"]) or [None]
        while tried < 6:
            entry = pick_key()
            if entry is None:
                emit("error", {"msg": "no alive keys in pool"})
                break
            tried += 1
            key = entry["key"]
            px = proxies[tried % len(proxies)]
            if not emit("pick", {"key": key[:14] + "...", "attempt": tried, "proxy": px}):
                break
            try:
                emit("solving", {"sitekey": sitekey, "wait": wait})
                st, resp = api_call(key, "POST", "/v1/solves?wait=" + str(wait),
                                    {"type": "hcaptcha", "sitekey": sitekey, "url": url},
                                    proxy=px, timeout=wait + 30)
                if st == 200 and isinstance(resp, dict) and resp.get("token"):
                    with _lock:
                        _state["solved"] += 1
                    emit("result", {"token": resp["token"][:20] + "...", "solve_id": resp.get("id")})
                    break
                if st == 202 and isinstance(resp, dict):
                    sid = resp.get("id")
                    emit("polling", {"solve_id": sid})
                    for _ in range(18):
                        time.sleep(5)
                        st2, r2 = api_call(key, "GET", "/v1/solves/" + str(sid), proxy=px, timeout=30)
                        if st2 == 200 and isinstance(r2, dict) and r2.get("token"):
                            with _lock:
                                _state["solved"] += 1
                            emit("result", {"token": r2["token"][:20] + "...", "solve_id": sid})
                            return
                        emit("poll", {"status": r2.get("status") if isinstance(r2, dict) else st2})
                    emit("error", {"msg": "poll timeout"})
                    continue
                if st in (401, 403):
                    code = resp.get("error", {}).get("code", "") if isinstance(resp, dict) else ""
                    if "lock" in str(code):
                        mark_key(entry, locked=True, alive=False)
                    else:
                        mark_key(entry, alive=False)
                    emit("error", {"msg": "HTTP " + str(st) + " " + str(code), "retry": True})
                    continue
                emit("error", {"msg": "HTTP " + str(st) + " " + str(resp)[:120], "retry": True})
            except Exception as e:
                emit("error", {"msg": str(e)[:120], "retry": True})
        with _lock:
            _state["failed"] += 1
        try:
            self.wfile.write(b"event: done\ndata: {}\n\n")
        except Exception:
            pass

    def _dashboard(self):
        with _lock:
            keys = [dict(k) for k in _state["keys"]]
            stats = {"uptime_s": int(time.time() - _state["started_at"]),
                     "requests": _state["requests"], "solved": _state["solved"],
                     "failed": _state["failed"], "proxies": len(_state["proxies"])}
        rows = ""
        for k in keys:
            st = "LOCKED" if k["locked"] else ("ALIVE" if k["alive"] else "DEAD")
            color = {"LOCKED": "#e74c3c", "ALIVE": "#2ecc71", "DEAD": "#95a5a6"}[st]
            rows += ("<tr><td>" + k["email"] + "</td><td>" + k["key"][:14] + "...</td>"
                     + "<td style='color:" + color + "'>" + st + "</td>"
                     + "<td>" + str(k["credits"] if k["credits"] is not None else "?") + "</td></tr>")
        html = """<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="15">
<title>NoneCap Gateway</title><style>
body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:24px}
h1{color:#58a6ff}table{border-collapse:collapse;width:100%}td,th{border:1px solid #30363d;padding:6px 10px;text-align:left}
.stats span{margin-right:24px;color:#8b949e}.stats b{color:#f0f6fc}</style></head><body>
<h1>NoneCap Gateway :""" + str(PORT) + """</h1>
<div class="stats"><span>uptime <b>""" + str(stats["uptime_s"]) + """s</b></span>
<span>requests <b>""" + str(stats["requests"]) + """</b></span>
<span>solved <b>""" + str(stats["solved"]) + """</b></span>
<span>failed <b>""" + str(stats["failed"]) + """</b></span>
<span>proxies <b>""" + str(stats["proxies"]) + """</b></span></div>
<table><tr><th>email</th><th>key</th><th>status</th><th>credits</th></tr>""" + rows + """</table>
<p style="color:#8b949e">POST /v1/solve {"sitekey","url","wait"} &middot; GET /v1/keys &middot; GET /health &middot; POST /pool/reload</p>
</body></html>"""
        return self._send(200, html.encode(), "text/html")


def main():
    global PORT
    if "--port" in sys.argv:
        PORT = int(sys.argv[sys.argv.index("--port") + 1])
    reload_pool()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("[gateway] listening on 127.0.0.1:" + str(PORT))
    srv.serve_forever()


if __name__ == "__main__":
    main()
