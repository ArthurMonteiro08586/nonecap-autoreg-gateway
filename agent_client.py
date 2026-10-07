#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent_client.py — пример tool-use интеграции агента с NoneCap Gateway (:9997).

Маппинг tool -> HTTP:
  hcaptcha_solve -> POST /v1/solve          (stream=true -> SSE)
  gateway_health -> GET  /health
  gateway_pool   -> GET  /v1/keys
  fs_list        -> GET  /files?path=DIR
  fs_read        -> GET  /files?path=FILE
  pool_reload    -> POST /pool/reload

Использование как библиотеки:
    from agent_client import NoneCapAgentClient
    c = NoneCapAgentClient()                     # ключ читает из gateway_key.txt
    r = c.call_tool("hcaptcha_solve", {"sitekey": "...", "url": "..."})
    print(r["token"], r["user_agent"])

Или отдать агенту tools.json (OpenAI function-calling формат) и роутить
его tool_calls через c.call_tool(name, arguments).
"""
import json
import urllib.request
import urllib.parse
from pathlib import Path

GW = "http://127.0.0.1:9997"
KEY_FILE = Path(__file__).parent / "gateway_key.txt"


class NoneCapAgentClient:
    def __init__(self, base=GW, key=None):
        self.base = base.rstrip("/")
        self.key = key or (KEY_FILE.read_text().strip() if KEY_FILE.exists() else "")

    def _req(self, method, path, payload=None, timeout=180):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"X-Gateway-Key": self.key,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))

    def call_tool(self, name, args=None):
        """Dispatch an OpenAI-style tool call to the gateway."""
        args = args or {}
        if name == "hcaptcha_solve":
            if args.get("stream"):
                return list(self.solve_stream(args["sitekey"], args["url"], args.get("wait", 30)))
            return self._req("POST", "/v1/solve", {
                "sitekey": args["sitekey"], "url": args["url"],
                "wait": args.get("wait", 30)})
        if name == "gateway_health":
            return self._req("GET", "/health")
        if name == "gateway_pool":
            return self._req("GET", "/v1/keys", timeout=300)
        if name in ("fs_list", "fs_read"):
            q = urllib.parse.quote(args.get("path", "Desktop"))
            return self._req("GET", "/files?path=" + q)
        if name == "pool_reload":
            return self._req("POST", "/pool/reload", {})
        raise ValueError("unknown tool: " + name)

    def solve_stream(self, sitekey, url, wait=30):
        """SSE generator: yields (event, data_dict)."""
        payload = json.dumps({"sitekey": sitekey, "url": url, "wait": wait, "stream": True}).encode()
        req = urllib.request.Request(self.base + "/v1/solve", data=payload, method="POST",
                                     headers={"X-Gateway-Key": self.key,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=wait + 120) as r:
            ev, data = None, None
            for raw in r:
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                if line.startswith("event: "):
                    ev = line[7:]
                elif line.startswith("data: "):
                    try:
                        data = json.loads(line[6:])
                    except Exception:
                        data = {"raw": line[6:]}
                elif line == "" and ev:
                    yield ev, data
                    ev, data = None, None
                    if ev == "done":
                        break

    def tools_schema(self):
        p = Path(__file__).parent / "tools.json"
        return json.loads(p.read_text(encoding="utf-8"))["tools"]


if __name__ == "__main__":
    c = NoneCapAgentClient()
    print("== tools schema:", len(c.tools_schema()), "tools")
    print("== health:", c.call_tool("gateway_health"))
    print("== fs_list Desktop:", json.dumps(c.call_tool("fs_list", {"path": "Desktop"}), ensure_ascii=False)[:300])
    print("== solve (demo hcaptcha):")
    r = c.call_tool("hcaptcha_solve", {"sitekey": "10000000-ffff-ffff-ffff-000000000001",
                                       "url": "https://demo.hcaptcha.com/", "wait": 60})
    print(json.dumps(r, ensure_ascii=False)[:300])
