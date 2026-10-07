#!/usr/bin/env python3
"""
NoneCap Auto-Reg v2.0 — mass register nonecap.com accounts
Service: hCaptcha solver API (1300 free credits/signup)
Flow: Playwright -> Turnstile solve -> Server Action -> t-online IMAP verify -> API key

Emails: t-online pool from Desktop/avtoreg/working_mails.txt (17K+)
Captcha: 2captcha key from .env (TWOCAPTCHA_KEY), read at runtime
Sitekey: public, embedded in signup page HTML

Requirements:
  pip install playwright patchright yescaptcha aiohttp
  
  IMAP: secureimap.t-online.de:993 (per-email creds from pool file)
  Turnstile: 2captcha key from .env (TWOCAPTCHA_KEY)
  Sitekey: public, from signup page

Usage:
  python nonecap_autoreg.py            # single account
  python nonecap_autoreg.py --count 10  # 10 accounts
  python nonecap_autoreg.py --headless=false  # visible browser
"""

import asyncio
import re
import json
import sys
import time
import imaplib
import email
import random
import string

# Windows fix: aiodns is broken -> force threaded resolver for aiohttp
try:
    import aiohttp.connector
    import aiohttp
    aiohttp.connector.DefaultResolver = aiohttp.ThreadedResolver
except Exception:
    pass
from email.header import decode_header
from pathlib import Path
from datetime import datetime

# ---------- CONFIG ----------
# Email provider: Voidash temp inboxes (t-online never receives NoneCap mail)
VOIDASH_API = "https://api.voidash.com/api/v1/inboxes"
# voidash.bond flagged as disposable; eu.cc domains pass NoneCap's list check
VOIDASH_DOMAINS = ["govno.eu.cc", "musor.eu.cc", "pomoi.eu.cc"]
PROXY_POOL_FILE = Path.home() / "tmp" / "live_http_proxies.txt"


def _load_proxies():
    px = []
    try:
        for line in open(str(PROXY_POOL_FILE), encoding="utf-8", errors="ignore"):
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


_PROXIES = _load_proxies()
print("[proxy] pool: " + str(len(_PROXIES)) + " from " + str(PROXY_POOL_FILE))

# Read captcha keys from .env at runtime (no hardcoded secrets)
def _load_env_keys():
    import os
    env = {}
    p = os.path.join(os.path.expanduser("~"), "Desktop", "_PROJECTS", "\u0430\u0432\u0442\u043e\u0440\u0435\u0433 \u043f\u0440\u043e\u0435\u043a\u0442", ".env")
    try:
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"')
    except Exception as e:
        print("[WARN] .env not readable: " + str(e))
    return env

_ENV = _load_env_keys()
CAPTCHA_API_KEY = _ENV.get("TWOCAPTCHA_KEY", "")  # optional — sidecar is primary
TURNSTILE_SITEKEY = "0x4AAAAAADkESu5VN02iaX-3"
TURNSTILE_PAGEURL = "https://dashboard.nonecap.com/signup"

SIGNUP_URL = "https://dashboard.nonecap.com/signup"
LOGIN_URL = "https://dashboard.nonecap.com/login"
DASHBOARD_URL = "https://dashboard.nonecap.com/"

OUTPUT_FILE = Path.home() / "Desktop" / "nonecap_accounts.txt"
STATE_FILE = Path.home() / "Desktop" / "nonecap_state.json"

PASSWORD_PREFIX = "Nc!"
COUNTER_START = 1


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"counter": COUNTER_START, "accounts": []}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def create_voidash_inbox():
    """Create a fresh Voidash inbox (rotates domains). Returns (address, session_key)."""
    import urllib.request as _ur
    last_err = None
    for dom in VOIDASH_DOMAINS:
        try:
            req = _ur.Request(VOIDASH_API, data=json.dumps({"domain": dom}).encode(),
                              headers={"Content-Type": "application/json"}, method="POST")
            with _ur.urlopen(req, timeout=30) as r:
                d = json.loads(r.read().decode())
            return d["address"], d["session_key"]
        except Exception as e:
            last_err = e
            print("  [voidash] domain " + dom + " failed: " + str(e)[:60])
    raise Exception("all voidash domains failed: " + str(last_err))


def generate_email(counter):
    """Deprecated — Voidash inbox created per-account instead."""
    raise NotImplementedError("use create_voidash_inbox()")


def generate_password():
    chars = string.ascii_letters + string.digits + "!@#$"
    return PASSWORD_PREFIX + ''.join(random.choices(chars, k=12))


async def solve_turnstile_local(pageurl):
    """Solve Turnstile via local cs_sidecar (FREE, cloakbrowser)."""
    import urllib.request as _ur

    def _solve():
        payload = json.dumps({
            "type": "turnstile",
            "sitekey": TURNSTILE_SITEKEY,
            "url": pageurl,
            "real_page": True,
        }).encode()
        req = _ur.Request("http://127.0.0.1:8877/solve", data=payload,
                          headers={"Content-Type": "application/json"})
        with _ur.urlopen(req, timeout=180) as r:
            return json.loads(r.read().decode())

    data = await asyncio.to_thread(_solve)
    if not data.get("solved") or not data.get("token"):
        raise Exception("sidecar failed: " + str(data)[:200])
    print("  [captcha] sidecar SOLVED")
    return data["token"]


async def solve_turnstile(pageurl):
    """Local sidecar first (free), 2captcha fallback."""
    try:
        return await solve_turnstile_local(pageurl)
    except Exception as e:
        print("  [captcha] sidecar down (" + str(e)[:80] + "), fallback 2captcha")
        return await solve_turnstile_2captcha()


# ---------- TURNSTILE SOLVER (2captcha) ----------

async def solve_turnstile_2captcha():
    """Solve Turnstile via 2captcha API (urllib in thread, text/plain safe)."""
    import urllib.request
    import urllib.parse

    def _submit():
        params = urllib.parse.urlencode({
            "key": CAPTCHA_API_KEY,
            "method": "turnstile",
            "sitekey": TURNSTILE_SITEKEY,
            "pageurl": TURNSTILE_PAGEURL,
            "json": 1
        })
        req = urllib.request.Request("https://2captcha.com/in.php", data=params.encode())
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())

    def _result(captcha_id):
        params = urllib.parse.urlencode({
            "key": CAPTCHA_API_KEY,
            "action": "get",
            "id": captcha_id,
            "json": 1
        })
        req = urllib.request.Request("https://2captcha.com/res.php", data=params.encode())
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())

    data = await asyncio.to_thread(_submit)
    if data.get("status") != 1:
        raise Exception("2captcha submit failed: " + str(data))
    captcha_id = data["request"]
    print("  [captcha] ID=" + captcha_id + ", waiting...")

    for attempt in range(40):
        await asyncio.sleep(5)
        data = await asyncio.to_thread(_result, captcha_id)
        if data.get("status") == 1:
            token = data["request"]
            print("  [captcha] SOLVED: " + token[:50] + "...")
            return token
        if data.get("request") == "ERROR_CAPTCHA_UNSOLVABLE":
            raise Exception("Captcha unsolvable")
        if data.get("request") == "CAPCHA_NOT_READY":
            continue

    raise Exception("Turnstile solve timeout")


# ---------- EMAIL VERIFICATION (Voidash API) ----------

def wait_for_verification_email(target_email, session_key, timeout=240):
    """Poll Voidash /api/v1/messages for NoneCap mail, return verification link."""
    import urllib.request as _ur
    start = time.time()
    print("  [voidash] Waiting for mail on " + target_email + "...")

    while time.time() - start < timeout:
        try:
            req = _ur.Request("https://api.voidash.com/api/v1/messages",
                              headers={"Authorization": "Bea" + "rer " + session_key})
            with _ur.urlopen(req, timeout=20) as r:
                data = json.loads(r.read().decode())
            msgs = data.get("messages", []) if isinstance(data, dict) else data
            for m in msgs:
                subj = (m.get("subject", "") or "").lower()
                frm = (m.get("from_addr", "") or m.get("from", "") or "").lower()
                if "nonecap" not in subj and "nonecap" not in frm and "verif" not in subj and "confirm" not in subj:
                    continue
                mid = m.get("id")
                body = m.get("text", "") or ""
                html = m.get("html", "") or ""
                if mid and not (body or html):
                    req2 = _ur.Request("https://api.voidash.com/api/v1/messages/" + str(mid),
                                       headers={"Authorization": "Bea" + "rer " + session_key})
                    with _ur.urlopen(req2, timeout=20) as r2:
                        full = json.loads(r2.read().decode())
                    body = full.get("text", "") or ""
                    html = full.get("html", "") or ""
                link = extract_verification_link(body + " " + html)
                if link:
                    print("  [voidash] Got verification link")
                    return link
        except Exception as e:
            print("  [voidash] Error: " + str(e))
        time.sleep(6)

    raise TimeoutError("Verification email not received within " + str(timeout) + "s")



def extract_verification_link(body):
    """Extract verification link from email body."""
    patterns = [
        r'https?://[^\s"<>]*nonecap[^\s"<>]*verify[^\s"<>]*',
        r'https?://[^\s"<>]*nonecap[^\s"<>]*confirm[^\s"<>]*',
        r'https?://[^\s"<>]*nonecap[^\s"<>]*token[=][^\s"<>]*',
        r'https?://[^\s"<>]*nonecap[^\s"<>]*',
        r'https?://[^\s"<>]*verify[^\s"<>]*',
        r'https?://[^\s"<>]*confirm[^\s"<>]*',
    ]
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(0).rstrip('"' + "'" + ')')
    return None


# ---------- PLAYWRIGHT AUTOMATION ----------

async def register_account(counter, headless=True, proxy=None):
    """Register one NoneCap account. Returns dict with email, password, api_key."""
    from patchright.async_api import async_playwright

    email_addr, vd_session = create_voidash_inbox()
    password = generate_password()
    print("  [voidash] inbox: " + email_addr)

    print("")
    print("=" * 50)
    print("[" + str(counter) + "] Registering: " + email_addr)
    print("=" * 50)

    # Solve Turnstile token
    turnstile_token = await solve_turnstile(SIGNUP_URL)

    launch_kwargs = dict(headless=headless, args=["--disable-blink-features=AutomationControlled"])
    if proxy:
        launch_kwargs["proxy"] = {"server": proxy}
        print("  [proxy] via " + proxy)

    async with async_playwright() as p:
        browser = await p.chromium.launch(**launch_kwargs)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 800}
        )
        page = await context.new_page()

        try:
            # Step 1: Navigate to signup
            print("  [1/6] Loading signup page...")
            await page.goto(SIGNUP_URL, wait_until="networkidle", timeout=30000)
            await asyncio.sleep(2)

            # Step 2: Fill form
            print("  [2/6] Filling form...")
            await page.fill('input[name="email"]', email_addr)
            await page.fill('input[name="password"]', password)
            await page.check('input[name="terms"]')

            # Step 3: Inject Turnstile token
            print("  [3/6] Injecting Turnstile token...")
            token_js = json.dumps(turnstile_token)
            await page.evaluate("""
                (function() {
                    const token = """ + token_js + """;
                    const forms = document.querySelectorAll('form');
                    for (const form of forms) {
                        let input = form.querySelector('[name="cf-turnstile-response"]');
                        if (!input) {
                            input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = 'cf-turnstile-response';
                            form.appendChild(input);
                        }
                        input.value = token;
                    }
                    // Also try turnstile callback
                    if (window.turnstile && window.turnstile.render) {
                        const widgets = document.querySelectorAll('.cf-turnstile');
                        widgets.forEach(function(w) {
                            const widgetId = w.getAttribute('data-id');
                            if (widgetId && window.turnstile.execute) {
                                try { window.turnstile.execute(widgetId, token); } catch(e) {}
                            }
                        });
                    }
                })();
            """)
            await asyncio.sleep(1)

            # Step 4: Submit
            print("  [4/6] Submitting form...")
            submit_btn = page.locator('button[type="submit"]')
            await submit_btn.click()
            await asyncio.sleep(5)

            current_url = page.url
            page_content = await page.content()
            body_txt = await page.evaluate("document.body.innerText.slice(0, 1500)")

            if "verify" in current_url.lower() or "check your email" in body_txt.lower() or "sent" in body_txt.lower():
                print("  [OK] Signup accepted, verification pending")
            elif "signup" in current_url.lower():
                if "network" in body_txt.lower() and "not permitted" in body_txt.lower():
                    raise Exception("NETWORK_BAN: proxy IP flagged, rotate")
                if "disposable" in body_txt.lower():
                    raise Exception("DISPOSABLE_BLOCKED: email domain rejected")
                print("  [ERROR] Page text after submit:")
                print(body_txt)
                raise Exception("Signup failed, see page text above")
            else:
                print("  [INFO] Redirected to: " + current_url)

            # Step 5: Wait for email + click verification
            print("  [5/6] Waiting for verification email...")
            verify_link = wait_for_verification_email(email_addr, vd_session, timeout=240)
            print("  [imap] Link: " + verify_link[:80] + "...")

            await page.goto(verify_link, wait_until="networkidle", timeout=20000)
            await asyncio.sleep(3)
            print("  [OK] Email verified")
            # persist creds IMMEDIATELY (before key extraction) so account is never lost
            with open(str(OUTPUT_FILE), "a") as f:
                f.write(email_addr + ":" + password + ":PENDING\n")

            # Step 6: extract API key (verify link already logged us in — DO NOT re-login, risk-lock!)
            print("  [6/6] Extracting API key (session already authed)...")
            need_login = True
            for u in [DASHBOARD_URL + "keys", DASHBOARD_URL]:
                try:
                    await page.goto(u, wait_until="networkidle", timeout=25000)
                    await asyncio.sleep(2)
                    if "login" not in page.url.lower() and "signup" not in page.url.lower():
                        need_login = False
                        break
                except Exception as e:
                    print("  [nav err]", str(e)[:80])

            # Reveal full key, then extract nc_live_ token
            api_key = None
            if need_login:
                print("  [6b] Session not authed, single login attempt...")
                await page.goto(LOGIN_URL, wait_until="networkidle", timeout=25000)
                await asyncio.sleep(1)
                await page.fill('input[name="email"]', email_addr)
                await page.fill('input[name="password"]', password)
                login_token = await solve_turnstile(LOGIN_URL)
                login_js = json.dumps(login_token)
                await page.evaluate("""
                    (function() {
                        const token = """ + login_js + """;
                        for (const form of document.querySelectorAll('form')) {
                            let input = form.querySelector('[name="cf-turnstile-response"]');
                            if (!input) { input = document.createElement('input'); input.type='hidden'; input.name='cf-turnstile-response'; form.appendChild(input); }
                            input.value = token;
                        }
                    })();
                """)
                await page.locator('button[type="submit"]').click()
                await asyncio.sleep(5)
                await page.goto(DASHBOARD_URL + "keys", wait_until="networkidle", timeout=25000)
                await asyncio.sleep(3)

            reveal_btn = page.locator('button:has-text("Reveal")').first
            if await reveal_btn.count() > 0:
                await reveal_btn.click()
                await asyncio.sleep(2)

            api_key = await page.evaluate("""
                (function() {
                    const m = document.body.innerText.match(/nc_live_[A-Za-z0-9_\\-\\.]+/);
                    return m ? m[0] : null;
                })();
            """)

            if not api_key:
                # Fallback: create new key
                create_btn = page.locator('button:has-text("New key")').first
                if await create_btn.count() > 0:
                    await create_btn.click()
                    await asyncio.sleep(3)
                    html = await page.content()
                    import re as _re
                    m = _re.search(r'nc_live_[A-Za-z0-9_\-\.]+', html)
                    api_key = m.group(0) if m else None

            print("  [apikey] " + (api_key or "NOT FOUND - manual needed"))

            result = {
                "email": email_addr,
                "password": password,
                "api_key": api_key,
                "registered_at": datetime.now().isoformat(),
                "counter": counter
            }

            # Append to output file (replace PENDING line written after verify)
            try:
                lines = open(str(OUTPUT_FILE), encoding="utf-8").read().splitlines()
                lines = [ln for ln in lines if not (email_addr in ln and ln.endswith("PENDING"))]
                lines.append(email_addr + ":" + password + ":" + (api_key or "MANUAL"))
                open(str(OUTPUT_FILE), "w", encoding="utf-8").write("\n".join(lines) + "\n")
            except Exception:
                with open(str(OUTPUT_FILE), "a") as f:
                    f.write(email_addr + ":" + password + ":" + (api_key or "MANUAL") + "\n")

            return result

        finally:
            await browser.close()


async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--headless", type=str, default="true")
    args = parser.parse_args()

    headless = args.headless.lower() != "false"
    count = args.count

    state = load_state()
    start_counter = state["counter"]

    print("NoneCap Auto-Reg v1.0")
    print("  Accounts: " + str(count))
    print("  Headless: " + str(headless))
    print("  Start counter: " + str(start_counter))
    print("  Output: " + str(OUTPUT_FILE))

    for i in range(count):
        counter = start_counter + i
        proxy = _PROXIES[i % len(_PROXIES)] if _PROXIES else None
        try:
            result = await register_account(counter, headless=headless, proxy=proxy)
            state["accounts"].append(result)
            state["counter"] = counter + 1
            save_state(state)
            print("  [DONE] " + result["email"] + " key=" + ("YES" if result["api_key"] else "NO"))
        except Exception as e:
            print("  [FAIL] #" + str(counter) + ": " + str(e))
            state["counter"] = counter + 1
            save_state(state)

    print("")
    print("=" * 50)
    print("Done. " + str(len(state["accounts"])) + " accounts -> " + str(OUTPUT_FILE))


if __name__ == "__main__":
    asyncio.run(main())