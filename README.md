# NoneCap Autoreg + Gateway

Полный стек для nonecap.com — hCaptcha solver API (1300 free credits на signup).

## Компоненты

| Файл | Назначение |
|------|-----------|
| `nonecap_register.py` | Авторег: Voidash inbox → Turnstile (локальный cs_sidecar, бесплатно) → signup → email verify → API key (`nc_live_...`) |
| `nonecap_gateway.py` | Шлюз :9997 — hCaptcha solve поверх пула ключей: ротация, прокси-фолбэк, SSE-стриминг, дашборд, file-browser API для агентов |
| `README.md` | Этот файл |

## Реверс API (nonecap.com/api-reference)

- Base: `https://api.nonecap.com/v1`, Bearer `nc_live_...`, JSON
- `POST /v1/solves?wait=N` (N 1–90с) — `{"type":"hcaptcha","sitekey":"...","url":"..."}` → 200 + `token` (P1_...) или 202 + null (poll)
- `GET /v1/solves/{id}` — статус solve
- `GET /v1/solves` — список, `DELETE /v1/solves/{id}` — отмена
- `GET /v1/me` — account & balance
- `POST /v1/feedback` — `{"solve_id":..., "outcome":"accepted|rejected"}` (обязательно репортить rejected!)
- Токен отправлять в `h-captcha-response` c тем же User-Agent, что в ответе solve

**Важно:** `api.nonecap.com` геоблочит наш IP (403 network refused) — все вызовы через HTTP-прокси.

## Анти-фрод NoneCap (проверено на практике)

1. **Disposable-домены блокируются на signup** (`voidash.bond` — «disposable email domains aren't supported»). Проходят: `govno.eu.cc`, `musor.eu.cc`, `pomoi.eu.cc` (Voidash alt-домены).
2. **Network-бан**: «Sign-ups from your network are not permitted» — нужен свежий прокси на каждую регистрацию.
3. **Risk-lock**: аккаунт блокируется (`account_locked` на `/v1/me`) если после verify сделать повторный login с того же прокси. Правило: verify link уже авторизует сессию — ключ добывать БЕЗ повторного логина.
4. t-online.de пул не годится — NoneCap вообще не шлёт туда письма (проверено: 0 писем в INBOX/Spam/Subscription/Archive/Trash).

## Капча

Cloudflare Turnstile sitekey `0x4AAAAAADkESu5VN02iaX-3` на signup И login.
Решается локально **бесплатно**: cs_sidecar :8877 (`POST /solve {"type":"turnstile","sitekey":...,"url":...,"real_page":true}`, cloakbrowser). 2captcha — только фолбэк.

## Запуск

```bash
# 1. sidecar капчи (должен быть поднят):  http://127.0.0.1:8877/health
# 2. регер (N акков):
cd Desktop && PYTHONPATH="" python311 -X utf8 nonecap_autoreg.py --count 3 --headless=true
# 3. шлюз:
cd Desktop/_PROJECTS/nonecap_autoreg && PYTHONPATH="" python311 nonecap_gateway.py --port 9997
```

## Gateway API (:9997)

Auth: `X-Gateway-Key: <gateway_key.txt>`.

```
POST /v1/solve   {"sitekey":"...","url":"...","wait":30}          → {"token":"P1_..."}
POST /v1/solve   {...,"stream":true}                              → SSE: pick/solving/polling/result/error
GET  /v1/keys    балансы всего пула (через прокси)
GET  /health     keys_alive/proxies/uptime/solved/failed
GET  /files?path=Desktop/tmp   листинг/чтение файлов агентами (whitelist: Desktop,tmp,SESSION-BASE, ≤2MB)
POST /pool/reload  перечитать пул ключей
GET  /dashboard  HTML (авто-рефреш 15с)
```

## Файлы данных

- `~/Desktop/nonecap_accounts.txt` — `email:password:nc_live_key` (PENDING = верифицирован, ключ ещё не добыт)
- `~/Desktop/nonecap_state.json` — counter/used_emails
- `~/tmp/live_http_proxies.txt` — пул прокси (формат `http://ip:port ...`)
