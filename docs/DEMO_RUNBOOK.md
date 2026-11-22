# Demo runbook — reproducible, disposable

Everything below uses `demo.db` (synthetic users) and `naive_lab.db`
(disposable lab). Nothing touches a development database or real credentials.
Mail: registration links and coupons print to the server terminal unless
`SECURESHOP_SMTP_*` vars point at Gmail (see `.env.example`).

## Accounts (synthetic — demo only)

| Email | Password | Role |
|---|---|---|
| `alice@demo.test` | `alice demo password` | customer |
| `bob@demo.test` | `bob demo password` | customer |
| `admin@demo.test` | `admin demo password` | admin |

Coupon: `DEMO10` (10% off, once per user). Products: 12 café items seeded by
`init_db`. Each user starts with $100.00 store credit.

## Setup (once)

```sh
cd SecureShop-Cafe
python3 -m venv .venv && source .venv/bin/activate   # Win: .venv\Scripts\activate
pip install -r requirements.txt
```

## Start

```sh
rm -f demo.db naive_lab.db
SECURESHOP_DB=$PWD/demo.db python scripts/seed_demo.py    # idempotent seed
SECURESHOP_DB=$PWD/demo.db python app.py                  # secure app -> :8000
python naive_lab.py                                       # naive lab -> :5050
```

Open `http://localhost:8000` (use **localhost**, not 127.0.0.1, for passkeys).

## Stop

`Ctrl+C` in each terminal, or:
```sh
pkill -f 'python app.py'; pkill -f naive_lab.py
```

## Reset to a clean state

```sh
pkill -f 'python app.py'; pkill -f naive_lab.py   # stop first
rm -f demo.db naive_lab.db
SECURESHOP_DB=$PWD/demo.db python scripts/seed_demo.py
# start again as above
```

**Footgun:** starting `app.py` while another instance still runs fails with
`Address already in use` — but a *stale* server may already hold :8000 with a
different DB and the new one never starts. `security_compare.py` detects this
(`no session row appeared in <db>`); for manual demo, always `pkill` first and
check `ss -tlnp | grep -E ':8000|:5050'` is clear before restarting.

## Naive lab containment (verified)

`naive_lab.py` binds `HTTPServer(('127.0.0.1', PORT), ...)` — no config can
make it listen externally. Measured: `curl http://127.0.0.1:5050/` → 200;
`curl http://<external-addr>:5050/` → connection refused. Keep it that way —
the secure app also defaults `SECURESHOP_HOST=127.0.0.1`.

## Walkthrough (10–15 min)

1. **Shopping (3 min)** — log in as `alice@demo.test`. Browse catalogue,
   filter a category, search. Add items, update quantity in cart.
2. **Checkout (2 min)** — checkout with `DEMO10` → order confirmation →
   `/orders` shows the order, credit dropped. Reopen `/checkout`: totals come
   from DB prices, not the form.
3. **Admin (1.5 min)** — log in as `bob@demo.test`, open `/admin` → **403**.
   Log in as `admin@demo.test` → `/admin` works: products, users, coupons,
   `/admin/audit` shows `login_success`, `admin_denied`, `checkout_complete`.
4. **Attacks (4 min)** — run `python scripts/security_compare.py` (both
   servers up) → prints `10/10 scenarios: naive vulnerable, secure defended`.
   Show `evidence/compare_summary.txt` — highlight three:
   - `price-tampering`: naive accepts POSTed `total=1`; secure bills 2499¢.
   - `idor-order`: naive `/order/1` to anyone; secure 404 for non-owner.
   - `sqli-search` or `csrf-profile`: naive concatenates/accepts; secure
     bound params / 403.
   For a live manual attack: `curl -b jar "http://127.0.0.1:5050/?q=%27%20OR%201%3D1--"`
   dumps the naive table; the same on :8000 returns nothing.
5. **MFA + recovery (2.5 min)** — `/mfa/setup` → scan QR (Google/Microsoft
   Authenticator) → TOTP code → **8 recovery codes shown once** (hashed in
   DB). Log out, log in → TOTP prompt; wrong code → 401; after 5 failures →
   durable 429 lockout (does not reset with the rolling window — F1 fix).
   Use a recovery code once → second use → 401. `/security` → regenerate.
6. **Honest WebAuthn/AAL3 statement (1 min)** — the passkey demo verifies
   ES256 signatures, origin, RP hash, UP/UV flags, one-time challenges and
   sign counters on localhost with `none` attestation only. It is **not** a
   claim of AAL3 or hardware non-exportability; no real-device ceremony was
   performed in this environment.

## Manual browser checklist (no E2E driver in this env)

Run through in a browser; check each:
- [ ] `/` catalogue renders desktop + narrow (mobile) widths, nav usable
- [ ] Register → confirmation link arrives by email (SMTP configured) or in
      the **server terminal** (dev outbox); link confirms → login succeeds
- [ ] Register with an existing email → identical page (no enumeration)
- [ ] Wrong password → generic 401; 6th rapid attempt → 429
- [ ] Cart persists across pages while logged in; qty=0 removes line
- [ ] Checkout double-click → one order, one debit (idempotency key)
- [ ] `/order/<other-user's-id>` → 404
- [ ] Newsletter submit → no code on screen; code arrives by email or
      terminal outbox
- [ ] `/mfa/setup` QR scans in authenticator app; TOTP login works; wrong
      code → 401; replay same code → 401; recovery code works once
- [ ] `/security/behavior` accepts 5 typed samples then blocks the 6th (409)
- [ ] Passkey register + risk check on a real device (optional, documented
      as pending if unsupported)
- [ ] `/admin` as bob → 403; as admin → 200; `/admin/audit` lists events
- [ ] Logout → `/account` is 401 until next login

## Independence from hidden state

- `demo.db` is created fresh by `seed_demo.py`; delete it to reset.
- Tests use temp DBs (`tests/test_app.py` sets `SECURESHOP_DB` to a tempdir).
- `security_compare.py` provisions its own `compare@example.test` fixture and
  clears it — run it against a throwaway DB as in this runbook.
- No SMTP, no external services, no real payment, no real PII.
