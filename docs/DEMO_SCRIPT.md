# Demo script — 10–15 minutes

Setup before presenting (3 commands):
```sh
python app.py                 # terminal 1 — secure app on :8000
python naive_lab.py           # terminal 2 — naive lab on :5050
# browser: http://localhost:8000   (use localhost, not 127.0.0.1, for passkeys)
```

## 1. The app (2 min)
- Home page: café catalogue, categories, search. Theme and identity are the
  original project, kept intact.
- Register → show the **confirmation link printed in the server terminal**
  (dev outbox instead of email) → confirm → log in. New accounts get $100
  store credit.

## 2. Core commerce (3 min)
- Add items to cart, change quantity, show totals from DB prices.
- Show newsletter: submit an email → **no coupon appears on screen** — it is
  printed to the server terminal. Explain: the old build showed the code to
  anyone; now only the mailbox owner gets it (coupon-harvesting fix).
- Checkout: show coupon field, place order, show order history + stock drop.

## 3. Live attack contrast (4 min) — the centerpiece
Run `python scripts/security_compare.py` in terminal 3 → 10/10 scenarios.
Walk 3–4 rows of `evidence/compare_summary.txt` live:
- `price-tampering`: naive accepts `total=1`; secure recomputes → 2499.
- `checkout-replay`: naive debits every POST (orders 2→3); secure replays the
  idempotency key → same receipt, one debit.
- `csrf-profile`: naive accepts a tokenless POST; secure 403.
- `sqli-search`: naive concatenates `q`; secure returns nothing.

## 4. Authentication depth (3 min)
- `/mfa/setup`: QR scan (Google/Microsoft Authenticator), verify TOTP →
  **8 recovery codes shown once**. Explain hashing + single-use + regen at
  `/mfa/recovery`.
- Log out, log in → TOTP challenge; show a wrong code → 401; reuse the same
  code → still 401 (step replay protection).
- `/security` page: typing enrollment (5 samples, only intervals stored),
  passkey registration, and the location/time risk assessment. State plainly:
  browser timing + geolocation are *signals in the audit log*, not identity.
- `/admin/audit`: show `login_failed`, `mfa_*`, `checkout_complete` events.

## 5. Wrap (1 min)
- 46 automated tests green + 10/10 HTTP comparisons, both reproducible. The
  final independent audit also retested MFA lockout, concurrent login limits,
  pending registration, and concurrent passkey replay; see
  `docs/REMEDIATION_REPORT.md`.
- Honest limits: educational WebAuthn, no real email, and synthetic local
  credentials. Parallel replay was retested over HTTP; real-device passkey and
  browser compatibility evidence remain pending.

## If asked "what did you change vs the original?"
Enum fixes on `/login` + `/register`, newsletter harvesting fix, recovery
codes, checkout idempotency key, the real-HTTP naive lab + compare runner,
pinned deps — each with its own regression test and commit.
