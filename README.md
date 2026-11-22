# SecureShop Café — CET431 Blue Team build

Local educational e-commerce site: customer/admin flows, Argon2id + TOTP MFA
with recovery codes, limited ES256 WebAuthn, typing-anomaly and location/time
risk signals, server-side checkout integrity, audit logging — plus a matched
**naive-vs-secure HTTP evidence harness**.

## Install

```sh
cd SecureShop-Cafe
python3 -m venv .venv          # Windows: py -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python app.py
```

Open `http://localhost:8000` (passkeys require the `localhost` RP/origin —
`127.0.0.1` won't work for them, though the app binds to loopback).

## Users

- **Customer:** `/register`, then copy the confirmation link printed to the
  server terminal (this dev build has no real email — terminal = outbox).
- **Admin** (empty DB only):
  ```sh
  export SECURESHOP_ADMIN_EMAIL='admin@example.test'
  export SECURESHOP_ADMIN_PASSWORD='<a long passphrase>'
  python app.py
  ```
- New accounts start with $100.00 store credit — checkout is credit-only, no
  card gateway exists.

## Naive vs secure evidence

```sh
python app.py                                   # terminal 1 (secure, :8000)
python naive_lab.py                             # terminal 2 (naive, :5050)
python scripts/security_compare.py              # terminal 3
# -> "10/10 scenarios: naive vulnerable, secure defended"
#    transcripts: evidence/compare_summary.txt, compare_transcripts.json
```

The compare script provisions its own `compare@example.test` fixture user in
the app database — run it against a throwaway DB (`SECURESHOP_DB=/tmp/x.db`).

## Routes

`/` catalogue · `/register` `/confirm` `/login` `/mfa` `/mfa/setup`
`/mfa/recovery` `/account` `/security` `/security/behavior` · `/cart`
`/checkout` `/orders` `/order/<id>` · `/newsletter` · `/admin` `/admin/audit`
· passkey JSON endpoints under `/passkey/*`.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `SECURESHOP_DB` | `./secureshop.db` | SQLite path (tests always use temp files) |
| `SECURESHOP_HOST`/`PORT` | `127.0.0.1:8000` | bind address — keep loopback |
| `SECURESHOP_HTTPS` | off | adds `Secure` cookie flag + HSTS |
| `SECURESHOP_RISK_GATE_ENFORCE` | off | forces passkey+geo/time gate at login |
| `SECURESHOP_NAIVE_DB`/`_PORT` | `./naive_lab.db:5050` | lab only |

## Honest limits

- Localhost teaching build, not production. WebAuthn covers ES256 + `none`
  attestation only (documented, tested with synthetic credentials).
- Geolocation and typing timings are browser-reported — risk *signals* in the
  audit log, never identity factors. The optional login gate is off by default.
- Confirmation links / newsletter coupons print to the server terminal instead
  of email, by design.
- The final independent local audit and F1–F4 remediation retest are recorded
  in `docs/REMEDIATION_REPORT.md`; real-device passkey and browser walkthroughs
  remain pending — see `docs/SECURITY_COVERAGE.md` and `docs/TEST_RESULTS.md`.

## Docs

`docs/ARCHITECTURE.md` (one-page) · `docs/DEMO_RUNBOOK.md` (**start here for
the demo**) · `docs/SECURITY_DESIGN_BLUE_TEAM.md` (threat model/STRIDE/DREAD) ·
`docs/SECURITY_COVERAGE.md` (matrix) · `docs/ATTACK_EVIDENCE.md` ·
`docs/DEMO_SCRIPT.md` · `docs/QA_PREP.md` · `docs/TEST_RESULTS.md` ·
`docs/THIRD_PARTY_CREDITS.md` · Menna's original Arabic review/evidence docs
preserved alongside.
