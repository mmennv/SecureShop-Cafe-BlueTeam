# SecureShop Café — one-page architecture

## Shape
Single-process Python 3 app: `ThreadingHTTPServer` (stdlib) serving server-rendered
HTML + one static JS file, backed by SQLite. Three dependencies: `argon2-cffi`,
`qrcode[pil]`, `cryptography`. No framework, no build step, runs identically on
Windows/macOS/Linux.

## Modules
| File | Responsibility |
|---|---|
| `app.py` | Routing, HTML, SQLite schema/migrations, sessions, CSRF, checkout, admin |
| `auth_security.py` | Argon2id hashing, RFC-6238 TOTP (+step replay guard) |
| `blue_security.py` | Typing-timing z-scores, haversine distance, Cairo time gate |
| `passkey_security.py` | Bounded CBOR parser + ES256 WebAuthn verification (localhost only) |
| `security.js` | Browser-only: keystroke gaps, WebAuthn ceremony calls (no secrets) |
| `naive_lab.py` | Deliberately vulnerable comparison server (127.0.0.1, own DB) |
| `scripts/security_compare.py` | Drives identical HTTP attacks at both servers, writes `evidence/` |

## Trust model
- Every security decision is server-side. Client values (prices, totals, roles,
  user ids, geolocation, keystroke timings) are never trusted.
- Session cookie = random 256-bit token; DB stores only its SHA-256 hash.
  Rotated on login/logout; `pending_user_id`/`pending_passkey_id` bind MFA and
  passkey challenges to the session that started them.
- All money in integer cents; checkout runs in `BEGIN IMMEDIATE` so debit,
  stock, coupon-use and cart-clear are atomic; `orders.idempotency_key`
  deduplicates retries.
- WebAuthn is an educational ES256/`none`-attestation implementation — honest
  limits documented; not a production claim.

## Data layout (SQLite, `secureshop.db` by default)
users, confirmations, pending_registrations, sessions, mfa_enrollments,
recovery_codes, mfa_throttles, products,
carts (session-bound), coupons, coupon_uses, newsletters, orders(+items,
idempotency_key), audit_events, login_attempts, behavior_profiles, passkeys,
passkey_challenges. Unverified registrations remain in `pending_registrations`
until a confirmation token atomically promotes them into `users`.

## Request lifecycle
`get_session` (issue/refresh cookie, expire old) → `parse_post` (content-type,
size, field-count, duplicate-field, CSRF) → route → `must_login`/`must_admin`
gate → business logic under transaction → response with security headers
(nosniff, XFO DENY, no-referrer, no-store, CSP `script-src 'self'`).
