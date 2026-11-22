# Individual Q&A preparation

**Where are passwords verified?** `route_post` `/login` → `verify_password`
(Argon2id, `auth_security.py`). Unknown emails verify a `DUMMY_PASSWORD_HASH`
so timing can't reveal existence.

**How is the session protected?** Cookie holds a random 256-bit token; SQLite
stores only `SHA-256(token)`. Login/logout rotate it (`rotate_session` deletes
the old row). `HttpOnly; SameSite=Lax` (+`Secure` under `SECURESHOP_HTTPS`).

**How is CSRF done?** Per-session token in every form; `parse_post` enforces
`hmac.compare_digest`. POSTs without a session cookie are rejected outright.

**Why can't a double-click double-charge?** GET `/checkout` mints a one-time
`key`; `orders.idempotency_key` is UNIQUE per user — a replayed POST returns
the same receipt inside the transaction.

**What stops price tampering?** `total`/`price_cents` fields are ignored;
totals are recomputed from `products.price_cents` inside `BEGIN IMMEDIATE`.

**TOTP replay?** `totp_last_step` persisted; accepted steps must be strictly
greater (window ±1 for clock skew). Recovery codes are SHA-256'd and deleted
on use.

**MFA cross-account binding?** `sessions.pending_user_id` — the MFA form has
no user field; the pending user comes from the session row.

**Is the typing behavior an auth factor?** No — deliberately. It's a z-score
anomaly *signal* audited as `behavior_anomaly`; browser timings are forgeable.

**Geolocation?** Same answer — checked against a 50 km radius + Cairo 08–22h
window for the risk demo, but documented as browser-reported and optional
(`SECURESHOP_RISK_GATE_ENFORCE`).

**WebAuthn scope?** Educational ES256/`none`-attestation verifier: RP hash,
UP+UV flags, origin, challenge, signature, sign-counter, one-time challenges.
Honest non-goal: full production WebAuthn.

**Where is user input dangerous?** Search (`/?q=`) → bound params + LIKE-escape;
all HTML output → `html.escape`; all writes → CSRF; all queries → placeholders.

**What would you add next?** Real email delivery, per-email (not only
IP+email) login throttling, a true parallel race test, and a maintained
WebAuthn library if this ever left localhost.

**Biggest remaining risk?** The SQLite file *is* the trust root — a local admin
can edit audit rows and balances; acceptable for the assignment, stated openly.
