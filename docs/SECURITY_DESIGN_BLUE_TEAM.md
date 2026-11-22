# CET431 Security Design — SecureShop Café (Blue Team)

**Implementation-oriented draft** | 20 November 2026 | Educational local deployment only

This report documents what the delivered code implements and identifies what requires further evidence. It must be reviewed by the student team, attributed appropriately, and supplemented with authenticated evidence from the final demo. No real attack against third-party systems is authorized.

## 1. Executive overview
The application is a Python ThreadingHTTPServer + SQLite secure-commerce educational implementation. There are two roles: customer and administrator. Users register, confirm accounts, authenticate, browse a catalogue, manage carts, redeem coupons, pay using simulated store credit, and view their own orders. Administrators manage accounts, inventory and coupons. Security-sensitive state is validated by the server and persisted in SQLite. The application is NOT suitable for direct public deployment without production hardening.

## 2. Assets and security objectives
| Asset | Confidentiality | Integrity | Availability | Primary owner |
|---|---|---|---|---|
| Account credentials (Argon2id hashes) | High | High | Medium | Customer/admin |
| TOTP secret & used-step counter | High | High | High | Account |
| Passkey public key, sign count and pending challenge | Medium | High | High | Account |
| Sessions and CSRF secrets | High | High | High | Application |
| Credits and balances | Medium | Critical | High | Account/server |
| Product prices, inventory and coupons | Public/medium | Critical | High | Admin/server |
| Orders and order ownership | High | High | Medium | User/server |
| Behavioral aggregates | Sensitive biometric-like risk metadata | High | Medium | User/server |
| Audit events | Medium | High | High | Operations |

## 3. Trust boundaries and data flow
1. Browser -> local HTTP listener: all URL parameters, form data, timestamps and geolocation are untrusted, even when a client-side input validator exists.
2. Request handler -> session store: cookie contains a random SID; only SHA-256 digest is stored as session identifier. Session rotation follows authentication and logout.
3. Business logic -> SQLite: SQL placeholders, explicit transactions for checkout, foreign keys and constraints enforce invariants.
4. Administrator -> catalog/role state: authenticated admin roles are checked on GET and mutation handlers, not simply hidden in navigation.
5. Authenticator app / platform passkey -> browser -> server: TOTP verified against enrolled secret; WebAuthn public-key challenge signatures verified on server.
6. External location signal: browser geolocation is user-reported, not tamper-resistant proof of physical location. No third-party location service is called.

## 4. Threat actors and attack surface
- Anonymous visitor: registration, login, search, newsletter, confirmation, malformed URL and CSRF attempts.
- Authenticated customer: own session, cart, checkout, coupons, order URLs, profile, security settings, attempts to access admin.
- Compromised password holder: attempts MFA bypass, TOTP replay, unusual typing or passkey misuse.
- Malicious administrator: insider data misuse or questionable stock/credit changes; auditing reduces but does not eliminate insider risk.
- Automated scanner or concurrent client: rate limit, exceptional input, race conditions and availability risks.

## 5. STRIDE (representative threats)
| Category | Threat | Mitigation in project | Remaining risk |
|---|---|---|---|
| Spoofing | Password stolen and account login | Argon2id password hashing, TOTP with bound pending-user session, hashed single-use recovery codes, durable per-user MFA lockout, optional WebAuthn ES256 challenge | Password limit remains keyed by direct peer IP+email; distributed spray controls need deployment support |
| Tampering | Client changes price, quantity, role or coupon | Read price from DB, positive qty, transaction validation, role authorization | Concurrency and full mutation fuzz tests pending |
| Repudiation | Admin denies catalog changes | Allowlisted persistent audit events with actor ID and time | Local SQLite admin can modify audit; retention policy absent |
| Information disclosure | Other user's order exposed | User-owned order query, server-side session checks | Further privacy tests required |
| Denial of Service | Repeated password attempts or large POST body | Atomic pre-hash attempt reservation, durable MFA lockout, size and field count caps | No reverse proxy/WAF; distributed abuse controls remain deployment work |
| Elevation of privilege | Customer accesses /admin | Server-side role check on all admin handlers | More mutation coverage recommended |

## 6. Attack scenario to defense matrix
| Source / topic | Scenario | Root cause | Defense & code | Local evidence | Confidence |
|---|---|---|---|---|---|
| Price integrity | Tampered price | Trust client-provided total | app.py /checkout reads products.price_cents | test_price_is_always_from_database | Tested |
| Coupon reuse protection | Repeated coupon in checkout | Missing coupon reuse state | app.py /checkout, coupon_uses uniqueness | test_coupon_single_use_and_no_negative_quantity | Tested |
| Input validation | Oversized registration email | Truncation and inconsistent validation | app.py /register | test_exceptional_email_rejected_not_truncated | Tested |
| Checkout workflow validation | Checkout skipped earlier steps | Missing workflow constraints | app.py /checkout atomic transaction, stock/credit/cart checks | test_checkout_bypass_blocked_and_no_side_effect | Tested |
| MFA verification | OTP attached to another user | Client-selected user identity during MFA | app.py /mfa pending_user_id from server session | test_mfa_binds_second_factor_to_authenticated_user | Tested |
| Typing behavior | Suspicious typing behavior | No user baseline | blue_security.py z-scores, app.py /security/behavior, JS timings, audit event | test_five_samples_then_anomaly; HTTP behavioral test | Tested as risk signal only |
| Location and time policy | Login from distant location | No geographic policy | blue_security.py haversine; app.py /passkey/auth/finish | test_location_time_policy | Browser geolocation is untrusted; not strong enforcement |
| Location and time policy | Login outside expected time | No time gate | server Africa/Cairo 08:00-22:00, optional login enforcement | test_hour_window_boundaries; HTTP gated login | Tested code path, manual device check pending |
| Location and time policy | Passkey challenge forged / replayed | Missing cryptographic challenge validation | passkey_security.py checks origin/RP ID/flags/signature/sign count; app.py challenge persistence | test_registration_none_attestation_and_real_es256_assertion; HTTP integration | Tested synthetic ES256 credential, real device pending |
| Lectures 2–4 | SQL injection | SQL concatenation | app.py SQLite placeholders | test_sql_query_input_does_not_expand_search | Tested basic scenario |
| Lectures 2–4 | XSS | User data rendered unsafely | app.py html.escape, CSP | test_xss_escaped_and_no_html_injection | Basic test only |
| Lectures 2–4 | CSRF | State changes without per-session token | app.py parse_post | test_csrf_missing_blocks_writes | Tested |
| Lectures 3–4 | IDOR | Order ID without account ownership | app.py /order/<id> | test_idor_and_admin_denied | Tested |
| Audit / governance | No record of security actions | Missing event instrumentation | app.py audit_event and /admin/audit | audit tests | Tested, tamper resistance pending |

## 7. Authentication and second-factor design
- **Password**: Argon2id via argon2-cffi with salted hash; no plaintext storage.
- **Account confirmation**: short-lived hashed token in `pending_registrations`; confirmation atomically promotes the pending record into `users`, so an unverified email never occupies an active-user row. Development-only link is logged to the local terminal. Email delivery is not implemented.
- **TOTP**: SHA-1 HMAC 30s, six digits, ±1 step window, persisted monotonic last accepted step to reject replay, and a per-user durable escalating lockout after each five failures. Pending login identity is read from server-side session, not form fields.
- **Behavioral anomaly**: Five successful password-backed typing enrollment samples, feature vector `{speed,gap_1..gap_5}`; per-feature mean and population standard deviation (floor to reduce false positives), average absolute z-score >3.0 creates audit event. Raw keys not stored. Browser timings are forgeable; cannot replace MFA or passkey.
- **WebAuthn**: Registration after password re-verification by logged-in user; challenge stored for 180 seconds keyed to session and atomically claimed; browser credential uses user-verification and user-presence flags; server accepts only ES256/P-256 / fmt none, checks rpIdHash, type, exact challenge, expected origin, signature and compare-and-swap sign counter. Authenticated session rotation is in the same transaction as the counter update. Authorization remains server-side. Demo intentionally limited to localhost and current device support.
- **risk gate**: Optional `SECURESHOP_RISK_GATE_ENFORCE=1` makes users who registered passkeys finish login with passkey signature + location/time checks. By default, /security contains a nonblocking demo check to avoid unintentional lockout. Clock is Africa/Cairo, allowed [08:00,22:00). Home is an illustrative Cairo landmark and not an actual user residence. This is not GPS attestation.

## 8. Input and business-logic enforcement
Every POST requires session CSRF secret and bounded urlencoded form. Cart quantities must be positive and within stock and cap; removing quantity zero is a dedicated operation. Checkout obtains authoritative product stock/prices, verifies active status, ensures sufficient store credit, applies coupons once and inserts order items and decrements balance/stock in one IMMEDIATE transaction. Database uniqueness and FK constraints add defense in depth. Admin mutations perform backend role checks. User profile rendering escapes HTML.

## 9. Auditing, privacy and operational concerns
Audit records use allowlisted event names, numeric actor and target IDs, server timestamps. No passwords, OTPs, TOTP seeds, confirmation tokens, location coordinates or raw keystrokes are logged. Behavioral profile contains only quantized timing features retained while the account exists. This data deserves explicit consent, minimization, erasure and retention policies before real-world use. Debug logs can still expose local confirmation links; never use this in production.

## 10. Testing strategy and evidence
- Automated: `python -m unittest discover -s tests -v` (46 tests OK in an isolated disposable database after F1–F4 remediation).
- Functional smoke test: User and Admin browser sessions, initial login through checkout, product edits, newsletter, store credit and order history.
- Security negative cases: price tampering, coupon reuse, empty cart, insufficient balance, missing CSRF, role restriction, IDOR, MFA account binding/replay, suspicious timing, out-of-policy location/time, invalid WebAuthn challenge/signature.
- Outstanding: Manual real-device passkey registration/authentication; broad SAST/DAST with course-approved tooling; browser/OS compatibility validation; distributed rate-limit and load testing.

## 11. Deployment limitations
This is a localhost educational prototype. No formal key management/HSM, email verification service, HTTPS termination, CSP nonce strategy, WAF, centralized audit retention, trusted location attestation, or production WebAuthn package integration. Student team should not expose the built-in Python server to internet or use real payment data. Do not pretend optional Location and time policy policy is enforced when the flag is off.

## Hardening-branch additions (feature/secure-shop-hardening)
- **Checkout idempotency:** `orders.idempotency_key` UNIQUE per user; GET `/checkout` mints a one-time key into the form; replayed submits return the same receipt without a second debit (`test_checkout_replay_returns_same_order_no_second_debit`).
- **MFA recovery codes:** 8 codes shown once at TOTP enrollment, SHA-256 digests only in `recovery_codes`, single-use DELETE on redemption, password-gated regeneration at `/mfa/recovery` (`test_recovery_code_single_use_login`, `test_recovery_regeneration_replaces_old_set`).
- **Account-enumeration closures:** `/login` verifies `DUMMY_PASSWORD_HASH` for unknown emails (timing parity); `/register` returns the identical page for taken emails (status + body) and issues no token.
- **Newsletter coupon harvesting closed:** codes are never rendered to the submitter; delivery follows the dev-console outbox model, with a uniform response whether or not the email was already subscribed (`test_newsletter_never_displays_coupon_to_submitter`).
- **Real-HTTP naive comparison:** `naive_lab.py` (loopback-only, disposable DB) + `scripts/security_compare.py` produce 10 matched attack/defense transcripts under `evidence/` (10/10 defended).
- **Final independent remediation:** F1 durable MFA lockout, F2 atomic login reservation, F3 pending registration records, and F4 atomic WebAuthn challenge claim were independently reproduced before and after the patch. The after-run included concurrent HTTP checks for F2 and F4; details are in `docs/REMEDIATION_REPORT.md`.
- **Pinned dependencies** (`requirements.txt` exact versions) and `docs/ARCHITECTURE.md`, `docs/ATTACK_EVIDENCE.md`, `docs/DEMO_SCRIPT.md`, `docs/QA_PREP.md`, `docs/THIRD_PARTY_CREDITS.md` added.

## 12. Next evidence before final submission
1. Collect redacted browser screenshots of UI and security denials.
2. Repeat real-device passkey and browser walkthroughs on the final demo environment.
3. Keep the F1–F4 remediation evidence and commit reference with the course submission.
4. Complete Git commits from all members, README architecture and 10–15 minute demo/Q&A rehearsals.
5. Cite any reused modules, standards, documentation and assistance per course academic integrity policy.


## Appendix: Verification revision
The final test build validates WebAuthn `rp.id=localhost`, `rpId=localhost`, and origin `http://localhost:8000` together. It rejects invalid signature and stale challenges, atomically consumes concurrent assertions, and tests time/location decision branches through HTTP with deterministic synthetic coordinates and fixed server time. The automated suite has 46 passing cases after the independent F1–F4 remediation. See `TEST_RESULTS.md`, `SECURITY_COVERAGE.md`, and `REMEDIATION_REPORT.md`.
