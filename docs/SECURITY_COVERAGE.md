# SecureShop Café — Security Coverage Matrix

**Status definition:** Tested = automated regression exists and passed locally. HTTP-evidence = exercised against running servers by `scripts/security_compare.py` (transcripts in `evidence/`). Manual pending = browser/device step still needs a human pass. No row is proof of independent Red Team testing.

Updated for the remediated `feature/secure-shop-hardening` build (46 tests + 10/10 HTTP comparisons).

| Topic | Threat / root cause | Code defense | Local automated evidence | Remaining work |
|---|---|---|---|---|
| Server-authoritative pricing | Client tampers price | `app.py /checkout` reads `products.price_cents`; client totals ignored | `test_price_is_always_from_database`; HTTP `price-tampering` | — |
| Checkout replay | Double-submit debits twice | `orders.idempotency_key` UNIQUE(user_id,key); replay returns same receipt | `test_checkout_replay_returns_same_order_no_second_debit`; HTTP `checkout-replay` | true parallel race test |
| Coupon reuse | Coupon reused | `coupon_uses` PK inside checkout transaction | `test_coupon_single_use_and_no_negative_quantity`; HTTP `coupon-reuse` | concurrent coupon test |
| Newsletter harvesting | Anyone mints coupons for any email | Code never in HTTP response; delivered to mailbox (dev console); uniform reply | `test_newsletter_never_displays_coupon_to_submitter`; HTTP `newsletter-harvest` | — |
| Account enumeration (register) | 409 reveals taken email / unverified reservation | `pending_registrations` stores no user until mailbox confirmation; repeated pending submissions replace the token and data; active-account response remains uniform | `test_registration_and_confirmation_required`, `test_registration_response_does_not_reveal_existing_email`, `test_unverified_registration_does_not_reserve_email` | Production mail ownership and resend service remain outside this local build |
| Account enumeration (login timing) | Unknown email skips Argon2 | `DUMMY_PASSWORD_HASH` verified for unknown users | `test_unknown_email_login_still_runs_argon2` | — |
| Exceptional input | Giant/ambiguous fields | Strict lengths, duplicate fields rejected, 16 KB body cap | `test_exceptional_email_rejected_not_truncated` | more fuzz forms |
| Checkout workflow | Skip cart/credit checks | Atomic `BEGIN IMMEDIATE` checkout; stock/credit/active re-checked | `test_checkout_bypass_blocked_and_no_side_effect` | — |
| Negative quantity | Negative qty in cart | `positive_int` + CHECK(qty>0) | `test_coupon_single_use_and_no_negative_quantity`; HTTP `negative-qty` | — |
| Cross-account MFA | Attacker picks MFA user | `pending_user_id` bound to session row | `test_mfa_binds_second_factor_to_authenticated_user` | — |
| TOTP replay / guessing | OTP reuse or renewable guessing budget | Persistent `totp_last_step` plus per-user durable escalating lockout (`mfa_throttles`, 5 failures per lock; 5-minute base capped at 1 hour) | MFA tests; `test_mfa_lockout_survives_rolling_window_reset` | Account recovery policy and distributed monitoring remain deployment work |
| MFA recovery | Lost authenticator lockout | 8 hashed single-use recovery codes; password-gated regeneration | `test_recovery_code_single_use_login`, `test_recovery_regeneration_replaces_old_set` | — |
| Password storage | Weak/plaintext hashes | Argon2id (t=3, m=64 MiB, p=2) | `test_argon2id_password_storage`; HTTP `admin-no-role` contrast | — |
| Session fixation/quality | Predictable/stealable sid | 256-bit token, SHA-256 stored, rotation on login/logout, HttpOnly+SameSite | session tests; HTTP `session-token` | — |
| Brute force | Password spraying and concurrent count bypass | Atomic `reserve_attempt` transaction admits at most 5 password attempts per IP+email window before Argon2; MFA has durable per-user lockout | `test_concurrent_login_attempts_are_reserved_before_hash`; `test_mfa_lockout_survives_rolling_window_reset`; HTTP evidence | Per-account distributed limit across source addresses remains untested |
| Typing behavior anomaly | Abnormal typing | 5 samples, z-score>3 → `behavior_anomaly` audit (signal only) | `BehavioralTests`, `test_security_page_protected_and_behaviour_five_enrollments` | spoofable browser signal — documented |
| Location/time policy | Impossible travel / off-hours | Haversine ≤50 km + Cairo 08:00–22:00 gate (optional enforcement) | `GeoTimeTests`, HTTP passkey policy tests | browser coords forgeable — documented |
| Passkey validation | Forged/replayed credential and concurrent challenge replay | ES256 verify: origin, RP hash, UP+UV flags, signature, compare-and-swap sign count, atomically claimed one-time challenge, session rotation in the same transaction | `WebAuthnTests`, HTTP passkey tests, `test_concurrent_passkey_assertion_replay_allows_at_most_one_login` | Real hardware passkey pending |
| Authorization/IDOR | Other user's order, /admin | Owner-scoped queries + `must_admin` on every admin route | `test_idor_and_admin_denied`; HTTP `idor-order`, `admin-no-role` | — |
| CSRF | Forged mutating POST | Per-session CSRF token, `hmac.compare_digest`, POSTs require session cookie | `test_csrf_missing_blocks_writes`; HTTP `csrf-profile` | — |
| XSS | HTML/JS injection | `html.escape` on all user output + CSP `script-src 'self'` | `test_xss_escaped_and_no_html_injection` | — |
| SQL injection | Search/query injection | Bound parameters; LIKE wildcards escaped | `test_sql_query_input_does_not_expand_search`; HTTP `sqli-search` | — |
| Security headers | Clickjacking/sniffing | nosniff, XFO DENY, no-referrer, no-store, CSP; HSTS under HTTPS | header assertions in tests | — |
| Audit | Repudiation, silent failures | Allowlisted events, actor+target, no secrets column | audit tests | admin can edit local SQLite — documented |
| Error handling | Stack/secret leakage | Generic error pages, no debug output, `sys_version=''` | error-path tests | — |

## Evidence revision
- 46-test suite green after F1–F4 remediation (`python -m unittest discover -s tests`).
- `scripts/security_compare.py` → **10/10 scenarios: naive vulnerable, secure defended**; transcripts in `evidence/compare_summary.txt` + `evidence/compare_transcripts.json`.
- Independent disposable-DB HTTP retest: F1 durable lockout remained 429 after the rolling rows were aged; F2 admitted 5 and rejected 3 concurrent password attempts; F3 created no `users` row before confirmation and replaced the pending record; F4 produced at most one successful response per assertion.
- `pip-audit -r requirements.txt` → **No known vulnerabilities found**.
- `localhost` is the only WebAuthn RP/Origin. `127.0.0.1` is the loopback bind.
- The four independent findings from the final audit and their retests are recorded in `docs/REMEDIATION_REPORT.md`.
