# Independent F1–F4 remediation report

Date: 2026-11-22
Scope: `/root/softsec/SecureShop-Cafe`, loopback-only local HTTP servers, fresh disposable SQLite databases. The tracked `compare_dev.db` and `naive_lab.db` files were not opened or modified.

## F1 — Durable MFA guessing protection (P1)

Before the patch, five invalid MFA requests returned 401, the sixth returned 429, and after the rolling `login_attempts` rows were aged past ten minutes another five invalid requests all returned 401. The original root cause was a renewable five-per-ten-minute counter with no durable per-user state.

The patch adds `mfa_throttles` and a per-user escalating lockout: every fifth cumulative failure locks for five minutes, doubling to a one-hour cap. The count and lock decision, code verification, failure recording, and successful reset run in one `BEGIN IMMEDIATE` transaction. A successful factor resets the state; a failure does not.

After the patch, the same probe returned five 401 responses, then 429, and all five requests after aging the generic rolling rows returned 429. The regression is `test_mfa_lockout_survives_rolling_window_reset`.

## F2 — Concurrent login-throttle bypass (P2)

Before the patch, eight simultaneous wrong-password POSTs for one email and source IP all returned 401 and eight attempt rows were recorded, although the configured limit was five. The root cause was a non-atomic count, expensive Argon2 verification, and later insert.

The patch adds `reserve_attempt`, which reserves a slot under `BEGIN IMMEDIATE` before Argon2 verification. Successful logins remove the reservations for that key; failures retain them.

The same eight-request HTTP probe after the patch returned five 401 responses and three 429 responses, with five rows recorded. The regression is `test_concurrent_login_attempts_are_reserved_before_hash`.

## F3 — Unverified registration email reservation (P2)

Before the patch, the first anonymous registration inserted an unconfirmed `users` row. A second registration for the same address returned the same 200 page but could not replace the first password or obtain a confirmation token; the attacker password remained valid in the unconfirmed row.

The patch adds `pending_registrations`. Registration stores only a short-lived pending record and replaces an existing pending record/token. Confirmation atomically consumes the pending token and inserts a confirmed `users` row. A legacy `confirmations` path remains readable for migration compatibility.

After the patch, two submissions still return uniform 200 responses, no `users` row exists before confirmation, the pending display name/password belong to the second submission, and the first password is invalid. The confirmation workflow is covered by `test_registration_and_confirmation_required`; the reservation regression is `test_unverified_registration_does_not_reserve_email`.

## F4 — Concurrent WebAuthn assertion replay (P2)

Before the patch, the same valid assertion sent concurrently could pass the separate challenge SELECT and DELETE race. In the independent HTTP reproduction, two of eight requests returned 200 and produced two authenticated sessions.

The patch atomically claims the live challenge with a DELETE row-count check. It then verifies the assertion, performs a compare-and-swap on the stored sign counter, and rotates the pending session inside the same transaction. A claimed challenge cannot be used by a second request.

After the patch, 12 rounds of eight concurrent copies produced zero rounds with multiple 200 responses; each round had at most one success and replays returned 403. The regression is `test_concurrent_passkey_assertion_replay_allows_at_most_one_login`.

## Verification

- `./run_all_tests.sh`: **46 tests, OK**.
- `scripts/security_compare.py` against fresh secure and naive loopback servers: **10/10 scenarios, naive vulnerable / secure defended**.
- `.venv/bin/pip-audit -r requirements.txt`: **No known vulnerabilities found**.
- Fresh-install schema smoke and all changed HTTP paths use disposable databases.

Remaining risks: real email delivery and mailbox ownership are not implemented; password spraying across many source addresses still needs deployment-level controls; no hardware-backed passkey or browser end-to-end walkthrough was performed; the naive lab remains educational and must stay loopback-only.

The final local commit hash is reported in the audit handoff; this report is included in that local commit and nothing was pushed.
