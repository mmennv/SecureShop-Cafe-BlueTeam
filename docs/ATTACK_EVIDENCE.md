# Attack Evidence Report — naive vs secure (real HTTP)

Method: `naive_lab.py` (deliberately vulnerable, 127.0.0.1:5050, disposable DB)
and SecureShop Café (127.0.0.1:8000) received the **same** attack requests via
`scripts/security_compare.py`. Transcripts: `evidence/compare_summary.txt`
(human-readable) and `evidence/compare_transcripts.json` (full request log,
secure session tokens redacted).

Result: **10/10 scenarios — naive vulnerable, secure defended.**

| # | Scenario | Naive result | Secure result | Root cause / defense |
|---|---|---|---|---|
| 1 | SQL injection in search | `' OR 1=1--` returns all products | No expansion | String-built SQL vs bound params + LIKE-escape |
| 2 | Price tampering | POST `total=1` → order total 1¢ | Order total 2499¢ | Client total trusted vs DB-authoritative price |
| 3 | Checkout replay | Each POST debits again (orders 2→3) | Same key → same receipt, 1 order, 1 debit | No idempotency vs UNIQUE(user_id, idempotency_key) |
| 4 | IDOR on order | `/order/1` readable by anyone | 404 for non-owner | No owner check vs owner-scoped query |
| 5 | Admin without role | `/admin` dumps users incl. plaintext passwords | 403 | No role check vs `must_admin` + Argon2id |
| 6 | CSRF | Tokenless cookie POST changes account | 403 | No CSRF token vs per-session token enforcement |
| 7 | Coupon reuse | Same code discounts repeatedly | 400 "already used" | No use-tracking vs `coupon_uses` PK |
| 8 | Newsletter harvesting | Coupon returned in response to any email | Code only via mailbox | Response disclosure vs out-of-band delivery |
| 9 | Session token | `sid=fixed-token-1`, no flags | 256-bit token, HttpOnly+SameSite | Predictable id vs random+hashed+flagged |
| 10 | Negative quantity | `qty=-5` stored | 400 | No validation vs `positive_int` + CHECK |

## Reproduce

```sh
python app.py                    # terminal 1
python naive_lab.py              # terminal 2
python scripts/security_compare.py   # exit 0 on 10/10
```

Caveats: scenarios are sequential HTTP, not parallel concurrency tests; the
secure fixture user (`compare@example.test`) is provisioned directly in the dev
DB by the script — transcripts show attack traffic only.
