# Third-party dependencies and credits

| Package | Version | Purpose | License |
|---|---|---|---|
| argon2-cffi | 25.1.0 | Argon2id password hashing | MIT |
| argon2-cffi-bindings | 26.2.0 (transitive) | low-level Argon2 bindings | MIT |
| qrcode[pil] | 8.2 | TOTP provisioning QR codes | BSD-3 |
| pillow | 13.0.0 (transitive) | QR image rendering | MIT-CMU |
| cryptography | 47.0.0 | ES256/P-256 WebAuthn signature verification | Apache-2.0/BSD |

Standard library: `http.server`, `sqlite3`, `hmac`, `secrets`, `hashlib`,
`zoneinfo`, `unittest`.

Fonts referenced by CSS (`Playfair Display`, `DM Sans`) are Google-Fonts names
used via system fallback stacks — no webfont files are bundled.

Original application and documentation: Menna (SecureShop-Cafe-BlueTeam).
Hardening changes are committed on `feature/secure-shop-hardening` and
attributed per-commit; no third-party student work is claimed.
