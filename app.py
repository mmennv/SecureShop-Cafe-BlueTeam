"""SecureShop: dependency-free educational secure e-commerce demo.
Run: python app.py. Python 3.11+ recommended.
"""
import hashlib
import json
import math
import base64
import io
import qrcode
from auth_security import hash_password, verify_password, new_totp_secret, match_totp_step
from blue_security import parse_timing, build_profile, anomaly_score, location_time_result
from passkey_security import challenge, verify_registration, verify_assertion, b64u
import hmac
import html
import os
import re
import secrets
import sqlite3
import time
import urllib.parse
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB_FILE = Path(os.environ.get('SECURESHOP_DB', str(BASE / 'secureshop.db')))
HOST = os.environ.get('SECURESHOP_HOST', '127.0.0.1')
PORT = int(os.environ.get('SECURESHOP_PORT', '8000'))
SESSION_AGE = 60 * 60 * 8
MFA_PENDING_AGE = 5 * 60
MFA_FAILURES_PER_LOCK = 5
MFA_LOCK_BASE = 5 * 60
MFA_LOCK_MAX = 60 * 60
MAX_BODY = 16_384
RISK_GATE_ENFORCE = os.environ.get('SECURESHOP_RISK_GATE_ENFORCE') == '1'  # Optional, otherwise demo check only

# Hash computed once at startup so a login attempt for an unknown email still
# performs a real Argon2 verification and leaks no existence signal by timing.
DUMMY_PASSWORD_HASH = hash_password('not a real password - timing parity')


@contextmanager
def db():
    conn = sqlite3.connect(DB_FILE, timeout=10, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA busy_timeout=5000')
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction(conn):
    conn.execute('BEGIN IMMEDIATE')
    try:
        yield
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def authenticator_qr(secret, account_email):
    """Render the TOTP provisioning URI locally; never contact a QR web service."""
    issuer = 'SecureShop Cafe'
    label = urllib.parse.quote(issuer + ':' + account_email, safe='')
    provisioning_uri = ('otpauth://totp/' + label + '?' + urllib.parse.urlencode({
        'secret': secret, 'issuer': issuer, 'algorithm': 'SHA1',
        'digits': '6', 'period': '30'
    }))
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=7, border=4)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    image = qr.make_image(fill_color='black', back_color='white')
    output = io.BytesIO()
    image.save(output, format='PNG')
    return base64.b64encode(output.getvalue()).decode('ascii')


def ip_budget(conn, bucket, ip, limit=10, window=600):
    """Fixed-window per-IP throttle for unauthenticated write endpoints."""
    key = token_hash(bucket + '|' + ip)
    cutoff = int(time.time()) - window
    conn.execute('DELETE FROM login_attempts WHERE at<?', (cutoff,))
    if conn.execute('SELECT COUNT(*) AS n FROM login_attempts WHERE key_hash=? AND at>?', (key, cutoff)).fetchone()['n'] >= limit:
        return False
    conn.execute('INSERT INTO login_attempts(key_hash,at) VALUES(?,?)', (key, int(time.time())))
    return True


def reserve_attempt(conn, key, limit=5, window=600):
    """Atomically reserve a password-attempt slot before expensive hashing."""
    now = int(time.time())
    cutoff = now - window
    with transaction(conn):
        conn.execute('DELETE FROM login_attempts WHERE at<?', (cutoff,))
        attempts = conn.execute(
            'SELECT COUNT(*) AS n FROM login_attempts WHERE key_hash=? AND at>?',
            (key, cutoff)).fetchone()['n']
        if attempts >= limit:
            return False
        conn.execute('INSERT INTO login_attempts(key_hash,at) VALUES(?,?)', (key, now))
    return True


def mfa_lock_seconds(failures):
    if failures % MFA_FAILURES_PER_LOCK:
        return 0
    level = max(0, failures // MFA_FAILURES_PER_LOCK - 1)
    return min(MFA_LOCK_MAX, MFA_LOCK_BASE * (2 ** level))


def issue_recovery_codes(conn, user_id):
    """Replace the user's single-use recovery set; returns the 8 plaintext
    codes for a one-time display. Only SHA-256 digests are persisted."""
    conn.execute('DELETE FROM recovery_codes WHERE user_id=?', (user_id,))
    codes = []
    for _ in range(8):
        code = secrets.token_hex(2).upper() + '-' + secrets.token_hex(2).upper()
        conn.execute('INSERT INTO recovery_codes(user_id,code_hash) VALUES(?,?)',
                     (user_id, token_hash(code)))
        codes.append(code)
    return codes


def audit_event(conn, event, actor_id=None, target_type=None, target_id=None):
    # Record security events without passwords, OTPs, tokens or user input.
    allowed = {
        'login_failed', 'login_success', 'mfa_failed', 'mfa_success', 'mfa_enabled',
        'mfa_recovery_used', 'mfa_recovery_regenerated',
        'admin_denied', 'csrf_rejected', 'checkout_complete',
        'admin_product_changed', 'admin_coupon_changed', 'admin_user_changed',
        'behavior_enrolled', 'behavior_anomaly', 'passkey_registered', 'passkey_rejected',
        'passkey_verified', 'risk_location_denied', 'risk_time_denied',
    }
    if event not in allowed:
        raise ValueError('Unknown audit event')
    conn.execute("INSERT INTO audit_events(event,actor_id,target_type,target_id,occurred_at) VALUES(?,?,?,?,?)",
                 (event, actor_id, target_type, target_id, int(time.time())))


def money(cents):
    return f'${cents / 100:,.2f}'


def escape(value):
    return html.escape(str(value), quote=True)


def positive_int(value, limit=100):
    if not re.fullmatch(r'[1-9][0-9]*', str(value or '')):
        raise ValueError('Enter a positive whole number.')
    n = int(value)
    if n > limit:
        raise ValueError('Quantity is above the allowed limit.')
    return n


def init_db():
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE,
          display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
          confirmed INTEGER NOT NULL DEFAULT 0,
          credit_cents INTEGER NOT NULL DEFAULT 10000 CHECK(credit_cents >= 0),
          totp_secret TEXT, totp_last_step INTEGER NOT NULL DEFAULT -1);
        CREATE TABLE IF NOT EXISTS confirmations (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS pending_registrations (
          email TEXT PRIMARY KEY, display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (
          id_hash TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          csrf TEXT NOT NULL, expires_at INTEGER NOT NULL, pending_user_id INTEGER REFERENCES users(id),
          pending_passkey_id INTEGER REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS mfa_enrollments (
          session_hash TEXT PRIMARY KEY REFERENCES sessions(id_hash) ON DELETE CASCADE,
          secret TEXT NOT NULL, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS products (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
          price_cents INTEGER NOT NULL CHECK(price_cents >= 0), stock INTEGER NOT NULL CHECK(stock >= 0),
          active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS carts (
          session_hash TEXT NOT NULL REFERENCES sessions(id_hash) ON DELETE CASCADE,
          product_id INTEGER NOT NULL REFERENCES products(id),
          qty INTEGER NOT NULL CHECK(qty > 0 AND qty <= 100),
          PRIMARY KEY(session_hash,product_id));
        CREATE TABLE IF NOT EXISTS coupons (
          id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE,
          percent_off INTEGER NOT NULL CHECK(percent_off BETWEEN 1 AND 90),
          active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS coupon_uses (
          user_id INTEGER NOT NULL REFERENCES users(id), coupon_id INTEGER NOT NULL REFERENCES coupons(id),
          PRIMARY KEY(user_id,coupon_id));
        CREATE TABLE IF NOT EXISTS newsletters (
          email TEXT PRIMARY KEY, coupon_id INTEGER NOT NULL REFERENCES coupons(id));
        CREATE TABLE IF NOT EXISTS orders (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          total_cents INTEGER NOT NULL, discount_cents INTEGER NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS order_items (
          order_id INTEGER NOT NULL REFERENCES orders(id), product_id INTEGER NOT NULL REFERENCES products(id),
          name_snapshot TEXT NOT NULL, unit_price_cents INTEGER NOT NULL, qty INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_events (
          id INTEGER PRIMARY KEY,
          event TEXT NOT NULL,
          actor_id INTEGER,
          target_type TEXT,
          target_id INTEGER,
          occurred_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events(occurred_at);
        CREATE TABLE IF NOT EXISTS login_attempts (
          key_hash TEXT NOT NULL, at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(key_hash,at);
        CREATE TABLE IF NOT EXISTS mfa_throttles (
          user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          failures INTEGER NOT NULL DEFAULT 0,
          locked_until INTEGER NOT NULL DEFAULT 0,
          last_failure_at INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS behavior_profiles (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            samples TEXT NOT NULL, updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS passkeys (
            credential_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);
        CREATE TABLE IF NOT EXISTS passkey_challenges (
            session_hash TEXT PRIMARY KEY REFERENCES sessions(id_hash) ON DELETE CASCADE,
            challenge TEXT NOT NULL, purpose TEXT NOT NULL, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS recovery_codes (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash TEXT PRIMARY KEY);

        ''')
        # Non-destructive migration for databases created before Location and time policy support.
        names = {row['name'] for row in c.execute('PRAGMA table_info(sessions)')}
        if 'pending_passkey_id' not in names:
            c.execute('ALTER TABLE sessions ADD COLUMN pending_passkey_id INTEGER REFERENCES users(id)')
        order_cols = {row['name'] for row in c.execute('PRAGMA table_info(orders)')}
        if 'idempotency_key' not in order_cols:
            c.execute('ALTER TABLE orders ADD COLUMN idempotency_key TEXT')
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_idem ON orders(user_id, idempotency_key)')
        if not c.execute('SELECT 1 FROM products LIMIT 1').fetchone():
            c.executemany('INSERT INTO products(name,description,price_cents,stock) VALUES(?,?,?,?)', [
                ('Spanish Latte', 'Velvety espresso, steamed milk, and our signature sweet condensed milk.', 2499, 40),
                ('Iced Spanish Latte', 'Our signature sweet Spanish latte poured over ice for a creamy chill.', 2799, 45),
                ('Caramel Macchiato', 'Smooth espresso layered with milk and a golden caramel drizzle.', 2999, 36),
                ('Classic Cappuccino', 'Rich espresso topped with silky foam and a dusting of cocoa.', 2299, 40),
                ('Iced Americano', 'Bold double-shot espresso with cool water and plenty of ice.', 1999, 50),
                ('Vanilla Cold Brew', 'Slow-steeped coffee with vanilla notes and a smooth finish.', 2599, 35),
                ('Matcha Latte', 'Earthy Japanese-style matcha whisked into creamy milk.', 2999, 30),
                ('Hot Chocolate', 'Warm, comforting cocoa topped with a cloud of milk foam.', 2199, 35),
                ('Chocolate Chip Cookie', 'Soft-baked buttery cookie with generous dark chocolate chunks.', 1299, 60),
                ('Double Chocolate Cookie', 'Fudgy cocoa cookie packed with chocolate chips.', 1499, 60),
                ('Butter Croissant', 'Flaky, golden layers baked until perfectly buttery.', 1699, 45),
                ('Cinnamon Roll', 'Soft swirls of cinnamon sugar finished with vanilla glaze.', 1899, 40),
            ])
        admin_email = os.environ.get('SECURESHOP_ADMIN_EMAIL')
        admin_password = os.environ.get('SECURESHOP_ADMIN_PASSWORD')
        if admin_email and admin_password and len(admin_password) >= 12:
            c.execute('INSERT OR IGNORE INTO users(email,display_name,password_hash,role,confirmed,credit_cents) VALUES(?,?,?,?,1,10000)',
                      (admin_email.lower().strip(), 'Administrator', hash_password(admin_password), 'admin'))


CSS = r"""

:root{--cream:#faf6f0;--paper:#fffdfa;--coffee:#3d2b24;--brown:#5a3b2b;--muted:#806e60;--caramel:#b77746;--line:#e9e0d5;--green:#426352;--shadow:0 15px 46px rgba(65,42,28,.07)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--cream);color:var(--coffee);font:15px/1.6 'DM Sans',system-ui,-apple-system,Arial,sans-serif}a{color:inherit}header{background:var(--paper);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:15}nav{max-width:1210px;min-height:82px;margin:auto;padding:12px 24px;display:flex;align-items:center;gap:22px;flex-wrap:wrap}nav a{text-decoration:none;font-size:13px;font-weight:700;color:#59483c;transition:color .2s}nav a:hover{color:var(--caramel)}nav .brand{display:flex;align-items:center;gap:9px;font-family:'Playfair Display',Georgia,serif;font-size:25px;font-weight:700;margin-right:auto;color:var(--coffee);white-space:nowrap}nav .brand .brand-mark{display:grid;place-items:center;background:#efe0cc;color:var(--coffee);border-radius:14px;width:44px;height:44px;font:26px system-ui}nav .nav-links{display:flex;align-items:center;gap:22px;flex-wrap:wrap}.nav-cta{border:1px solid var(--line);border-radius:100px;padding:9px 17px}.nav-cta:hover{border-color:var(--caramel)}nav form.inline button{background:transparent;border:1px solid var(--line);border-radius:100px;padding:8px 15px;color:var(--brown);margin:0}main{max-width:1210px;margin:36px auto 60px;padding:0 24px;min-height:60vh}h1,h2,h3{color:var(--coffee)}h1,h2{font-family:'Playfair Display',Georgia,serif}h1{font-size:clamp(30px,4vw,46px);margin:0 0 24px;line-height:1.2}h2{font-size:29px;margin:10px 0 15px}h3{font-size:19px;line-height:1.3}.panel{background:var(--paper);border:1px solid var(--line);border-radius:22px;padding:26px;margin:0 0 23px;box-shadow:var(--shadow)}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:22px}.product{background:var(--paper);border:1px solid var(--line);border-radius:21px;overflow:hidden;box-shadow:0 12px 28px rgba(61,43,36,.045);transition:transform .18s,box-shadow .18s;display:flex;flex-direction:column}.product:hover{transform:translateY(-5px);box-shadow:0 18px 38px rgba(61,43,36,.13)}.product h3{font-family:'Playfair Display',Georgia,serif;font-size:21px;margin:6px 0}.product h3 a{text-decoration:none}.product p{color:var(--muted);font-size:13px;margin:7px 0 12px;min-height:60px}.product-copy{padding:18px 19px 19px;display:flex;flex-direction:column;flex:1}.product-topline,.product-bottom{display:flex;align-items:center;justify-content:space-between;gap:8px}.product-bottom{margin-top:auto;padding-top:15px}.product-bottom strong{font-size:21px;color:var(--brown)}.tag{display:inline-flex;border-radius:100px;padding:4px 10px;background:#f4e8d8;color:#986439;font-size:11px;font-weight:800;letter-spacing:.03em;text-transform:uppercase}.product-media{display:grid;place-items:center;position:relative;height:207px;overflow:hidden;background:linear-gradient(140deg,#e9dac8,#c6a98c)}.product-media::before{content:'';width:220px;height:220px;position:absolute;right:-65px;top:-95px;border:35px solid rgba(255,255,255,.17);border-radius:100%}.product-media::after{content:'';width:160px;height:70px;position:absolute;bottom:-46px;left:-12px;background:rgba(255,255,255,.14);border-radius:50%}.product-media .art{font:96px/1 system-ui;z-index:1;filter:drop-shadow(0 15px 11px rgba(60,31,16,.18));transform:rotate(-9deg)}.product-media.iced{background:linear-gradient(145deg,#e4d7c8,#b2c2b4)}.product-media.bakery{background:linear-gradient(145deg,#f5deb7,#c48b61)}.product-media.matcha{background:linear-gradient(145deg,#dbe4cc,#9eb487)}.product-media.chocolate{background:linear-gradient(145deg,#d3b09a,#9c7162)}.product-media.hot{background:linear-gradient(145deg,#eedcc6,#be9477)}.product-media.detail-art{height:430px;border-radius:22px}.product-media.detail-art .art{font-size:180px}.hero{background:#e8d9c7;border-radius:28px;min-height:355px;display:grid;grid-template-columns:1.15fr .85fr;align-items:center;overflow:hidden;position:relative;margin-bottom:38px;padding:36px 54px}.hero:after{content:'';position:absolute;width:330px;height:330px;border:70px solid rgba(255,255,255,.12);border-radius:50%;right:-60px;top:-145px;pointer-events:none}.eyebrow{font-size:11px;letter-spacing:.19em;text-transform:uppercase;color:#8e5b39;font-weight:800}.hero h1{font-size:clamp(38px,5.5vw,69px);line-height:1.04;margin:14px 0 20px;max-width:610px}.hero p{max-width:460px;color:#6e5140;font-size:16px;margin:0 0 25px}.hero-illustration{min-height:270px;display:grid;place-items:center;position:relative;isolation:isolate}.hero-circle{position:absolute;width:275px;height:275px;border-radius:50%;background:linear-gradient(145deg,#e9c29b,#b27b54);z-index:-1;box-shadow:0 25px 45px #67402b30}.hero-cup{font:200px/1 system-ui;filter:drop-shadow(0 22px 16px #68452d40);transform:rotate(-9deg)}.hero-note{position:absolute;background:var(--paper);padding:8px 14px;border-radius:15px;box-shadow:var(--shadow);font-size:12px;font-weight:800;bottom:18px;right:0;transform:rotate(6deg)}.hero-buttons{display:flex;gap:12px;flex-wrap:wrap}.btn,button{display:inline-flex;align-items:center;justify-content:center;gap:8px;font:700 13px 'DM Sans',system-ui;letter-spacing:.01em;padding:11px 19px;background:var(--brown);color:#fff;border:1px solid transparent;border-radius:100px;text-decoration:none;cursor:pointer;transition:background .18s,transform .18s}.btn:hover,button:hover{background:#805639;transform:translateY(-1px)}.btn.light{background:#fff7ee;color:var(--brown);border-color:#d2bba4}.btn.light:hover{background:#fff}.btn.small{padding:9px 13px;font-size:12px}.section-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin:0 0 21px}.section-heading h2{margin:0}.section-heading p{color:var(--muted);margin:6px 0 0}.filters{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0 26px}.filter{display:inline-block;padding:10px 19px;background:#fffaf4;border:1px solid var(--line);border-radius:100px;text-decoration:none;font-size:13px;font-weight:800;color:#715747}.filter:hover,.filter.active{background:var(--brown);color:#fff;border-color:var(--brown)}.search-panel{background:var(--paper);border:1px solid var(--line);border-radius:16px;padding:10px;display:flex;align-items:center;gap:9px;max-width:380px}.search-panel input{border:0;box-shadow:none;outline:none;margin:0;padding:9px}.search-panel button{white-space:nowrap}.catalog-controls{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}.empty-state{text-align:center;background:var(--paper);border:1px dashed #d6c3b4;border-radius:18px;padding:48px;grid-column:1/-1}.empty-state .icon{font-size:54px}.newsletter-banner{display:grid;grid-template-columns:1fr 1fr;gap:26px;align-items:center;background:#3f594b;color:#fff;border-radius:25px;padding:33px 42px;margin-top:45px}.newsletter-banner h2{color:white;margin:6px 0}.newsletter-banner p{color:#dae2d8;margin:0}.newsletter-banner .btn{background:#f1e0c8;color:#3e3029}.detail-layout{display:grid;grid-template-columns:1fr 1fr;gap:34px;align-items:start}.detail-info{padding:20px 3px}.detail-info h1{font-size:51px;margin:17px 0}.detail-info p{font-size:17px;color:var(--muted)}.detail-price{font-size:31px;font-weight:800;color:var(--brown);margin:17px 0}.stock-note{color:var(--green);font-weight:700}.detail-info form{max-width:240px}form{margin:12px 0}label{display:block;font-weight:700;margin:14px 0 6px;color:#53463c;font-size:13px}input,textarea,select{font:inherit;color:var(--coffee);background:#fff;border:1px solid #d9cbbf;border-radius:11px;padding:11px 12px;max-width:100%;width:100%}input:focus,textarea:focus,select:focus{outline:2px solid #bc916e80;border-color:#bb906d}.inline{display:inline}.inline button{margin:0}table{border-collapse:collapse;width:100%;background:transparent}td,th{padding:14px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}th{color:#7f6c5e;font-size:12px;text-transform:uppercase;letter-spacing:.08em}.notice{background:#ecf6ed;border:1px solid #c4deca;padding:14px 17px;border-radius:12px;margin-bottom:16px;color:#326747}.error{background:#fff0ef;border:1px solid #edc1bb;padding:14px;border-radius:12px;color:#9e382c}small{color:var(--muted)}.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.actions input{width:95px}.muted{color:var(--muted)}footer{background:#30251f;color:#e4d6c8;padding:30px 24px;text-align:center;font-size:12px}.page-caption{color:var(--muted);margin:-12px 0 26px}.breadcrumbs{font-size:13px;color:#8b7160;margin-bottom:16px}.breadcrumbs a{text-decoration:none;color:var(--brown)}.form-narrow{max-width:650px;margin:0 auto}.feature-strip{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:25px 0 48px}.feature{background:#fffaf5;border:1px solid var(--line);padding:15px 20px;border-radius:16px;display:flex;gap:12px;align-items:center;font-size:13px;font-weight:700}.feature .feature-icon{font-size:25px}.auth-intro{margin-bottom:15px;color:var(--muted)}
@media(max-width:1100px){.grid{grid-template-columns:repeat(3,minmax(0,1fr))}nav{gap:14px}nav .nav-links{gap:13px}}@media(max-width:760px){main{padding:0 16px;margin-top:22px}nav{padding:10px 16px;min-height:70px}nav .nav-links{gap:12px}nav a{font-size:12px}.hero{grid-template-columns:1fr;padding:30px 25px}.hero h1{font-size:45px}.hero-illustration{min-height:230px}.hero-cup{font-size:170px}.hero-circle{width:200px;height:200px}.hero-note{right:20px}.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}.product-media{height:170px}.product-media .art{font-size:76px}.product-copy{padding:13px}.product h3{font-size:19px}.product p{min-height:75px}.detail-layout,.newsletter-banner{grid-template-columns:1fr}.detail-info h1{font-size:39px}.feature-strip{grid-template-columns:1fr}.catalog-controls{align-items:stretch}.search-panel{max-width:none}.panel{padding:18px}table{display:block;overflow-x:auto}}@media(max-width:390px){.grid{grid-template-columns:1fr}.product p{min-height:0}nav .nav-links{gap:8px}.hero h1{font-size:38px}}
"""

PRODUCT_LOOK = {
    'Spanish Latte': ('☕', 'hot', 'Best seller', 'coffee'),
    'Iced Spanish Latte': ('🥤', 'iced', 'Fan favorite', 'iced'),
    'Caramel Macchiato': ('☕', 'hot', 'Sweet & cozy', 'coffee'),
    'Classic Cappuccino': ('☕', 'hot', 'Classic', 'coffee'),
    'Iced Americano': ('🧊', 'iced', 'Refreshing', 'iced'),
    'Vanilla Cold Brew': ('🥤', 'iced', 'Slow brewed', 'iced'),
    'Matcha Latte': ('🍵', 'matcha', 'Matcha love', 'coffee'),
    'Hot Chocolate': ('🍫', 'chocolate', 'Cozy pick', 'coffee'),
    'Chocolate Chip Cookie': ('🍪', 'bakery', 'Fresh baked', 'bakery'),
    'Double Chocolate Cookie': ('🍪', 'chocolate', 'Choco bliss', 'bakery'),
    'Butter Croissant': ('🥐', 'bakery', 'Flaky', 'bakery'),
    'Cinnamon Roll': ('🥮', 'bakery', 'Warm & sweet', 'bakery'),
}

def product_look(name):
    return PRODUCT_LOOK.get(name, ('☕', 'hot', 'Café special', 'coffee'))

def product_media(name, detail=False):
    emoji, tone, _, _ = product_look(name)
    return '<div class="product-media ' + tone + (' detail-art' if detail else '') + '" role="img" aria-label="Illustration of ' + escape(name) + '"><span class="art" aria-hidden="true">' + emoji + '</span></div>'



class App(BaseHTTPRequestHandler):
    server_version = 'SecureShop'
    sys_version = ''

    def log_message(self, fmt, *args):
        # Avoid logging token-bearing query strings / sensitive form fields.
        print('%s - %s %s' % (self.address_string(), self.command, urllib.parse.urlsplit(self.path).path))

    def send_html(self, status, content, extra_headers=None):
        content = content.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Cache-Control', 'no-store')
        if os.environ.get('SECURESHOP_HTTPS') == '1':
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status, item, cookies=None):
        raw = json.dumps(item, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        for cookie in (cookies or []): self.send_header('Set-Cookie',cookie)
        self.end_headers()
        self.wfile.write(raw)

    def redirect(self, path, cookies=None):
        self.send_response(303)
        self.send_header('Location', path)
        self.send_header('Cache-Control', 'no-store')
        for cookie in (cookies or []):
            self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def session_cookie(self, token, max_age=SESSION_AGE):
        flags = '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + str(max_age)
        if os.environ.get('SECURESHOP_HTTPS') == '1':
            flags += '; Secure'
        return 'sid=' + token + flags

    def get_session(self, c):
        raw = self.headers.get('Cookie', '')[:4096]
        try:
            cookie = SimpleCookie(); cookie.load(raw)
            sid = cookie['sid'].value if 'sid' in cookie else ''
        except Exception:
            sid = ''
        session = c.execute('SELECT * FROM sessions WHERE id_hash=? AND expires_at>?', (token_hash(sid), int(time.time()))).fetchone() if sid else None
        if session:
            self.sid_hash = session['id_hash']
            self.csrf = session['csrf']
            self.user = c.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone() if session['user_id'] else None
            self.pending_user_id = session['pending_user_id']
            self.pending_passkey_id = session['pending_passkey_id']
            return []
        token = secrets.token_urlsafe(32)
        self.sid_hash = token_hash(token)
        self.csrf = secrets.token_urlsafe(32)
        self.user = None
        self.pending_user_id = None
        self.pending_passkey_id = None
        c.execute('INSERT INTO sessions(id_hash,csrf,expires_at) VALUES(?,?,?)', (self.sid_hash, self.csrf, int(time.time()) + SESSION_AGE))
        return [self.session_cookie(token)]

    def rotate_session(self, c, user_id=None, pending_user_id=None, pending_passkey_id=None):
        c.execute('DELETE FROM sessions WHERE id_hash=?', (self.sid_hash,))
        token = secrets.token_urlsafe(32)
        self.sid_hash = token_hash(token)
        self.csrf = secrets.token_urlsafe(32)
        age = MFA_PENDING_AGE if (pending_user_id or pending_passkey_id) else SESSION_AGE
        self.pending_passkey_id = pending_passkey_id
        c.execute('INSERT INTO sessions(id_hash,user_id,csrf,expires_at,pending_user_id,pending_passkey_id) VALUES(?,?,?,?,?,?)',
                  (self.sid_hash, user_id, self.csrf, int(time.time()) + age, pending_user_id, pending_passkey_id))
        return [self.session_cookie(token, age)]

    def csrf_field(self):
        return '<input type="hidden" name="csrf" value="' + escape(self.csrf) + '">'

    def page(self, title, body, alert='', error=False, home=False):
        user = self.user
        menu = '<a href="/">Menu</a>'
        if user:
            menu += '<a href="/cart">Your cart</a><a href="/orders">Orders</a><a href="/account">Account</a>'
            if user['role'] == 'admin':
                menu += '<a href="/admin">Admin</a>'
            menu += '<form class="inline" method="post" action="/logout">' + self.csrf_field() + '<button>Log out</button></form>'
        else:
            menu += '<a href="/newsletter">Rewards</a><a href="/login">Log in</a><a class="nav-cta" href="/register">Join the café</a>'
        note = '<div class="' + ('error' if error else 'notice') + '">' + escape(alert) + '</div>' if alert else ''
        heading = '' if home else '<h1>' + escape(title) + '</h1>'
        if title in ('Login', 'Register', 'Two-factor verification', 'Enable authenticator MFA'):
            body = '<div class="form-narrow">' + body + '</div>'
        return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
                '<meta name="theme-color" content="#faf6f0"><meta name="description" content="SecureShop Café - freshly brewed coffee, iced lattes, and bakery treats.">'
                '<title>' + escape(title) + ' | SecureShop Café</title><link rel="stylesheet" href="/static/style.css"><script defer src="/static/security.js"></script></head><body>'
                '<header><nav><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">☕</span> SecureShop Café</a><div class="nav-links">' + menu + '</div></nav></header><main>' + heading + note + body + '</main>'
                '<footer>☕ SecureShop Café &nbsp; • &nbsp; Brewed with care &nbsp; • &nbsp; Educational project, no real payments</footer></body></html>')

    def error(self, status, message):
        self.send_html(status, self.page('Request not completed', '<div class="panel">' + escape(message) + '</div>'))

    def must_login(self):
        if not self.user:
            self.error(401, 'Please log in first.')
            return False
        return True

    def must_admin(self):
        if not self.must_login():
            return False
        if self.user['role'] != 'admin':
            with db() as ac: audit_event(ac, 'admin_denied', self.user['id'])
            self.error(403, 'Access denied.')
            return False
        return True

    def parse_post(self):
        if 'application/x-www-form-urlencoded' not in self.headers.get('Content-Type', ''):
            raise ValueError('Unsupported form type.')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise ValueError('Invalid body length.')
        if length <= 0 or length > MAX_BODY:
            raise ValueError('Invalid form size.')
        parsed = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'), keep_blank_values=True, max_num_fields=32)
        if any(len(v) != 1 for v in parsed.values()):
            raise ValueError('Duplicate form field.')
        d = {k:v[0] for k,v in parsed.items()}
        if not hmac.compare_digest(d.get('csrf', ''), self.csrf):
            raise PermissionError('Invalid CSRF token.')
        return d

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        path = url.path
        if path == '/static/security.js':
            data = (BASE/'security.js').read_bytes()
            self.send_response(200); self.send_header('Content-Type', 'application/javascript; charset=utf-8')
            self.send_header('Content-Length', str(len(data)));self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(data)
            return
        if path == '/static/style.css':
            data = CSS.encode()
            self.send_response(200); self.send_header('Content-Type','text/css; charset=utf-8')
            self.send_header('Content-Length',str(len(data)))
            self.send_header('X-Content-Type-Options','nosniff')
            self.end_headers();self.wfile.write(data)
            return
        try:
            with db() as c:
                cookies = self.get_session(c)
                if cookies:
                    self.redirect('/' if path == '/' else self.path, cookies)
                    return
                self.route_get(c, path, urllib.parse.parse_qs(url.query))
        except (sqlite3.Error, OSError):
            self.error(500, 'An internal error occurred.')

    def do_POST(self):
        try:
            with db() as c:
                cookies = self.get_session(c)
                if cookies:
                    self.error(403, 'Please reload the page and try again.')
                    return
                try:
                    data = self.parse_post()
                except PermissionError:
                    audit_event(c, 'csrf_rejected', self.user['id'] if self.user else None)
                    self.error(403, 'Security token verification failed.')
                    return
                except (ValueError, UnicodeDecodeError):
                    self.error(400, 'Invalid form submission.')
                    return
                self.route_post(c, urllib.parse.urlsplit(self.path).path, data)
        except (sqlite3.Error, OSError):
            self.error(500, 'An internal error occurred.')
        except ValueError as exc:
            self.error(400, str(exc))

    def route_get(self, c, path, query):
        if path == '/':
            term = query.get('q', [''])[0][:80]
            category = query.get('category', ['all'])[0]
            if category not in ('all', 'coffee', 'iced', 'bakery'):
                category = 'all'
            escaped_term = '%' + term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
            products = c.execute("SELECT * FROM products WHERE active=1 AND name LIKE ? ESCAPE '\\' ORDER BY id", (escaped_term,)).fetchall()
            products = [p for p in products if category == 'all' or product_look(p['name'])[3] == category]
            hero = ('<section class="hero"><div class="hero-content"><div class="eyebrow">✦ GOOD DAYS START HERE</div>'
                    '<h1>Your daily dose<br>of <em>coffee & joy.</em></h1>'
                    '<p>Made with love, poured with care. Discover rich Spanish lattes, refreshing iced coffee, and freshly baked treats.</p>'
                    '<div class="hero-buttons"><a class="btn" href="#menu">Explore our menu →</a><a class="btn light" href="/newsletter">Get 10% off</a></div></div>'
                    '<div class="hero-illustration"><div class="hero-circle"></div><span class="hero-cup" role="img" aria-label="Coffee cup">☕</span><div class="hero-note">♥ Freshly brewed daily</div></div></section>')
            features = ('<div class="feature-strip"><div class="feature"><span class="feature-icon">☕</span><span>Crafted fresh with care</span></div>'
                        '<div class="feature"><span class="feature-icon">🍪</span><span>Perfect coffee pairings</span></div>'
                        '<div class="feature"><span class="feature-icon">✨</span><span>Secure, simple checkout</span></div></div>')
            search = ('<div class="catalog-controls"><div><span class="eyebrow">THE GOOD STUFF</span><h2 id="menu">Explore our menu</h2>'
                      '<p class="muted">Sip something wonderful. Treat yourself a little.</p></div>'
                      '<form class="search-panel" method="get" action="/"><input type="search" aria-label="Search products" name="q" maxlength="80" placeholder="Search your favorite..." value="' + escape(term) + '">'
                      '<button type="submit">Search</button></form></div>')
            categories = '<div class="filters" aria-label="Product categories">'
            for slug, label in [('all', 'All goodies'), ('coffee', '☕ Hot coffee & drinks'), ('iced', '🧊 Iced favorites'), ('bakery', '🍪 Cookies & bakery')]:
                href = '/?category=' + slug + ('&q=' + urllib.parse.quote(term) if term else '') + '#menu'
                categories += '<a class="filter' + (' active' if slug == category else '') + '" href="' + href + '">' + label + '</a>'
            categories += '</div>'
            cards = '<div class="grid">'
            for p in products:
                _, _, badge, _ = product_look(p['name'])
                cards += ('<article class="product">' + product_media(p['name']) + '<div class="product-copy"><div class="product-topline"><span class="tag">' + escape(badge) + '</span>'
                          '<small>' + ('In stock' if p['stock'] else 'Sold out') + '</small></div><h3><a href="/product/' + str(p['id']) + '">' + escape(p['name']) + '</a></h3>'
                          '<p>' + escape(p['description']) + '</p><div class="product-bottom"><strong>' + money(p['price_cents']) + '</strong>'
                          '<a class="btn small" href="/product/' + str(p['id']) + '">View →</a></div></div></article>')
            if not products:
                cards += '<div class="empty-state"><div class="icon">☕</div><h3>No drinks found</h3><p>Try another search or category.</p><a class="btn" href="/#menu">See all goodies</a></div>'
            cards += '</div>'
            newsletter = ('<section class="newsletter-banner"><div><span class="eyebrow" style="color:#ebd2b4">A LITTLE TREAT</span>'
                          '<h2>Good coffee. Better rewards.</h2><p>Join our newsletter for your own one-time 10% off coupon.</p></div>'
                          '<div><a href="/newsletter" class="btn">Grab your coupon →</a></div></section>')
            self.send_html(200, self.page('Our Menu', hero + features + search + categories + cards + newsletter, home=True))
        elif path.startswith('/product/'):
            pid = positive_int(path.split('/')[-1], 10**9)
            p = c.execute('SELECT * FROM products WHERE id=? AND active=1', (pid,)).fetchone()
            if not p: return self.error(404, 'Product not found.')
            form = ('<form method="post" action="/cart/add">' + self.csrf_field() + '<input type="hidden" name="product_id" value="' + str(pid) + '">'
                    '<label for="qty">Quantity</label><input id="qty" name="qty" type="number" min="1" max="100" value="1">'
                    '<button type="submit">Add to cart →</button></form>')
            _, _, badge, _ = product_look(p['name'])
            body = ('<div class="breadcrumbs"><a href="/">Menu</a> / ' + escape(p['name']) + '</div><div class="detail-layout">'
                    + product_media(p['name'], True) + '<div class="detail-info"><span class="tag">' + escape(badge) + '</span><h1>' + escape(p['name']) + '</h1>'
                    '<p>' + escape(p['description']) + '</p><div class="detail-price">' + money(p['price_cents']) + '</div>'
                    '<div class="stock-note">' + ('✓ Fresh and available' if p['stock'] else 'Currently sold out') + '</div>'
                    + form + '<p class="muted"><small>All prices and quantities are validated securely at checkout.</small></p></div></div>')
            self.send_html(200, self.page(p['name'], body, home=True))
        elif path == '/passkey/login':
            if not self.pending_passkey_id or self.user:
                return self.error(403,'No pending passkey login.')
            body=('<div class="panel"><p>Enhanced passkey sign-in: verify your passkey, Cairo local time [08:00,22:00), '
                  'and browser-reported location within 50 km of the demo home coordinates. '
                  'Location can be spoofed and is not an independent authentication factor.</p>'
                  '<form id="passkey-check-form" data-login="1">'+self.csrf_field()+
                  '<button type="submit">Verify passkey and finish login</button></form>'
                  '<div id="security-result" role="status" class="notice" aria-live="polite">Ready.</div></div>')
            self.send_html(200,self.page('Passkey verification',body))
        elif path == '/security':
            if not self.must_login(): return
            profile = c.execute('SELECT samples FROM behavior_profiles WHERE user_id=?',(self.user['id'],)).fetchone()
            credentials = c.execute('SELECT COUNT(*) FROM passkeys WHERE user_id=?',(self.user['id'],)).fetchone()[0]
            recovery_left = c.execute('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id=?',(self.user['id'],)).fetchone()['n']
            content = ('<div class="panel"><h2>Account security center</h2>'
                       '<p>Behavioral enrollment: '+('Ready' if profile and len(json.loads(profile['samples']))>=5 else 'Not ready')+'</p>'
                       '<p>Registered passkeys: '+str(credentials)+'</p>'
                       + ('<p>Recovery codes remaining: '+str(recovery_left)+' — <a href="/mfa/recovery">manage</a></p>' if self.user['totp_secret'] else '') +
                       '<p><a class="btn" href="/security/behavior">Enroll typing rhythm</a></p>'
                       '<p><strong>Passkey registration (localhost / supported browser)</strong></p>'
                       '<form id="passkey-register-form">'+self.csrf_field()+
                       '<label>Confirm your account password</label><input name="password" type="password" required autocomplete="current-password">'
                       '<button type="submit">Register this device passkey</button></form>'
                       '<hr><p>Identity risk assessment: verify passkey signature, browser-reported location within 50 km of enrolled home, and server-side Cairo hour [08:00,22:00).</p>'
                       '<p><strong>Demo home:</strong> Cairo (30.0444, 31.2357). Browser coordinates can be spoofed and are not an identity factor.</p>'
                       '<form id="passkey-check-form">'+self.csrf_field()+'<button type="submit">Run security risk assessment</button></form>'
                       '<div class="notice" id="security-result" role="status" aria-live="polite">Ready.</div></div>')
            self.send_html(200,self.page('Security settings',content))
        elif path == '/security/behavior':
            if not self.must_login(): return
            profile=c.execute('SELECT samples FROM behavior_profiles WHERE user_id=?',(self.user['id'],)).fetchone()
            num=len(json.loads(profile['samples'])) if profile else 0
            body=('<div class="panel"><p>Typing behavior enrollment: type your existing account password naturally five separate times. '
                  'Only aggregate intervals are stored; passwords and exact keys are never saved in this profile.</p>'
                  '<p>Samples collected: <strong>'+str(num)+'/5</strong></p>')
            if num >= 5:
                body += ('<div class="notice">Typing enrollment complete (5/5). '
                         'Your trusted profile is saved and cannot be accidentally overwritten.</div>')
            else:
                body += ('<form method="post" action="/security/behavior" data-typing-form="1">'
                         +self.csrf_field()+'<label>Current password</label>'
                         '<input type="password" required name="password" autocomplete="off">'
                         '<input type="hidden" name="timing"><button>Save trusted sample</button></form>')
            body += '<p><a href="/security">Back to security settings</a></p></div>'
            self.send_html(200,self.page('Typing profile enrollment',body))
        elif path in ('/login','/register'):
            register = path == '/register'
            body = '<div class="panel"><form method="post" action="'+path+'">'+self.csrf_field()
            if register: body += '<label>Name</label><input required name="name" maxlength="80">'
            body += '<label>Email</label><input type="email" required name="email" maxlength="254"><label>Password</label><input type="password" required name="password" minlength="12">'
            if not register: body += '<input type="hidden" name="timing">'
            body += '<button>'+('Create account' if register else 'Login')+'</button></form></div>'
            if not register: body=body.replace('<form method="post" action="/login">','<form data-typing-form="1" method="post" action="/login">')
            self.send_html(200,self.page('Register' if register else 'Login',body))
        elif path == '/confirm':
            token = query.get('token', [''])[0]
            if not token: return self.error(400,'Confirmation link invalid or expired.')
            with transaction(c):
                now=int(time.time())
                row=c.execute('SELECT email,display_name,password_hash FROM pending_registrations WHERE token_hash=? AND expires_at>?',(token_hash(token),now)).fetchone()
                if row:
                    existing=c.execute('SELECT id,confirmed FROM users WHERE email=?',(row['email'],)).fetchone()
                    if existing and existing['confirmed']:
                        c.execute('DELETE FROM pending_registrations WHERE email=?',(row['email'],))
                    else:
                        if existing:
                            c.execute('DELETE FROM users WHERE id=?',(existing['id'],))
                        c.execute('INSERT INTO users(email,display_name,password_hash,confirmed) VALUES(?,?,?,1)',
                                  (row['email'],row['display_name'],row['password_hash']))
                        c.execute('DELETE FROM pending_registrations WHERE email=?',(row['email'],))
                else:
                    legacy=c.execute('SELECT user_id FROM confirmations WHERE token_hash=? AND expires_at>?',(token_hash(token),now)).fetchone()
                    if not legacy:
                        return self.error(400,'Confirmation link invalid or expired.')
                    c.execute('UPDATE users SET confirmed=1 WHERE id=?',(legacy['user_id'],))
                    c.execute('DELETE FROM confirmations WHERE user_id=?',(legacy['user_id'],))
            self.send_html(200,self.page('Account confirmed','<div class="notice">Your email is confirmed. <a href="/login">Log in</a>.</div>'))
        elif path == '/mfa':
            if not self.pending_user_id or self.user:
                return self.error(403, 'No pending two-factor challenge.')
            body = ('<div class="panel"><p>Enter the 6-digit code from your authenticator app, or a recovery code.</p>'
                    '<form method="post" action="/mfa">'+self.csrf_field()+
                    '<label>Code</label><input name="code" required maxlength="9" autocomplete="one-time-code">'
                    '<button>Verify and sign in</button></form>'
                    '<p><small>Lost your authenticator? Use one of your recovery codes (format ABCD-EF12).</small></p></div>')
            self.send_html(200,self.page('Two-factor verification',body))
        elif path == '/mfa/recovery':
            if not self.must_login(): return
            if not self.user['totp_secret']: return self.error(403,'Enable authenticator MFA first.')
            remaining = c.execute('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id=?',(self.user['id'],)).fetchone()['n']
            body = ('<div class="panel"><p>Recovery codes remaining: <strong>'+str(remaining)+'</strong></p>'
                    '<p>Regenerating replaces all unused codes.</p>'
                    '<form method="post" action="/mfa/recovery">'+self.csrf_field()+
                    '<label>Confirm your account password</label><input type="password" required name="password" autocomplete="current-password">'
                    '<button>Generate new recovery codes</button></form></div>')
            self.send_html(200,self.page('Recovery codes',body))
        elif path == '/mfa/setup':
            if not self.must_login(): return
            if self.user['totp_secret']:
                return self.error(409,'Two-factor authentication is already enabled.')
            secret = new_totp_secret()
            c.execute('INSERT INTO mfa_enrollments(session_hash,secret,expires_at) VALUES(?,?,?) ON CONFLICT(session_hash) DO UPDATE SET secret=excluded.secret,expires_at=excluded.expires_at', (self.sid_hash,secret,int(time.time())+600))
            png = authenticator_qr(secret, self.user['email'])
            body = ('<div class="panel"><h2>Scan with your authenticator app</h2>'
                    '<p>Open Google Authenticator or Microsoft Authenticator, tap + and scan this QR code.</p>'
                    '<p><img class="mfa-qr" alt="Authenticator setup QR code" width="240" height="240" '
                    'src="data:image/png;base64,'+png+'"></p>'
                    '<p>If you cannot scan, enter this setup key manually:</p>'
                    '<p><code>'+escape(secret)+'</code></p>'
                    '<p><small>Private setup key: do not share this screen. Setup expires in 10 minutes. '
                    'Do not refresh this page; refreshing generates a new key.</small></p>'
                    '<form action="/mfa/setup" method="post">'+self.csrf_field()
                    +'<label>Current account password</label><input type="password" name="password" required autocomplete="current-password">'
                    +'<label>6-digit code from authenticator</label><input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required>'
                    +'<button>Enable MFA</button></form></div>')
            self.send_html(200,self.page('Enable authenticator MFA',body))
        elif path == '/cart':
            if not self.must_login(): return
            rows = self.cart_rows(c)
            body = '<div class="panel"><table><tr><th>Product</th><th>Price</th><th>Quantity</th><th>Action</th></tr>'
            for r in rows:
                body += '<tr><td>'+escape(r['name'])+'</td><td>'+money(r['price_cents'])+'</td><td>'+str(r['qty'])+'</td><td><form class="actions" method="post" action="/cart/update">'+self.csrf_field()+'<input type="hidden" name="product_id" value="'+str(r['product_id'])+'"><input type="number" name="qty" value="'+str(r['qty'])+'" min="0" max="100"><button>Update (0 removes)</button></form></td></tr>'
            body += '</table><p><strong>Subtotal: '+money(sum(r['price_cents']*r['qty'] for r in rows))+'</strong></p><a class="btn" href="/checkout">Checkout</a></div>'
            self.send_html(200,self.page('Shopping cart',body))
        elif path == '/checkout':
            if not self.must_login(): return
            rows = self.cart_rows(c)
            subtotal = sum(r['price_cents']*r['qty'] for r in rows)
            checkout_key = secrets.token_urlsafe(16)
            body = '<div class="panel"><p>Subtotal: <strong>'+money(subtotal)+'</strong></p><p>Available store credit: '+money(self.user['credit_cents'])+'</p><form method="post" action="/checkout">'+self.csrf_field()+'<input type="hidden" name="key" value="'+checkout_key+'"><label>Coupon code (optional)</label><input name="coupon" maxlength="40"><button>Pay with store credit</button></form><p><small>Totals, discount, stock, and balance are verified on the server during checkout.</small></p></div>'
            self.send_html(200,self.page('Checkout',body))
        elif path == '/account':
            if not self.must_login(): return
            u = self.user
            body = '<div class="panel"><p>Email: '+escape(u['email'])+'</p><p>Role: '+escape(u['role'])+'</p><p>Credit: '+money(u['credit_cents'])+'</p><p>MFA: '+('Enabled' if u['totp_secret'] else '<a href="/mfa/setup">Enable authenticator MFA</a>')+'</p><form action="/account" method="post">'+self.csrf_field()+'<label>Display name</label><input name="name" maxlength="80" value="'+escape(u['display_name'])+'"><button>Update profile</button></form></div>'
            self.send_html(200,self.page('My account',body + '<p><a class="btn" href="/security">Security settings: typing and passkeys</a></p>'))
        elif path == '/orders':
            if not self.must_login(): return
            orders = c.execute('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC',(self.user['id'],)).fetchall()
            body = '<div class="panel">'+''.join('<p><a href="/order/'+str(o['id'])+'">Order #'+str(o['id'])+'</a> — '+money(o['total_cents'])+'</p>' for o in orders)+'</div>'
            self.send_html(200,self.page('Order history',body))
        elif path.startswith('/order/'):
            if not self.must_login(): return
            oid = positive_int(path.split('/')[-1], 10**9)
            order = c.execute('SELECT * FROM orders WHERE id=? AND user_id=?',(oid,self.user['id'])).fetchone()
            if not order: return self.error(404,'Order not found.')
            items = c.execute('SELECT * FROM order_items WHERE order_id=?',(oid,)).fetchall()
            body = '<div class="panel"><p>Order confirmed! Total: '+money(order['total_cents'])+'</p><p>Discount: '+money(order['discount_cents'])+'</p>'+''.join('<p>'+escape(i['name_snapshot'])+' × '+str(i['qty'])+'</p>' for i in items)+'</div>'
            self.send_html(200,self.page('Order #'+str(oid),body))
        elif path == '/newsletter':
            body = '<div class="panel"><p>Subscribe for a unique one-time 10% coupon.</p><form method="post" action="/newsletter">'+self.csrf_field()+'<label>Email</label><input name="email" type="email" required><button>Subscribe</button></form></div>'
            self.send_html(200,self.page('Newsletter',body))
        elif path == '/admin/audit':
            if not self.must_admin(): return
            events = c.execute('SELECT id,event,actor_id,target_type,target_id,occurred_at FROM audit_events ORDER BY id DESC LIMIT 50').fetchall()
            rows = ''.join('<tr><td>'+str(e['id'])+'</td><td>'+escape(e['event'])+'</td><td>'+escape(e['actor_id'] if e['actor_id'] is not None else '-')+'</td><td>'+escape(e['target_type'] if e['target_type'] else '-')+'</td><td>'+escape(e['target_id'] if e['target_id'] is not None else '-')+'</td><td>'+escape(time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(e['occurred_at'])))+'</td></tr>' for e in events)
            body = ('<div class="panel"><p>Last 50 security events. Passwords, tokens and OTP values are never stored here.</p>'
                    '<div style="overflow-x:auto"><table cellpadding="10"><thead><tr><th>ID</th><th>Event</th><th>Actor ID</th><th>Target type</th><th>Target ID</th><th>Time</th></tr></thead><tbody>'
                    + rows + '</tbody></table></div><p><a href="/admin">Back to admin dashboard</a></p></div>')
            self.send_html(200,self.page('Security audit log',body))
        elif path == '/admin':
            if not self.must_admin(): return
            users = c.execute('SELECT id,email,display_name,role,confirmed,credit_cents FROM users ORDER BY id').fetchall()
            products = c.execute('SELECT * FROM products ORDER BY id').fetchall()
            coupons = c.execute('SELECT * FROM coupons ORDER BY id').fetchall()
            body = '<div class="panel"><p><a href="/admin/audit">View security audit log</a></p><h2>Add product</h2><form action="/admin/product" method="post">'+self.csrf_field()+'<input name="name" placeholder="Product name" required maxlength="100"><input name="description" placeholder="Description" required maxlength="500"><input name="price_cents" placeholder="Price in cents" type="number" min="0" required><input name="stock" type="number" min="0" placeholder="Stock" required><button>Add product</button></form><h2>Products</h2>'
            for p in products:
                body += '<form action="/admin/product" method="post">'+self.csrf_field()+'<input type="hidden" name="id" value="'+str(p['id'])+'"><label>Product #'+str(p['id'])+'</label><input name="name" value="'+escape(p['name'])+'" maxlength="100"><input name="description" value="'+escape(p['description'])+'" maxlength="500"><input name="price_cents" type="number" min="0" value="'+str(p['price_cents'])+'"><input name="stock" type="number" min="0" value="'+str(p['stock'])+'"><select name="active"><option value="1" '+('selected' if p['active'] else '')+'>Active</option><option value="0" '+('selected' if not p['active'] else '')+'>Inactive</option></select><button>Save product</button></form>'
            body += '</div><div class="panel"><h2>Create coupon</h2><form action="/admin/coupon" method="post">'+self.csrf_field()+'<input name="code" maxlength="40" placeholder="Coupon code" required><input name="percent" type="number" min="1" max="90" placeholder="Percent off" required><button>Create coupon</button></form><h2>Coupons</h2>'
            for cp in coupons:
                body += '<form action="/admin/coupon" method="post">'+self.csrf_field()+'<input type="hidden" name="id" value="'+str(cp['id'])+'"><strong>'+escape(cp['code'])+' ('+str(cp['percent_off'])+'%)</strong><select name="active"><option value="1" '+('selected' if cp['active'] else '')+'>Active</option><option value="0" '+('selected' if not cp['active'] else '')+'>Inactive</option></select><button>Update</button></form>'
            body += '</div><div class="panel"><h2>Users</h2>'
            for u in users:
                body += '<form action="/admin/user" method="post">'+self.csrf_field()+'<input type="hidden" name="id" value="'+str(u['id'])+'"><label>User #'+str(u['id'])+': '+escape(u['email'])+'</label><select name="role"><option value="user" '+('selected' if u['role']=='user' else '')+'>User</option><option value="admin" '+('selected' if u['role']=='admin' else '')+'>Admin</option></select><label>Credit in cents</label><input type="number" name="credit_cents" min="0" max="10000000" value="'+str(u['credit_cents'])+'"><button>Update user</button></form>'
            body += '</div>'
            self.send_html(200,self.page('Admin dashboard',body))
        else:
            self.error(404,'Page not found.')

    def recovery_codes_panel(self, codes, enabled=False):
        items = ''.join('<li><strong>' + escape(code) + '</strong></li>' for code in codes)
        return ('<div class="panel">' + ('<h2>MFA: Enabled</h2>' if enabled else '<h2>New recovery codes</h2>') +
                '<p>Save these 8 single-use recovery codes now. Each works once if you lose your '
                'authenticator. They are stored only as hashes and <strong>will not be shown again</strong>.</p>'
                '<ul>' + items + '</ul>'
                '<p><a class="btn" href="/account">Done</a></p></div>')

    def cart_rows(self, c):
        return c.execute('SELECT carts.product_id,carts.qty,products.name,products.price_cents,products.stock,products.active FROM carts JOIN products ON products.id=carts.product_id WHERE carts.session_hash=? ORDER BY products.id',(self.sid_hash,)).fetchall()

    def route_post(self, c, path, d):
        if path == '/register':
            email = d.get('email','').strip().lower(); name = d.get('name','').strip(); password = d.get('password','')
            if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or len(email)>254 or not (1<=len(name)<=80) or not (12<=len(password)<=128):
                raise ValueError('Enter a valid name/email and a password of 12–128 characters.')
            if not ip_budget(c, 'register', self.client_address[0]):
                return self.error(429,'Too many registrations. Try again later.')
            token = secrets.token_urlsafe(32)
            with transaction(c):
                existing=c.execute('SELECT id,confirmed FROM users WHERE email=?',(email,)).fetchone()
                if existing and existing['confirmed']:
                    # Keep the response uniform and do not disturb an active account.
                    c.execute('DELETE FROM pending_registrations WHERE email=?',(email,))
                    token=None
                else:
                    if existing:
                        # Remove legacy unconfirmed reservations before replacing them
                        # with an ownership-pending registration.
                        c.execute('DELETE FROM users WHERE id=?',(existing['id'],))
                    c.execute('INSERT INTO pending_registrations(email,display_name,password_hash,token_hash,expires_at) VALUES(?,?,?,?,?) '
                              'ON CONFLICT(email) DO UPDATE SET display_name=excluded.display_name,password_hash=excluded.password_hash,token_hash=excluded.token_hash,expires_at=excluded.expires_at',
                              (email,name,hash_password(password),token_hash(token),int(time.time())+3600))
            if token is None:
                self.send_html(200,self.page('Registration submitted','<div class="notice">If the email can be registered, a confirmation link was sent. In this local development environment, confirmation links are printed to the server terminal.</div>'))
                return
            # Local demo only: log verification URL, never publish this pattern for production.
            print('DEVELOPMENT CONFIRMATION LINK: http://%s:%s/confirm?token=%s' % (HOST,PORT,token), flush=True)
            self.send_html(200,self.page('Registration submitted','<div class="notice">If the email can be registered, a confirmation link was sent. In this local development environment, confirmation links are printed to the server terminal.</div>'))
        elif path == '/login':
            email = d.get('email','').strip().lower(); password = d.get('password','')
            if len(email)>254: raise ValueError('Invalid email length.')
            key = token_hash(self.client_address[0]+'|'+email)
            if not reserve_attempt(c, key):
                return self.error(429,'Too many attempts. Try again later.')
            u = c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
            # Always run Argon2 (even for unknown emails) so response timing
            # does not reveal whether an account exists.
            stored_hash = u['password_hash'] if u else DUMMY_PASSWORD_HASH
            password_ok = verify_password(password,stored_hash)
            if not u or not password_ok or not u['confirmed']:
                audit_event(c, 'login_failed')
                return self.error(401,'Invalid credentials or unconfirmed account.')
            profile=c.execute('SELECT samples FROM behavior_profiles WHERE user_id=?',(u['id'],)).fetchone()
            if profile:
                enrolled_samples = json.loads(profile['samples'])
                # A partially enrolled user must still be able to log in and finish
                # enrollment. Risk scoring is valid only after five trusted samples.
                if len(enrolled_samples) >= 5:
                    sample=parse_timing(d.get('timing',''))
                    if sample:
                        profile_data=build_profile(enrolled_samples)
                        score=anomaly_score(sample,profile_data)
                        if score>3.0: audit_event(c,'behavior_anomaly',u['id'])
                        # Browser timing is forgeable: never use it as sole identity proof.
                    else:
                        audit_event(c,'behavior_anomaly',u['id'])
            c.execute('DELETE FROM login_attempts WHERE key_hash=?',(key,))
            if u['totp_secret']:
                self.redirect('/mfa',self.rotate_session(c,pending_user_id=u['id']))
            elif RISK_GATE_ENFORCE and c.execute('SELECT 1 FROM passkeys WHERE user_id=? LIMIT 1',(u['id'],)).fetchone():
                self.redirect('/passkey/login',self.rotate_session(c,pending_passkey_id=u['id']))
            else:
                audit_event(c, 'login_success', u['id'])
                self.redirect('/account',self.rotate_session(c,u['id']))
        elif path == '/mfa':
            if self.user or not self.pending_user_id:
                return self.error(403,'No pending MFA login.')
            u=c.execute('SELECT id,totp_secret,totp_last_step FROM users WHERE id=?',(self.pending_user_id,)).fetchone()
            if not u or not u['totp_secret']: return self.error(403,'Invalid MFA session.')
            key=token_hash('mfa|'+str(u['id']))
            now=int(time.time())
            locked_until=0
            blocked=False
            failed=False
            recovery=False
            with transaction(c):
                state=c.execute('SELECT failures,locked_until FROM mfa_throttles WHERE user_id=?',(u['id'],)).fetchone()
                if state and state['locked_until']>now:
                    locked_until=state['locked_until']
                    blocked=True
                else:
                    current=c.execute('SELECT totp_secret,totp_last_step FROM users WHERE id=?',(u['id'],)).fetchone()
                    supplied = d.get('code','').strip().upper()
                    recovery = bool(re.fullmatch(r'[A-F0-9]{4}-[A-F0-9]{4}',supplied))
                    if recovery:
                        ok = c.execute('DELETE FROM recovery_codes WHERE user_id=? AND code_hash=?',
                                       (u['id'],token_hash(supplied))).rowcount == 1
                        step = None
                    else:
                        step = match_totp_step(current['totp_secret'],supplied)
                        ok = step is not None and step > current['totp_last_step']
                    if not ok:
                        failures=(state['failures'] if state else 0)+1
                        lock_seconds=mfa_lock_seconds(failures)
                        locked_until=now+lock_seconds if lock_seconds else 0
                        c.execute('INSERT INTO mfa_throttles(user_id,failures,locked_until,last_failure_at) VALUES(?,?,?,?) '
                                  'ON CONFLICT(user_id) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until,last_failure_at=excluded.last_failure_at',
                                  (u['id'],failures,locked_until,now))
                        c.execute('INSERT INTO login_attempts(key_hash,at) VALUES(?,?)',(key,now))
                        audit_event(c, 'mfa_failed', u['id'])
                        failed=True
                    else:
                        if not recovery:
                            updated=c.execute('UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<?',(step,u['id'],step)).rowcount
                            if updated!=1: raise ValueError('Security code already used.')
                        c.execute('DELETE FROM login_attempts WHERE key_hash=?',(key,))
                        c.execute('INSERT INTO mfa_throttles(user_id,failures,locked_until,last_failure_at) VALUES(?,?,?,?) '
                                  'ON CONFLICT(user_id) DO UPDATE SET failures=0,locked_until=0,last_failure_at=0',
                                  (u['id'],0,0,0))
                        audit_event(c, 'mfa_recovery_used' if recovery else 'mfa_success', u['id'])
                        if not (RISK_GATE_ENFORCE and c.execute('SELECT 1 FROM passkeys WHERE user_id=? LIMIT 1',(u['id'],)).fetchone()):
                            audit_event(c, 'login_success', u['id'])
            if blocked:
                return self.error(429,'Too many MFA attempts. Try again later.')
            if failed:
                return self.error(401,'Invalid or already used security code.')
            if RISK_GATE_ENFORCE and c.execute('SELECT 1 FROM passkeys WHERE user_id=? LIMIT 1',(u['id'],)).fetchone():
                self.redirect('/passkey/login',self.rotate_session(c,pending_passkey_id=u['id']))
            else:
                self.redirect('/account',self.rotate_session(c,u['id']))
        elif path == '/mfa/setup':
            if not self.must_login():return
            if self.user['totp_secret']:return self.error(409,'MFA already enabled.')
            enrollment=c.execute('SELECT * FROM mfa_enrollments WHERE session_hash=? AND expires_at>?',(self.sid_hash,int(time.time()))).fetchone()
            if not enrollment or not verify_password(d.get('password',''),self.user['password_hash']):
                return self.error(403,'Setup expired or authentication failed.')
            step=match_totp_step(enrollment['secret'],d.get('code',''))
            if step is None:return self.error(400,'Invalid security code.')
            with transaction(c):
                c.execute('UPDATE users SET totp_secret=?,totp_last_step=? WHERE id=? AND totp_secret IS NULL',(enrollment['secret'],step,self.user['id']))
                c.execute('DELETE FROM mfa_enrollments WHERE session_hash=?',(self.sid_hash,))
                codes = issue_recovery_codes(c, self.user['id'])
                audit_event(c, 'mfa_enabled', self.user['id'])
            self.send_html(200,self.page('Recovery codes',self.recovery_codes_panel(codes,enabled=True)))
        elif path == '/mfa/recovery':
            if not self.must_login(): return
            if not self.user['totp_secret']: return self.error(403,'Enable authenticator MFA first.')
            if not verify_password(d.get('password',''),self.user['password_hash']):
                return self.error(403,'Password not verified.')
            with transaction(c):
                codes = issue_recovery_codes(c, self.user['id'])
                audit_event(c, 'mfa_recovery_regenerated', self.user['id'])
            self.send_html(200,self.page('Recovery codes',self.recovery_codes_panel(codes)))
        elif path == '/security/behavior':
            if not self.must_login(): return
            if not verify_password(d.get('password',''),self.user['password_hash']):
                return self.error(403,'Password not verified.')
            sample=parse_timing(d.get('timing',''))
            if sample is None: return self.error(400,'Type naturally; do not paste or use autofill. At least 6 typed characters are needed.')
            row=c.execute('SELECT samples FROM behavior_profiles WHERE user_id=?',(self.user['id'],)).fetchone()
            samples=json.loads(row['samples']) if row else []
            if len(samples)>=5: return self.error(409,'Typing profile already enrolled; saved samples preserved.')
            samples.append(sample)
            c.execute('INSERT INTO behavior_profiles(user_id,samples,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET samples=excluded.samples,updated_at=excluded.updated_at',
                      (self.user['id'],json.dumps(samples),int(time.time())))
            if len(samples)==5: audit_event(c,'behavior_enrolled',self.user['id'])
            self.redirect('/security/behavior')
        elif path == '/passkey/start':
            if not self.must_login(): return
            if not verify_password(d.get('password',''),self.user['password_hash']):
                return self.send_json(403,{'error':'Password confirmation failed'})
            ch=challenge()
            c.execute('INSERT INTO passkey_challenges(session_hash,challenge,purpose,expires_at) VALUES(?,?,?,?) ON CONFLICT(session_hash) DO UPDATE SET challenge=excluded.challenge,purpose=excluded.purpose,expires_at=excluded.expires_at',
                      (self.sid_hash,ch,'register',int(time.time())+180))
            self.send_json(200,{'challenge':ch,'rp':{'name':'SecureShop Cafe','id':'localhost'},
                'user':{'id':b64u(str(self.user['id']).encode()),'name':self.user['email'],'displayName':self.user['display_name']},
                'pubKeyCredParams':[{'type':'public-key','alg':-7}], 'timeout':60000,
                'attestation':'none','authenticatorSelection':{'residentKey':'preferred','userVerification':'required'}})
        elif path == '/passkey/finish':
            if not self.must_login(): return
            pending=c.execute('SELECT * FROM passkey_challenges WHERE session_hash=? AND purpose=? AND expires_at>?',
                    (self.sid_hash,'register',int(time.time()))).fetchone()
            if not pending: return self.send_json(403,{'error':'Registration challenge expired'})
            try:
                credential=json.loads(d.get('credential',''))
                rp='localhost'
                if rp not in ('127.0.0.1','localhost'): raise ValueError('Loopback only')
                credential_id,pub,count=verify_registration(credential,pending['challenge'],'http://localhost:'+str(PORT),rp)
                with transaction(c):
                    c.execute('INSERT INTO passkeys(credential_id,user_id,public_key,sign_count,created_at) VALUES(?,?,?,?,?)',
                              (credential_id,self.user['id'],pub,count,int(time.time())))
                    c.execute('DELETE FROM passkey_challenges WHERE session_hash=?',(self.sid_hash,))
                    audit_event(c,'passkey_registered',self.user['id'])
            except (ValueError,KeyError,TypeError,sqlite3.IntegrityError):
                audit_event(c,'passkey_rejected',self.user['id'])
                return self.send_json(400,{'error':'Passkey registration rejected'})
            self.send_json(200,{'message':'Passkey registered successfully'})
        elif path == '/passkey/auth/start':
            if not self.user and not self.pending_passkey_id: return self.send_json(403,{'error':'Sign in first'})
            candidate_id = self.user['id'] if self.user else self.pending_passkey_id
            keys=c.execute('SELECT credential_id FROM passkeys WHERE user_id=?',(candidate_id,)).fetchall()
            if not keys: return self.send_json(403,{'error':'Enroll a passkey first'})
            ch=challenge()
            c.execute('INSERT INTO passkey_challenges(session_hash,challenge,purpose,expires_at) VALUES(?,?,?,?) ON CONFLICT(session_hash) DO UPDATE SET challenge=excluded.challenge,purpose=excluded.purpose,expires_at=excluded.expires_at',
                      (self.sid_hash,ch,'verify',int(time.time())+180))
            self.send_json(200,{'challenge':ch,'rpId':'localhost',
                'allowCredentials':[{'type':'public-key','id':k['credential_id']} for k in keys],
                'userVerification':'required','timeout':60000})
        elif path == '/passkey/auth/finish':
            if not self.user and not self.pending_passkey_id: return self.send_json(403,{'error':'Sign in first'})
            candidate_id = self.user['id'] if self.user else self.pending_passkey_id
            now=int(time.time())
            with transaction(c):
                pending=c.execute('SELECT * FROM passkey_challenges WHERE session_hash=? AND purpose=? AND expires_at>?',
                    (self.sid_hash,'verify',now)).fetchone()
                if not pending: return self.send_json(403,{'error':'Challenge expired'})
                claimed=c.execute('DELETE FROM passkey_challenges WHERE session_hash=? AND challenge=? AND purpose=? AND expires_at>? ',
                                  (self.sid_hash,pending['challenge'],'verify',now)).rowcount
                if claimed != 1: return self.send_json(403,{'error':'Challenge expired'})
            try:
                credential=json.loads(d.get('credential',''))
                raw_id=credential['rawId']
                key=c.execute('SELECT * FROM passkeys WHERE credential_id=? AND user_id=?',(raw_id,candidate_id)).fetchone()
                if not key: raise ValueError('Unregistered credential')
                rp='localhost'
                if rp not in ('127.0.0.1','localhost'): raise ValueError('Loopback only')
                count=verify_assertion(credential,pending['challenge'],'http://localhost:'+str(PORT),rp,
                                       key['credential_id'],key['public_key'],key['sign_count'])
                lat=float(d.get('lat','nan')); lon=float(d.get('lon','nan'))
                allowed,reason,distance=location_time_result(lat,lon,30.0444,31.2357)
                cookies=None
                with transaction(c):
                    updated=c.execute('UPDATE passkeys SET sign_count=? WHERE credential_id=? AND sign_count=?',
                                      (count,key['credential_id'],key['sign_count'])).rowcount
                    if updated != 1: raise ValueError('Credential counter did not advance.')
                    audit_event(c,'passkey_verified',candidate_id)
                    if not allowed:
                        audit_event(c,'risk_'+reason+'_denied',candidate_id)
                    elif self.pending_passkey_id:
                        audit_event(c,'login_success',candidate_id)
                        cookies=self.rotate_session(c,user_id=candidate_id)
                if not allowed:
                    return self.send_json(403,{'error':'Security policy denied ('+reason+'). Browser location is not trusted proof.'})
                if cookies:
                    return self.send_json(200,{'message':'Security policy approved: authentic passkey + local hours + location policy',
                                           'distance_km':round(distance,2), 'login_complete':bool(cookies)},cookies=cookies)
                return self.send_json(200,{'message':'Security policy approved: authentic passkey + local hours + location policy',
                                           'distance_km':round(distance,2), 'login_complete':False})
            except (ValueError,KeyError,TypeError,OverflowError,sqlite3.Error):
                audit_event(c,'passkey_rejected',candidate_id)
                return self.send_json(403,{'error':'Passkey verification or location failed'})
        elif path == '/logout':
            self.redirect('/',self.rotate_session(c))
        elif path == '/cart/add':
            if not self.must_login(): return
            pid = positive_int(d.get('product_id'),10**9); qty = positive_int(d.get('qty'))
            with transaction(c):
                p = c.execute('SELECT * FROM products WHERE id=? AND active=1',(pid,)).fetchone()
                if not p or p['stock'] < qty: raise ValueError('Product is unavailable or stock is insufficient.')
                existing = c.execute('SELECT qty FROM carts WHERE session_hash=? AND product_id=?',(self.sid_hash,pid)).fetchone()
                newqty = qty + (existing['qty'] if existing else 0)
                if newqty > min(100,p['stock']): raise ValueError('Quantity exceeds stock or cart limit.')
                c.execute('INSERT INTO carts(session_hash,product_id,qty) VALUES(?,?,?) ON CONFLICT(session_hash,product_id) DO UPDATE SET qty=excluded.qty',(self.sid_hash,pid,newqty))
            self.redirect('/cart')
        elif path == '/cart/update':
            if not self.must_login(): return
            pid = positive_int(d.get('product_id'),10**9)
            raw = d.get('qty','')
            if raw == '0':
                c.execute('DELETE FROM carts WHERE session_hash=? AND product_id=?',(self.sid_hash,pid))
            else:
                qty = positive_int(raw)
                p = c.execute('SELECT stock,active FROM products WHERE id=?',(pid,)).fetchone()
                if not p or not p['active'] or qty>p['stock']: raise ValueError('Not enough stock.')
                c.execute('UPDATE carts SET qty=? WHERE session_hash=? AND product_id=?',(qty,self.sid_hash,pid))
            self.redirect('/cart')
        elif path == '/checkout':
            if not self.must_login(): return
            code = d.get('coupon','').strip().upper()
            if len(code)>40: raise ValueError('Invalid coupon.')
            key = d.get('key','')
            if not re.fullmatch(r'[A-Za-z0-9_-]{10,80}',key): raise ValueError('Invalid checkout key. Reload the checkout page.')
            with transaction(c):
                existing = c.execute('SELECT id FROM orders WHERE user_id=? AND idempotency_key=?',(self.user['id'],key)).fetchone()
                if existing:
                    order_id = existing['id']  # replayed submit returns the same receipt; no second debit
                else:
                    rows = self.cart_rows(c)
                    if not rows: raise ValueError('Cart is empty.')
                    if any(not r['active'] or r['qty']>r['stock'] for r in rows): raise ValueError('A product is unavailable. Please update cart.')
                    subtotal = sum(r['price_cents']*r['qty'] for r in rows)
                    coupon = None; discount = 0
                    if code:
                        coupon = c.execute('SELECT * FROM coupons WHERE code=? AND active=1',(code,)).fetchone()
                        if not coupon: raise ValueError('Coupon invalid or inactive.')
                        if c.execute('SELECT 1 FROM coupon_uses WHERE user_id=? AND coupon_id=?',(self.user['id'],coupon['id'])).fetchone():
                            raise ValueError('Coupon already used.')
                        discount = subtotal*coupon['percent_off']//100
                    total = subtotal-discount
                    account = c.execute('SELECT credit_cents FROM users WHERE id=?',(self.user['id'],)).fetchone()
                    if account['credit_cents'] < total: raise ValueError('Insufficient store credit.')
                    c.execute('UPDATE users SET credit_cents=credit_cents-? WHERE id=?',(total,self.user['id']))
                    order_id = c.execute('INSERT INTO orders(user_id,total_cents,discount_cents,created_at,idempotency_key) VALUES(?,?,?,?,?)',(self.user['id'],total,discount,int(time.time()),key)).lastrowid
                    for r in rows:
                        c.execute('UPDATE products SET stock=stock-? WHERE id=?',(r['qty'],r['product_id']))
                        c.execute('INSERT INTO order_items(order_id,product_id,name_snapshot,unit_price_cents,qty) VALUES(?,?,?,?,?)',(order_id,r['product_id'],r['name'],r['price_cents'],r['qty']))
                    if coupon: c.execute('INSERT INTO coupon_uses(user_id,coupon_id) VALUES(?,?)',(self.user['id'],coupon['id']))
                    c.execute('DELETE FROM carts WHERE session_hash=?',(self.sid_hash,))
                    audit_event(c, 'checkout_complete', self.user['id'], 'order', order_id)
            self.redirect('/order/'+str(order_id))
        elif path == '/account':
            if not self.must_login(): return
            name = d.get('name','').strip()
            if not 1<=len(name)<=80: raise ValueError('Name must be 1–80 characters.')
            c.execute('UPDATE users SET display_name=? WHERE id=?',(name,self.user['id']))
            self.redirect('/account')
        elif path == '/newsletter':
            email = d.get('email','').strip().lower()
            if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email) or len(email)>254: raise ValueError('Invalid email.')
            if not ip_budget(c, 'newsletter', self.client_address[0]):
                return self.error(429,'Too many subscriptions. Try again later.')
            existing = c.execute('SELECT coupon_id FROM newsletters WHERE email=?',(email,)).fetchone()
            if not existing:
                code = 'NEWS-'+secrets.token_hex(6).upper()
                with transaction(c):
                    cp_id = c.execute('INSERT INTO coupons(code,percent_off) VALUES(?,10)',(code,)).lastrowid
                    c.execute('INSERT INTO newsletters(email,coupon_id) VALUES(?,?)',(email,cp_id))
                # Coupons must never be shown to whoever submits a form: only the
                # mailbox owner may learn the code. Local dev prints to the
                # server terminal like the confirmation link; production email.
                print('DEVELOPMENT NEWSLETTER COUPON for %s: %s' % (email,code), flush=True)
            self.send_html(200,self.page('Newsletter','<div class="notice">If this email is new to our list, your one-time 10% coupon was sent to it. In this local development environment, it is printed to the server terminal.</div>'))
        elif path == '/admin/product':
            if not self.must_admin(): return
            name=d.get('name','').strip(); desc=d.get('description','').strip()
            if not (1<=len(name)<=100 and 1<=len(desc)<=500): raise ValueError('Product fields are invalid.')
            price_raw=d.get('price_cents',''); stock_raw=d.get('stock','')
            if not re.fullmatch(r'[0-9]{1,9}',price_raw) or not re.fullmatch(r'[0-9]{1,6}',stock_raw): raise ValueError('Invalid price or stock.')
            price=int(price_raw);stock=int(stock_raw)
            if d.get('id'):
                pid=positive_int(d['id'],10**9)
                if d.get('active') not in ('0','1'): raise ValueError('Invalid status.')
                c.execute('UPDATE products SET name=?,description=?,price_cents=?,stock=?,active=? WHERE id=?',(name,desc,price,stock,int(d['active']),pid))
                audit_event(c, 'admin_product_changed', self.user['id'], 'product', pid)
            else:
                cur = c.execute('INSERT INTO products(name,description,price_cents,stock) VALUES(?,?,?,?)',(name,desc,price,stock))
                audit_event(c, 'admin_product_changed', self.user['id'], 'product', cur.lastrowid)
            self.redirect('/admin')
        elif path == '/admin/coupon':
            if not self.must_admin(): return
            if d.get('id'):
                cid=positive_int(d['id'],10**9)
                if d.get('active') not in ('0','1'): raise ValueError('Invalid status.')
                c.execute('UPDATE coupons SET active=? WHERE id=?',(int(d['active']),cid))
                audit_event(c, 'admin_coupon_changed', self.user['id'], 'coupon', cid)
            else:
                code=d.get('code','').strip().upper();raw=d.get('percent','')
                if not re.fullmatch(r'[A-Z0-9-]{3,40}',code) or not re.fullmatch(r'[0-9]{1,2}',raw) or not (1<=int(raw)<=90): raise ValueError('Invalid coupon code or percent.')
                try:
                    cur = c.execute('INSERT INTO coupons(code,percent_off) VALUES(?,?)',(code,int(raw)))
                    audit_event(c, 'admin_coupon_changed', self.user['id'], 'coupon', cur.lastrowid)
                except sqlite3.IntegrityError:return self.error(409,'Coupon code already exists.')
            self.redirect('/admin')
        elif path == '/admin/user':
            if not self.must_admin(): return
            uid=positive_int(d.get('id'),10**9);role=d.get('role');raw=d.get('credit_cents','')
            if role not in ('user','admin') or not re.fullmatch(r'[0-9]{1,8}',raw) or int(raw)>10_000_000: raise ValueError('Invalid user update.')
            if uid==self.user['id'] and role!='admin': raise ValueError('Cannot remove your own admin access.')
            c.execute('UPDATE users SET role=?,credit_cents=? WHERE id=?',(role,int(raw),uid))
            audit_event(c, 'admin_user_changed', self.user['id'], 'user', uid)
            self.redirect('/admin')
        else:
            self.error(404,'Page not found.')


def main():
    init_db()
    print(f'SecureShop running at http://{HOST}:{PORT}', flush=True)
    ThreadingHTTPServer((HOST,PORT),App).serve_forever()


if __name__=='__main__':
    main()
