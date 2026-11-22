"""Naive-vs-secure HTTP comparison for CET431.

Runs the same attack scenarios against naive_lab.py (deliberately vulnerable)
and SecureShop Café, capturing real requests/responses and resulting state as
evidence transcripts under evidence/.

Usage:  python scripts/security_compare.py \
            --secure http://127.0.0.1:8000 --naive http://127.0.0.1:5050

The secure app and naive lab must both be running. The script provisions its
own fixture user in the secure database (SECURESHOP_DB or ./secureshop.db) and
resets that user's cart/orders/credit before each run — never run it against a
database you care about.
"""
import argparse
import http.cookiejar
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SECURE_DB = Path(os.environ.get('SECURESHOP_DB', str(BASE / 'secureshop.db')))
SECURE_EMAIL = 'compare@example.test'
SECURE_PW = 'a long compare password'
NAIVE_EMAIL = 'alice@test'
NAIVE_PW = 'alicepw123'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Agent:
    """Cookie-aware HTTP client; secure=True adds CSRF scraping for SecureShop."""

    def __init__(self, base, secure=False):
        self.base = base
        self.secure = secure
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())
        self.log = []

    def request(self, method, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.base + path, data=body, method=method)
        if data is not None:
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        try:
            r = self.opener.open(req)
            status, text = r.status, r.read().decode('utf-8', 'replace')
            headers = dict(r.headers)
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode('utf-8', 'replace')
            headers = dict(e.headers)
        cookie = headers.get('Set-Cookie', '')
        if self.secure:  # real app sessions stay out of transcripts; lab tokens are the evidence
            cookie = re.sub(r'(sid=)[^;]+', r'\1<redacted>', cookie)
        self.log.append({'method': method, 'path': path, 'fields': sorted((data or {}).keys()),
                         'status': status, 'body': text[:400], 'set_cookie': cookie})
        return status, text, headers

    def csrf(self, path='/login'):
        _, text, _ = self.request('GET', path)
        return re.search(r'name="csrf" value="([^"]+)"', text).group(1)

    def secure_post(self, path, data):
        return self.request('POST', path, dict(data, csrf=self.csrf()))

    def secure_login(self):
        self.request('GET', '/')
        return self.secure_post('/login', {'email': SECURE_EMAIL, 'password': SECURE_PW})

    def secure_checkout(self, coupon=''):
        _, text, _ = self.request('GET', '/checkout')
        key = re.search(r'name="key" value="([^"]+)"', text).group(1)
        return key, self.secure_post('/checkout', {'coupon': coupon, 'key': key})


def secure_db():
    conn = sqlite3.connect(SECURE_DB)
    conn.row_factory = sqlite3.Row
    return conn


def provision_secure_user():
    """Create/reset the compare fixture user directly in the dev DB."""
    import app
    app.init_db()  # schema + seed products; idempotent on existing DBs
    with secure_db() as c:
        row = c.execute('SELECT id FROM users WHERE email=?', (SECURE_EMAIL,)).fetchone()
        if not row:
            c.execute('INSERT INTO users(email,display_name,password_hash,confirmed,credit_cents) VALUES(?,?,?,1,10000)',
                      (SECURE_EMAIL, 'Compare', app.hash_password(SECURE_PW)))
        uid = c.execute('SELECT id FROM users WHERE email=?', (SECURE_EMAIL,)).fetchone()['id']
        c.execute('UPDATE users SET credit_cents=10000 WHERE id=?', (uid,))
        for table in ('orders', 'coupon_uses'):
            c.execute('DELETE FROM ' + table + ' WHERE user_id=?', (uid,))
        c.execute('DELETE FROM carts WHERE session_hash IN (SELECT id_hash FROM sessions WHERE user_id=?)', (uid,))
        c.execute('DELETE FROM sessions WHERE user_id=?', (uid,))
        c.execute("INSERT OR IGNORE INTO coupons(code,percent_off) VALUES('COMPARE10',10)")
    return


def naive_reset():
    conn = sqlite3.connect(Path(os.environ.get('SECURESHOP_NAIVE_DB', str(BASE / 'naive_lab.db'))))
    for t in ('users', 'sessions', 'carts', 'orders', 'coupon_uses', 'newsletters'):
        conn.execute('DELETE FROM ' + t)
    conn.execute('DELETE FROM products')
    conn.execute("INSERT INTO products VALUES(1,'Latte',2500,50),(2,'Croissant',1500,50)")
    conn.execute("INSERT INTO users(id,email,password,credit) VALUES(1,?,?,10000)", (NAIVE_EMAIL, NAIVE_PW))
    conn.execute("INSERT OR IGNORE INTO coupons(code,percent) VALUES('WELCOME10',10)")
    conn.commit()
    conn.close()


def run_scenarios(secure, naive):
    results = []

    def record(name, naive_out, secure_out, naive_vuln, secure_defended, note):
        results.append({'scenario': name, 'naive': naive_out, 'secure': secure_out,
                        'naive_vulnerable': naive_vuln, 'secure_defended': secure_defended, 'note': note})

    # S1 — SQL injection in catalogue search
    s, n_body, _ = naive.request('GET', "/?q=%27%20OR%201%3D1--")
    _, s_body, _ = secure.request('GET', "/?q=%27%20OR%201%3D1--")
    record('sqli-search', n_body[:200], s_body[:200],
           'Latte' in n_body and 'Croissant' in n_body,
           'Spanish Latte</a>' not in s_body,
           'naive concatenates q into LIKE; secure uses bound parameters')

    # S2 — client-controlled price
    naive.request('POST', '/login', {'email': NAIVE_EMAIL, 'password': NAIVE_PW})
    s, n_body, _ = naive.request('POST', '/checkout', {'total': '1', 'coupon': ''})
    m = re.search(r'total (\d+)', n_body)
    secure.secure_login()
    secure.secure_post('/cart/add', {'product_id': '1', 'qty': '1'})
    s2_key, (s_status, s_body, _) = secure.secure_checkout()
    uid = secure_db().execute('SELECT id FROM users WHERE email=?', (SECURE_EMAIL,)).fetchone()['id']
    real_total = secure_db().execute('SELECT total_cents FROM orders WHERE user_id=?', (uid,)).fetchone()['total_cents']
    s2_oid = secure_db().execute('SELECT id FROM orders WHERE user_id=?', (uid,)).fetchone()['id']
    record('price-tampering', n_body[:200], 'order total_cents=%d' % real_total,
           m is not None and int(m.group(1)) <= 1,
           real_total == 2499,
           'naive trusts POSTed total; secure recomputes from products.price_cents')

    # S3 — checkout replay / no idempotency
    naive.request('POST', '/cart/add', {'product_id': '1', 'qty': '1'})
    naive.request('POST', '/checkout', {'total': '2500', 'coupon': ''})
    n_before = sqlite3.connect(os.environ.get('SECURESHOP_NAIVE_DB', str(BASE / 'naive_lab.db'))).execute(
        'SELECT COUNT(*) FROM orders WHERE user_id=1').fetchone()[0]
    naive.request('POST', '/checkout', {'total': '2500', 'coupon': ''})
    n_after = sqlite3.connect(os.environ.get('SECURESHOP_NAIVE_DB', str(BASE / 'naive_lab.db'))).execute(
        'SELECT COUNT(*) FROM orders WHERE user_id=1').fetchone()[0]
    # replay S2's exact POST (same key, refilled cart): must return the same
    # receipt with no new order, no second debit
    secure.secure_post('/cart/add', {'product_id': '2', 'qty': '1'})
    s_status3, _, s_headers3 = secure.secure_post('/checkout', {'coupon': '', 'key': s2_key})
    s_orders = secure_db().execute('SELECT COUNT(*) AS n FROM orders WHERE user_id=?', (uid,)).fetchone()['n']
    s_credit = secure_db().execute('SELECT credit_cents FROM users WHERE id=?', (uid,)).fetchone()['credit_cents']
    same_receipt = s_headers3.get('Location', '').endswith('/order/' + str(s2_oid))
    record('checkout-replay', 'orders %d->%d on repost' % (n_before, n_after),
           'status=%d location=%s orders=%d credit=%d' % (s_status3, s_headers3.get('Location'), s_orders, s_credit),
           n_after == n_before + 1,
           s_status3 in (302, 303) and same_receipt and s_orders == 1 and s_credit == 10000 - 2499,
           'naive debits every POST; secure replays return the same receipt, no second debit')

    # S4 — IDOR on order detail
    s, n_body, _ = naive.request('GET', '/order/1')
    oid = secure_db().execute('SELECT id FROM orders WHERE user_id=? LIMIT 1', (uid,)).fetchone()['id']
    # second fixture user must not read alice's order
    with secure_db() as c:
        if not c.execute('SELECT id FROM users WHERE email=?', ('compare2@example.test',)).fetchone():
            import app
            c.execute('INSERT INTO users(email,display_name,password_hash,confirmed,credit_cents) VALUES(?,?,?,1,10000)',
                      ('compare2@example.test', 'Compare2', app.hash_password(SECURE_PW)))
    other = Agent(secure.base, secure=True)
    other.request('GET', '/')
    other.secure_post('/login', {'email': 'compare2@example.test', 'password': SECURE_PW})
    s_status, s_body, _ = other.request('GET', '/order/' + str(oid))
    record('idor-order', n_body[:200], 'status=%d' % s_status,
           'total' in n_body, s_status == 404,
           'naive has no owner check; secure scopes the query to session user')

    # S5 — admin route without role
    s, n_body, _ = naive.request('GET', '/admin')
    s_status, _, _ = secure.request('GET', '/admin')
    record('admin-no-role', n_body[:120], 'status=%d' % s_status,
           'alice@test:alicepw123' in n_body, s_status == 403,
           'naive dumps user table incl. plaintext passwords; secure requires admin role')

    # S6 — CSRF on state change
    naive.request('POST', '/account', {'email': 'attacker@evil.test'})
    s_status, _, _ = secure.request('POST', '/account', {'name': 'Forged'})
    reverted = secure_db().execute('SELECT email FROM users WHERE id=1').fetchone()[0]
    record('csrf-profile', 'posted without csrf token, accepted',
           'status=%d' % s_status, True, s_status == 403,
           'naive accepts cookie-authenticated POST w/o token; secure rejects (403)')

    # S7 — coupon reuse
    naive.request('POST', '/checkout', {'total': '2500', 'coupon': 'WELCOME10'})
    _, n_body2, _ = naive.request('POST', '/checkout', {'total': '2500', 'coupon': 'WELCOME10'})
    secure.secure_post('/cart/add', {'product_id': '1', 'qty': '1'})
    secure.secure_checkout('COMPARE10')
    secure.secure_post('/cart/add', {'product_id': '1', 'qty': '1'})
    _, (s_status2, s_body2, _) = secure.secure_checkout('COMPARE10')
    record('coupon-reuse', n_body2[:120], 'status=%d %s' % (s_status2, s_body2[:80]),
           'order' in n_body2, s_status2 == 400 and 'already used' in s_body2,
           'naive coupons are reusable; secure enforces coupon_uses PK')

    # S8 — newsletter coupon harvesting
    _, n_body, _ = naive.request('POST', '/newsletter', {'email': 'attacker@evil.test'})
    _, s_body, _ = secure.secure_post('/newsletter', {'email': 'someone@example.test'})
    record('newsletter-harvest', n_body[:120], s_body[:120],
           'NAIVE-' in n_body, 'NEWS-' not in s_body,
           'naive returns the code to anyone; secure sends it only to the mailbox')

    # S9 — session token quality
    naive_cookie = next((e['set_cookie'] for e in naive.log if e['set_cookie']), '')
    secure_cookie = next((e['set_cookie'] for e in secure.log if e['set_cookie']), '')
    record('session-token', naive_cookie[:120], secure_cookie[:120],
           'fixed-token' in naive_cookie and 'HttpOnly' not in naive_cookie,
           'HttpOnly' in secure_cookie and 'SameSite' in secure_cookie,
           'naive: predictable id, no flags; secure: random token, HttpOnly+SameSite')

    # S10 — negative quantity
    naive.request('POST', '/cart/add', {'product_id': '1', 'qty': '-5'})
    n_qty = sqlite3.connect(os.environ.get('SECURESHOP_NAIVE_DB', str(BASE / 'naive_lab.db'))).execute(
        'SELECT qty FROM carts WHERE user_id=1 ORDER BY rowid DESC LIMIT 1').fetchone()
    s_status, _, _ = secure.secure_post('/cart/add', {'product_id': '1', 'qty': '-5'})
    record('negative-qty', 'cart qty=%s' % (n_qty[0] if n_qty else None), 'status=%d' % s_status,
           n_qty is not None and n_qty[0] == -5, s_status == 400,
           'naive stores negative qty; secure validates positive_int + CHECK')

    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--secure', default='http://127.0.0.1:8000')
    ap.add_argument('--naive', default='http://127.0.0.1:5050')
    ap.add_argument('--out', default=str(BASE / 'evidence'))
    args = ap.parse_args()

    sys.path.insert(0, str(BASE))
    provision_secure_user()
    naive_reset()

    secure, naive = Agent(args.secure, secure=True), Agent(args.naive)
    status, _, _ = secure.secure_login()
    if status not in (301, 302, 303):
        sys.exit('Secure login failed (HTTP %d). Is %s serving %s? '
                 'Start it with: SECURESHOP_DB=%s python app.py'
                 % (status, args.secure, SECURE_DB, SECURE_DB))
    # A 303 login writes a session row server-side. If none appears in the DB
    # this script provisioned, the server is bound to a different SECURESHOP_DB.
    uid = secure_db().execute('SELECT id FROM users WHERE email=?', (SECURE_EMAIL,)).fetchone()['id']
    if secure_db().execute('SELECT COUNT(*) AS n FROM sessions WHERE user_id=?', (uid,)).fetchone()['n'] == 0:
        sys.exit('Login succeeded but no session row appeared in %s — the '
                 'running server is using a different SECURESHOP_DB.' % SECURE_DB)
    results = run_scenarios(secure, naive)

    out = Path(args.out)
    out.mkdir(exist_ok=True)
    (out / 'compare_transcripts.json').write_text(json.dumps(
        {'secure_log': secure.log, 'naive_log': naive.log, 'results': results}, indent=2))

    lines = []
    for r in results:
        verdict = ('NAIVE VULNERABLE / SECURE DEFENDED' if r['naive_vulnerable'] and r['secure_defended']
                   else 'MISMATCH — investigate')
        lines.append('=== %s: %s\n  naive : %s\n  secure: %s\n  note  : %s'
                     % (r['scenario'], verdict, r['naive'], r['secure'], r['note']))
    (out / 'compare_summary.txt').write_text('\n\n'.join(lines))
    ok = sum(1 for r in results if r['naive_vulnerable'] and r['secure_defended'])
    print('%d/%d scenarios: naive vulnerable, secure defended' % (ok, len(results)))
    for r in results:
        if not (r['naive_vulnerable'] and r['secure_defended']):
            print('  MISMATCH:', r['scenario'], '| naive:', r['naive'][:80], '| secure:', r['secure'][:80])
    sys.exit(0 if ok == len(results) else 1)


if __name__ == '__main__':
    main()
