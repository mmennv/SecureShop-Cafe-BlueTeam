"""Naive Lab — deliberately insecure teaching server for CET431 contrast demos.

Binds to 127.0.0.1 only, uses its own disposable SQLite database, and shares
nothing with SecureShop Café. It exists so the same HTTP attack scenario can be
run against a vulnerable build and the hardened build side by side.

Run: SECURESHOP_NAIVE_DB=/tmp/naive.db python naive_lab.py   (port 5050)
"""
import http.server
import os
import sqlite3
import time
import urllib.parse
from pathlib import Path

DB = Path(os.environ.get('SECURESHOP_NAIVE_DB', str(Path(__file__).parent / 'naive_lab.db')))
PORT = int(os.environ.get('SECURESHOP_NAIVE_PORT', '5050'))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT, password TEXT, credit INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT, price INTEGER, stock INTEGER);
CREATE TABLE IF NOT EXISTS carts(user_id INTEGER, product_id INTEGER, qty INTEGER);
CREATE TABLE IF NOT EXISTS coupons(id INTEGER PRIMARY KEY, code TEXT, percent INTEGER);
CREATE TABLE IF NOT EXISTS coupon_uses(user_id INTEGER, coupon_id INTEGER);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER, total INTEGER);
CREATE TABLE IF NOT EXISTS newsletters(email TEXT PRIMARY KEY, coupon_id INTEGER);
"""


def init_db():
    fresh = not DB.exists()
    conn = sqlite3.connect(DB)
    conn.executescript(SCHEMA)
    if fresh:
        conn.execute("INSERT INTO products VALUES(1,'Latte',2500,50),(2,'Croissant',1500,50)")
        conn.execute("INSERT INTO coupons(code,percent) VALUES('WELCOME10',10)")
        conn.execute("INSERT INTO users(email,password,credit) VALUES('alice@test','alicepw123',10000)")
        conn.commit()
    conn.close()


class Naive(http.server.BaseHTTPRequestHandler):
    server_version = 'NaiveLab/1.0'
    protocol_version = 'HTTP/1.0'

    def log_message(self, fmt, *args):
        print('127.0.0.1 - ' + fmt % args, flush=True)

    def user(self):
        cookie = self.headers.get('Cookie', '')
        token = dict(p.split('=', 1) for p in cookie.split('; ') if '=' in p).get('sid', '')
        conn = sqlite3.connect(DB)
        row = conn.execute('SELECT user_id FROM sessions WHERE token=?', (token,)).fetchone()
        conn.close()
        return row[0] if row else None

    def post_fields(self):
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length).decode()
        return {k: v[0] for k, v in urllib.parse.parse_qs(data).items()}

    def out(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        conn = sqlite3.connect(DB)
        path = urllib.parse.urlsplit(self.path).path
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if path == '/':
            # VULN: string-built SQL — injectable search
            term = q.get('q', [''])[0]
            rows = conn.execute("SELECT id,name,price FROM products WHERE name LIKE '%" + term + "%'").fetchall()
            conn.close()
            self.out(200, '<br>'.join('%d %s %d' % r for r in rows))
        elif path.startswith('/order/'):
            # VULN: no ownership check (IDOR)
            oid = path.split('/')[-1]
            row = conn.execute('SELECT id,user_id,total FROM orders WHERE id=' + oid).fetchone()
            conn.close()
            self.out(200, 'order %s user %s total %s' % row if row else 'not found')
        elif path == '/admin':
            # VULN: no admin check at all
            users = conn.execute('SELECT email,password FROM users').fetchall()
            conn.close()
            self.out(200, '<br>'.join('%s:%s' % u for u in users))
        else:
            conn.close()
            self.out(404, 'not found')

    def do_POST(self):
        conn = sqlite3.connect(DB)
        d = self.post_fields()
        path = urllib.parse.urlsplit(self.path).path
        if path == '/login':
            # VULN: plaintext password compare, SQL injection, no lockout, session never rotates
            email, pw = d.get('email', ''), d.get('password', '')
            row = conn.execute("SELECT id FROM users WHERE email='" + email + "' AND password='" + pw + "'").fetchone()
            if not row:
                conn.close()
                return self.out(200, 'bad login')
            token = 'fixed-token-' + str(row[0])  # VULN: predictable session id
            conn.execute('INSERT OR REPLACE INTO sessions VALUES(?,?)', (token, row[0]))
            conn.commit()
            conn.close()
            self.send_response(302)
            self.send_header('Set-Cookie', 'sid=' + token + '; Path=/')  # VULN: no flags
            self.send_header('Location', '/')
            self.end_headers()
        elif path == '/cart/add':
            uid = self.user()
            qty = int(d.get('qty', '1'))  # VULN: negative qty allowed
            conn.execute('INSERT INTO carts VALUES(?,?,?)', (uid, int(d.get('product_id', '0')), qty))
            conn.commit()
            conn.close()
            self.out(200, 'added')
        elif path == '/checkout':
            # VULN: trusts client total, no stock/credit/transaction checks, no
            # idempotency — every POST debits again.
            uid = self.user()
            total = int(d.get('total', '0'))
            code = d.get('coupon', '')
            if code:
                cp = conn.execute('SELECT id,percent FROM coupons WHERE code=?', (code,)).fetchone()
                if cp:
                    total = total - total * cp[1] // 100  # VULN: coupon reusable forever
            conn.execute('UPDATE users SET credit=credit-? WHERE id=?', (total, uid))
            oid = conn.execute('INSERT INTO orders(user_id,total) VALUES(?,?)', (uid, total)).lastrowid
            conn.execute('DELETE FROM carts WHERE user_id=?', (uid,))
            conn.commit()
            conn.close()
            self.out(200, 'order %d total %d' % (oid, total))
        elif path == '/newsletter':
            # VULN: coupon code returned to any submitted email
            email = d.get('email', '')
            row = conn.execute('SELECT coupon_id FROM newsletters WHERE email=?', (email,)).fetchone()
            if row:
                conn.close()
                return self.out(200, 'already subscribed')
            code = 'NAIVE-' + email.split('@')[0].upper()[:8]  # VULN: predictable code
            cid = conn.execute('INSERT INTO coupons(code,percent) VALUES(?,10)', (code,)).lastrowid
            conn.execute('INSERT INTO newsletters VALUES(?,?)', (email, cid))
            conn.commit()
            conn.close()
            self.out(200, 'your coupon: ' + code)
        elif path == '/account':
            # VULN: no CSRF check — any cross-site POST with the cookie works
            uid = self.user()
            conn.execute('UPDATE users SET email=? WHERE id=?', (d.get('email', ''), uid))
            conn.commit()
            conn.close()
            self.out(200, 'updated')
        else:
            conn.close()
            self.out(404, 'not found')


if __name__ == '__main__':
    init_db()
    print('Naive lab on http://127.0.0.1:%d (disposable db %s)' % (PORT, DB), flush=True)
    http.server.HTTPServer(('127.0.0.1', PORT), Naive).serve_forever()
