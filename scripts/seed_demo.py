"""Seed a fresh disposable demo database with synthetic accounts only.

Usage:  SECURESHOP_DB=demo.db python scripts/seed_demo.py

Creates (idempotent): alice@demo.test, bob@demo.test (confirmed, $100 credit),
admin@demo.test (admin, $100 credit), and coupon DEMO10 (10% off).
Passwords are documented demo credentials — never reuse them for real accounts.
"""
import os
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
os.environ.setdefault('SECURESHOP_DB', str(BASE / 'demo.db'))

import app

DEMO_USERS = [
    ('alice@demo.test', 'Alice Demo', 'user', 'alice demo password'),
    ('bob@demo.test', 'Bob Demo', 'user', 'bob demo password'),
    ('admin@demo.test', 'Demo Admin', 'admin', 'admin demo password'),
]


def seed():
    app.init_db()
    with app.db() as c:
        for email, name, role, pw in DEMO_USERS:
            c.execute('INSERT OR IGNORE INTO users(email,display_name,password_hash,role,confirmed,credit_cents) '
                      'VALUES(?,?,?,?,1,10000)', (email, name, app.hash_password(pw), role))
        c.execute("INSERT OR IGNORE INTO coupons(code,percent_off) VALUES('DEMO10',10)")
    print('Seeded %s: %d users + DEMO10 coupon' % (os.environ['SECURESHOP_DB'], len(DEMO_USERS)))


if __name__ == '__main__':
    seed()
