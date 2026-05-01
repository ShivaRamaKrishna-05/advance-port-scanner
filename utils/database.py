import os
import sqlite3
from flask import current_app, g

# ---------- DATABASE SCHEMA ----------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    scan_name TEXT,
    target TEXT,
    ports TEXT,
    open_count INTEGER,
    closed_count INTEGER,
    filtered_count INTEGER,
    notes TEXT,
    severity TEXT,
    risk_score INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    port INTEGER,
    status TEXT,
    service TEXT,
    version TEXT,
    protocol TEXT,
    response_time TEXT,
    risk TEXT,
    banner TEXT,
    suggestion TEXT
);
"""

# ---------- GET DATABASE ----------
def get_db():
    if 'db' not in g:
        db_path = current_app.config['DATABASE']
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row

    return g.db

# ---------- CLOSE DATABASE ----------
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ---------- INITIALIZE DATABASE ----------
def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()

# ---------- FIXED FUNCTION (THIS WAS MISSING) ----------
def init_app(app):
    app.teardown_appcontext(close_db)