import os
import sqlite3
from flask import current_app, g

# =========================================================
# DATABASE SCHEMA
# =========================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    scan_name TEXT,
    target TEXT,
    resolved_ip TEXT,
    port_range TEXT,
    total_open_ports INTEGER,
    is_favorite INTEGER DEFAULT 0,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id) REFERENCES users(id)
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

    os TEXT,

    vulnerability TEXT,

    banner TEXT,

    suggestion TEXT,

    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
"""

# =========================================================
# GET DATABASE CONNECTION
# =========================================================

def get_db():

    if "db" not in g:

        db_path = current_app.config["DATABASE"]

        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        g.db = sqlite3.connect(db_path)

        g.db.row_factory = sqlite3.Row

    return g.db


# =========================================================
# CLOSE DATABASE
# =========================================================

def close_db(e=None):

    db = g.pop("db", None)

    if db is not None:
        db.close()


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def init_db():

    db = get_db()

    db.executescript(SCHEMA)

    db.commit()


# =========================================================
# REGISTER DATABASE WITH APP
# =========================================================

def init_app(app):

    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()