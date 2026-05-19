DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS scan_results;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);

CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    scan_name TEXT,
    target TEXT NOT NULL,
    resolved_ip TEXT NOT NULL,
    port_range TEXT NOT NULL,
    total_open_ports INTEGER DEFAULT 0,
    is_favorite INTEGER DEFAULT 0,
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL,
    service TEXT,
    version TEXT,
    protocol TEXT,
    response_time TEXT,
    risk TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);