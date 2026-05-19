import sqlite3
from pathlib import Path

# Create instance folder if not exists
Path("instance").mkdir(exist_ok=True)

# Connect DB
conn = sqlite3.connect("instance/scanner.db")

# Load schema
with open("schema.sql", "r") as f:
    conn.executescript(f.read())

conn.commit()
conn.close()

print("Database initialized successfully.")