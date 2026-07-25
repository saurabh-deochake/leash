"""
Sandbox environment for real-LLM LEASH experiments.

Creates a temporary directory with:
    - A sample Python codebase with intentional vulnerabilities
    - A SQLite database with sample data
    - Cleanup on context manager exit
"""

import os
import sys
import tempfile
import shutil
import sqlite3
from pathlib import Path


# ---------------------------------------------------------------------------
# Sample codebase files — intentionally flawed for agent analysis tasks
# ---------------------------------------------------------------------------

SAMPLE_FILES = {
    "app.py": '''\
"""Flask web application with intentional security issues for agent analysis."""
from flask import Flask, request, jsonify, render_template_string
import sqlite3
import os
import subprocess

app = Flask(__name__)
DATABASE = "app.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/users")
def list_users():
    db = get_db()
    # BUG: SQL injection via unsanitized query parameter
    role = request.args.get("role", "")
    query = f"SELECT * FROM users WHERE role = '{role}'"
    users = db.execute(query).fetchall()
    return jsonify([dict(u) for u in users])

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # BUG: Reflected XSS — user input rendered without escaping
    template = f"<h1>Results for: {q}</h1><p>No results found.</p>"
    return render_template_string(template)

@app.route("/run", methods=["POST"])
def run_command():
    cmd = request.json.get("cmd", "")
    # BUG: Command injection — unsanitized shell execution
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify({"stdout": result.stdout, "stderr": result.stderr})

@app.route("/config")
def show_config():
    # BUG: Hardcoded secret exposed via endpoint
    return jsonify({
        "db": DATABASE,
        "secret_key": "supersecret123",
        "debug": True,
        "api_key": os.environ.get("API_KEY", "default-key-12345"),
    })

@app.route("/upload", methods=["POST"])
def upload_file():
    f = request.files.get("file")
    if f:
        # BUG: Path traversal — no filename sanitization
        save_path = os.path.join("/tmp/uploads", f.filename)
        f.save(save_path)
        return jsonify({"saved": save_path})
    return jsonify({"error": "No file"}), 400

if __name__ == "__main__":
    app.run(debug=True)
''',

    "models.py": '''\
"""Database models and helpers."""
import sqlite3
import hashlib

DATABASE = "app.db"

def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            email TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            timestamp REAL,
            user_id INTEGER,
            action TEXT,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    # BUG: Using MD5 for password hashing (insecure)
    return hashlib.md5(password.encode()).hexdigest()

def create_user(username: str, password: str, role: str = "user") -> int:
    conn = sqlite3.connect(DATABASE)
    pw_hash = hash_password(password)
    cursor = conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, pw_hash, role),
    )
    conn.commit()
    uid = cursor.lastrowid
    conn.close()
    return uid

def authenticate(username: str, password: str) -> bool:
    conn = sqlite3.connect(DATABASE)
    pw_hash = hash_password(password)
    # BUG: Timing side-channel — string comparison is not constant-time
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row is None:
        return False
    return row[0] == pw_hash
''',

    "utils.py": '''\
"""Utility functions."""
import logging
import json
import os

logger = logging.getLogger(__name__)

def load_config(path: str) -> dict:
    """Load configuration from a JSON file."""
    with open(path, "r") as f:
        return json.load(f)

def ensure_directory(path: str) -> None:
    """Create directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)

def sanitize_input(value: str) -> str:
    """Basic input sanitization (incomplete)."""
    # BUG: Incomplete sanitization — only strips angle brackets
    return value.replace("<", "").replace(">", "")

def format_response(data: dict, status: str = "ok") -> dict:
    """Standard API response wrapper."""
    return {"status": status, "data": data}
''',

    "config.json": '''\
{
    "app_name": "VulnApp",
    "version": "1.2.3",
    "database": "app.db",
    "log_level": "DEBUG",
    "allowed_origins": ["*"],
    "rate_limit": 0,
    "session_timeout": 86400,
    "password_min_length": 4
}
''',

    "requirements.txt": """\
flask==2.3.0
sqlite3
requests
""",
}


# ---------------------------------------------------------------------------
# Sample database
# ---------------------------------------------------------------------------

def _populate_db(db_path: str) -> None:
    """Create and populate the sample SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            email TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            timestamp REAL,
            user_id INTEGER,
            action TEXT,
            details TEXT
        )
    """)
    sample_users = [
        ("alice", "5f4dcc3b5aa765d61d8327deb882cf99", "admin", "alice@example.com"),
        ("bob", "482c811da5d5b4bc6d497ffa98491e38", "user", "bob@example.com"),
        ("charlie", "900150983cd24fb0d6963f7d28e17f72", "user", "charlie@test.com"),
        ("admin", "21232f297a57a5a743894a0e4a801fc3", "admin", "admin@example.com"),
        ("eve", "d8578edf8458ce06fbc5bb76a58c5ca4", "user", "eve@malicious.com"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
        sample_users,
    )
    sample_logs = [
        (1609459200.0, 1, "login", "Successful login from 10.0.0.1"),
        (1609459260.0, 4, "config_change", "Changed debug=True"),
        (1609459320.0, 5, "login_failed", "Failed login attempt from 192.168.1.100"),
        (1609459380.0, 1, "data_export", "Exported users table"),
    ]
    conn.executemany(
        "INSERT INTO audit_log (timestamp, user_id, action, details) VALUES (?, ?, ?, ?)",
        sample_logs,
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Sandbox context manager
# ---------------------------------------------------------------------------

class Sandbox:
    """
    Creates and manages a temporary sandbox environment.

    Usage::

        with Sandbox() as sb:
            print(sb.root)       # /tmp/leash_sandbox_xxxxx
            print(sb.db_path)    # /tmp/leash_sandbox_xxxxx/app.db
            # ... run experiment ...
        # sandbox directory is deleted on exit
    """

    def __init__(self, keep: bool = False):
        self.keep = keep
        self.root: str = ""
        self.db_path: str = ""

    # -- context manager ----------------------------------------------------

    def __enter__(self) -> "Sandbox":
        self.root = tempfile.mkdtemp(prefix="leash_sandbox_")
        # Write sample codebase
        for filename, content in SAMPLE_FILES.items():
            path = os.path.join(self.root, filename)
            with open(path, "w") as f:
                f.write(content)
        # Populate database
        self.db_path = os.path.join(self.root, "app.db")
        _populate_db(self.db_path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.keep and os.path.isdir(self.root):
            shutil.rmtree(self.root, ignore_errors=True)
        return False

    # -- helpers ------------------------------------------------------------

    def list_files(self) -> list[str]:
        """List all files in the sandbox."""
        return sorted(os.listdir(self.root))

    def file_path(self, name: str) -> str:
        """Return absolute path to a sandbox file."""
        return os.path.join(self.root, name)
