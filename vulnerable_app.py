"""
vulnerable_app.py

A small Flask-based user management app, written for a Secure Code Review
exercise (CodeAlpha Cyber Security Internship, Task 3).

WARNING: This file contains INTENTIONAL security vulnerabilities, planted
on purpose for review/teaching purposes. Do NOT deploy this code anywhere,
and do NOT use these patterns in real projects. See review_notes.md for
the full breakdown of each issue, and secure_version.py for the fixed
version.
"""

import sqlite3
import hashlib
import os
import pickle
import subprocess

from flask import Flask, request, render_template_string

app = Flask(__name__)

# --- VULNERABILITY 1: Hardcoded secrets ------------------------------------
# Credentials and API keys should never be hardcoded in source code.
ADMIN_PASSWORD = "SuperSecret123"
API_KEY = "sk_live_51H8xJ2eZvKYlo2C0FAKEKEYFORDEMO"

DB_PATH = "users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)"
    )
    return conn


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # --- VULNERABILITY 2: Weak password hashing ----------------------------
    # MD5 is cryptographically broken and far too fast, making it easy to
    # brute-force. Passwords should never be hashed this way.
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    conn.execute(
        f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed}')"
    )
    # --- VULNERABILITY 3: SQL Injection -------------------------------------
    # User input is inserted directly into the SQL string above via an
    # f-string, instead of using parameterized queries. An attacker could
    # submit a username like:  ', 'x'); DROP TABLE users; --
    conn.commit()
    conn.close()
    return "User registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    # --- VULNERABILITY 3 (again): SQL Injection in the login query ---------
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        return "Login successful"
    return "Login failed"


@app.route("/profile")
def profile():
    name = request.args.get("name", "World")
    # --- VULNERABILITY 4: Cross-Site Scripting (XSS) ------------------------
    # User input is rendered directly into an HTML template without
    # escaping, so a name like <script>alert(1)</script> would execute.
    template = f"<h1>Welcome, {name}!</h1>"
    return render_template_string(template)


@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host", "")
    # --- VULNERABILITY 5: Command Injection ---------------------------------
    # User input is passed straight into a shell command. A value like
    # "127.0.0.1; rm -rf /" would be executed as a second shell command.
    result = os.popen(f"ping -c 1 {host}").read()
    return f"<pre>{result}</pre>"


@app.route("/load_session", methods=["POST"])
def load_session():
    # --- VULNERABILITY 6: Insecure Deserialization --------------------------
    # pickle.loads() on untrusted input can execute arbitrary code during
    # deserialization. Never unpickle data from a source you don't control.
    data = request.data
    session_obj = pickle.loads(data)
    return f"Session loaded for: {session_obj}"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # --- VULNERABILITY 7: Path Traversal -------------------------------------
    # No validation on the filename means a value like "../../etc/passwd"
    # could read files far outside the intended directory.
    with open(filename, "r") as f:
        return f.read()


@app.route("/admin/backup", methods=["POST"])
def backup():
    # --- VULNERABILITY 8: Missing authentication / broken access control ----
    # There is no check that the caller is actually an admin before running
    # a sensitive operation.
    subprocess.run(["cp", DB_PATH, "backup_users.db"])
    return "Backup complete"


if __name__ == "__main__":
    # --- VULNERABILITY 9: Debug mode enabled --------------------------------
    # Flask's debug mode exposes an interactive debugger and stack traces
    # to anyone who can reach the server — never enable this in production.
    app.run(debug=True, host="0.0.0.0")