"""
secure_version.py

A remediated version of vulnerable_app.py, fixing every issue identified in
review_notes.md and bandit_report.txt. Each fix is commented with a
reference back to the corresponding vulnerability number from the review.

CodeAlpha Cyber Security Internship — Task 3: Secure Coding Review.
"""

import os
import sqlite3
import ipaddress
import subprocess
from functools import wraps

from flask import Flask, request, render_template_string, abort
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- FIX 1: Secrets loaded from environment variables, not hardcoded ------
# Set these in your environment before running, e.g.:
#   export ADMIN_TOKEN="choose-a-strong-random-value"
#   export API_KEY="your-real-key-here"
# Never commit real values for these to source control.
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")
API_KEY = os.environ.get("API_KEY")

DB_PATH = "users.db"

# --- FIX 7: Downloads are restricted to one safe, known directory ---------
SAFE_DOWNLOAD_DIR = os.path.realpath("safe_files")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)"
    )
    return conn


def require_admin(view_func):
    """
    FIX 8: Simple auth decorator enforcing that sensitive endpoints require
    a valid admin token before executing. In a real production app this
    would check a proper session/JWT rather than a static token, but this
    demonstrates the core fix: sensitive actions must check who is calling.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get("X-Admin-Token")
        if not ADMIN_TOKEN or supplied != ADMIN_TOKEN:
            abort(403, description="Admin authentication required.")
        return view_func(*args, **kwargs)
    return wrapper


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return "Username and password are required", 400

    # --- FIX 2: Proper password hashing (PBKDF2 via werkzeug.security) ----
    # This is salted and deliberately slow, unlike MD5.
    hashed = generate_password_hash(password)

    conn = get_db()
    try:
        # --- FIX 3: Parameterized query, no string concatenation ----------
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return "Username already exists", 409
    finally:
        conn.close()

    return "User registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    conn = get_db()
    # --- FIX 3 (again): Parameterized query for login lookup --------------
    cursor = conn.execute(
        "SELECT password FROM users WHERE username = ?", (username,)
    )
    row = cursor.fetchone()
    conn.close()

    # --- FIX 2 (again): Verify using the hash comparison function ---------
    if row and check_password_hash(row[0], password):
        return "Login successful"
    return "Login failed", 401


@app.route("/profile")
def profile():
    name = request.args.get("name", "World")
    # --- FIX 4: Escape user input before inserting into HTML --------------
    # markupsafe.escape() converts special characters (<, >, &, etc.) into
    # safe HTML entities, preventing injected scripts from executing.
    safe_name = escape(name)
    template = f"<h1>Welcome, {safe_name}!</h1>"
    return render_template_string(template)


@app.route("/ping", methods=["POST"])
def ping():
    host = request.form.get("host", "").strip()

    # --- FIX 5: Strictly validate input as a real IP address before use ---
    # This closes the command injection hole: only a syntactically valid
    # IPv4/IPv6 address can ever reach the subprocess call below.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "Invalid IP address", 400

    # subprocess.run with a list of arguments (not a shell string) means
    # there is no shell interpreting the input, so no command chaining
    # (e.g. "; rm -rf /") is possible.
    result = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True, timeout=5
    )
    return f"<pre>{escape(result.stdout)}</pre>"


@app.route("/load_session", methods=["POST"])
def load_session():
    # --- FIX 6: Use JSON instead of pickle for deserialization ------------
    # JSON is data-only and cannot execute code during parsing, unlike
    # pickle, which was a direct remote-code-execution vector.
    try:
        session_obj = request.get_json(force=True)
    except Exception:
        return "Invalid session data", 400
    return f"Session loaded for: {escape(str(session_obj))}"


@app.route("/download")
def download():
    filename = request.args.get("file", "")

    # --- FIX 7 (again): Resolve the real path and confirm it's still ------
    # inside the one safe directory we allow downloads from. This blocks
    # "../" traversal sequences regardless of how they're encoded.
    requested_path = os.path.realpath(os.path.join(SAFE_DOWNLOAD_DIR, filename))
    if not requested_path.startswith(SAFE_DOWNLOAD_DIR + os.sep):
        abort(400, description="Invalid file path")

    if not os.path.isfile(requested_path):
        abort(404)

    with open(requested_path, "r") as f:
        return f.read()


@app.route("/admin/backup", methods=["POST"])
@require_admin
def backup():
    # --- FIX 8 (again): This endpoint is now wrapped in @require_admin, ---
    # so only requests carrying a valid admin token can trigger it.
    subprocess.run(["cp", DB_PATH, "backup_users.db"])
    return "Backup complete"


if __name__ == "__main__":
    # --- FIX 9: Debug mode disabled, bound to localhost only --------------
    # For real deployment, use a production WSGI server (e.g. Gunicorn)
    # instead of Flask's built-in development server entirely.
    app.run(debug=False, host="127.0.0.1")