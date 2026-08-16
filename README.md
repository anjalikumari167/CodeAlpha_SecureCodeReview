# CodeAlpha_SecureCodeReview
## Secure Coding Review — Sample App Audit

A hands-on secure code review exercise built for the **CodeAlpha Cyber Security Internship (Task 3)**. This project audits a small Python/Flask application, documents the vulnerabilities found using both automated and manual review methods, and delivers a fully remediated version.

## Project structure
```
CodeAlpha_SecureCodeReview/
├── vulnerable_app.py          # Sample app with 9 intentionally planted vulnerabilities
├── secure_version.py          # Fully remediated version of the same app
├── bandit_report.txt          # Automated scan results — BEFORE fixes
├── bandit_report_secure.txt   # Automated scan results — AFTER fixes
├── review_notes.md            # Manual, line-by-line vulnerability writeup
├── requirements.txt
└── README.md
```

## What was done
1. **Built a deliberately vulnerable Flask app** (`vulnerable_app.py`) containing 9 realistic, well-known vulnerability classes — the kind that show up repeatedly in real-world security incidents.
2. **Ran an automated static analysis scan** using [Bandit](https://bandit.readthedocs.io/), a Python-specific security linter, producing `bandit_report.txt`.
3. **Performed a manual code review**, going beyond what the automated tool caught — explaining *impact*, not just detection, and identifying issues like missing access control that pattern-matching tools can miss. Documented in `review_notes.md`.
4. **Rewrote the app with every issue fixed**, producing `secure_version.py`, with inline comments tying each fix back to the vulnerability it addresses.
5. **Re-ran Bandit against the fixed version** to verify the fixes actually worked (`bandit_report_secure.txt`) — a before/after comparison, not just a claim.

## Results: before vs. after

| Severity | Before (vulnerable_app.py) | After (secure_version.py) |
|---|---|---|
| High | 4 | 0 |
| Medium | 4 | 0 |
| Low | 5 | 5 (generic subprocess-usage cautions, not real issues) |

All Critical and High severity findings were eliminated. The remaining Low findings are Bandit's standard advisory notices about `subprocess` usage in general — flagged on every subprocess call regardless of how safely it's used — and are documented rather than hidden, in the interest of an honest audit.

## Vulnerabilities covered

1. Hardcoded Secrets
2. Weak Password Hashing (MD5)
3. SQL Injection
4. Cross-Site Scripting (XSS)
5. Command Injection
6. Insecure Deserialization (pickle)
7. Path Traversal
8. Broken Access Control
9. Debug Mode Enabled in Production

Full explanations, exploit scenarios, and fixes for each are in [`review_notes.md`](./review_notes.md).

## Tools used

- **Python 3** / **Flask** — the sample application framework
- **Bandit** — automated static analysis for Python security issues
- **Manual line-by-line review** — for impact analysis and catching logic-level issues (like missing auth checks) that automated tools can't reason about

## Running the apps locally

```bash
pip install -r requirements.txt

# Vulnerable version (for educational reference only — do not deploy):
python vulnerable_app.py

# Secure, remediated version:
python secure_version.py
```

**Important:** `vulnerable_app.py` is intentionally insecure and exists purely for this teaching exercise. It should never be deployed or exposed to a network. Run it locally only, if at all.

## Disclaimer

This repository is an educational exercise demonstrating secure code review methodology. All vulnerabilities were deliberately introduced for the purpose of this internship task — none are present in, or reflect issues in, any real production system.

---
*Built as part of the CodeAlpha Cyber Security Internship.*
