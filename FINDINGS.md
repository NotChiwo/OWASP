# Vulnerability Findings — Vincent & Partner

There are **6** security bugs planted in `app/main.py`.

| # | OWASP 2025 code & name | Where (route / line) | How an attacker abuses it | Your fix (1 line) |
|---|------------------------|----------------------|---------------------------|-------------------|
| 1 | A03:2025 Injection | `POST /login` | The username is interpolated directly into SQL, so an attacker can inject `' OR '1'='1`-style payloads and bypass authentication or read arbitrary rows. | Use parameterized SQL and verify the password with a safe hash check. |
| 2 | A02:2025 Cryptographic Failures | `init_db()` + `POST /register` + `POST /login` | Passwords are stored and compared in plaintext, so a leaked database exposes every account immediately. | Store PBKDF2-HMAC hashes and compare them with a constant-time check. |
| 3 | A07:2025 Identification and Authentication Failures | `current_user()` and the auth token flow | The app treats the user ID itself as the bearer token, making it guessable and easy to forge. | Sign each session token with HMAC and validate it before looking up the user. |
| 4 | A01:2025 Broken Access Control | `GET /notes/{note_id}` | The route loads a note by ID without checking whether it belongs to the logged-in user, enabling IDOR. | Only return a note if `row["owner_id"] == user["id"]`. |
| 5 | A01:2025 Broken Access Control | `GET /admin/users` | The guard is wrapped in `try/except: pass`, so non-admin users still receive all users because the exception suppresses the block. | Fail closed and reject non-admin requests with a 403. |
| 6 | A05:2025 Security Misconfiguration | `CORSMiddleware` + `handle_everything` | Wildcard CORS allows any browser origin, and the generic exception handler leaks stack traces and internal details to clients. | Restrict allowed origins and return a safe generic 500 response without the traceback. |

## Reflection (3–4 sentences)
The most damaging bug is the IDOR in `GET /notes/{note_id}` because it breaks user isolation and allows any logged-in user to read another user's private data. In a real app, that could expose secrets, financial records, or workplace information without needing to compromise an admin account. It also amplifies the impact of a lower-level bug like weak passwords or poor session handling, because stolen or guessable credentials can immediately lead to data exposure. This is especially dangerous because the app appears harmless, so users may trust it and not realize notes are not protected by ownership checks.
