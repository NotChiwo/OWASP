"""
SecureNotes API  —  Week 13 Security Lab (FIXED VERSION)
Web Systems and Technologies

Same app, same behaviour (register / login / notes), minus the 6 planted
OWASP Top 10 (2025) bugs. See FINDINGS.md for what each bug was and why
it mattered. Comments below are tagged with the risk code they fix.

Run it:
    uvicorn app.main:app --reload
Open the interactive docs at:
    http://127.0.0.1:8000/docs
"""

import os
import sqlite3
import hmac
import hashlib
import secrets
import time
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- app + config ------------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

# [A02 fix] Secret comes from an environment variable, never hardcoded/committed.
# Falls back to a random one-off secret so the app still runs out of the box
# in the lab (tokens just won't survive a server restart).
SECRET_KEY = os.environ.get("SECURENOTES_SECRET") or secrets.token_hex(32)

# [A07 fix] Tokens expire instead of living forever.
TOKEN_TTL_SECONDS = 60 * 60  # 1 hour

# [A02 fix] CORS locked to real origins instead of "*" (which, combined with
# allow_credentials=True, would let ANY website read authenticated responses).
ALLOWED_ORIGINS = os.environ.get(
    "SECURENOTES_ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# --- database (SQLite, created fresh on startup) ------------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


# [A04 fix] Salted PBKDF2 password hashing — never store or compare plaintext.
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    test_digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    # Constant-time comparison so response timing can't leak how close a guess was.
    return hmac.compare_digest(test_digest, digest)


def init_db():
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    # seed: one admin, two normal users, a few notes — passwords hashed, not plain.
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
        ("admin", hash_password("admin123")),
    )
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
        ("alice", hash_password("alicepass")),
    )
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
        ("bob", hash_password("bobpass")),
    )
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2,'Alice diary','Alice secret note')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3,'Bob plans','Bob secret note')")
    db.commit()


init_db()


# --- request models ------------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- tokens: signed + expiring (replaces "the user's id as a string") ----------
# [A07 fix]
def make_token(user_id: int) -> str:
    expiry = int(time.time()) + TOKEN_TTL_SECONDS
    payload = f"{user_id}:{expiry}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def read_token(token: str):
    """Return the user id if the token is well-formed, correctly signed, and unexpired."""
    try:
        user_id_str, expiry_str, sig = token.split(":")
        payload = f"{user_id_str}:{expiry_str}"
        expected_sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, sig):
            return None
        if int(expiry_str) < time.time():
            return None
        return int(user_id_str)
    except (ValueError, AttributeError):
        return None


# --- auth helper -----------------------------------------------------------
# [A10 fix] Fails CLOSED: any missing/bad/expired token is rejected (401) here,
# instead of letting a broken check silently fall through and continue.
def current_user(authorization: str = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization[len("Bearer "):]
    user_id = read_token(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return row


# --- error handling --------------------------------------------------------
# [A02 fix] No more leaking exception text or a full stack trace to the client.
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    # In a real deployment, log `exc` server-side here (e.g. logging.exception(exc)).
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# --- routes ----------------------------------------------------------------
@app.post("/register")
def register(creds: Credentials):
    try:
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (creds.username, hash_password(creds.password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already taken")
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    # [A05 fix] Parameterized query — the username can never break out of the
    # SQL string, no matter what characters it contains.
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?", (creds.username,)
    ).fetchone()
    # [A07 fix] One generic error for "no such user" AND "wrong password", so
    # an attacker can't use the API to enumerate which usernames exist.
    if row is None or not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"token": make_token(row["id"])}


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = current_user(authorization)
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = current_user(authorization)
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    # [A01 fix] Confirm the note actually belongs to the caller before
    # returning it — not just that a note with this id exists somewhere.
    if row is None or row["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, authorization: str = Header(default=None)):
    user = current_user(authorization)
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = current_user(authorization)
    # [A10 fix] No try/except-and-ignore here — if this check can't prove the
    # caller is an admin, the request is denied. Fail closed, not open.
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    # Bonus hardening (not one of the 6 graded bugs, but good practice):
    # don't hand back password hashes just because an endpoint lists users.
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
