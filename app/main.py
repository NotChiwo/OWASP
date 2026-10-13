"""
SecureNotes API  —  Week 13 Security Lab (STUDENT VERSION)
Web Systems and Technologies

A tiny notes service: users register, log in, and keep private notes.
It works... but it is NOT secure. Somewhere in this file are SECURITY BUGS
that map to the OWASP Top 10 (2025). Your job is to find them and fix them.

Run it:
    uvicorn app.main:app --reload
Open the interactive docs at:
    http://127.0.0.1:8000/docs

Do NOT change the behaviour students rely on (register, login, notes still work).
Only make it secure. See the lab handout for the task list and rubric.
"""

import hashlib
import hmac
import logging
import secrets
import sqlite3
import time
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

# A secret used to sign things. Keep it safe.
SECRET_KEY = "supersecret123"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- database (SQLite, created fresh on startup) ---------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$")
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    salt = bytes.fromhex(salt_hex)
    expected = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
    return hmac.compare_digest(expected.hex(), digest_hex)


def create_token(user_id: int) -> str:
    payload = f"{user_id}:{int(time.time())}:{secrets.token_hex(16)}"
    signature = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def decode_token(token: str):
    if not token:
        return None
    try:
        payload, signature = token.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        user_id, _, _ = payload.split(":", 2)
        return int(user_id)
    except (TypeError, ValueError):
        return None


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
    # seed: one admin, two normal users, a few notes
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


# --- request models --------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- auth helper -----------------------------------------------------------
def current_user(authorization: str = Header(default=None)):
    """Read the token from the Authorization header and return the user row."""
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    user_id = decode_token(token)
    if user_id is None:
        return None
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def require_user(authorization: str = Header(default=None)):
    user = current_user(authorization)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    logging.exception("Unhandled app error")
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
        raise HTTPException(status_code=409, detail="Username already exists")
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?",
        (creds.username,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No account with that username")
    if not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Wrong password")
    return {"token": create_token(row["id"]) }


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = require_user(authorization)
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = require_user(authorization)
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None or row["owner_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, authorization: str = Header(default=None)):
    user = require_user(authorization)
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = require_user(authorization)
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    rows = db.execute("SELECT * FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
