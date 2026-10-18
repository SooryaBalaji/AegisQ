"""Dashboard users, roles, passwords and sign-in sessions.

Passwords are stored only as scrypt hashes. A sign-in creates a random session id that the browser keeps in an
HttpOnly cookie; the server stores only its SHA-256, so a copy of the database cannot be used to sign in.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegisq.workspace import RESERVED_APPROVERS, Sqlite

ROLES = ("viewer", "operator", "approver", "admin")
GRANTS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"view"}),
    "operator": frozenset({"view", "run"}),
    "approver": frozenset({"view", "approve"}),
    "admin": frozenset({"view", "run", "approve", "admin"}),
}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
MIN_PASSWORD = 12
MAX_PASSWORD = 256
SESSION_IDLE_S = 12 * 3600
SESSION_MAX_S = 7 * 24 * 3600
_SCRYPT = {"n": 2**14, "r": 8, "p": 1}


def can(role: str, permission: str) -> bool:
    return permission in GRANTS.get(role, frozenset())


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${_b64(salt)}${_b64(dk)}"


def check_password(password: str, stored: str | None) -> bool:
    try:
        algo, n, r, p, salt, want = (stored or "").split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(
            password.encode("utf-8"), salt=base64.b64decode(salt), dklen=32, n=int(n), r=int(r), p=int(p)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, base64.b64decode(want))


_DUMMY = hash_password(secrets.token_urlsafe(16))  # verified against for unknown names, so timing reveals nothing


def validate_password(name: str, password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise ValueError(f"passwords need at least {MIN_PASSWORD} characters")
    if len(password) > MAX_PASSWORD:
        raise ValueError(f"passwords can be at most {MAX_PASSWORD} characters")
    if password.strip().lower() == name.lower():
        raise ValueError("the password cannot be the user name")


def validate(name: str, role: str) -> None:
    if not NAME_RE.match(name or ""):
        raise ValueError("user names are 1-64 letters, digits, '.', '_', '@' or '-'")
    if name.lower() in RESERVED_APPROVERS:
        raise ValueError(f"{name!r} is reserved")
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")


def _sid_hash(sid: str) -> str:
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()


@dataclass
class User:
    name: str
    role: str
    created_at: float | None = None
    created_by: str | None = None
    has_password: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "has_password": self.has_password,
            "permissions": sorted(GRANTS[self.role]),
        }


class UserStore(Sqlite):
    def __init__(self, db_path: Path) -> None:
        super().__init__(db_path)
        with self._conn() as c:
            cols = {r["name"] for r in c.execute("PRAGMA table_info(users)").fetchall()}
            if "token_sha256" in cols:  # upgrade from token sign-in: keep people and roles, drop tokens
                c.execute("ALTER TABLE users RENAME TO users_tokens_old")
                cols = set()
            if not cols:
                c.execute(
                    """CREATE TABLE users (
                        name TEXT PRIMARY KEY,
                        role TEXT NOT NULL CHECK (role IN ('viewer','operator','approver','admin')),
                        password_hash TEXT,
                        created_at REAL NOT NULL,
                        created_by TEXT,
                        password_changed_at REAL
                    )"""
                )
                if c.execute("SELECT name FROM sqlite_master WHERE name='users_tokens_old'").fetchone():
                    c.execute(
                        "INSERT INTO users (name, role, created_at, created_by) "
                        "SELECT name, role, created_at, created_by FROM users_tokens_old"
                    )
                    c.execute("DROP TABLE users_tokens_old")
            c.execute(
                """CREATE TABLE IF NOT EXISTS sessions (
                    sid_sha256 TEXT PRIMARY KEY,
                    name TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
                    created_at REAL NOT NULL,
                    seen_at REAL NOT NULL
                )"""
            )

    # ------------------------------------------------------------ users
    def _user(self, r: sqlite3.Row) -> User:
        return User(r["name"], r["role"], r["created_at"], r["created_by"], bool(r["password_hash"]))

    def add(self, name: str, role: str, password: str, created_by: str | None = None) -> User:
        validate(name, role)
        validate_password(name, password)
        now = time.time()
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO users (name, role, password_hash, created_at, created_by, password_changed_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (name, role, hash_password(password), now, created_by, now),
                )
        except sqlite3.IntegrityError:
            raise ValueError(f"user {name!r} already exists") from None
        return User(name, role, now, created_by)

    def set_password(self, name: str, password: str, keep_session: str | None = None) -> None:
        """New password; every session of this user ends except ``keep_session`` (the one changing it)."""
        validate_password(name, password)
        with self._conn() as c:
            n = c.execute(
                "UPDATE users SET password_hash=?, password_changed_at=? WHERE name=?",
                (hash_password(password), time.time(), name),
            ).rowcount
            if n != 1:
                raise LookupError(f"no user {name!r}")
            keep = _sid_hash(keep_session) if keep_session else ""
            c.execute("DELETE FROM sessions WHERE name=? AND sid_sha256<>?", (name, keep))

    def set_role(self, name: str, role: str) -> None:
        validate(name, role)
        with self._conn() as c:
            if c.execute("UPDATE users SET role=? WHERE name=?", (role, name)).rowcount != 1:
                raise LookupError(f"no user {name!r}")

    def remove(self, name: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE name=?", (name,))
            if c.execute("DELETE FROM users WHERE name=?", (name,)).rowcount != 1:
                raise LookupError(f"no user {name!r}")

    def get(self, name: str) -> User | None:
        with self._conn(write=False) as c:
            r = c.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
        return self._user(r) if r else None

    def all(self) -> list[User]:
        with self._conn(write=False) as c:
            return [self._user(r) for r in c.execute("SELECT * FROM users ORDER BY name").fetchall()]

    def count(self) -> int:
        with self._conn(write=False) as c:
            return int(c.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def count_admins(self) -> int:
        with self._conn(write=False) as c:
            return int(c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0])

    def verify(self, name: str, password: str) -> User | None:
        """The user, if the password is right. Takes the same time whether or not the name exists."""
        with self._conn(write=False) as c:
            r = c.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone() if NAME_RE.match(name) else None
        ok = check_password(password[:MAX_PASSWORD], r["password_hash"] if r and r["password_hash"] else _DUMMY)
        return self._user(r) if r and r["password_hash"] and ok else None

    # --------------------------------------------------------- sessions
    def start_session(self, name: str) -> str:
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self._conn() as c:
            c.execute(
                "DELETE FROM sessions WHERE seen_at < ? OR created_at < ?", (now - SESSION_IDLE_S, now - SESSION_MAX_S)
            )
            c.execute("INSERT INTO sessions VALUES (?,?,?,?)", (_sid_hash(sid), name, now, now))
        return sid

    def session_user(self, sid: str, now: float | None = None) -> User | None:
        if not sid or len(sid) > 128:
            return None
        now = now or time.time()
        key = _sid_hash(sid)
        with self._conn(write=False) as c:
            r = c.execute(
                "SELECT s.created_at AS s_created, s.seen_at, u.* FROM sessions s JOIN users u ON u.name = s.name "
                "WHERE s.sid_sha256=?",
                (key,),
            ).fetchone()
        if r is None:
            return None
        if now - r["seen_at"] > SESSION_IDLE_S or now - r["s_created"] > SESSION_MAX_S:
            self.end_session(sid)
            return None
        if now - r["seen_at"] > 60:
            with self._conn() as c:
                c.execute("UPDATE sessions SET seen_at=? WHERE sid_sha256=?", (now, key))
        return self._user(r)

    def end_session(self, sid: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE sid_sha256=?", (_sid_hash(sid),))
