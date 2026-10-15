"""Dashboard users and roles. Tokens are stored only as SHA-256 hashes; the plain token is shown once."""

from __future__ import annotations

import hashlib
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


def can(role: str, permission: str) -> bool:
    return permission in GRANTS.get(role, frozenset())


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class User:
    name: str
    role: str
    source: str = "database"  # database | environment
    created_at: float | None = None
    created_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "source": self.source,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "permissions": sorted(GRANTS[self.role]),
        }


def validate(name: str, role: str) -> None:
    if not NAME_RE.match(name or ""):
        raise ValueError("user names are 1-64 letters, digits, '.', '_', '@' or '-'")
    if name.lower() in RESERVED_APPROVERS:
        raise ValueError(f"{name!r} is reserved")
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")


class UserStore(Sqlite):
    def __init__(self, db_path: Path) -> None:
        super().__init__(db_path)
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    name TEXT PRIMARY KEY,
                    role TEXT NOT NULL CHECK (role IN ('viewer','operator','approver','admin')),
                    token_sha256 TEXT NOT NULL UNIQUE,
                    created_at REAL NOT NULL,
                    created_by TEXT
                )"""
            )

    def add(self, name: str, role: str, created_by: str | None = None) -> str:
        validate(name, role)
        token = secrets.token_urlsafe(24)
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO users (name, role, token_sha256, created_at, created_by) VALUES (?,?,?,?,?)",
                    (name, role, token_hash(token), time.time(), created_by),
                )
        except sqlite3.IntegrityError:
            raise ValueError(f"user {name!r} already exists") from None
        return token

    def rotate(self, name: str) -> str:
        token = secrets.token_urlsafe(24)
        with self._conn() as c:
            if c.execute("UPDATE users SET token_sha256=? WHERE name=?", (token_hash(token), name)).rowcount != 1:
                raise LookupError(f"no user {name!r}")
        return token

    def set_role(self, name: str, role: str) -> None:
        validate(name, role)
        with self._conn() as c:
            if c.execute("UPDATE users SET role=? WHERE name=?", (role, name)).rowcount != 1:
                raise LookupError(f"no user {name!r}")

    def remove(self, name: str) -> None:
        with self._conn() as c:
            if c.execute("DELETE FROM users WHERE name=?", (name,)).rowcount != 1:
                raise LookupError(f"no user {name!r}")

    def list(self) -> list[User]:
        with self._conn(write=False) as c:
            rows = c.execute("SELECT name, role, created_at, created_by FROM users ORDER BY name").fetchall()
        return [User(r["name"], r["role"], "database", r["created_at"], r["created_by"]) for r in rows]

    def count_admins(self) -> int:
        with self._conn(write=False) as c:
            return int(c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0])

    def by_token(self, token: str) -> User | None:
        with self._conn(write=False) as c:
            r = c.execute(
                "SELECT name, role, created_at, created_by FROM users WHERE token_sha256=?", (token_hash(token),)
            ).fetchone()
        return User(r["name"], r["role"], "database", r["created_at"], r["created_by"]) if r else None


def env_users(tokens: dict[str, str]) -> dict[str, User]:
    """AEGISQ_API_TOKENS entries: name:token (admin) or name:token:role, keyed by token hash."""
    out: dict[str, User] = {}
    for token, ident in tokens.items():
        name, _, role = ident.partition(":")
        role = role or "admin"
        validate(name, role)
        out[token_hash(token)] = User(name, role, "environment")
    return out
