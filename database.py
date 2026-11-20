"""Database models and persistence layer."""

import sqlite3
import threading
import time

import bcrypt

BCRYPT_ROUNDS = 12
# Used when a username does not exist, so a failed login takes the same time
# either way and does not reveal which usernames are registered.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(4))

DEFAULT_SETTINGS = {
    "registration_open": "1",
    "max_failed_logins": "5",
    "lockout_seconds": "60",
}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)).decode("ascii")


def check_password(password: str, pw_hash: str | None) -> bool:
    target = pw_hash.encode("ascii") if pw_hash else _DUMMY_HASH
    ok = bcrypt.checkpw(password.encode("utf-8"), target)
    return ok and pw_hash is not None


class UserDB:
    def __init__(self, path: str):
        self._lock = threading.Lock()   # one writer at a time across client threads
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            c = self._conn
            c.execute("PRAGMA foreign_keys = ON")
            c.execute("""CREATE TABLE IF NOT EXISTS users (
                username   TEXT PRIMARY KEY COLLATE NOCASE,
                pw_hash    TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created    REAL NOT NULL)""")
            cols = {r["name"] for r in c.execute("PRAGMA table_info(users)")}
            if "last_login" not in cols:   # upgrade databases from the first version
                c.execute("ALTER TABLE users ADD COLUMN last_login REAL")
            if "banned" not in cols:
                c.execute("ALTER TABLE users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0")
            c.execute("""CREATE TABLE IF NOT EXISTS admins (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                pw_hash  TEXT NOT NULL,
                created  REAL NOT NULL)""")
            c.execute("""CREATE TABLE IF NOT EXISTS friends (
                requester TEXT NOT NULL COLLATE NOCASE,
                addressee TEXT NOT NULL COLLATE NOCASE,
                status    TEXT NOT NULL CHECK (status IN ('pending', 'accepted')),
                created   REAL NOT NULL,
                PRIMARY KEY (requester, addressee))""")
            c.execute("""CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, kind TEXT NOT NULL,
                username TEXT, ip TEXT, details TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, admin TEXT NOT NULL,
                action TEXT NOT NULL, target TEXT, details TEXT)""")
            c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            for k, v in DEFAULT_SETTINGS.items():
                c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    def _write(self, sql, args=()):
        with self._lock, self._conn:
            return self._conn.execute(sql, args)

    def _all(self, sql, args=()):
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    def _one(self, sql, args=()):
        with self._lock:
            row = self._conn.execute(sql, args).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------ users

    def add_user(self, username: str, password: str, public_key: str) -> bool:
        """Return False if the username is already taken (by a user or an admin)."""
        if self.get_admin(username):
            return False
        pw_hash = hash_password(password)
        try:
            self._write("INSERT INTO users (username, pw_hash, public_key, created) VALUES (?, ?, ?, ?)",
                        (username, pw_hash, public_key, time.time()))
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username: str) -> dict | None:
        return self._one("SELECT * FROM users WHERE username = ?", (username,))

    def list_users(self) -> list[dict]:
        return self._all("SELECT username, public_key, created, last_login, banned FROM users "
                         "ORDER BY username COLLATE NOCASE")

    def touch_login(self, username: str) -> None:
        self._write("UPDATE users SET last_login = ? WHERE username = ?", (time.time(), username))

    def set_password(self, username: str, password: str) -> None:
        self._write("UPDATE users SET pw_hash = ? WHERE username = ?", (hash_password(password), username))

    def set_banned(self, username: str, banned: bool) -> bool:
        return self._write("UPDATE users SET banned = ? WHERE username = ?",
                           (1 if banned else 0, username)).rowcount == 1

    def delete_user(self, username: str) -> bool:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM friends WHERE requester = ? OR addressee = ?", (username, username))
            return self._conn.execute("DELETE FROM users WHERE username = ?", (username,)).rowcount == 1

    def count_users(self) -> int:
        return self._one("SELECT COUNT(*) AS n FROM users")["n"]

    # ------------------------------------------------------------------ admins

    def add_admin(self, username: str, password: str) -> bool:
        if self.get_user(username):
            return False
        try:
            self._write("INSERT INTO admins (username, pw_hash, created) VALUES (?, ?, ?)",
                        (username, hash_password(password), time.time()))
            return True
        except sqlite3.IntegrityError:
            return False

    def get_admin(self, username: str) -> dict | None:
        return self._one("SELECT * FROM admins WHERE username = ?", (username,))

    # ------------------------------------------------------------------ friends

    def friend_status(self, a: str, b: str) -> dict | None:
        """The friendship row between a and b in either direction, or None."""
        return self._one("SELECT * FROM friends WHERE (requester = ? AND addressee = ?) "
                         "OR (requester = ? AND addressee = ?)", (a, b, b, a))

    def add_friend_request(self, requester: str, addressee: str) -> None:
        self._write("INSERT INTO friends (requester, addressee, status, created) VALUES (?, ?, 'pending', ?)",
                    (requester, addressee, time.time()))

    def accept_friend(self, requester: str, addressee: str) -> bool:
        return self._write("UPDATE friends SET status = 'accepted' WHERE requester = ? AND addressee = ? "
                           "AND status = 'pending'", (requester, addressee)).rowcount == 1

    def remove_friend(self, a: str, b: str) -> bool:
        return self._write("DELETE FROM friends WHERE (requester = ? AND addressee = ?) "
                           "OR (requester = ? AND addressee = ?)", (a, b, b, a)).rowcount > 0

    def are_friends(self, a: str, b: str) -> bool:
        row = self.friend_status(a, b)
        return bool(row and row["status"] == "accepted")

    def friend_lists(self, username: str) -> dict:
        """{'friends': [names], 'incoming': [names], 'outgoing': [names]}"""
        rows = self._all("SELECT * FROM friends WHERE requester = ? OR addressee = ?", (username, username))
        out = {"friends": [], "incoming": [], "outgoing": []}
        me = username.lower()
        for r in rows:
            other = r["addressee"] if r["requester"].lower() == me else r["requester"]
            if r["status"] == "accepted":
                out["friends"].append(other)
            elif r["requester"].lower() == me:
                out["outgoing"].append(other)
            else:
                out["incoming"].append(other)
        return out

    def count_friendships(self) -> int:
        return self._one("SELECT COUNT(*) AS n FROM friends WHERE status = 'accepted'")["n"]

    # ------------------------------------------------------------------ events / audit / settings

    def log_event(self, kind: str, username: str | None = None, ip: str | None = None, details: str = "") -> None:
        self._write("INSERT INTO security_events (ts, kind, username, ip, details) VALUES (?, ?, ?, ?, ?)",
                    (time.time(), kind, username, ip, details))

    def recent_events(self, limit: int = 100, username: str | None = None) -> list[dict]:
        if username:
            return self._all("SELECT * FROM security_events WHERE username = ? ORDER BY id DESC LIMIT ?",
                             (username, limit))
        return self._all("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))

    def audit(self, admin: str, action: str, target: str | None = None, details: str = "") -> None:
        self._write("INSERT INTO audit_log (ts, admin, action, target, details) VALUES (?, ?, ?, ?, ?)",
                    (time.time(), admin, action, target, details))

    def audit_log(self, limit: int = 100) -> list[dict]:
        return self._all("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

    def get_settings(self) -> dict:
        return {r["key"]: r["value"] for r in self._all("SELECT key, value FROM settings")}

    def set_setting(self, key: str, value: str) -> None:
        if key not in DEFAULT_SETTINGS:
            raise KeyError(key)
        self._write("UPDATE settings SET value = ? WHERE key = ?", (value, key))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
