"""Username and password rules. Checked on the client for fast feedback AND on the
server, because a modified client could skip its own checks."""

import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_BYTES = 72   # bcrypt only uses the first 72 bytes; reject longer instead of truncating


def check_username(username: str) -> str | None:
    """Return an error message, or None if the username is valid."""
    if not USERNAME_RE.fullmatch(username or ""):
        return "Username must be 3-20 characters: letters, digits or underscore."
    return None


def check_password(password: str) -> str | None:
    """Return an error message, or None if the password meets the policy."""
    password = password or ""
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return f"Password must be at most {MAX_PASSWORD_BYTES} bytes."
    groups = [
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ]
    if sum(groups) < 3:
        return "Password needs 3 of: lowercase, uppercase, digits, symbols."
    return None
