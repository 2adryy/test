"""Admin web interface and management endpoints."""

import json
import logging
import mimetypes
import os
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .database import check_password

STATIC_DIR = os.path.join(os.path.dirname(__file__), "web")
SESSION_IDLE = 30 * 60
MAX_BODY = 16 * 1024
ADMIN_MAX_FAILS = 5
ADMIN_LOCKOUT = 60
COOKIE = "sc_admin"

log = logging.getLogger("securechat.admin")


class AdminSessions:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict[str, dict] = {}            # token -> {admin, expires}
        self._fails: dict[str, tuple[int, float]] = {}  # admin(lower) -> (count, locked_until)

    def create(self, admin: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = {"admin": admin, "expires": time.time() + SESSION_IDLE}
        return token

    def check(self, token: str | None) -> str | None:
        if not token:
            return None
        with self._lock:
            s = self._sessions.get(token)
            if not s or s["expires"] < time.time():
                self._sessions.pop(token, None)
                return None
            s["expires"] = time.time() + SESSION_IDLE   # sliding expiry
            return s["admin"]

    def destroy(self, token: str | None) -> None:
        with self._lock:
            self._sessions.pop(token or "", None)

    def locked(self, name: str) -> int:
        with self._lock:
            _, until = self._fails.get(name.lower(), (0, 0.0))
        return max(0, int(until - time.time()) + 1) if until > time.time() else 0

    def failed(self, name: str) -> None:
        with self._lock:
            count, _ = self._fails.get(name.lower(), (0, 0.0))
            count += 1
            self._fails[name.lower()] = (0, time.time() + ADMIN_LOCKOUT) if count >= ADMIN_MAX_FAILS else (count, 0.0)

    def succeeded(self, name: str) -> None:
        with self._lock:
            self._fails.pop(name.lower(), None)


def make_handler(server, sessions: AdminSessions, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "SecureChatAdmin"

        def log_message(self, fmt, *args):
            pass

        def _headers(self, status, ctype, length=None, extra=()):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                             "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            for k, v in extra:
                self.send_header(k, v)
            if length is not None:
                self.send_header("Content-Length", str(length))
            self.end_headers()

        def _json(self, obj, status=200, extra=()):
            data = json.dumps(obj).encode("utf-8")
            self._headers(status, "application/json", len(data), extra)
            self.wfile.write(data)

        def _token(self):
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            return cookie[COOKIE].value if COOKIE in cookie else None

        def _host_ok(self):
            if self.headers.get("Host") not in allowed_hosts:
                self._json({"error": "Bad host"}, 403)
                return False
            return True

        # ------------------------------------------------------------ GET

        def do_GET(self):
            if not self._host_ok():
                return
            path = urlparse(self.path).path
            if path == "/":
                return self._file("admin.html")
            if path.startswith("/static/"):
                name = path[len("/static/"):]
                if name in ("admin.css", "admin.js", "app.css", "theme.js", "shield.svg", "shield-soft.svg",
                            "shield-red.svg"):
                    return self._file(name)
                return self._json({"error": "Not found"}, 404)
            admin = sessions.check(self._token())
            if path == "/api/me":
                return self._json({"admin": admin})
            if path == "/api/dashboard":
                if not admin:
                    return self._json({"error": "Not logged in"}, 401)
                return self._json(server.dashboard())
            self._json({"error": "Not found"}, 404)

        def _file(self, name):
            with open(os.path.join(STATIC_DIR, name), "rb") as f:
                data = f.read()
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self._headers(200, ctype, len(data))
            self.wfile.write(data)

        # ------------------------------------------------------------ POST

        def do_POST(self):
            if not self._host_ok():
                return
            if self.headers.get("X-SecureChat-Admin") != "1":
                return self._json({"error": "Missing CSRF header"}, 403)
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._json({"error": "JSON required"}, 415)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > MAX_BODY:
                    return self._json({"error": "Too large"}, 413)
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json({"error": "Bad JSON"}, 400)

            path = urlparse(self.path).path
            if path == "/api/login":
                return self._login(body)

            token = self._token()
            admin = sessions.check(token)
            if not admin:
                return self._json({"ok": False, "error": "Not logged in"}, 401)
            if path == "/api/logout":
                sessions.destroy(token)
                server.db.audit(admin, "admin_logout")
                return self._json({"ok": True}, extra=[("Set-Cookie", f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")])

            user = str(body.get("username", ""))
            actions = {
                "/api/kick": lambda: server.admin_kick(admin, user),
                "/api/ban": lambda: server.admin_ban(admin, user, True),
                "/api/unban": lambda: server.admin_ban(admin, user, False),
                "/api/unlock": lambda: server.admin_unlock(admin, user),
                "/api/delete": lambda: server.admin_delete(admin, user),
                "/api/announce": lambda: server.admin_announce(admin, str(body.get("text", ""))),
                "/api/settings": lambda: server.admin_settings(admin, body),
            }
            action = actions.get(path)
            if not action:
                return self._json({"error": "Not found"}, 404)
            ok, message = action()
            log.info("admin %s %s %s -> %s", admin, path, user, message)
            self._json({"ok": ok, "message": message if ok else "", "error": "" if ok else message})

        def _login(self, body):
            name = str(body.get("username", ""))
            password = str(body.get("password", ""))
            ip = self.client_address[0]
            wait = sessions.locked(name)
            if wait:
                return self._json({"ok": False, "error": f"Too many attempts. Try again in {wait}s."})
            row = server.db.get_admin(name)
            if not check_password(password, row["pw_hash"] if row else None):
                sessions.failed(name)
                server.db.log_event("admin_login_failed", name, ip)
                return self._json({"ok": False, "error": "Wrong admin username or password"})
            sessions.succeeded(name)
            token = sessions.create(row["username"])
            server.db.audit(row["username"], "admin_login", None, ip)
            cookie = f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_IDLE}"
            self._json({"ok": True, "admin": row["username"]}, extra=[("Set-Cookie", cookie)])

    return Handler


def start_admin_web(server, port: int) -> ThreadingHTTPServer:
    """Start the admin page in a background thread. Returns the HTTP server."""
    httpd = ThreadingHTTPServer(("127.0.0.1", port), None)
    httpd.RequestHandlerClass = make_handler(server, AdminSessions(), httpd.server_port)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    log.info("Admin page: http://127.0.0.1:%d/  (create an admin with: python server.py --create-admin)",
             httpd.server_port)
    return httpd
