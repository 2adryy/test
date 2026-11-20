"""SecureChat local web client interface."""

import argparse
import base64
import binascii
import json
import mimetypes
import os
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import DEFAULT_PORT
from .client_core import MAX_FILE_BYTES, ChatClient, ChatError, ServerKeyChanged, safe_filename

STATIC_DIR = os.path.join(os.path.dirname(__file__), "web")
MAX_BODY = 64 * 1024
MAX_UPLOAD_BODY = MAX_FILE_BYTES * 4 // 3 + 64 * 1024   # a 10 MiB file, base64-encoded, plus JSON
MAX_EVENTS = 2000


class Session:
    """State of the one user of this local client (kept in memory only)."""

    def __init__(self, data_dir: str, default_host: str, default_port: int):
        self.data_dir = data_dir
        self.default_host, self.default_port = default_host, default_port
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        self.client: ChatClient | None = None
        self.auth_busy = False
        self.events: list[dict] = []      # ordered event stream for the browser
        self.first_event_id = 0           # id of events[0]
        self.log: list[dict] = []
        self.contacts: list[dict] = []
        self.incoming: list[str] = []
        self.outgoing: list[str] = []
        self.history: dict[str, list[dict]] = {}
        self.files: dict[str, str] = {}   # random id -> path of a received file (for download)

    # ------------------------------------------------------------------ events

    def push(self, kind: str, data) -> None:
        with self.cond:
            self.events.append({"kind": kind, "data": data})
            if len(self.events) > MAX_EVENTS:
                drop = len(self.events) - MAX_EVENTS
                del self.events[:drop]
                self.first_event_id += drop
            self.cond.notify_all()

    def on_client_event(self, client: ChatClient, kind: str, data) -> None:
        """Called from network threads by ChatClient."""
        if kind == "log":
            entry = {"t": time.strftime("%H:%M:%S"), "level": data[0], "text": data[1]}
            with self.lock:
                self.log.append(entry)
            self.push("log", entry)
            return
        if client is not self.client:      # an old/failed connection - ignore
            return
        if kind == "friends":
            with self.lock:
                self.contacts = data["contacts"]
                self.incoming = data["incoming"]
                self.outgoing = data["outgoing"]
            self.push("friends", data)
        elif kind == "announcement":
            self.push("announcement", data)
        elif kind == "message":
            self.add_item(data["from"], "in", data["text"], data["ts"], encrypted=data["encrypted"])
        elif kind == "file":
            file_id = secrets.token_urlsafe(12)
            with self.lock:
                self.files[file_id] = data["path"]
            self.add_item(data["from"], "file_in", data["name"], data["ts"], size=data["size"],
                          file_id=file_id, encrypted=data["encrypted"])
        elif kind in ("security", "error"):
            text = data["text"] if isinstance(data, dict) else data
            who = data.get("from") if isinstance(data, dict) else None
            self.add_item(who, "alert", text, time.time())
        elif kind == "disconnected":
            self.reset()
            self.push("disconnected", data)

    def add_item(self, contact: str | None, kind: str, text: str, ts: float, **extra) -> None:
        item = {"contact": contact, "kind": kind, "text": text, "ts": ts, **extra}
        if contact:
            with self.lock:
                self.history.setdefault(contact, []).append(item)
        self.push("item", item)

    def reset(self) -> None:
        with self.lock:
            self.client = None
            self.contacts, self.incoming, self.outgoing = [], [], []
            self.history = {}
            self.files = {}

    def state(self) -> dict:
        with self.lock:
            c = self.client
            return {
                "logged_in": c is not None,
                "username": c.username if c else None,
                "my_fingerprint": c.my_fingerprint if c else "",
                "server_fingerprint": c.server_fp if c else "",
                "server_address": c.server_address if c else "",
                "plain": c.plain if c else False,
                "profile": c.profile if c else {},
                "announcements": c.announcements[-10:] if c else [],
                "contacts": self.contacts,
                "incoming": self.incoming,
                "outgoing": self.outgoing,
                "history": self.history,
                "log": self.log[-300:],
                "next_event": self.first_event_id + len(self.events),
                "default_host": self.default_host,
                "default_port": self.default_port,
            }

    # ------------------------------------------------------------------ actions

    def login(self, body: dict) -> dict:
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        host = str(body.get("host", "")).strip()
        register = bool(body.get("register"))
        plain = bool(body.get("plain"))
        try:
            port = int(body.get("port"))
            if not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            return {"ok": False, "error": "Port must be a number between 1 and 65535."}
        if not host or not username or not password:
            return {"ok": False, "error": "Fill in username, password and server."}

        with self.lock:
            if self.client or self.auth_busy:
                return {"ok": False, "error": "Already logged in or busy."}
            self.auth_busy = True

        client = ChatClient(self.data_dir)
        client.on_event = lambda k, d: self.on_client_event(client, k, d)
        try:
            client.connect(host, port, plain=plain)
            if register:
                client.register(username, password)
            # make this the active client before login starts the listener thread,
            # so the first contact list is not dropped
            with self.lock:
                self.client = client
            client.login(username, password)
            return {"ok": True}
        except ServerKeyChanged as exc:
            return {"ok": False, "error": str(exc),
                    "server_key_changed": {"address": exc.address, "old": exc.old_fp, "new": exc.new_fp}}
        except ChatError as exc:
            self.reset()
            client.logout()
            return {"ok": False, "error": str(exc)}
        except Exception as exc:   # unexpected bug: report instead of hanging
            self.reset()
            client.logout()
            return {"ok": False, "error": f"Unexpected error: {exc}"}
        finally:
            with self.lock:
                self.auth_busy = False

    def trust_server(self, body: dict) -> dict:
        ChatClient(self.data_dir, on_event=lambda k, d: self.on_client_event(None, k, d)).trust_server_key(
            str(body.get("host", "")), int(body.get("port", 0)), str(body.get("fingerprint", "")))
        return {"ok": True}

    def send(self, body: dict) -> dict:
        client = self.client
        if not client:
            return {"ok": False, "error": "Not logged in."}
        to = str(body.get("to", ""))
        try:
            sent = client.send_text(to, str(body.get("text", "")))
        except ChatError as exc:
            return {"ok": False, "error": str(exc)}
        self.add_item(to, "out", sent["text"], sent["ts"], encrypted=sent["encrypted"])
        return {"ok": True}

    def send_file(self, body: dict) -> dict:
        client = self.client
        if not client:
            return {"ok": False, "error": "Not logged in."}
        to = str(body.get("to", ""))
        try:
            data = base64.b64decode(str(body.get("data", "")), validate=True)
        except (binascii.Error, ValueError):
            return {"ok": False, "error": "Could not read the file."}
        try:
            sent = client.send_file(to, str(body.get("name", "file")), data)
        except ChatError as exc:
            return {"ok": False, "error": str(exc)}
        self.add_item(to, "file_out", sent["name"], sent["ts"], size=sent["size"], encrypted=sent["encrypted"])
        return {"ok": True}

    def file_path(self, file_id: str) -> str | None:
        with self.lock:
            return self.files.get(file_id)

    def logout(self) -> dict:
        client = self.client
        self.reset()
        if client:
            client.logout()
            self.on_client_event(None, "log", ("info", "Logged out. Chat history cleared from memory."))
        return {"ok": True}

    def contact_action(self, body: dict, action: str) -> dict:
        """Actions on friends and the own account. ChatError -> {"ok": False, "error": ...}"""
        client = self.client
        if not client:
            return {"ok": False, "error": "Not logged in."}
        name = str(body.get("name", ""))
        try:
            if action == "verify":
                client.mark_verified(name)
            elif action == "trust":
                client.trust_new_key(name)
            elif action == "add":
                return {"ok": True, "message": client.add_friend(name)}
            elif action == "respond":
                client.respond_friend(name, bool(body.get("accept")))
            elif action == "remove":
                client.remove_friend(name)
                with self.lock:
                    self.history.pop(name, None)
            elif action == "password":
                client.change_password(str(body.get("old", "")), str(body.get("new", "")))
            elif action == "security":
                return {"ok": True, "events": client.my_security_events()}
        except ChatError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}


def make_handler(session: Session, token: str, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "SecureChatLocal"

        def log_message(self, fmt, *args):   # keep the terminal quiet
            pass

        # ---------------------------------------------------------- helpers

        def _headers(self, status: int, ctype: str, length: int | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; style-src 'self'; "
                             "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                             "base-uri 'none'; form-action 'none'")
            if length is not None:
                self.send_header("Content-Length", str(length))
            self.end_headers()

        def _json(self, obj, status=200):
            data = json.dumps(obj).encode("utf-8")
            self._headers(status, "application/json", len(data))
            self.wfile.write(data)

        def _host_ok(self) -> bool:
            if self.headers.get("Host") not in allowed_hosts:
                self._json({"error": "Bad host"}, 403)
                return False
            return True

        def _token_ok(self, given: str | None) -> bool:
            if not given or not secrets.compare_digest(given, token):
                self._json({"error": "Missing or bad token"}, 403)
                return False
            return True

        # ---------------------------------------------------------- GET

        def do_GET(self):
            if not self._host_ok():
                return
            url = urlparse(self.path)
            if url.path == "/":
                with open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8") as f:
                    html = f.read().replace("{{TOKEN}}", token)
                data = html.encode("utf-8")
                self._headers(200, "text/html; charset=utf-8", len(data))
                self.wfile.write(data)
            elif url.path.startswith("/static/"):
                self._static(url.path[len("/static/"):])
            elif url.path == "/api/state":
                if self._token_ok(self.headers.get("X-SecureChat-Token")):
                    self._json(session.state())
            elif url.path == "/api/file":
                q = parse_qs(url.query)
                if self._token_ok(q.get("token", [None])[0]):
                    self._download(session.file_path(q.get("id", [""])[0]))
            elif url.path == "/api/events":
                q = parse_qs(url.query)
                if self._token_ok(q.get("token", [None])[0]):
                    self._stream(int(q.get("since", ["0"])[0] or 0))
            else:
                self._json({"error": "Not found"}, 404)

        def _static(self, name: str):
            # only plain file names from our own folder - no "../" path traversal
            if not name or "/" in name or "\\" in name or name.startswith("."):
                return self._json({"error": "Not found"}, 404)
            path = os.path.join(STATIC_DIR, name)
            if not os.path.isfile(path):
                return self._json({"error": "Not found"}, 404)
            with open(path, "rb") as f:
                data = f.read()
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self._headers(200, ctype, len(data))
            self.wfile.write(data)

        def _download(self, path: str | None):
            """Received files are ALWAYS sent as a download (attachment, octet-stream),
            never shown inside this page: a received .html/.svg file must not be able to
            run scripts on our origin (that would be XSS through a file)."""
            if not path or not os.path.isfile(path):
                return self._json({"error": "Not found"}, 404)
            with open(path, "rb") as f:
                data = f.read()
            name = safe_filename(os.path.basename(path))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _stream(self, since: int):
            """Server-Sent Events: push new events to the browser as they happen."""
            self._headers(200, "text/event-stream")
            nxt = since
            try:
                while True:
                    with session.cond:
                        end = session.first_event_id + len(session.events)
                        if nxt >= end:
                            session.cond.wait(timeout=15)
                            end = session.first_event_id + len(session.events)
                        start = max(nxt, session.first_event_id)
                        batch = session.events[start - session.first_event_id:end - session.first_event_id]
                    if batch:
                        for i, ev in enumerate(batch):
                            self.wfile.write(f"id: {start + i}\ndata: {json.dumps(ev)}\n\n".encode("utf-8"))
                        nxt = end
                    else:
                        self.wfile.write(b": ping\n\n")   # keeps the connection alive
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        # ---------------------------------------------------------- POST

        def do_POST(self):
            if not self._host_ok() or not self._token_ok(self.headers.get("X-SecureChat-Token")):
                return
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._json({"error": "JSON required"}, 415)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                limit = MAX_UPLOAD_BODY if urlparse(self.path).path == "/api/send_file" else MAX_BODY
                if length > limit:
                    return self._json({"error": "Request too large"}, 413)
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json({"error": "Bad JSON"}, 400)

            routes = {
                "/api/login": session.login,
                "/api/send": session.send,
                "/api/send_file": session.send_file,
                "/api/logout": lambda b: session.logout(),
                "/api/trust_server": session.trust_server,
                "/api/verify_contact": lambda b: session.contact_action(b, "verify"),
                "/api/trust_contact": lambda b: session.contact_action(b, "trust"),
                "/api/friend_add": lambda b: session.contact_action(b, "add"),
                "/api/friend_respond": lambda b: session.contact_action(b, "respond"),
                "/api/friend_remove": lambda b: session.contact_action(b, "remove"),
                "/api/change_password": lambda b: session.contact_action(b, "password"),
                "/api/my_security": lambda b: session.contact_action(b, "security"),
            }
            action = routes.get(urlparse(self.path).path)
            if not action:
                return self._json({"error": "Not found"}, 404)
            self._json(action(body))

    return Handler


def main():
    parser = argparse.ArgumentParser(description="SecureChat web client (opens in your browser)")
    parser.add_argument("--host", default="127.0.0.1", help="chat server address (pre-filled)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="chat server port (pre-filled)")
    parser.add_argument("--web-port", type=int, default=8080,
                        help="local port for the web page (next free port is used if busy)")
    parser.add_argument("--data", default="client_data", help="folder for your keys and trust data")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    args = parser.parse_args()

    session = Session(args.data, args.host, args.port)
    token = secrets.token_urlsafe(32)

    httpd = None
    for web_port in range(args.web_port, args.web_port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", web_port), make_handler(session, token, web_port))
            break
        except OSError:
            continue
    if httpd is None:
        raise SystemExit("No free local port found for the web page.")
    httpd.daemon_threads = True

    url = f"http://127.0.0.1:{web_port}/"
    print(f"SecureChat is running. Open {url} in your browser.  (Ctrl+C to quit)")
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        session.logout()
        httpd.server_close()


if __name__ == "__main__":
    main()
