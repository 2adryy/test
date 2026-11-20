"""SecureChat server implementation."""

import argparse
import getpass
import json
import logging
import os
import socket
import sqlite3
import threading
import time

from . import DEFAULT_PORT
from . import crypto_utils as cu
from . import policy
from .database import UserDB, check_password
from .protocol import MAX_FRAME, Channel, ProtocolError

HANDSHAKE_TIMEOUT = 15
MAX_ANNOUNCEMENT = 500
KEEP_ANNOUNCEMENTS = 20

log = logging.getLogger("securechat.server")


class ChatServer:
    def __init__(self, host: str, port: int, data_dir: str, allow_plain: bool = False,
                 attack: str | None = None):
        self.host, self.port = host, port
        # DEMO OPTIONS (off by default):
        #   allow_plain - accept clients in "Plain demo" mode (no encryption at all)
        #   attack      - "tamper" or "replay": act like a hacked server to show the defenses
        if attack not in (None, "tamper", "replay"):
            raise ValueError("attack must be None, 'tamper' or 'replay'")
        self.allow_plain, self.attack = allow_plain, attack
        os.makedirs(data_dir, exist_ok=True)
        self.db = UserDB(os.path.join(data_dir, "users.db"))
        self.private_key = self._load_or_create_key(os.path.join(data_dir, "server_private.pem"))
        self.public_pem = cu.public_pem(self.private_key)
        self.fingerprint = cu.fingerprint(self.public_pem)

        self._lock = threading.RLock()
        self.online: dict[str, dict] = {}                   # username -> {ch, ip, since, plain}
        self.failures: dict[str, tuple[int, float]] = {}    # username(lower) -> (count, locked_until)
        self.announcements: list[dict] = []
        self.stats = {"started": time.time(), "relayed": 0, "files": 0, "blocked": 0}
        self._sock: socket.socket | None = None
        self._running = threading.Event()

    # ------------------------------------------------------------------ setup

    @staticmethod
    def _load_or_create_key(path: str):
        if os.path.exists(path):
            with open(path, "rb") as f:
                return cu.load_private_key(f.read(), None)
        key = cu.generate_private_key()
        # The server must start unattended, so its key is not password-protected.
        # Restrict the file to the owner instead.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(cu.private_key_to_pem(key, None))
        log.info("Generated new server key")
        return key

    def start(self) -> None:
        """Bind and listen. Returns once the socket is ready (accept loop runs in a thread)."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self.port = self._sock.getsockname()[1]   # real port if 0 was requested
        self._sock.listen()
        self._running.set()
        threading.Thread(target=self._accept_loop, daemon=True).start()
        log.info("Listening on %s:%d", self.host, self.port)
        log.info("Server key fingerprint: %s", self.fingerprint)
        if self.allow_plain:
            log.warning("DEMO: Plain (unencrypted) mode is ALLOWED. Never use this for real chats.")
        if self.attack:
            log.warning("DEMO: server is acting as a HACKED server (attack=%s)", self.attack)

    def stop(self) -> None:
        self._running.clear()
        if self._sock:
            self._sock.close()
        with self._lock:
            channels = [s["ch"] for s in self.online.values()]
        for ch in channels:
            ch.close()
        self.db.close()

    def _accept_loop(self) -> None:
        while self._running.is_set():
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

    def settings(self) -> dict:
        s = self.db.get_settings()
        return {"registration_open": s["registration_open"] == "1",
                "max_failed_logins": int(s["max_failed_logins"]),
                "lockout_seconds": int(s["lockout_seconds"])}

    # ------------------------------------------------------------------ per client

    def _handle_client(self, conn: socket.socket, addr) -> None:
        ch = Channel(conn, is_client=False)
        ip = addr[0]
        user = None
        try:
            conn.settimeout(HANDSHAKE_TIMEOUT)
            plain = self._handshake(ch)
            conn.settimeout(None)
            if plain:
                log.warning("%s:%d connected in PLAIN demo mode - everything is readable", *addr)
                self.db.log_event("plain_mode_connection", None, ip, "unencrypted demo session")
            else:
                log.info("%s:%d secure channel established", *addr)
            while True:
                msg = ch.recv()
                kind = msg["type"]
                if user is None:
                    if kind == "register":
                        self._on_register(ch, msg, ip)
                    elif kind == "login":
                        user = self._on_login(ch, msg, ip, plain)
                    else:
                        self._error(ch, "Please log in first")
                    continue
                handler = {
                    "relay": self._on_relay,
                    "friend_request": self._on_friend_request,
                    "friend_respond": self._on_friend_respond,
                    "friend_remove": self._on_friend_remove,
                    "change_password": self._on_change_password,
                    "my_security": self._on_my_security,
                }.get(kind)
                if kind == "logout":
                    break
                if handler:
                    handler(ch, user, msg, ip)
                else:
                    self._error(ch, f"Unknown request '{kind}'")
        except (ConnectionError, ProtocolError, OSError, socket.timeout) as exc:
            log.info("%s:%d disconnected (%s)", addr[0], addr[1], exc)
        finally:
            if user:
                with self._lock:
                    if self.online.get(user, {}).get("ch") is ch:
                        del self.online[user]
                log.info("%s logged out", user)
                try:
                    if self._running.is_set():
                        self._notify_friends_of(user)
                except sqlite3.ProgrammingError:
                    pass   # server is shutting down and the database is already closed
            ch.close()

    def _handshake(self, ch: Channel) -> bool:
        """The client pins our key (trust on first use). Only the real server can
        unwrap the channel key, so an impostor fails at the first encrypted frame.
        Returns True for a Plain demo session (no channel encryption)."""
        ch.send({"type": "hello", "server_key": self.public_pem, "allow_plain": self.allow_plain})
        msg = ch.recv()
        if msg["type"] == "plain_mode":
            if not self.allow_plain:
                ch.send({"type": "error", "error": "This server does not allow Plain mode "
                                                   "(start it with --allow-plain for the demo)"})
                raise ProtocolError("Plain mode refused")
            ch.send({"type": "channel_ready", "plain": True})
            return True
        if msg["type"] != "channel_key":
            raise ProtocolError("Expected channel_key")
        try:
            key = cu.rsa_unwrap(self.private_key, cu.b64d(msg["ek"]))
        except (KeyError, ValueError, cu.CryptoError) as exc:
            raise ProtocolError("Bad channel key") from exc
        ch.enable_encryption(key)
        ch.send({"type": "channel_ready"})
        return False

    # ------------------------------------------------------------------ replies

    @staticmethod
    def _reply(ch: Channel, msg: dict, ok: bool, error: str = "", **extra) -> None:
        ch.send({"type": "result", "req": msg["type"], "rid": msg.get("rid"),
                 "ok": ok, "error": error, **extra})

    @staticmethod
    def _error(ch: Channel, text: str) -> None:
        ch.send({"type": "error", "error": text})

    def _send_to(self, username: str, obj: dict) -> None:
        with self._lock:
            sess = self.online.get(username)
        if sess:
            try:
                sess["ch"].send(obj)
            except (OSError, ProtocolError):
                pass

    # ------------------------------------------------------------------ account

    def _on_register(self, ch: Channel, msg: dict, ip: str) -> None:
        username = str(msg.get("username", ""))
        password = str(msg.get("password", ""))
        pub = str(msg.get("public_key", ""))
        err = None
        if not self.settings()["registration_open"]:
            err = "Registration is closed by the administrator"
        err = err or policy.check_username(username) or policy.check_password(password)
        if not err:
            try:
                cu.load_public_key(pub)
            except Exception:
                err = "Invalid public key"
        if not err and not self.db.add_user(username, password, pub):
            err = "Username already taken"
        if err:
            self._reply(ch, msg, False, err)
            return
        log.info("Registered user %s (%s)", username, cu.fingerprint(pub))
        self.db.log_event("registered", username, ip, cu.fingerprint(pub))
        self._reply(ch, msg, True)

    def _on_login(self, ch: Channel, msg: dict, ip: str, plain: bool = False) -> str | None:
        username = str(msg.get("username", ""))
        password = str(msg.get("password", ""))
        key = username.lower()
        cfg = self.settings()

        with self._lock:
            count, locked_until = self.failures.get(key, (0, 0.0))
        if time.time() < locked_until:
            wait = int(locked_until - time.time()) + 1
            self._reply(ch, msg, False, f"Account locked. Try again in {wait}s.")
            return None

        row = self.db.get_user(username)
        if not check_password(password, row["pw_hash"] if row else None):
            count += 1
            locked = count >= cfg["max_failed_logins"]
            with self._lock:
                self.failures[key] = (0, time.time() + cfg["lockout_seconds"]) if locked else (count, 0.0)
            self.db.log_event("failed_login", row["username"] if row else username, ip, f"attempt {count}")
            if locked:
                self.db.log_event("account_locked", row["username"] if row else username, ip,
                                  f"{cfg['lockout_seconds']}s after {count} failures")
            log.warning("Failed login for %r (%d)", username, count)
            self._reply(ch, msg, False, "Wrong username or password")
            return None

        canonical = row["username"]
        if row["banned"]:
            self.db.log_event("banned_login", canonical, ip, "login refused")
            self._reply(ch, msg, False, "This account has been banned by an administrator")
            return None
        with self._lock:
            self.failures.pop(key, None)
            if canonical in self.online:
                self._reply(ch, msg, False, "This account is already logged in elsewhere")
                return None
            self.online[canonical] = {"ch": ch, "ip": ip, "since": time.time(), "plain": plain}
        ch.max_frame = MAX_FRAME   # logged in: large frames (files) are now allowed
        self.db.touch_login(canonical)
        self.db.log_event("login", canonical, ip)
        log.info("%s logged in", canonical)
        self._reply(ch, msg, True, username=canonical, created=row["created"],
                    last_login=row["last_login"], announcements=self.announcements[-5:])
        self._send_friends(canonical)
        self._notify_friends_of(canonical)
        return canonical

    def _on_change_password(self, ch, user, msg, ip):
        old, new = str(msg.get("old", "")), str(msg.get("new", ""))
        row = self.db.get_user(user)
        if not row or not check_password(old, row["pw_hash"]):
            self.db.log_event("password_change_failed", user, ip, "wrong current password")
            return self._reply(ch, msg, False, "Current password is wrong")
        err = policy.check_password(new)
        if err:
            return self._reply(ch, msg, False, err)
        self.db.set_password(user, new)
        self.db.log_event("password_changed", user, ip)
        self._reply(ch, msg, True)

    def _on_my_security(self, ch, user, msg, ip):
        events = self.db.recent_events(30, username=user)
        self._reply(ch, msg, True, events=events)

    # ------------------------------------------------------------------ friends

    def _friend_payload(self, username: str) -> dict:
        lists = self.db.friend_lists(username)
        with self._lock:
            online = set(self.online)
        friends = []
        for name in lists["friends"]:
            row = self.db.get_user(name)
            if row and not row["banned"]:
                friends.append({"name": row["username"], "online": row["username"] in online,
                                "public_key": row["public_key"]})
        return {"type": "friends", "friends": friends,
                "incoming": lists["incoming"], "outgoing": lists["outgoing"]}

    def _send_friends(self, username: str) -> None:
        self._send_to(username, self._friend_payload(username))

    def _notify_friends_of(self, username: str) -> None:
        """Someone came online/offline: refresh the lists of their online friends."""
        for name in self.db.friend_lists(username)["friends"]:
            row = self.db.get_user(name)
            if row:
                self._send_friends(row["username"])

    def _on_friend_request(self, ch, user, msg, ip):
        target = self.db.get_user(str(msg.get("to", "")))
        if not target:
            return self._reply(ch, msg, False, "No user with that name")
        other = target["username"]
        if other == user:
            return self._reply(ch, msg, False, "You cannot add yourself")
        row = self.db.friend_status(user, other)
        if row and row["status"] == "accepted":
            return self._reply(ch, msg, False, f"You are already friends with {other}")
        if row and row["requester"].lower() == user.lower():
            return self._reply(ch, msg, False, "Friend request already sent")
        if row:   # they already asked us -> adding them back accepts
            self.db.accept_friend(other, user)
            text = f"You are now friends with {other}"
        else:
            self.db.add_friend_request(user, other)
            text = f"Friend request sent to {other}"
        self._reply(ch, msg, True, message=text)
        self._send_friends(user)
        self._send_friends(other)

    def _on_friend_respond(self, ch, user, msg, ip):
        target = self.db.get_user(str(msg.get("name", "")))
        if not target:
            return self._reply(ch, msg, False, "No user with that name")
        other = target["username"]
        if msg.get("accept"):
            if not self.db.accept_friend(other, user):
                return self._reply(ch, msg, False, "No pending request from that user")
        else:
            row = self.db.friend_status(user, other)
            if not row or row["status"] != "pending":
                return self._reply(ch, msg, False, "No pending request from that user")
            self.db.remove_friend(user, other)
        self._reply(ch, msg, True)
        self._send_friends(user)
        self._send_friends(other)

    def _on_friend_remove(self, ch, user, msg, ip):
        target = self.db.get_user(str(msg.get("name", "")))
        if not target or not self.db.remove_friend(user, target["username"]):
            return self._reply(ch, msg, False, "Not in your friends list")
        self._reply(ch, msg, True)
        self._send_friends(user)
        self._send_friends(target["username"])

    # ------------------------------------------------------------------ relay

    def _on_relay(self, ch, user, msg, ip):
        to = str(msg.get("to", ""))
        packet = msg.get("packet")
        if not isinstance(packet, dict) or not isinstance(packet.get("header"), dict):
            return self._error(ch, "Malformed packet")
        # The server cannot read the content, but it can stop a logged-in user from
        # claiming to be someone else in the (signed) header.
        if packet["header"].get("from") != user or packet["header"].get("to") != to:
            self.stats["blocked"] += 1
            self.db.log_event("spoofed_packet", user, ip, f"header claims from={packet['header'].get('from')!r}")
            return self._error(ch, "Packet header does not match sender/recipient")
        if not self.db.are_friends(user, to):
            self.stats["blocked"] += 1
            return self._error(ch, f"You can only message friends. Add {to} first.")
        with self._lock:
            target = self.online.get(to)
        if not target:
            return self._error(ch, f"{to} is offline")
        kind = packet["header"].get("kind")
        if "plain" in packet:
            # Plain demo: the server (and anyone on the network) can read everything.
            log.warning("Relay %s -> %s PLAIN %s: %.80r", user, to, kind, packet["plain"])
        else:
            log.info("Relay %s -> %s (%s, %d bytes ciphertext)", user, to, kind, len(packet.get("ct", "")))
        out = {"type": "relay", "from": user, "packet": packet}
        if self.attack == "tamper":
            out["packet"] = self._tamper(packet)
        try:
            target["ch"].send(out)
            if self.attack == "replay":
                log.warning("ATTACK DEMO: re-sending the same packet to %s (replay)", to)
                target["ch"].send(out)
            self.stats["relayed"] += 1
            if kind == "file":
                self.stats["files"] += 1
        except (OSError, ProtocolError):
            self._error(ch, f"Could not deliver to {to}")

    @staticmethod
    def _tamper(packet: dict) -> dict:
        """ATTACK DEMO: a hacked server changes the message on its way.
        Encrypted packet -> flip bits in the ciphertext (the signature check catches it).
        Plain packet     -> rewrite the text (nothing can detect it - that's the point)."""
        packet = json.loads(json.dumps(packet))   # deep copy
        if "plain" in packet:
            if packet["header"].get("kind") == "text":
                packet["plain"] = "[CHANGED BY HACKED SERVER] Send the money to account 666"
            log.warning("ATTACK DEMO: rewrote a PLAIN packet - the receiver cannot notice")
        elif packet.get("ct"):
            ct = bytearray(cu.b64d(packet["ct"]))
            ct[len(ct) // 2] ^= 0xFF
            packet["ct"] = cu.b64e(bytes(ct))
            log.warning("ATTACK DEMO: flipped bits in an encrypted packet")
        return packet

    # ================================================================== admin operations
    # Called by admin_web.py. Every action is written to the audit log.

    def kick(self, username: str, reason: str = "Disconnected by an administrator") -> bool:
        with self._lock:
            sess = self.online.get(username)
        if not sess:
            return False
        try:
            sess["ch"].send({"type": "kicked", "reason": reason})
        except (OSError, ProtocolError):
            pass
        sess["ch"].close()   # the client's thread then cleans up and notifies friends
        return True

    def admin_kick(self, admin: str, username: str) -> tuple[bool, str]:
        if not self.kick(username):
            return False, f"{username} is not online"
        self.db.audit(admin, "kick", username)
        return True, f"{username} was disconnected"

    def admin_ban(self, admin: str, username: str, banned: bool) -> tuple[bool, str]:
        row = self.db.get_user(username)
        if not row:
            return False, "No such user"
        self.db.set_banned(row["username"], banned)
        if banned:
            self.kick(row["username"], "Your account has been banned by an administrator")
        for name in self.db.friend_lists(row["username"])["friends"]:
            self._send_friends(name)   # banned users disappear from friends' lists
        self.db.audit(admin, "ban" if banned else "unban", row["username"])
        return True, f"{row['username']} {'banned' if banned else 'unbanned'}"

    def admin_unlock(self, admin: str, username: str) -> tuple[bool, str]:
        with self._lock:
            removed = self.failures.pop(username.lower(), None)
        if not removed:
            return False, f"{username} is not locked"
        self.db.audit(admin, "unlock", username)
        return True, f"{username} unlocked"

    def admin_delete(self, admin: str, username: str) -> tuple[bool, str]:
        row = self.db.get_user(username)
        if not row:
            return False, "No such user"
        name = row["username"]
        friends = self.db.friend_lists(name)
        self.kick(name, "Your account has been deleted by an administrator")
        self.db.delete_user(name)
        for other in friends["friends"] + friends["incoming"] + friends["outgoing"]:
            self._send_friends(other)
        self.db.audit(admin, "delete_user", name)
        return True, f"{name} deleted"

    def admin_announce(self, admin: str, text: str) -> tuple[bool, str]:
        text = text.strip()
        if not text or len(text) > MAX_ANNOUNCEMENT:
            return False, f"Announcement must be 1-{MAX_ANNOUNCEMENT} characters"
        item = {"text": text, "ts": time.time(), "by": "Administrator"}
        with self._lock:
            self.announcements = (self.announcements + [item])[-KEEP_ANNOUNCEMENTS:]
            names = list(self.online)
        for name in names:
            self._send_to(name, {"type": "announcement", **item})
        self.db.audit(admin, "announce", None, text[:100])
        return True, f"Announcement sent to {len(names)} online user(s)"

    def admin_settings(self, admin: str, new: dict) -> tuple[bool, str]:
        try:
            changes = {}
            if "registration_open" in new:
                changes["registration_open"] = "1" if new["registration_open"] else "0"
            if "max_failed_logins" in new:
                v = int(new["max_failed_logins"])
                if not 3 <= v <= 20:
                    return False, "Max failed logins must be 3-20"
                changes["max_failed_logins"] = str(v)
            if "lockout_seconds" in new:
                v = int(new["lockout_seconds"])
                if not 10 <= v <= 3600:
                    return False, "Lockout must be 10-3600 seconds"
                changes["lockout_seconds"] = str(v)
        except (TypeError, ValueError):
            return False, "Invalid value"
        for k, v in changes.items():
            self.db.set_setting(k, v)
        self.db.audit(admin, "settings", None, ", ".join(f"{k}={v}" for k, v in changes.items()))
        return True, "Settings saved"

    def dashboard(self) -> dict:
        """Everything the admin page shows. Metadata only - there are no messages to show."""
        now = time.time()
        with self._lock:
            online = {n: {"ip": s["ip"], "since": s["since"], "plain": s.get("plain", False)}
                      for n, s in self.online.items()}
            locked = {k: until for k, (_, until) in self.failures.items() if until > now}
            announcements = list(self.announcements)
        users = []
        for u in self.db.list_users():
            lists = self.db.friend_lists(u["username"])
            users.append({
                "username": u["username"],
                "created": u["created"],
                "last_login": u["last_login"],
                "banned": bool(u["banned"]),
                "online": u["username"] in online,
                "ip": online.get(u["username"], {}).get("ip"),
                "plain": online.get(u["username"], {}).get("plain", False),
                "locked_until": locked.get(u["username"].lower()),
                "friends": len(lists["friends"]),
                "fingerprint": cu.fingerprint(u["public_key"]),
            })
        return {
            "stats": {
                "registered": len(users),
                "online": len(online),
                "banned": sum(u["banned"] for u in users),
                "locked": len(locked),
                "friendships": self.db.count_friendships(),
                "relayed": self.stats["relayed"],
                "files": self.stats["files"],
                "blocked": self.stats["blocked"],
                "uptime": now - self.stats["started"],
            },
            "server": {"address": f"{self.host}:{self.port}", "fingerprint": self.fingerprint,
                       "allow_plain": self.allow_plain, "attack": self.attack},
            "users": users,
            "events": self.db.recent_events(60),
            "audit": self.db.audit_log(40),
            "settings": self.settings(),
            "announcements": announcements[::-1],
        }


def create_admin(data_dir: str) -> None:
    """Interactive: python server.py --create-admin"""
    os.makedirs(data_dir, exist_ok=True)
    db = UserDB(os.path.join(data_dir, "users.db"))
    print("Create a SecureChat administrator account (admins cannot chat or read messages).")
    username = input("Admin username: ").strip()
    err = policy.check_username(username)
    if err:
        raise SystemExit(err)
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match.")
    err = policy.check_password(password)
    if err:
        raise SystemExit(err)
    if not db.add_admin(username, password):
        raise SystemExit("That name is already used by a user or another admin.")
    db.audit(username, "admin_created", username)
    print(f"Admin '{username}' created. Start the server and open the admin page.")


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureChat server")
    parser.add_argument("--host", default="127.0.0.1",
                        help="127.0.0.1 = this computer only, 0.0.0.0 = local network")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--data", default="server_data", help="folder for users.db and server key")
    parser.add_argument("--admin-port", type=int, default=8090,
                        help="port of the admin web page (always 127.0.0.1 only)")
    parser.add_argument("--no-admin", action="store_true", help="do not start the admin page")
    parser.add_argument("--create-admin", action="store_true", help="create an admin account and exit")
    demo = parser.add_argument_group("presentation demos (never use for real chats)")
    demo.add_argument("--allow-plain", action="store_true",
                      help="accept clients in Plain (unencrypted) demo mode")
    demo.add_argument("--attack", choices=["tamper", "replay"],
                      help="act like a hacked server: change (tamper) or re-send (replay) messages")
    args = parser.parse_args()

    if args.create_admin:
        create_admin(args.data)
        return

    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")
    server = ChatServer(args.host, args.port, args.data, allow_plain=args.allow_plain, attack=args.attack)
    server.start()
    if not args.no_admin:
        from .admin_web import start_admin_web
        start_admin_web(server, args.admin_port)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.stop()


if __name__ == "__main__":
    main()
