"""Client networking and cryptography implementation."""

import base64
import itertools
import json
import os
import re
import socket
import threading
import time
import uuid

from . import crypto_utils as cu
from . import policy
from .protocol import MAX_FRAME, Channel, ProtocolError

REPLAY_WINDOW = 300          # seconds a message timestamp may differ from our clock
MAX_TEXT_CHARS = 4000
MAX_FILE_BYTES = 10 * 1024 * 1024   # 10 MiB (must stay well below the protocol MAX_FRAME)
REQUEST_TIMEOUT = 30


def safe_filename(name: str) -> str:
    """Make a received file name harmless: no folders ("../../x"), no strange characters."""
    name = os.path.basename(str(name).replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._ ()-]", "_", name).strip(" .")
    if not name:
        name = "file"
    stem, ext = os.path.splitext(name)
    return stem[:90] + ext[:10]


class ChatError(Exception):
    """A user-facing error (shown in the UI as-is)."""


class ServerKeyChanged(ChatError):
    """The server's key differs from the one we pinned earlier - possible impostor."""

    def __init__(self, address: str, old_fp: str, new_fp: str, new_pem: str):
        super().__init__(f"The key of server {address} has CHANGED.")
        self.address, self.old_fp, self.new_fp, self.new_pem = address, old_fp, new_fp, new_pem


class ChatClient:
    def __init__(self, data_dir: str = "client_data", on_event=None):
        self.data_dir = data_dir
        self.on_event = on_event or (lambda kind, data: None)
        os.makedirs(os.path.join(data_dir, "keys"), exist_ok=True)

        self.channel: Channel | None = None
        self.server_address = ""
        self.server_fp = ""
        self.username: str | None = None
        self.profile: dict = {}
        self.announcements: list[dict] = []
        self.incoming: list[str] = []          # friend requests waiting for me
        self.outgoing: list[str] = []          # friend requests I sent
        self._private_key = None
        self._public_pem = ""
        self._lock = threading.Lock()
        self.contacts: dict[str, dict] = {}     # friend name -> {public_key, fingerprint, online, trusted, changed, verified}
        self._seen_ids: dict[str, float] = {}   # message id -> timestamp (replay protection)
        self.plain = False                      # DEMO: Plain mode = no encryption at all
        self._rids = itertools.count(1)
        self._pending: dict[int, dict] = {}     # request id -> {"event", "reply"}
        self._listening = False

    # ------------------------------------------------------------------ helpers

    def _emit(self, kind, data=None):
        self.on_event(kind, data)

    def _log(self, level, text):
        self._emit("log", (level, text))

    def _path(self, name):
        return os.path.join(self.data_dir, name)

    def _load_json(self, name) -> dict:
        try:
            with open(self._path(name), encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_json(self, name, data) -> None:
        tmp = self._path(name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self._path(name))   # atomic: never leaves a half-written file

    def _key_path(self, username):
        return os.path.join(self.data_dir, "keys", f"{username.lower()}_private.pem")

    def has_local_key(self, username) -> bool:
        return os.path.exists(self._key_path(username))

    # ------------------------------------------------------------------ connection

    def connect(self, host: str, port: int, plain: bool = False) -> None:
        """Open TCP, pin/check the server key, and set up the encrypted channel.

        plain=True is the presentation demo: NOTHING is encrypted or signed, so a
        network sniffer (mitm_proxy.py) can read passwords and messages."""
        try:
            sock = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            raise ChatError(f"Cannot connect to {host}:{port} ({exc.strerror or exc})") from exc
        ch = Channel(sock, is_client=True)
        try:
            hello = ch.recv()
            if hello["type"] != "hello":
                raise ProtocolError("Expected hello")
            server_pem = hello["server_key"]
            server_pub = cu.load_public_key(server_pem)
            self.server_fp = cu.fingerprint(server_pem)

            # Trust on first use: remember the server key per address, warn if it changes.
            address = f"{host}:{port}"
            known = self._load_json("known_servers.json")
            if address not in known:
                known[address] = self.server_fp
                self._save_json("known_servers.json", known)
                self._log("warn", f"First connection to {address}. Pinned server key {self.server_fp}")
            elif known[address] != self.server_fp:
                raise ServerKeyChanged(address, known[address], self.server_fp, server_pem)
            else:
                self._log("ok", f"Server key matches pinned fingerprint {self.server_fp}")

            if plain:
                ch.send({"type": "plain_mode"})
                reply = ch.recv()
                if reply["type"] == "error":
                    raise ChatError(reply.get("error", "Plain mode refused"))
                if reply["type"] != "channel_ready":
                    raise ProtocolError("Handshake failed")
                self._log("error", "PLAIN DEMO MODE: passwords and messages are sent WITHOUT encryption")
                sock.settimeout(REQUEST_TIMEOUT)
                self.channel, self.server_address, self.plain = ch, address, True
                return

            # Random channel key, readable only by the holder of the server private key.
            channel_key = cu.new_aes_key()
            ch.send({"type": "channel_key", "ek": cu.b64e(cu.rsa_wrap(server_pub, channel_key))})
            ch.enable_encryption(channel_key)
            if ch.recv()["type"] != "channel_ready":
                raise ProtocolError("Handshake failed")
            self._log("ok", "Encrypted channel established (RSA-OAEP key exchange, AES-256-GCM)")
        except ChatError:
            ch.close()
            raise
        except (ProtocolError, ConnectionError, OSError, KeyError, cu.CryptoError) as exc:
            ch.close()
            raise ChatError(f"Secure handshake failed: {exc}") from exc
        sock.settimeout(REQUEST_TIMEOUT)
        self.channel = ch
        self.server_address = address

    def trust_server_key(self, host: str, port: int, fp: str) -> None:
        known = self._load_json("known_servers.json")
        known[f"{host}:{port}"] = fp
        self._save_json("known_servers.json", known)
        self._log("warn", f"Accepted NEW server key for {host}:{port}: {fp}")

    def _request(self, msg: dict) -> dict:
        """Send a request and wait for its result.

        Before login we read the reply directly; after login the listener thread
        receives everything, so we wait for it to hand us the matching reply."""
        if not self.channel:
            raise ChatError("Not connected.")
        rid = next(self._rids)
        msg = {**msg, "rid": rid}
        if not self._listening:
            try:
                self.channel.send(msg)
                while True:
                    reply = self.channel.recv()
                    if reply["type"] == "result" and reply.get("rid") == rid:
                        return reply
                    if reply["type"] == "error":
                        raise ChatError(reply.get("error", "Server error"))
            except (ProtocolError, ConnectionError, OSError) as exc:
                raise ChatError(f"Connection lost: {exc}") from exc

        slot = {"event": threading.Event(), "reply": None}
        with self._lock:
            self._pending[rid] = slot
        try:
            self.channel.send(msg)
            if not slot["event"].wait(REQUEST_TIMEOUT) or slot["reply"] is None:
                raise ChatError("The server did not answer in time.")
            return slot["reply"]
        except (ProtocolError, OSError) as exc:
            raise ChatError(f"Connection lost: {exc}") from exc
        finally:
            with self._lock:
                self._pending.pop(rid, None)

    # ------------------------------------------------------------------ account

    def register(self, username: str, password: str) -> None:
        err = policy.check_username(username) or policy.check_password(password)
        if err:
            raise ChatError(err)
        if self.has_local_key(username):
            raise ChatError("A local key for this username already exists on this computer.")

        self._log("info", "Generating RSA-2048 key pair locally...")
        private_key = cu.generate_private_key()
        reply = self._request({
            "type": "register",
            "username": username,
            "password": password,
            "public_key": cu.public_pem(private_key),   # the private key never leaves this device
        })
        if not reply["ok"]:
            raise ChatError(reply.get("error") or "Registration failed")

        # Private key is stored encrypted with the user's password.
        fd = os.open(self._key_path(username), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(cu.private_key_to_pem(private_key, password))
        self._log("ok", f"Account '{username}' registered. Private key saved (password-encrypted).")

    def login(self, username: str, password: str) -> None:
        if not self.has_local_key(username):
            raise ChatError("No private key for this user on this computer.")
        reply = self._request({"type": "login", "username": username, "password": password})
        if not reply["ok"]:
            raise ChatError(reply.get("error") or "Login failed")

        with open(self._key_path(username), "rb") as f:
            try:
                self._private_key = cu.load_private_key(f.read(), password)
            except cu.CryptoError as exc:
                raise ChatError("Could not unlock your private key with this password.") from exc
        self._public_pem = cu.public_pem(self._private_key)
        self.username = reply.get("username", username)
        self.profile = {"created": reply.get("created"), "last_login": reply.get("last_login"),
                        "logged_in_at": time.time()}
        self.announcements = list(reply.get("announcements") or [])
        self._log("ok", f"Logged in as {self.username}. Your key: {self.my_fingerprint}")

        self.channel.sock.settimeout(None)
        self.channel.max_frame = MAX_FRAME   # logged in: large frames (files) allowed
        self._listening = True
        threading.Thread(target=self._listen, daemon=True).start()

    @property
    def my_fingerprint(self) -> str:
        return cu.fingerprint(self._public_pem) if self._public_pem else ""

    def logout(self) -> None:
        if self.channel:
            try:
                self.channel.send({"type": "logout"})
            except (OSError, ProtocolError):
                pass
            self.channel.close()
        self.channel = None
        self._private_key = None
        self.username = None

    def change_password(self, old: str, new: str) -> None:
        """Change the server password AND re-encrypt the local private key with it."""
        if not self.username:
            raise ChatError("Not logged in.")
        err = policy.check_password(new)
        if err:
            raise ChatError(err)
        if old == new:
            raise ChatError("The new password must be different.")
        path = self._key_path(self.username)
        with open(path, "rb") as f:
            try:
                key = cu.load_private_key(f.read(), old)   # proves the old password locally
            except cu.CryptoError as exc:
                raise ChatError("Current password is wrong.") from exc
        reply = self._request({"type": "change_password", "old": old, "new": new})
        if not reply["ok"]:
            raise ChatError(reply.get("error") or "Password change failed")
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(cu.private_key_to_pem(key, new))
        os.replace(tmp, path)
        self._log("ok", "Password changed. Private key re-encrypted with the new password.")

    def my_security_events(self) -> list[dict]:
        reply = self._request({"type": "my_security"})
        if not reply["ok"]:
            raise ChatError(reply.get("error") or "Could not load security events")
        return reply.get("events", [])

    # ------------------------------------------------------------------ friends

    def _simple(self, msg: dict, default_error: str) -> str:
        reply = self._request(msg)
        if not reply["ok"]:
            raise ChatError(reply.get("error") or default_error)
        return reply.get("message", "")

    def add_friend(self, name: str) -> str:
        name = name.strip()
        if policy.check_username(name):
            raise ChatError("Enter a valid username.")
        result = self._simple({"type": "friend_request", "to": name}, "Could not send friend request")
        self._log("info", result)
        return result

    def respond_friend(self, name: str, accept: bool) -> None:
        self._simple({"type": "friend_respond", "name": name, "accept": bool(accept)}, "Could not answer request")
        self._log("info", f"{'Accepted' if accept else 'Declined'} friend request from {name}")

    def remove_friend(self, name: str) -> None:
        self._simple({"type": "friend_remove", "name": name}, "Could not remove friend")
        self._log("info", f"Removed {name} from friends")

    # ------------------------------------------------------------------ sending

    def _recipient(self, to: str):
        with self._lock:
            contact = self.contacts.get(to)
            if contact is None:
                raise ChatError(f"{to} is not in your friends list.")
            if not contact["online"]:
                raise ChatError(f"{to} is offline. Messages are only delivered to online friends.")
            if not contact["trusted"]:
                raise ChatError(f"{to}'s key changed. Verify and accept it before sending.")
            return cu.load_public_key(contact["public_key"])

    def _send_packet(self, to: str, kind: str, content: bytes) -> dict:
        """Build, encrypt + sign (or, in Plain demo mode, NOT) and send one packet."""
        recipient_pub = self._recipient(to)
        header = {"from": self.username, "to": to, "ts": time.time(),
                  "id": uuid.uuid4().hex, "kind": kind}
        if self.plain:
            packet = {"header": header, "plain": content.decode("utf-8")}   # readable by anyone!
        else:
            packet = cu.encrypt_message(self._private_key, recipient_pub, header, content)
        try:
            self.channel.send({"type": "relay", "to": to, "packet": packet})
        except (OSError, ProtocolError, AttributeError) as exc:
            raise ChatError(f"Send failed: {exc}") from exc
        if self.plain:
            self._log("error", f"Sent {kind} to {to} in PLAIN text (not encrypted, not signed)")
        else:
            self._log("info", f"Sent {kind} to {to}: {len(packet['ct'])} bytes ciphertext, id {header['id'][:8]}")
        return header

    def send_text(self, to: str, text: str) -> dict:
        text = text.strip()
        if not text:
            raise ChatError("Message is empty.")
        if len(text) > MAX_TEXT_CHARS:
            raise ChatError(f"Message is too long (max {MAX_TEXT_CHARS} characters).")
        header = self._send_packet(to, "text", text.encode("utf-8"))
        return {"from": self.username, "to": to, "text": text, "ts": header["ts"], "id": header["id"],
                "encrypted": not self.plain}

    def send_file(self, to: str, name: str, data: bytes) -> dict:
        """Send a file end-to-end encrypted: same path as text, with kind="file".
        Only the base name is sent - never the folder path of this computer."""
        if not data:
            raise ChatError("The file is empty.")
        if len(data) > MAX_FILE_BYTES:
            raise ChatError(f"File is too large (max {MAX_FILE_BYTES // (1024 * 1024)} MiB).")
        name = safe_filename(name)
        content = json.dumps({"name": name, "size": len(data),
                              "data": base64.b64encode(data).decode("ascii")}).encode("utf-8")
        header = self._send_packet(to, "file", content)
        return {"from": self.username, "to": to, "name": name, "size": len(data), "ts": header["ts"],
                "id": header["id"], "encrypted": not self.plain}

    def send_file_path(self, to: str, path: str) -> dict:
        size = os.path.getsize(path)   # check before reading, so a huge file is never loaded
        if size > MAX_FILE_BYTES:
            raise ChatError(f"File is too large (max {MAX_FILE_BYTES // (1024 * 1024)} MiB).")
        with open(path, "rb") as f:
            return self.send_file(to, os.path.basename(path), f.read())

    # ------------------------------------------------------------------ receiving

    def _listen(self) -> None:
        reason = "Disconnected from server"
        try:
            while True:
                msg = self.channel.recv()
                kind = msg["type"]
                if kind == "result":
                    with self._lock:
                        slot = self._pending.get(msg.get("rid"))
                    if slot:
                        slot["reply"] = msg
                        slot["event"].set()
                elif kind == "friends":
                    self._update_friends(msg)
                elif kind == "relay":
                    self._handle_relay(msg)
                elif kind == "announcement":
                    item = {k: msg.get(k) for k in ("text", "ts", "by")}
                    self.announcements.append(item)
                    self._log("warn", f"Announcement: {item['text']}")
                    self._emit("announcement", item)
                elif kind == "kicked":
                    reason = str(msg.get("reason") or "Disconnected by the server")
                    self._log("error", reason)
                elif kind == "error":
                    self._emit("error", msg.get("error", "Server error"))
        except ProtocolError as exc:
            reason = f"Connection closed: {exc}"
            self._log("error", reason)
        except (ConnectionError, OSError, AttributeError):
            pass
        self._listening = False
        with self._lock:   # wake anyone still waiting for an answer
            for slot in self._pending.values():
                slot["event"].set()
        self._emit("disconnected", reason)

    def _pins_file(self):
        return f"known_keys_{self.username.lower()}.json"

    def _contact_list(self) -> list[dict]:
        return sorted(self.contacts.values(), key=lambda c: (not c["online"], c["name"].lower()))

    def _emit_friends(self) -> None:
        self._emit("friends", {"contacts": self._contact_list(),
                               "incoming": list(self.incoming), "outgoing": list(self.outgoing)})

    def _update_friends(self, msg: dict) -> None:
        pins = self._load_json(self._pins_file())
        pins_changed = False
        contacts = {}
        for u in msg.get("friends", []):
            name, pem = u.get("name"), u.get("public_key")
            if not name or name == self.username:
                continue
            try:
                fp = cu.fingerprint(pem)
            except Exception:
                self._log("error", f"Ignoring {name}: invalid public key")
                continue
            pin = pins.get(name)
            if pin is None:
                pins[name] = {"fingerprint": fp, "verified": False}
                pins_changed = True
                trusted, changed, verified = True, False, False
                self._log("warn", f"New contact {name}, pinned key {fp} (not yet verified)")
            elif pin["fingerprint"] == fp:
                trusted, changed, verified = True, False, pin.get("verified", False)
            else:
                trusted, changed, verified = False, True, False
                if not self.contacts.get(name, {}).get("changed"):
                    alert = f"KEY CHANGED for {name}! Was {pin['fingerprint']}, now {fp}"
                    self._log("error", alert)
                    self._emit("security", {"from": name,
                                            "text": alert + ". Messages blocked until you verify."})
            contacts[name] = {"name": name, "public_key": pem, "fingerprint": fp, "online": bool(u.get("online")),
                              "trusted": trusted, "changed": changed, "verified": verified}
        if pins_changed:
            self._save_json(self._pins_file(), pins)
        with self._lock:
            self.contacts = contacts
            self.incoming = [str(n) for n in msg.get("incoming", [])]
            self.outgoing = [str(n) for n in msg.get("outgoing", [])]
        self._emit_friends()

    def trust_new_key(self, name: str) -> None:
        """User explicitly accepts a changed key (after checking it out-of-band)."""
        with self._lock:
            c = self.contacts.get(name)
            if not c:
                return
            c.update(trusted=True, changed=False, verified=True)
        pins = self._load_json(self._pins_file())
        pins[name] = {"fingerprint": c["fingerprint"], "verified": True}
        self._save_json(self._pins_file(), pins)
        self._log("warn", f"Accepted new key for {name}: {c['fingerprint']}")
        self._emit_friends()

    def mark_verified(self, name: str) -> None:
        with self._lock:
            c = self.contacts.get(name)
            if not c or not c["trusted"]:
                return
            c["verified"] = True
        pins = self._load_json(self._pins_file())
        pins[name] = {"fingerprint": c["fingerprint"], "verified": True}
        self._save_json(self._pins_file(), pins)
        self._log("ok", f"Marked {name}'s key as verified")
        self._emit_friends()

    def _handle_relay(self, msg: dict) -> None:
        sender = msg.get("from", "?")
        packet = msg.get("packet") or {}
        header = packet.get("header") if isinstance(packet, dict) else None

        def reject(reason):
            self._log("error", f"REJECTED message from {sender}: {reason}")
            self._emit("security", {"from": sender, "text": f"Message rejected: {reason}"})

        if not isinstance(header, dict) or header.get("kind") not in ("text", "file"):
            return reject("malformed packet")
        if header.get("from") != sender or header.get("to") != self.username:
            return reject("header does not match sender/recipient")
        with self._lock:
            contact = self.contacts.get(sender)
        if contact is None:
            return reject("sender is not in your friends list")
        if not contact["trusted"]:
            return reject("sender's key changed and is not trusted")

        encrypted = "plain" not in packet
        if not encrypted:
            # An unencrypted, unsigned packet: anyone could have written or changed it.
            if not self.plain:
                return reject("unencrypted (Plain mode) message refused - you are in Secure mode")
            plaintext = str(packet["plain"]).encode("utf-8")
        else:
            try:
                plaintext = cu.decrypt_message(self._private_key,
                                               cu.load_public_key(contact["public_key"]), packet)
            except cu.CryptoError as exc:
                return reject(f"{exc} - possible tampering / man-in-the-middle")

        # Only check replay AFTER the signature is valid, so forged packets cannot
        # fill our seen-ID list.
        err = self._check_replay(header)
        if err:
            return reject(err)

        if header["kind"] == "file":
            return self._receive_file(sender, header, plaintext, encrypted, reject)
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return reject("content is not valid text")
        if encrypted:
            self._log("ok", f"Message from {sender}: signature verified, decrypted, id {header['id'][:8]}")
        else:
            self._log("error", f"PLAIN message from {sender}: NOT verified - it could have been changed")
        self._emit("message", {"from": sender, "to": self.username, "text": text,
                               "ts": header["ts"], "id": header["id"], "encrypted": encrypted})

    def _receive_file(self, sender, header, plaintext, encrypted, reject) -> None:
        try:
            info = json.loads(plaintext.decode("utf-8"))
            data = base64.b64decode(info["data"], validate=True)
            name = safe_filename(info["name"])
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            return reject("file content is malformed")
        if len(data) > MAX_FILE_BYTES or len(data) != info.get("size"):
            return reject("file size is wrong or too large")
        path = self._save_file(name, data)
        self._log("ok" if encrypted else "error",
                  f"File from {sender}: {name} ({len(data)} bytes) "
                  f"{'signature verified, decrypted' if encrypted else 'PLAIN, not verified'}, saved to {path}")
        self._emit("file", {"from": sender, "to": self.username, "name": os.path.basename(path),
                            "size": len(data), "path": path, "ts": header["ts"], "id": header["id"],
                            "encrypted": encrypted})

    def _save_file(self, name: str, data: bytes) -> str:
        """Save into client_data/downloads/<me>/ without ever overwriting an existing file."""
        folder = os.path.join(self.data_dir, "downloads", self.username.lower())
        os.makedirs(folder, exist_ok=True)
        stem, ext = os.path.splitext(name)
        for i in range(1000):
            candidate = os.path.join(folder, name if i == 0 else f"{stem} ({i}){ext}")
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            return candidate
        raise OSError("Too many files with the same name")

    def _check_replay(self, header: dict) -> str | None:
        now = time.time()
        ts, mid = header.get("ts"), header.get("id")
        if not isinstance(ts, (int, float)) or not isinstance(mid, str):
            return "missing timestamp or id"
        if abs(now - ts) > REPLAY_WINDOW:
            return "timestamp outside the 5-minute window (old or replayed message)"
        with self._lock:
            # forget IDs that are older than the window - they would fail the time check anyway
            self._seen_ids = {k: v for k, v in self._seen_ids.items() if now - v <= REPLAY_WINDOW * 2}
            if mid in self._seen_ids:
                return "duplicate message id (replay attack)"
            self._seen_ids[mid] = ts
        return None
