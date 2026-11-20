"""Wire protocol implementation."""

import json
import socket
import struct
import threading

from . import crypto_utils as cu

MAX_FRAME = 25 * 1024 * 1024       # largest frame after login (a 10 MiB file grows ~1.8x when encoded)
PRE_AUTH_FRAME = 64 * 1024         # before login only small frames are accepted (limits abuse)
HEADER = struct.Struct(">IB")


class ProtocolError(Exception):
    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """TCP may return fewer bytes than asked for, so keep reading until we have n."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf.extend(chunk)
    return bytes(buf)


class Channel:
    """A JSON message channel over a socket that can switch to encrypted mode."""

    def __init__(self, sock: socket.socket, is_client: bool):
        self.sock = sock
        self._send_dir = b"C2S" if is_client else b"S2C"
        self._recv_dir = b"S2C" if is_client else b"C2S"
        self._key: bytes | None = None
        self._send_ctr = 0
        self._recv_ctr = 0
        self._send_lock = threading.Lock()   # several threads may send on one socket
        self.max_frame = PRE_AUTH_FRAME      # raised to MAX_FRAME once the user is logged in

    @property
    def encrypted(self) -> bool:
        return self._key is not None

    def enable_encryption(self, key: bytes) -> None:
        if len(key) != cu.AES_KEY_BYTES:
            raise ProtocolError("Bad channel key length")
        self._key = key

    def send(self, obj: dict) -> None:
        data = json.dumps(obj).encode("utf-8")
        with self._send_lock:
            if self._key is None:
                kind, payload = b"P", data
            else:
                aad = self._send_dir + self._send_ctr.to_bytes(8, "big")
                nonce, ct = cu.aes_encrypt(self._key, data, aad)
                self._send_ctr += 1
                kind, payload = b"S", nonce + ct
            if len(payload) + 1 > MAX_FRAME:
                raise ProtocolError("Message too large")
            self.sock.sendall(HEADER.pack(len(payload) + 1, kind[0]) + payload)

    def recv(self) -> dict:
        length, kind = HEADER.unpack(_recv_exact(self.sock, HEADER.size))
        if length < 1 or length > self.max_frame:
            raise ProtocolError(f"Invalid frame length {length}")
        payload = _recv_exact(self.sock, length - 1)

        if self._key is None:
            if kind != ord("P"):
                raise ProtocolError("Expected plain frame")
            data = payload
        else:
            # Once encrypted, a plain frame means someone is tampering - refuse it.
            if kind != ord("S") or len(payload) < cu.NONCE_BYTES + 16:
                raise ProtocolError("Expected encrypted frame")
            aad = self._recv_dir + self._recv_ctr.to_bytes(8, "big")
            try:
                data = cu.aes_decrypt(self._key, payload[:cu.NONCE_BYTES],
                                      payload[cu.NONCE_BYTES:], aad)
            except cu.CryptoError as exc:
                raise ProtocolError("Channel integrity check failed") from exc
            self._recv_ctr += 1

        try:
            obj = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("Invalid JSON") from exc
        if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
            raise ProtocolError("Message must be an object with a 'type'")
        return obj

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
