"""Man-in-the-middle proxy for demonstration purposes."""

import argparse
import itertools
import json
import socket
import struct
import threading

from . import DEFAULT_PORT

HEADER = struct.Struct(">IB")
MAX_FRAME = 32 * 1024 * 1024

RED, GREEN, YELLOW, CYAN, DIM, BOLD, RESET = ("\033[31m", "\033[32m", "\033[33m", "\033[36m",
                                               "\033[2m", "\033[1m", "\033[0m")
_print_lock = threading.Lock()
_conn_ids = itertools.count(1)


def say(text: str) -> None:
    with _print_lock:
        print(text, flush=True)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf.extend(chunk)
    return bytes(buf)


def _summarize_plain(obj: dict) -> str:
    """Show what matters to an attacker in a readable frame."""
    kind = obj.get("type")
    if kind in ("login", "register"):
        return (f"{RED}{BOLD}{kind.upper()}  username={obj.get('username')!r}  "
                f"PASSWORD={obj.get('password')!r}{RESET}")
    if kind == "change_password":
        return f"{RED}{BOLD}PASSWORD CHANGE  old={obj.get('old')!r}  new={obj.get('new')!r}{RESET}"
    if kind == "relay":
        packet = obj.get("packet") or {}
        header = packet.get("header") or {}
        who = f"{header.get('from')} -> {header.get('to')}"
        if "plain" in packet:
            content = packet["plain"]
            if header.get("kind") == "file":
                try:
                    info = json.loads(content)
                    content = f"FILE {info.get('name')!r} ({info.get('size')} bytes) - full content visible"
                except ValueError:
                    pass
            return f"{RED}{BOLD}MESSAGE {who}: {str(content)[:200]!r}{RESET}"
        return f"{GREEN}MESSAGE {who}: end-to-end encrypted, {len(packet.get('ct', ''))} chars of ciphertext{RESET}"
    if kind == "hello":
        return f"{DIM}server hello (public key){RESET}"
    if kind == "friends":
        names = [f.get("name") for f in obj.get("friends", [])]
        return f"{YELLOW}friends list: {names}{RESET}"
    text = json.dumps(obj)
    return f"{YELLOW}{text[:160]}{'…' if len(text) > 160 else ''}{RESET}"


def _tamper_plain(obj: dict) -> dict | None:
    packet = obj.get("packet") if obj.get("type") == "relay" else None
    if isinstance(packet, dict) and "plain" in packet and (packet.get("header") or {}).get("kind") == "text":
        packet["plain"] = "[CHANGED BY ATTACKER ON THE NETWORK] Meet me at 3am"
        return obj
    return None


def pipe(src: socket.socket, dst: socket.socket, direction: str, conn_id: int, tamper: bool) -> None:
    label = f"#{conn_id} {direction}"
    encrypted_seen = 0
    try:
        while True:
            head = _recv_exact(src, HEADER.size)
            length, kind = HEADER.unpack(head)
            if length < 1 or length > MAX_FRAME:
                say(f"{RED}[{label}] invalid frame length {length}, closing{RESET}")
                break
            payload = _recv_exact(src, length - 1)

            if kind == ord("P"):
                try:
                    obj = json.loads(payload)
                    say(f"[{label}] {RED}READABLE{RESET}  {_summarize_plain(obj)}")
                    if tamper:
                        changed = _tamper_plain(obj)
                        if changed is not None:
                            payload = json.dumps(changed).encode()
                            head = HEADER.pack(len(payload) + 1, kind)
                            say(f"{RED}{BOLD}[{label}] TAMPERED: rewrote the message text. "
                                f"Plain mode has no integrity check, so this goes unnoticed.{RESET}")
                except ValueError:
                    say(f"[{label}] plain frame, {len(payload)} bytes")
            else:
                preview = payload[:24].hex(" ")
                say(f"[{label}] {GREEN}ENCRYPTED{RESET} {len(payload):>7} bytes  {DIM}{preview} …{RESET}")
                # Tamper with the first chat message (message frames carry an RSA-wrapped key
                # and a signature, so they are much larger than login/friend requests).
                if tamper and direction == "client→server" and not encrypted_seen and len(payload) > 900:
                    encrypted_seen = 1
                    data = bytearray(payload)
                    data[-1] ^= 0x01
                    payload = bytes(data)
                    say(f"{RED}{BOLD}[{label}] TAMPERED: flipped 1 bit in an encrypted frame. "
                        f"AES-GCM will detect it and the server will drop the connection.{RESET}")
            dst.sendall(head + payload)
    except (ConnectionError, OSError):
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()


def handle(client: socket.socket, addr, target: tuple, tamper: bool) -> None:
    try:
        server = socket.create_connection(target, timeout=10)
        server.settimeout(None)
    except OSError as exc:
        say(f"{RED}cannot reach the real server {target[0]}:{target[1]}: {exc}{RESET}")
        client.close()
        return
    conn_id = next(_conn_ids)
    say(f"{CYAN}=== connection #{conn_id} intercepted from {addr[0]}:{addr[1]} ==={RESET}")
    threading.Thread(target=pipe, args=(client, server, "client→server", conn_id, tamper), daemon=True).start()
    threading.Thread(target=pipe, args=(server, client, "server→client", conn_id, tamper), daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="DEMO man-in-the-middle proxy for SecureChat")
    parser.add_argument("--listen-port", type=int, default=6000, help="clients connect here")
    parser.add_argument("--server-host", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--tamper", action="store_true", help="also try to modify the traffic")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.listen_port))
    sock.listen()
    say(f"{BOLD}MITM demo proxy{RESET}: clients -> 127.0.0.1:{args.listen_port} -> "
        f"server {args.server_host}:{args.server_port}   tamper={'ON' if args.tamper else 'off'}")
    say("In the client's Connection box, use port "
        f"{args.listen_port} instead of {args.server_port}. Ctrl+C to stop.\n")
    try:
        while True:
            client, addr = sock.accept()
            handle(client, addr, (args.server_host, args.server_port), args.tamper)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
