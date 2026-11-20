"""Cryptographic operations and primitives."""

import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_BITS = 2048
AES_KEY_BYTES = 32   # 256-bit
NONCE_BYTES = 12     # 96-bit nonce, the standard size for GCM


class CryptoError(Exception):
    """Raised when decryption or signature verification fails."""


# --------------------------------------------------------------------------- encoding
# Base64 only turns bytes into text so they fit inside JSON. It is NOT encryption.

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def canonical_json(obj) -> bytes:
    """Same object -> same bytes every time, so both sides sign/verify identical data."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------- RSA keys

def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_BITS)


def public_pem(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_public_key(pem: str) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < RSA_KEY_BITS:
        raise CryptoError("Public key must be RSA-2048 or larger")
    return key


def private_key_to_pem(private_key: rsa.RSAPrivateKey, password: str | None) -> bytes:
    """Serialize a private key. With a password it is encrypted at rest."""
    encryption = (
        serialization.BestAvailableEncryption(password.encode("utf-8"))
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )


def load_private_key(pem: bytes, password: str | None) -> rsa.RSAPrivateKey:
    try:
        return serialization.load_pem_private_key(
            pem, password.encode("utf-8") if password else None
        )
    except (ValueError, TypeError) as exc:
        raise CryptoError("Could not unlock private key (wrong password?)") from exc


def fingerprint(pem: str) -> str:
    """Short, human-comparable SHA-256 fingerprint: 'B5BC 7916 E69B ...' (128 bits)."""
    digest = hashlib.sha256(load_public_key(pem).public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).hexdigest().upper()[:32]
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


# --------------------------------------------------------------------------- RSA operations

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def rsa_wrap(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    return public_key.encrypt(data, _OAEP)


def rsa_unwrap(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    try:
        return private_key.decrypt(data, _OAEP)
    except ValueError as exc:
        raise CryptoError("Could not unwrap key") from exc


def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(data, _PSS, hashes.SHA256())


def verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> None:
    try:
        public_key.verify(signature, data, _PSS, hashes.SHA256())
    except InvalidSignature as exc:
        raise CryptoError("Invalid signature") from exc


# --------------------------------------------------------------------------- AES-GCM

def new_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=AES_KEY_BYTES * 8)


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_BYTES)   # never reuse a nonce with the same key
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError("Ciphertext was modified or the key is wrong") from exc


# --------------------------------------------------------------------------- E2E messages

def _signed_part(packet: dict) -> bytes:
    """Everything except the signature itself is covered by the signature."""
    return canonical_json({k: packet[k] for k in ("header", "ek", "nonce", "ct")})


def encrypt_message(sender_private, recipient_public, header: dict, plaintext: bytes) -> dict:
    """Hybrid encryption and signature."""
    msg_key = new_aes_key()
    nonce, ct = aes_encrypt(msg_key, plaintext, canonical_json(header))
    packet = {
        "header": header,
        "ek": b64e(rsa_wrap(recipient_public, msg_key)),
        "nonce": b64e(nonce),
        "ct": b64e(ct),
    }
    packet["sig"] = b64e(sign(sender_private, _signed_part(packet)))
    return packet


def decrypt_message(recipient_private, sender_public, packet: dict) -> bytes:
    """Verify the signature FIRST, then unwrap the key, then decrypt."""
    try:
        verify(sender_public, b64d(packet["sig"]), _signed_part(packet))
        msg_key = rsa_unwrap(recipient_private, b64d(packet["ek"]))
        return aes_decrypt(msg_key, b64d(packet["nonce"]), b64d(packet["ct"]),
                           canonical_json(packet["header"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise CryptoError("Malformed packet") from exc
