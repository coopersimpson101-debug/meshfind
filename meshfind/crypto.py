"""Thin, explicit wrappers around the primitives meshfind uses.

Everything in the protocol is built from exactly four primitives:

* X25519 (RFC 7748)            -- tag keys and relay ephemeral keys
* HKDF-SHA256 (RFC 5869)       -- every derivation (ratchet, epoch keys, ECIES)
* ChaCha20-Poly1305 (RFC 8439) -- report encryption (AEAD)
* SHA-256 (FIPS 180-4)         -- report index (key hash) and message ids

The Python reference uses the ``cryptography`` package; the firmware uses a
portable C implementation (``firmware/common/src/mf_crypto_ref.c``) or mbedTLS.
Both are checked against the same JSON vectors.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

__all__ = [
    "InvalidTag",
    "sha256",
    "hmac_sha256",
    "hkdf",
    "clamp",
    "x25519",
    "x25519_base",
    "aead_encrypt",
    "aead_decrypt",
]

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 extract-and-expand (RFC 5869).

    Implemented directly (rather than via ``cryptography``'s HKDF class) so the
    exact construction mirrored in C is obvious. An empty salt means 32 zero
    bytes, as in the RFC.
    """
    if length > 255 * 32:
        raise ValueError("HKDF length too large")
    if not salt:
        salt = b"\x00" * 32
    prk = hmac_sha256(salt, ikm)
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        out += t
        counter += 1
    return out[:length]


def clamp(scalar: bytes) -> bytes:
    """RFC 7748 scalar clamping. X25519 implementations clamp internally;
    we clamp explicitly so stored private keys are canonical."""
    if len(scalar) != 32:
        raise ValueError("scalar must be 32 bytes")
    b = bytearray(scalar)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def x25519(scalar: bytes, u: bytes) -> bytes:
    """Raw X25519 function. Raises ValueError on an all-zero shared secret
    (low-order input point), which we must reject in ECIES."""
    priv = X25519PrivateKey.from_private_bytes(scalar)
    pub = X25519PublicKey.from_public_bytes(u)
    return priv.exchange(pub)


def x25519_base(scalar: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(scalar)
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """ChaCha20-Poly1305; returns ciphertext || 16-byte tag."""
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag on any tampering."""
    return ChaCha20Poly1305(key).decrypt(nonce, ct_and_tag, aad)
