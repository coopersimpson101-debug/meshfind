"""Encrypted location reports (ECIES over X25519 + HKDF + ChaCha20-Poly1305).

A relay that hears a tag advertising public key ``P`` builds a report::

    e      = clamp(random32)              # fresh per report, then erased
    E      = X25519(e, 9)
    S      = X25519(e, P)                 # reject all-zero (low-order P)
    okm    = HKDF(ikm=S, salt=E || P, info="meshfind/v1/report", L=44)
    k, n   = okm[0:32], okm[32:44]
    hdr    = ver(1)=1 | flags(1)=0 | H=SHA-256(P) (32) | E (32)
    body   = ChaCha20-Poly1305(k, n, plaintext, aad=hdr)
    report = hdr || body                  # 66 + 26 + 16 = 108 bytes

Only the holder of ``d`` (the owner) can recompute ``S``. Because every report
uses a fresh ``e``, two reports from the same relay share nothing except the
public index ``H``, which every observer of the advertisement already knows.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from . import crypto
from .ratchet import key_hash

ENV_VERSION = 1
HEADER_LEN = 66
PLAINTEXT_LEN = 26
ENVELOPE_LEN = HEADER_LEN + PLAINTEXT_LEN + crypto.TAG_LEN  # 108
INFO_REPORT = b"meshfind/v1/report"

PT_FLAG_TIME_SYNCED = 0x01
PT_FLAG_LOCAL_FRAME = 0x02  # x/y/z are centimetres in a site-local frame

_PT = struct.Struct("<BBIIiiiHbB")
assert _PT.size == PLAINTEXT_LEN


class ReportError(ValueError):
    pass


@dataclass(frozen=True)
class Sighting:
    """What the relay knows about one observation. Mirrors ``mf_sighting_t``.

    Position is either WGS84 (x=lat*1e7, y=lon*1e7, z=altitude cm) or, with
    ``PT_FLAG_LOCAL_FRAME``, centimetres in a building-local frame -- the
    natural choice for fixed indoor mesh nodes.
    """

    seen_ts: int
    node_id: int
    x: int
    y: int
    z: int
    accuracy_cm: int
    rssi: int
    tag_status: int
    flags: int = PT_FLAG_TIME_SYNCED | PT_FLAG_LOCAL_FRAME
    version: int = 1

    def pack(self) -> bytes:
        return _PT.pack(
            self.version, self.flags, self.seen_ts, self.node_id,
            self.x, self.y, self.z, self.accuracy_cm, self.rssi, self.tag_status,
        )

    @classmethod
    def unpack(cls, b: bytes) -> "Sighting":
        if len(b) != PLAINTEXT_LEN:
            raise ReportError("bad plaintext length")
        v, fl, ts, nid, x, y, z, acc, rssi, st = _PT.unpack(b)
        if v != 1:
            raise ReportError("unknown plaintext version")
        return cls(ts, nid, x, y, z, acc, rssi, st, fl, v)


def _kdf(shared: bytes, eph_pub: bytes, tag_pub: bytes) -> tuple[bytes, bytes]:
    okm = crypto.hkdf(shared, eph_pub + tag_pub, INFO_REPORT, 44)
    return okm[:32], okm[32:]


def seal(tag_pub: bytes, sighting: Sighting, eph_secret: bytes | None = None) -> bytes:
    """Relay side. ``eph_secret`` is only passed explicitly for test vectors."""
    if len(tag_pub) != 32:
        raise ReportError("tag public key must be 32 bytes")
    e = crypto.clamp(eph_secret if eph_secret is not None else os.urandom(32))
    E = crypto.x25519_base(e)
    try:
        shared = crypto.x25519(e, tag_pub)
    except ValueError as exc:  # all-zero shared secret
        raise ReportError("low-order tag key rejected") from exc
    if shared == bytes(32):
        raise ReportError("low-order tag key rejected")
    k, n = _kdf(shared, E, tag_pub)
    hdr = bytes([ENV_VERSION, 0]) + key_hash(tag_pub) + E
    return hdr + crypto.aead_encrypt(k, n, sighting.pack(), hdr)


@dataclass(frozen=True)
class Envelope:
    version: int
    flags: int
    key_hash: bytes
    eph_pub: bytes
    body: bytes
    raw: bytes

    @classmethod
    def parse(cls, raw: bytes) -> "Envelope":
        if len(raw) != ENVELOPE_LEN:
            raise ReportError(f"envelope must be {ENVELOPE_LEN} bytes")
        if raw[0] != ENV_VERSION:
            raise ReportError("unknown envelope version")
        return cls(raw[0], raw[1], raw[2:34], raw[34:66], raw[HEADER_LEN:], raw)

    @property
    def report_id(self) -> bytes:
        """Server-side dedup / replay key: the ephemeral key is unique per report."""
        return crypto.sha256(self.raw)[:16]


def open_(tag_priv: bytes, tag_pub: bytes, raw: bytes) -> Sighting:
    """Owner side. Raises ReportError on any mismatch or tampering."""
    env = Envelope.parse(raw)
    if env.key_hash != key_hash(tag_pub):
        raise ReportError("report is not for this key")
    try:
        shared = crypto.x25519(tag_priv, env.eph_pub)
    except ValueError as exc:
        raise ReportError("invalid ephemeral key") from exc
    k, n = _kdf(shared, env.eph_pub, tag_pub)
    try:
        pt = crypto.aead_decrypt(k, n, env.body, raw[:HEADER_LEN])
    except crypto.InvalidTag as exc:
        raise ReportError("authentication failed") from exc
    return Sighting.unpack(pt)
