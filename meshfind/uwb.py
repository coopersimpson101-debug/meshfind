"""UWB last-metre extension (design + reference maths; no radio code yet).

For tags fitted with a Qorvo DW3000, the owner can range to the tag with
double-sided two-way ranging (DS-TWR). See docs/UWB.md for the full message
design. This module holds the parts that are protocol, not driver:

* the BLE *ranging request* the owner broadcasts to wake the tag's UWB radio,
  authenticated so strangers cannot drain the battery or probe for the tag;
* the per-session STS (scrambled timestamp sequence) key, so only the owner
  can obtain secure (tamper-resistant) range measurements;
* the DS-TWR time-of-flight estimator, which cancels first-order clock drift.
"""

from __future__ import annotations

import hmac
import struct

from . import crypto
from .adv import AD_TYPE_MSD, COMPANY_ID, AdvError

SPEED_OF_LIGHT = 299_702_547.0  # m/s in air
DW_TIME_UNIT = 1.0 / (499.2e6 * 128)  # DW3000 timestamp tick, ~15.65 ps
RANGING_MARKER = 0x51
RANGING_REQ_LEN = 29
INFO_UWB_REQ = b"meshfind/v1/uwb-req"
INFO_UWB_STS = b"meshfind/v1/uwb-sts"


def request_key(sk: bytes) -> bytes:
    return crypto.hkdf(sk, b"", INFO_UWB_REQ, 32)


def sts_key(sk: bytes, nonce: bytes) -> bytes:
    """128-bit AES key for the DW3000 STS, unique per epoch and session."""
    return crypto.hkdf(sk, nonce, INFO_UWB_STS, 16)


def encode_request(sk: bytes, epoch: int, nonce: bytes) -> bytes:
    """[0x1C][0xFF][0xFFFF][0x51][nonce 8][HMAC(req_key, epoch|nonce)[:16]] (29 bytes)."""
    if len(nonce) != 8:
        raise AdvError("nonce must be 8 bytes")
    tag = crypto.hmac_sha256(request_key(sk), struct.pack("<I", epoch) + nonce)[:16]
    return bytes([0x1C, AD_TYPE_MSD, COMPANY_ID & 0xFF, COMPANY_ID >> 8, RANGING_MARKER]) + nonce + tag


def verify_request(sk: bytes, epoch: int, payload: bytes, seen_nonces: set[bytes]) -> bytes:
    """Tag side. Returns the nonce if authentic and fresh, else raises AdvError."""
    if len(payload) != RANGING_REQ_LEN or payload[4] != RANGING_MARKER or payload[:2] != b"\x1c\xff":
        raise AdvError("not a ranging request")
    nonce, tag = payload[5:13], payload[13:29]
    expect = crypto.hmac_sha256(request_key(sk), struct.pack("<I", epoch) + nonce)[:16]
    if not hmac.compare_digest(tag, expect):
        raise AdvError("bad ranging request MAC")
    if nonce in seen_nonces:
        raise AdvError("replayed ranging request")
    seen_nonces.add(nonce)
    return nonce


def ds_twr_tof(round_a: float, reply_a: float, round_b: float, reply_b: float) -> float:
    """Asymmetric DS-TWR (Neirynck et al.):

        ToF = (Ra*Rb - Da*Db) / (Ra + Rb + Da + Db)

    Ra: initiator Poll->Response round, Da: initiator Response->Final reply,
    Rb: responder Response->Final round, Db: responder Poll->Response reply.
    Each value is measured on its own device's clock, so a constant clock
    offset error cancels to first order.
    """
    return (round_a * round_b - reply_a * reply_b) / (round_a + round_b + reply_a + reply_b)


def ss_twr_tof(round_a: float, reply_b: float) -> float:
    """Single-sided TWR, for comparison: error grows with reply time x drift."""
    return (round_a - reply_b) / 2


def distance_m(tof_s: float) -> float:
    return tof_s * SPEED_OF_LIGHT
