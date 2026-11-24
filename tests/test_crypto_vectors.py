"""Published test vectors for every primitive (RFC 5869, 7748, 8439, FIPS 180)."""

import pytest

from meshfind import crypto
from meshfind.vectors import RFC_AEAD, RFC_AEAD_PT, RFC_HKDF, RFC_SHA256, RFC_X25519


@pytest.mark.parametrize("msg,digest", RFC_SHA256)
def test_sha256(msg, digest):
    assert crypto.sha256(bytes.fromhex(msg)).hex() == digest


@pytest.mark.parametrize("v", RFC_HKDF)
def test_hkdf_rfc5869(v):
    out = crypto.hkdf(bytes.fromhex(v["ikm"]), bytes.fromhex(v["salt"]), bytes.fromhex(v["info"]), v["length"])
    assert out.hex() == v["okm"]


def test_hkdf_matches_cryptography_library():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    for n in (1, 32, 44, 77):
        ref = HKDF(hashes.SHA256(), n, b"salty", b"info").derive(b"ikm-bytes")
        assert crypto.hkdf(b"ikm-bytes", b"salty", b"info", n) == ref


@pytest.mark.parametrize("v", RFC_X25519)
def test_x25519_rfc7748(v):
    assert crypto.x25519(bytes.fromhex(v["scalar"]), bytes.fromhex(v["u"])).hex() == v["out"]


def test_x25519_low_order_point_rejected():
    with pytest.raises(ValueError):
        crypto.x25519(crypto.clamp(bytes(range(32))), bytes(32))


def test_chacha20poly1305_rfc8439():
    key, nonce, aad = (bytes.fromhex(RFC_AEAD[k]) for k in ("key", "nonce", "aad"))
    ct = crypto.aead_encrypt(key, nonce, RFC_AEAD_PT, aad)
    assert ct[-16:].hex() == RFC_AEAD["tag"]
    assert ct[:16].hex() == "d31a8d34648e60db7b86afbc53ef7ec2"
    assert crypto.aead_decrypt(key, nonce, ct, aad) == RFC_AEAD_PT


def test_clamp():
    c = crypto.clamp(b"\xff" * 32)
    assert c[0] == 0xF8 and c[31] == 0x7F
    assert crypto.clamp(bytes(32))[31] == 0x40
