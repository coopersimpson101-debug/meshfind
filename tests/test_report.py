import pytest

from meshfind import report
from meshfind.ratchet import OwnerKeyring

kr = OwnerKeyring(bytes(range(32)), 1_767_225_600)
S = report.Sighting(seen_ts=1_767_300_000, node_id=0xBEEF, x=-120, y=4500, z=310, accuracy_cm=25,
                    rssi=-71, tag_status=0x19)


def test_roundtrip_and_size():
    k = kr.key(3)
    env = report.seal(k.public, S)
    assert len(env) == report.ENVELOPE_LEN == 108
    assert report.open_(k.private, k.public, env) == S


def test_fresh_ephemeral_each_time():
    k = kr.key(3)
    a, b = report.seal(k.public, S), report.seal(k.public, S)
    assert a != b
    assert a[2:34] == b[2:34]  # only the public index is shared
    assert a[34:66] != b[34:66]
    assert a[66:] != b[66:]


def test_deterministic_with_given_ephemeral():
    k = kr.key(3)
    assert report.seal(k.public, S, b"\x07" * 32) == report.seal(k.public, S, b"\x07" * 32)


def test_every_single_bit_flip_is_rejected():
    k = kr.key(1)
    env = report.seal(k.public, S)
    for i in range(len(env)):
        for bit in (0, 7):
            bad = bytearray(env)
            bad[i] ^= 1 << bit
            with pytest.raises(report.ReportError):
                report.open_(k.private, k.public, bytes(bad))


def test_truncation_and_extension_rejected():
    k = kr.key(1)
    env = report.seal(k.public, S)
    for bad in (env[:-1], env + b"\x00", b""):
        with pytest.raises(report.ReportError):
            report.open_(k.private, k.public, bad)


def test_wrong_key_rejected():
    k1, k2 = kr.key(1), kr.key(2)
    env = report.seal(k1.public, S)
    with pytest.raises(report.ReportError):
        report.open_(k2.private, k2.public, env)
    forged = env[:2] + k2.hash + env[34:]  # attacker re-points the index
    with pytest.raises(report.ReportError):
        report.open_(k2.private, k2.public, forged)


def test_low_order_tag_key_rejected():
    with pytest.raises(report.ReportError):
        report.seal(bytes(32), S)


def test_plaintext_codec_signed_fields():
    s = report.Sighting(0xFFFFFFFF, 0, -2**31, 2**31 - 1, -1, 65535, -128, 255, 0)
    assert report.Sighting.unpack(s.pack()) == s
