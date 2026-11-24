import pytest

from meshfind import adv, uwb
from meshfind.ratchet import OwnerKeyring

kr = OwnerKeyring(bytes(range(32)), 1_767_225_600)
SK = kr._sk(12, False)


def test_ranging_request_auth_and_replay():
    nonce = bytes(range(8))
    p = uwb.encode_request(SK, 12, nonce)
    assert len(p) == uwb.RANGING_REQ_LEN <= 31
    seen: set = set()
    assert uwb.verify_request(SK, 12, p, seen) == nonce
    with pytest.raises(adv.AdvError):
        uwb.verify_request(SK, 12, p, seen)  # replay
    with pytest.raises(adv.AdvError):
        uwb.verify_request(SK, 13, uwb.encode_request(SK, 12, b"\x01" * 8), set())  # wrong epoch
    with pytest.raises(adv.AdvError):
        uwb.verify_request(kr._sk(13, False), 12, uwb.encode_request(SK, 12, b"\x02" * 8), set())


def test_sts_key_unique_per_session_and_epoch():
    keys = {uwb.sts_key(kr._sk(e, False), n.to_bytes(8, "little")) for e in range(5) for n in range(5)}
    assert len(keys) == 25 and all(len(k) == 16 for k in keys)


@pytest.mark.parametrize("dist,ppm_a,ppm_b", [(0.5, 20, -20), (3.0, -15, 10), (12.0, 40, -5)])
def test_ds_twr_cancels_clock_drift(dist, ppm_a, ppm_b):
    tof = dist / uwb.SPEED_OF_LIGHT
    reply_b, reply_a = 300e-6, 450e-6  # responder / initiator turnaround (true time)
    ka, kb = 1 + ppm_a * 1e-6, 1 + ppm_b * 1e-6  # clock scale errors
    round_a = (2 * tof + reply_b) * ka
    round_b = (2 * tof + reply_a) * kb
    est = uwb.distance_m(uwb.ds_twr_tof(round_a, reply_a * ka, round_b, reply_b * kb))
    assert abs(est - dist) < 0.01
    ss = uwb.distance_m(uwb.ss_twr_tof(round_a, reply_b * kb))
    assert abs(ss - dist) > 0.5  # single-sided is wrecked by tens of ppm
