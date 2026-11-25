import pytest

from meshfind import adv
from meshfind.ratchet import OwnerKeyring

kr = OwnerKeyring(bytes(range(32)), 1_767_225_600)


@pytest.mark.parametrize("i", range(40))
def test_roundtrip(i):
    k = kr.key(i).public
    a = adv.TagAdvert(k, battery=i % 4, separated=bool(i % 3 == 0))
    addr, payload = adv.encode(a)
    assert len(payload) == 31 and len(addr) == 6
    assert addr[0] & 0xC0 == 0xC0  # static random address
    assert adv.decode(addr, payload) == a


def test_all_top_bit_combinations():
    for top in range(4):
        k = bytes([(top << 6) | 0x15]) + bytes(range(1, 32))
        addr, payload = adv.encode(adv.TagAdvert(k))
        assert adv.decode(addr, payload).public_key == k


def test_layout():
    k = bytes(range(32))
    addr, p = adv.encode(adv.TagAdvert(k, adv.BATT_LOW, True))
    assert addr == bytes([0xC0, 1, 2, 3, 4, 5])
    assert p[:4] == bytes([0x1E, 0xFF, 0xFF, 0xFF])
    assert p[4] == (2 << 4) | 0x08 | 1
    assert p[5:] == k[6:]


@pytest.mark.parametrize("mutate", [
    lambda a, p: (a, p[:-1]),
    lambda a, p: (a, bytes([0x1D]) + p[1:]),
    lambda a, p: (a, p[:1] + b"\x09" + p[2:]),
    lambda a, p: (a, p[:2] + b"\x4c\x00" + p[4:]),
    lambda a, p: (bytes([a[0] & 0x3F]) + a[1:], p),
    lambda a, p: (a, p[:4] + bytes([(p[4] & 0xF8) | 2]) + p[5:]),
    lambda a, p: (a[:5], p),
])
def test_rejects_foreign_adverts(mutate):
    addr, p = adv.encode(adv.TagAdvert(kr.key(0).public))
    a2, p2 = mutate(addr, p)
    with pytest.raises(adv.AdvError):
        adv.decode(a2, p2)


def test_battery_aware_interval():
    assert adv.adv_interval_ms(100, False) == 2000
    assert adv.adv_interval_ms(20, False) == 4000
    assert adv.adv_interval_ms(5, False) == 8000
    assert adv.adv_interval_ms(100, True) == 1000
    assert adv.adv_interval_ms(5, True) == 4000
    for sep in (False, True):  # lower battery never advertises faster
        vals = [adv.adv_interval_ms(p, sep) for p in range(100, -1, -1)]
        assert vals == sorted(vals)


def test_duty_cycled_adv_sleep_and_current_model():
    assert adv.adv_sleep_ms(2000, 1) == 1999
    assert adv.adv_sleep_ms(1000, 1000) == 0
    assert adv.adv_sleep_ms(0, 1) == 0
    # 10 ms TX at 10 mA, 1990 ms sleep at 200 uA, 2 s interval -> ~249 uA
    assert adv.adv_avg_current_ua(2000, 10_000, 200, tx_ms=10) == 249
    # Continuous TX equals tx current
    assert adv.adv_avg_current_ua(1000, 5000, 100, tx_ms=1000) == 5000
    # Presence: 50 ms scan at 20 mA every 60 s on a 249 uA base
    assert adv.presence_avg_current_ua(60, 50, 20_000, 249) == 265
    # Longer scan raises average; zero period keeps the base
    assert adv.presence_avg_current_ua(60, 300, 20_000, 249) > adv.presence_avg_current_ua(60, 50, 20_000, 249)
    assert adv.presence_avg_current_ua(0, 50, 20_000, 249) == 249


def test_presence_beacon_roundtrip_and_never_parses_as_tag():
    from meshfind import ratchet
    pk = ratchet.presence_key(bytes(range(32)))
    tok = ratchet.presence_token(pk, 77)
    p = adv.encode_presence(tok)
    assert len(p) == adv.PRESENCE_LEN and adv.decode_presence(p) == tok
    with pytest.raises(adv.AdvError):
        adv.decode(bytes([0xC1, 2, 3, 4, 5, 6]), p + bytes(10))
    with pytest.raises(adv.AdvError):
        adv.decode_presence(p[:-1])
