"""Ratchet determinism, owner/tag agreement and unlinkability properties."""

import itertools

import pytest

from meshfind import adv, ratchet
from meshfind.ratchet import OwnerKeyring, TagState

MASTER = bytes(range(32))
E0 = 1_767_225_600


def test_tag_and_owner_agree_over_many_epochs():
    kr = OwnerKeyring(MASTER, E0)
    tag = TagState.provision(MASTER, E0)
    for i in list(range(0, 300, 7)) + [1000]:
        t = E0 + i * 900 + 450
        assert tag.current_public(t) == kr.key(i).public
    for d in (0, 1, 5, 11):
        assert tag.current_public(E0 + d * 86400 + 10, separated=True) == kr.key(d, True).public


def test_checkpoints_do_not_change_results():
    a = OwnerKeyring(MASTER, E0, checkpoint_every=5)
    b = OwnerKeyring(MASTER, E0, checkpoint_every=10_000)
    for i in (0, 4, 5, 6, 37, 99, 13, 250):
        assert a.key(i).public == b.key(i).public


def test_ratchet_is_one_way_and_cannot_rewind():
    tag = TagState.provision(MASTER, E0)
    tag.advance_to(10)
    with pytest.raises(ValueError):
        tag.advance_to(9)
    kr = OwnerKeyring(MASTER, E0)
    assert tag.sk == kr._sk(10, False)
    # the tag's stored state equals none of the earlier chain values
    assert all(tag.sk != kr._sk(i, False) for i in range(10))


def test_epoch_index():
    assert ratchet.epoch_index(E0, E0) == 0
    assert ratchet.epoch_index(E0 + 899.9, E0) == 0
    assert ratchet.epoch_index(E0 + 900, E0) == 1
    with pytest.raises(ValueError):
        ratchet.epoch_index(E0 - 1, E0)


def test_keys_unique_and_no_constant_byte_positions():
    kr = OwnerKeyring(MASTER, E0)
    keys = [kr.key(i).public for i in range(400)] + [kr.key(d, True).public for d in range(30)]
    assert len(set(keys)) == len(keys)
    addrs = [adv.encode(adv.TagAdvert(k))[0] for k in keys]
    assert len(set(addrs)) == len(addrs)
    for pos in range(32):
        assert len({k[pos] for k in keys}) > 50


def test_consecutive_keys_look_independent():
    """Hamming distance between consecutive keys ~ 50% of the 255 usable bits."""
    kr = OwnerKeyring(MASTER, E0)
    keys = [int.from_bytes(kr.key(i).public, "little") for i in range(300)]
    dists = [bin(a ^ b).count("1") for a, b in zip(keys, keys[1:])]
    mean = sum(dists) / len(dists)
    assert 120 < mean < 135
    assert min(dists) > 90
    ones = sum(bin(k).count("1") for k in keys) / (len(keys) * 255)
    assert 0.47 < ones < 0.53


def test_different_masters_never_collide():
    a = OwnerKeyring(MASTER, E0)
    b = OwnerKeyring(bytes(reversed(MASTER)), E0)
    assert not {a.key(i).public for i in range(100)} & {b.key(i).public for i in range(100)}


def test_window_covers_drift_and_separated_keys():
    kr = OwnerKeyring(MASTER, E0)
    t = E0 + 10 * 86400 + 3600
    keys = kr.keys_for_window(t - 1800, t)
    idx = {k.index for k in keys if not k.separated}
    assert {ratchet.epoch_index(t, E0) + d for d in (-2, -1, 0, 1, 2)} <= idx
    assert any(k.separated and k.index == 10 for k in keys)


def test_presence_tokens_rotate():
    pk = ratchet.presence_key(MASTER)
    toks = [ratchet.presence_token(pk, e) for e in range(200)]
    assert len(set(toks)) == 200 and all(len(t) == 16 for t in toks)


def test_domain_separation():
    sk = ratchet.chain_init(MASTER)
    vals = [sk, ratchet.chain_init(MASTER, True), ratchet.presence_key(MASTER), ratchet.chain_step(sk),
            ratchet.epoch_private(sk)]
    assert all(a != b for a, b in itertools.combinations(vals, 2))
