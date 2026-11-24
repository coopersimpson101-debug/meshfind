"""Rotating-key ratchet for meshfind tags.

A tag is provisioned with a 32-byte master secret ``MS`` shared with its owner.
Two one-way hash chains are derived from it:

* the *near-owner* chain, stepped once per epoch (default 15 min), and
* the *separated* chain, stepped once per day, used when the tag has not seen
  its owner for a while (makes unwanted-tracking detection possible, see
  docs/THREAT_MODEL.md).

    SK_0      = HKDF(MS,   info="meshfind/v1/chain-init")
    SK_{i+1}  = HKDF(SK_i, info="meshfind/v1/chain-step")
    d_i       = clamp(HKDF(SK_i, info="meshfind/v1/epoch-priv"))
    P_i       = X25519(d_i, 9)            # advertised public key
    H_i       = SHA-256(P_i)              # server index ("key hash")

The tag stores only the *current* SK_i and deletes SK_{i-1} after stepping,
so a physically compromised tag cannot reveal where it was in the past
(forward secrecy of the location history). The owner keeps MS and can derive
any epoch; ``OwnerKeyring`` caches checkpoints so that is cheap.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

from . import crypto

EPOCH_SECONDS = 15 * 60
DAY_SECONDS = 24 * 60 * 60

INFO_CHAIN_INIT = b"meshfind/v1/chain-init"
INFO_SEP_CHAIN_INIT = b"meshfind/v1/sep-chain-init"
INFO_CHAIN_STEP = b"meshfind/v1/chain-step"
INFO_EPOCH_PRIV = b"meshfind/v1/epoch-priv"
INFO_PRESENCE = b"meshfind/v1/presence"


def chain_init(master: bytes, separated: bool = False) -> bytes:
    if len(master) != 32:
        raise ValueError("master secret must be 32 bytes")
    info = INFO_SEP_CHAIN_INIT if separated else INFO_CHAIN_INIT
    return crypto.hkdf(master, b"", info, 32)


def chain_step(sk: bytes) -> bytes:
    return crypto.hkdf(sk, b"", INFO_CHAIN_STEP, 32)


def epoch_private(sk: bytes) -> bytes:
    return crypto.clamp(crypto.hkdf(sk, b"", INFO_EPOCH_PRIV, 32))


def epoch_public(sk: bytes) -> bytes:
    return crypto.x25519_base(epoch_private(sk))


def key_hash(pub: bytes) -> bytes:
    return crypto.sha256(pub)


def presence_key(master: bytes) -> bytes:
    return crypto.hkdf(master, b"", INFO_PRESENCE, 32)


def presence_token(pkey: bytes, epoch: int) -> bytes:
    """16-byte token the owner's device advertises so the tag knows its owner
    is nearby (keeps it in fast-rotating near-owner mode)."""
    return crypto.hmac_sha256(pkey, b"presence" + struct.pack("<I", epoch))[:16]


def epoch_index(t: float, epoch0: int, epoch_seconds: int = EPOCH_SECONDS) -> int:
    if t < epoch0:
        raise ValueError("time before tag provisioning")
    return int((t - epoch0) // epoch_seconds)


@dataclass
class EpochKey:
    index: int
    separated: bool
    private: bytes
    public: bytes

    @property
    def hash(self) -> bytes:
        return key_hash(self.public)


@dataclass
class TagState:
    """What a tag keeps in flash. Mirrors ``mf_tag_state_t`` in C."""

    sk: bytes
    index: int
    sep_sk: bytes
    sep_index: int
    presence_key: bytes
    epoch0: int
    epoch_seconds: int = EPOCH_SECONDS

    @classmethod
    def provision(cls, master: bytes, epoch0: int, epoch_seconds: int = EPOCH_SECONDS) -> "TagState":
        return cls(
            sk=chain_init(master),
            index=0,
            sep_sk=chain_init(master, separated=True),
            sep_index=0,
            presence_key=presence_key(master),
            epoch0=epoch0,
            epoch_seconds=epoch_seconds,
        )

    def advance_to(self, index: int) -> None:
        if index < self.index:
            raise ValueError("ratchet cannot move backwards")
        while self.index < index:
            self.sk = chain_step(self.sk)
            self.index += 1

    def advance_sep_to(self, day: int) -> None:
        if day < self.sep_index:
            raise ValueError("ratchet cannot move backwards")
        while self.sep_index < day:
            self.sep_sk = chain_step(self.sep_sk)
            self.sep_index += 1

    def current_public(self, t: float, separated: bool = False) -> bytes:
        if separated:
            self.advance_sep_to(epoch_index(t, self.epoch0, DAY_SECONDS))
            return epoch_public(self.sep_sk)
        self.advance_to(epoch_index(t, self.epoch0, self.epoch_seconds))
        return epoch_public(self.sk)


@dataclass
class OwnerKeyring:
    """Owner-side derivation of any epoch key, with checkpoint caching."""

    master: bytes
    epoch0: int
    epoch_seconds: int = EPOCH_SECONDS
    checkpoint_every: int = 96
    _cp: dict = field(default_factory=dict, repr=False)

    @classmethod
    def generate(cls, epoch0: int, epoch_seconds: int = EPOCH_SECONDS) -> "OwnerKeyring":
        return cls(master=os.urandom(32), epoch0=epoch0, epoch_seconds=epoch_seconds)

    def _sk(self, index: int, separated: bool) -> bytes:
        if index < 0:
            raise ValueError("negative epoch")
        cps = self._cp.setdefault(separated, {0: chain_init(self.master, separated)})
        base = max(i for i in cps if i <= index)
        sk = cps[base]
        i = base
        while i < index:
            sk = chain_step(sk)
            i += 1
            if i % self.checkpoint_every == 0:
                cps[i] = sk
        return sk

    def key(self, index: int, separated: bool = False) -> EpochKey:
        sk = self._sk(index, separated)
        priv = epoch_private(sk)
        return EpochKey(index, separated, priv, crypto.x25519_base(priv))

    def keys_for_window(self, t_start: float, t_end: float, slack_epochs: int = 2):
        """All keys (near-owner and separated) a tag could have used in
        [t_start, t_end], widened by ``slack_epochs`` for tag clock drift."""
        t_start = max(t_start, self.epoch0)
        lo = max(0, epoch_index(t_start, self.epoch0, self.epoch_seconds) - slack_epochs)
        hi = epoch_index(max(t_end, self.epoch0), self.epoch0, self.epoch_seconds) + slack_epochs
        out = [self.key(i) for i in range(lo, hi + 1)]
        dlo = max(0, epoch_index(t_start, self.epoch0, DAY_SECONDS) - 1)
        dhi = epoch_index(max(t_end, self.epoch0), self.epoch0, DAY_SECONDS) + 1
        out += [self.key(d, separated=True) for d in range(dlo, dhi + 1)]
        return out

    def epoch_window(self, key: EpochKey) -> tuple[float, float]:
        """Wall-clock interval during which ``key`` is advertised."""
        span = DAY_SECONDS if key.separated else self.epoch_seconds
        start = self.epoch0 + key.index * span
        return start, start + span
