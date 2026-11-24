"""Owner client: derive key hashes, query the server, decrypt, validate."""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass

from .locate import Observation
from .ratchet import EpochKey, OwnerKeyring
from .report import PT_FLAG_LOCAL_FRAME, PT_FLAG_TIME_SYNCED, Envelope, ReportError, Sighting, open_

CLOCK_SLACK_S = 30 * 60  # tolerated tag/relay clock disagreement


@dataclass(frozen=True)
class DecryptedReport:
    key: EpochKey
    sighting: Sighting
    report_id: bytes
    plausible_time: bool

    def observation(self) -> Observation:
        s = self.sighting
        if s.flags & PT_FLAG_LOCAL_FRAME:
            return Observation(s.x / 100.0, s.y / 100.0, s.rssi, s.node_id, s.seen_ts)
        # WGS84: equirectangular metres around the point -- good enough per site
        import math
        lat, lon = s.x / 1e7, s.y / 1e7
        return Observation(lon * 111_320 * math.cos(math.radians(lat)), lat * 110_574, s.rssi, s.node_id, s.seen_ts)


def query_hashes(keys: list[EpochKey], decoys: int = 0) -> list[bytes]:
    """Hashes to ask the server for, optionally padded with random decoys so
    the server learns less about how many keys (and which window) we own."""
    hs = [k.hash for k in keys] + [os.urandom(32) for _ in range(decoys)]
    order = sorted(range(len(hs)), key=lambda _: os.urandom(4))
    return [hs[i] for i in order]


def fetch(server: str, hashes: list[bytes], since: int = 0, timeout: float = 10.0) -> dict[bytes, list[bytes]]:
    body = json.dumps({"key_hashes": [h.hex() for h in hashes], "since": since}).encode()
    req = urllib.request.Request(server.rstrip("/") + "/v1/query", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (user-supplied server URL)
        data = json.loads(r.read())
    return {bytes.fromhex(k): [bytes.fromhex(e) for e in v] for k, v in data["reports"].items()}


def decrypt_all(keyring: OwnerKeyring, keys: list[EpochKey], found: dict[bytes, list[bytes]]) -> list[DecryptedReport]:
    by_hash = {k.hash: k for k in keys}
    out, seen = [], set()
    for kh, envs in found.items():
        key = by_hash.get(kh)
        if key is None:
            continue  # decoy or foreign hash
        for raw in envs:
            try:
                env = Envelope.parse(raw)
                s = open_(key.private, key.public, raw)
            except ReportError:
                continue  # forged / corrupted / not ours: drop silently
            if env.report_id in seen:
                continue
            seen.add(env.report_id)
            lo, hi = keyring.epoch_window(key)
            ok = not (s.flags & PT_FLAG_TIME_SYNCED) or (lo - CLOCK_SLACK_S <= s.seen_ts <= hi + CLOCK_SLACK_S)
            out.append(DecryptedReport(key, s, env.report_id, ok))
    out.sort(key=lambda r: r.sighting.seen_ts)
    return out


def latest_window(reports: list[DecryptedReport], window_s: int = 15 * 60) -> list[DecryptedReport]:
    """Reports within ``window_s`` of the newest plausible one."""
    good = [r for r in reports if r.plausible_time]
    if not good:
        return []
    t1 = good[-1].sighting.seen_ts
    return [r for r in good if r.sighting.seen_ts >= t1 - window_s]
