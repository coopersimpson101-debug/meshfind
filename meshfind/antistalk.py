"""Unknown-tracker ("is something following me?") detection for scanners.

Any phone/ESP32 running a meshfind scanner sees raw advertisements. Keys
rotate, so a stalker's tag shows up as a *sequence* of short-lived keys. The
detector:

1. groups sightings by advertised key into **tracks**;
2. **stitches** tracks into **key groups** (chains): track B continues track A
   if B appears within ``max_rotation_gap`` seconds after A was last seen, at a
   similar RSSI, in the same mode, and -- once a chain has rotated before --
   at the chain's rotation phase (tags rotate every ``epoch_seconds`` exactly,
   so successive rotations are ``epoch_seconds`` apart);
3. flags a chain when it has been with the user for a long time **while the
   user moved** across several distinct places. A neighbour's tag (long
   duration, one place) or a fellow commuter (several places, short) does
   not alert.

Tags in *separated* mode keep one key for 24 h and set a flag bit, so they
need no stitching and get stricter (lower) thresholds -- this is the main
anti-stalking lever in the protocol, see docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScanEvent:
    t: float            # unix seconds
    x: float            # scanner's own position, metres (local ENU frame)
    y: float
    key: bytes          # advertised public key (address + payload, see adv.py)
    rssi: int
    separated: bool = False


@dataclass
class Track:
    key: bytes
    separated: bool
    events: list[ScanEvent] = field(default_factory=list)

    @property
    def first(self) -> float:
        return self.events[0].t

    @property
    def last(self) -> float:
        return self.events[-1].t

    def edge_rssi(self, head: bool, k: int = 3) -> float:
        ev = self.events[:k] if head else self.events[-k:]
        return statistics.median(e.rssi for e in ev)


@dataclass
class KeyGroup:
    tracks: list[Track]
    confirmed: int = 0  # rotations whose timing matched the chain's rotation phase

    @property
    def events(self) -> list[ScanEvent]:
        return [e for t in self.tracks for e in t.events]

    @property
    def first(self) -> float:
        return self.tracks[0].first

    @property
    def last(self) -> float:
        return self.tracks[-1].last

    @property
    def separated(self) -> bool:
        return any(t.separated for t in self.tracks)

    @property
    def rotations(self) -> list[float]:
        return [t.first for t in self.tracks[1:]]


@dataclass(frozen=True)
class Alert:
    group: KeyGroup
    duration_s: float
    places: int
    displacement_m: float
    separated: bool

    def describe(self) -> str:
        mode = "separated-mode" if self.separated else "rotating"
        return (f"Unknown {mode} tracker has been near you for {self.duration_s / 60:.0f} min "
                f"across {self.places} places ({self.displacement_m:.0f} m travelled); "
                f"{len(self.group.tracks)} key(s), latest key {self.group.tracks[-1].key[:6].hex()}")


@dataclass
class DetectorConfig:
    epoch_seconds: int = 900
    max_rotation_gap: float = 180.0
    phase_tolerance: float = 60.0
    min_confirmed_rotations: int = 2
    max_merge_gap: float = 300.0
    merge_slack: float = 30.0
    max_rssi_jump: float = 12.0
    place_radius_m: float = 250.0
    min_duration_s: float = 45 * 60
    min_places: int = 3
    min_displacement_m: float = 500.0
    sep_min_duration_s: float = 15 * 60
    sep_min_places: int = 2


def _tracks(events: list[ScanEvent]) -> list[Track]:
    by: dict[bytes, Track] = {}
    for e in sorted(events, key=lambda e: e.t):
        tr = by.setdefault(e.key, Track(e.key, e.separated))
        tr.events.append(e)
    return sorted(by.values(), key=lambda t: t.first)


def stitch(events: list[ScanEvent], cfg: DetectorConfig = DetectorConfig()) -> list[KeyGroup]:
    groups: list[KeyGroup] = []
    for tr in _tracks(events):
        if tr.separated:
            groups.append(KeyGroup([tr]))
            continue
        best, best_score, best_phase = None, math.inf, False
        for g in groups:
            tail = g.tracks[-1]
            if g.separated:
                continue
            gap = tr.first - tail.last
            if not (-5.0 <= gap <= cfg.max_rotation_gap):
                continue
            drssi = abs(tr.edge_rssi(True) - tail.edge_rssi(False))
            if drssi > cfg.max_rssi_jump:
                continue
            phase_ok = False
            if g.rotations:
                # successive rotations must be ~k*epoch apart
                since = tr.first - g.rotations[-1]
                k = max(1, round(since / cfg.epoch_seconds))
                if abs(since - k * cfg.epoch_seconds) > cfg.phase_tolerance:
                    continue
                phase_ok = True
            score = abs(gap) / cfg.max_rotation_gap + drssi / cfg.max_rssi_jump - phase_ok
            if score < best_score:
                best, best_score, best_phase = g, score, phase_ok
        if best is None:
            groups.append(KeyGroup([tr]))
        else:
            best.tracks.append(tr)
            best.confirmed += best_phase
    return _merge_fragments(groups, cfg)


def _phase_ok(a: float, b: float, cfg: DetectorConfig) -> bool:
    k = max(1, round((b - a) / cfg.epoch_seconds))
    return abs((b - a) - k * cfg.epoch_seconds) <= cfg.phase_tolerance


def _merge_fragments(groups: list[KeyGroup], cfg: DetectorConfig) -> list[KeyGroup]:
    """Second pass: re-join chains broken by missed scans around a rotation.

    Fragment B continues fragment A if it starts within ``max_merge_gap`` of
    A's end, at a similar RSSI, and B's rotations are on A's rotation phase.
    """
    groups = sorted(groups, key=lambda g: g.first)
    out: list[KeyGroup] = []
    for g in groups:
        target = None
        if not g.separated and g.rotations:
            for a in out:
                if a.separated or not a.rotations:
                    continue
                gap = g.first - a.last
                if not (0 <= gap <= cfg.max_merge_gap):
                    continue
                if abs(g.tracks[0].edge_rssi(True) - a.tracks[-1].edge_rssi(False)) > cfg.max_rssi_jump:
                    continue
                # the missed rotation must fall inside the gap, on a's phase ...
                r0, ep = a.rotations[-1], cfg.epoch_seconds
                k = math.ceil((a.last - cfg.merge_slack - r0) / ep)
                if r0 + k * ep > g.first + cfg.merge_slack:
                    continue
                # ... and g's own rotations must be on the same phase
                if _phase_ok(r0, g.rotations[0], cfg):
                    target = a
                    break
        if target is None:
            out.append(g)
        else:
            target.tracks.extend(g.tracks)
            target.confirmed += g.confirmed + 1
    return out


def _places(events: list[ScanEvent], radius: float) -> int:
    centres: list[tuple[float, float]] = []
    for e in events:
        if all(math.hypot(e.x - cx, e.y - cy) > radius for cx, cy in centres):
            centres.append((e.x, e.y))
    return len(centres)


def _displacement(events: list[ScanEvent]) -> float:
    d = 0.0
    for a, b in zip(events, events[1:]):
        d += math.hypot(b.x - a.x, b.y - a.y)
    return d


def detect(events: list[ScanEvent], own_keys: set[bytes] = frozenset(),
           cfg: DetectorConfig = DetectorConfig()) -> list[Alert]:
    """Returns alerts for key groups that appear to travel with the scanner.
    ``own_keys`` (the user's own tags, derivable from their keyring) are ignored."""
    alerts = []
    for g in stitch([e for e in events if e.key not in own_keys], cfg):
        ev = sorted(g.events, key=lambda e: e.t)
        dur = g.last - g.first
        places = _places(ev, cfg.place_radius_m)
        disp = _displacement(ev)
        if g.separated:
            hit = dur >= cfg.sep_min_duration_s and places >= cfg.sep_min_places
        else:
            hit = (dur >= cfg.min_duration_s and places >= cfg.min_places
                   and g.confirmed >= cfg.min_confirmed_rotations)
        if hit and disp >= cfg.min_displacement_m:
            alerts.append(Alert(g, dur, places, disp, g.separated))
    return alerts
