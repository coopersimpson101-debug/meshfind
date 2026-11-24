"""Unknown-tracker detection on a simulated day out.

The victim's scanner samples every 60 s while they go home -> cafe -> office.
Present: a rotating stalker tag in their bag, a neighbour's tag at home, tags
at the cafe and office, a stranger walking alongside for 20 min, the victim's
own tag, and (separately) a separated-mode stalker tag.
"""

import math
import random

import pytest

from meshfind import antistalk
from meshfind.ratchet import OwnerKeyring

E0 = 1_767_225_600


def victim_path(t):
    """Piecewise route in metres; t in seconds from start."""
    legs = [  # (duration, start, end)
        (1800, (0, 0), (0, 0)),          # home
        (1200, (0, 0), (1500, 0)),       # walk to cafe
        (2400, (1500, 0), (1500, 0)),    # cafe
        (1200, (1500, 0), (1500, 1200)), # walk to office
        (3600, (1500, 1200), (1500, 1200)),
    ]
    for dur, a, b in legs:
        if t <= dur:
            f = t / dur
            return a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f
        t -= dur
    return legs[-1][2]


TOTAL = 10200


class SimTag:
    def __init__(self, rng, pos_fn, separated=False):
        self.kr = OwnerKeyring(bytes(rng.getrandbits(8) for _ in range(32)), E0 - rng.randrange(0, 900))
        self.pos_fn = pos_fn
        self.separated = separated

    def key(self, t):
        if self.separated:
            return self.kr.key(int((t - self.kr.epoch0) // 86400), True).public
        return self.kr.key(int((t - self.kr.epoch0) // 900)).public


def scan(tags, rng, t0=E0 + 3600, step=60, rng_range=40.0):
    events = []
    for s in range(0, TOTAL, step):
        t = t0 + s + rng.uniform(0, 5)
        me = victim_path(s)
        for tag in tags:
            p = tag.pos_fn(s, me)
            if p is None:
                continue
            d = math.dist(me, p)
            if d > rng_range or rng.random() > 0.9:
                continue
            rssi = int(-59 - 22 * math.log10(max(d, 0.5)) + rng.gauss(0, 3))
            events.append(antistalk.ScanEvent(t, me[0], me[1], tag.key(t), rssi, tag.separated))
    return events


def fixed(x, y):
    return lambda s, me: (x, y)


def world(rng, stalker=True, separated_stalker=False):
    tags = {
        "neighbour": SimTag(rng, fixed(8, 6)),
        "cafe1": SimTag(rng, fixed(1505, 3)),
        "cafe2": SimTag(rng, fixed(1490, -8)),
        "office1": SimTag(rng, fixed(1500, 1210)),
        "office2": SimTag(rng, fixed(1512, 1195)),
        "office3": SimTag(rng, fixed(1488, 1203)),
        "co_walker": SimTag(rng, lambda s, me: (me[0] + 3, me[1]) if 1800 <= s <= 3000 else None),
        "own": SimTag(rng, lambda s, me: (me[0] + 0.3, me[1])),
    }
    if stalker:
        tags["stalker"] = SimTag(rng, lambda s, me: (me[0] + 0.5, me[1] + 0.2))
    if separated_stalker:
        tags["sep_stalker"] = SimTag(rng, lambda s, me: (me[0], me[1] + 1) if 2400 <= s <= 4200 else None,
                                     separated=True)
    return tags


def _owner_of(alert, tags, t0=E0 + 3600):
    keys = {e.key for e in alert.group.events}
    names = set()
    for name, tag in tags.items():
        if any(tag.key(t) in keys for t in range(t0, t0 + TOTAL + 900, 300)):
            names.add(name)
    return names


def _run(seed, stalker=True):
    rng = random.Random(seed)
    tags = world(rng, stalker=stalker)
    own = {tags["own"].key(t) for t in range(E0, E0 + 4 * 86400, 900)}
    alerts = antistalk.detect(scan(list(tags.values()), rng), own_keys=own)
    return tags, alerts, set().union(*(_owner_of(a, tags) for a in alerts)) if alerts else set()


@pytest.mark.parametrize("seed", range(8))
def test_rotating_stalker_detected(seed):
    tags, alerts, flagged = _run(seed)
    assert "stalker" in flagged, "stalker not detected"
    # the stalker's key group really spans several rotations
    assert max(len(a.group.tracks) for a in alerts) >= 4


def test_detection_and_false_alarm_rates():
    """Statistical bar over 40 simulated days with and without a stalker.
    (larger measurement in README.)"""
    detected = sum("stalker" in _run(500 + s)[2] for s in range(40))
    false_alarm_days = sum(bool(_run(900 + s, stalker=False)[2]) for s in range(40))
    assert detected == 40
    assert false_alarm_days <= 4


def test_own_tag_would_alert_if_not_excluded():
    rng = random.Random(42)
    tags = world(rng, stalker=False)
    alerts = antistalk.detect(scan(list(tags.values()), rng))
    assert {n for a in alerts for n in _owner_of(a, tags)} == {"own"}


def test_separated_mode_stalker_detected_quickly():
    rng = random.Random(7)
    tags = world(rng, stalker=False, separated_stalker=True)
    own = {tags["own"].key(t) for t in range(E0, E0 + 4 * 86400, 900)}
    alerts = antistalk.detect(scan(list(tags.values()), rng), own_keys=own)
    assert [a.separated for a in alerts] == [True]
    assert _owner_of(alerts[0], tags) == {"sep_stalker"}
    assert "separated-mode" in alerts[0].describe()


def test_stitching_links_rotations():
    rng = random.Random(3)
    tag = SimTag(rng, lambda s, me: (me[0] + 1, me[1]))
    groups = antistalk.stitch(scan([tag], rng))
    assert len(groups) == 1
    assert len(groups[0].tracks) >= 10
