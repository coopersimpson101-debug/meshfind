"""Position estimation accuracy on a simulated 50 m x 30 m floor with fixed
relays every 10 m (log-distance path loss, 4 dB shadowing, full mesh path)."""

import math
import random
import statistics

import pytest

from meshfind.locate import Observation, PathLoss, estimate, trilaterate, weighted_centroid
from meshfind.scenario import run_building


def _positions(n, seed=0):
    r = random.Random(seed)
    return [(r.uniform(2, 48), r.uniform(2, 28)) for _ in range(n)]


def test_noise_free_trilateration_is_exact():
    m = PathLoss()
    nodes = [(0, 0), (10, 0), (0, 10), (10, 10), (20, 5)]
    tag = (6.0, 3.0)
    obs = [Observation(x, y, m.rssi(math.dist((x, y), tag)), i) for i, (x, y) in enumerate(nodes)]
    x, y = trilaterate(obs, m)
    assert math.dist((x, y), tag) < 0.1


@pytest.mark.parametrize("p0", [-63, -55])
def test_moderate_tx_power_mismatch_is_tolerated(p0):
    m = PathLoss()
    nodes = [(0, 0), (10, 0), (0, 10), (10, 10), (20, 5), (20, 15)]
    tag = (12.0, 7.0)
    obs = [Observation(x, y, PathLoss(p0, m.n).rssi(math.dist((x, y), tag)), i) for i, (x, y) in enumerate(nodes)]
    assert math.dist(trilaterate(obs, m), tag) < 3.0


def test_centroid_with_single_node():
    x, y, method = estimate([Observation(3, 4, -70, 1)])
    assert (x, y, method) == (3, 4, "weighted-centroid")


def test_building_accuracy():
    errs, cent = [], []
    for s, pos in enumerate(_positions(40)):
        r = run_building(pos, seed=s)
        assert r.estimate is not None
        errs.append(r.error_m)
        cent.append(math.dist(weighted_centroid(r.observations), pos))
    errs.sort()
    # simulation results (see README): median ~1.1 m, p90 ~2.5 m
    assert statistics.median(errs) < 2.0
    assert errs[int(0.9 * len(errs))] < 4.0
    # trilateration beats the centroid baseline
    assert statistics.median(errs) < statistics.median(cent)


@pytest.mark.parametrize("p0", [-53, -65])
def test_building_accuracy_with_tx_power_mismatch(p0):
    errs = sorted(run_building(pos, seed=s, true_p0=p0).error_m for s, pos in enumerate(_positions(30, 7)))
    assert statistics.median(errs) < 4.0
