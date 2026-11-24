"""Owner-side position estimation from decrypted sightings.

Fixed mesh nodes know their own position (configured at install time), so the
owner can localise a tag indoors without GPS:

* ``weighted_centroid`` -- robust, works with 1+ nodes; weights 1/d^2 where d
  comes from a log-distance path-loss model.
* ``trilaterate`` -- maximum-likelihood fit under log-normal shadowing: find
  the position p minimising sum_i (rssi_i - (A - 10 n log10 |p - n_i|))^2,
  with the tag's 1 m reference power A solved in closed form at every step
  (so differing tag TX powers do not bias the result). Needs >= 3 nodes.

Pure Python, 2-D (floors are handled by grouping nodes per floor upstream).
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass


@dataclass(frozen=True)
class PathLoss:
    p0: float = -59.0   # dBm at 1 m (typical ESP32-C3 at 0 dBm TX)
    n: float = 2.2      # path-loss exponent (2 free space, 2-3.5 indoors)

    def distance(self, rssi: float) -> float:
        return max(0.3, 10 ** ((self.p0 - rssi) / (10 * self.n)))

    def rssi(self, d: float) -> float:
        return self.p0 - 10 * self.n * math.log10(max(d, 0.3))


@dataclass(frozen=True)
class Observation:
    x: float      # metres
    y: float
    rssi: float
    node_id: int = 0
    t: float = 0.0


def _per_node(obs: list[Observation]) -> list[Observation]:
    """Median RSSI per node: multiple advertisements average out fast fading."""
    groups: dict[tuple, list[Observation]] = {}
    for o in obs:
        groups.setdefault((o.node_id, o.x, o.y), []).append(o)
    return [Observation(k[1], k[2], statistics.median(o.rssi for o in g), k[0], max(o.t for o in g))
            for k, g in groups.items()]


def weighted_centroid(obs: list[Observation], model: PathLoss = PathLoss()) -> tuple[float, float]:
    pts = _per_node(obs)
    if not pts:
        raise ValueError("no observations")
    ws = [1.0 / model.distance(o.rssi) ** 2 for o in pts]
    s = sum(ws)
    return sum(w * o.x for w, o in zip(ws, pts)) / s, sum(w * o.y for w, o in zip(ws, pts)) / s


PRIOR_WEIGHT = 10.0  # strength of the prior A ~ model.p0, in "virtual observations" (tuned in simulation)


def _cost(p, pts, model, box):
    if not (box[0] <= p[0] <= box[1] and box[2] <= p[1] <= box[3]):
        return math.inf
    n = model.n
    ds = [max(0.3, math.hypot(p[0] - o.x, p[1] - o.y)) for o in pts]
    # closed-form MAP estimate of the tag's 1 m reference power A at this
    # position (Gaussian prior around model.p0 keeps it from running away)
    a = (sum(o.rssi + 10 * n * math.log10(d) for o, d in zip(pts, ds)) + PRIOR_WEIGHT * model.p0) / (
        len(pts) + PRIOR_WEIGHT)
    return (sum((o.rssi - (a - 10 * n * math.log10(d))) ** 2 for o, d in zip(pts, ds))
            + PRIOR_WEIGHT * (a - model.p0) ** 2)


def trilaterate(obs: list[Observation], model: PathLoss = PathLoss(), iters: int = 200) -> tuple[float, float]:
    pts = _per_node(obs)
    if len(pts) < 3:
        return weighted_centroid(obs, model)
    p = list(weighted_centroid(obs, model))
    xs = [o.x for o in pts]
    ys = [o.y for o in pts]
    span = max(max(xs) - min(xs), max(ys) - min(ys), 1.0)
    m = max(5.0, 0.25 * span)  # the tag is assumed to be near the hearing nodes
    box = (min(xs) - m, max(xs) + m, min(ys) - m, max(ys) + m)
    # multi-start pattern search: derivative-free, robust to the log singularity
    best = (p, _cost(p, pts, model, box))
    starts = [p] + [[o.x + 0.5, o.y + 0.5] for o in sorted(pts, key=lambda o: -o.rssi)[:3]]
    for s in starts:
        q, c, step = list(s), _cost(s, pts, model, box), span / 4
        for _ in range(iters):
            improved = False
            for dx, dy in ((step, 0), (-step, 0), (0, step), (0, -step),
                           (step, step), (-step, -step), (step, -step), (-step, step)):
                cand = [q[0] + dx, q[1] + dy]
                cc = _cost(cand, pts, model, box)
                if cc < c:
                    q, c, improved = cand, cc, True
                    break
            if not improved:
                step /= 2
                if step < 0.01:
                    break
        if c < best[1]:
            best = (q, c)
    return best[0][0], best[0][1]


def estimate(obs: list[Observation], model: PathLoss = PathLoss()) -> tuple[float, float, str]:
    method = "trilateration" if len(_per_node(obs)) >= 3 else "weighted-centroid"
    fn = trilaterate if method == "trilateration" else weighted_centroid
    x, y = fn(obs, model)
    return x, y, method
