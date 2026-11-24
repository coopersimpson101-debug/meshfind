"""End-to-end simulated building: tag -> BLE -> relays -> mesh -> server -> owner.

Used by ``python -m meshfind simulate`` and the end-to-end tests. Radio
models are simple (log-distance path loss + Gaussian shadowing for BLE,
unit-disc + i.i.d. loss for ESP-NOW) -- see README "Honest status".
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass

from . import adv, report
from .locate import Observation, PathLoss, estimate
from .mesh import MeshSimulator, NodeConfig
from .owner import decrypt_all, latest_window
from .ratchet import OwnerKeyring, TagState
from .server import ReportStore

UNIX0 = 1_767_225_600


def grid_nodes(width: float = 50.0, depth: float = 30.0, spacing: float = 10.0) -> list[tuple[float, float]]:
    nx, ny = int(width // spacing) + 1, int(depth // spacing) + 1
    return [(i * spacing, j * spacing) for j in range(ny) for i in range(nx)]


@dataclass
class BuildingResult:
    truth: tuple[float, float]
    estimate: tuple[float, float] | None
    method: str
    error_m: float
    reports_sent: int
    reports_delivered: int
    observations: list[Observation]
    nodes: list[tuple[float, float]]


def run_building(tag_pos: tuple[float, float], seed: int = 0, nodes: list[tuple[float, float]] | None = None,
                 shadow_sigma: float = 4.0, advs_per_node: int = 7, sensitivity_dbm: float = -92.0,
                 mesh_loss: float = 0.15, mesh_range: float = 22.0, model: PathLoss = PathLoss(),
                 true_p0: float | None = None) -> BuildingResult:
    rng = random.Random(seed)
    nodes = nodes or grid_nodes()
    keyring = OwnerKeyring(bytes(rng.getrandbits(8) for _ in range(32)), UNIX0)
    tag = TagState.provision(keyring.master, UNIX0)
    t = UNIX0 + 3 * 86400 + rng.uniform(0, 86400)
    pub = tag.current_public(t)
    addr, payload = adv.encode(adv.TagAdvert(pub, adv.battery_level(80), False))

    sim = MeshSimulator(positions=nodes, n_gateways=1, radio_range=mesh_range, loss=mesh_loss, seed=seed,
                        cfg=NodeConfig())
    sim.run(25.0)  # let beacons build the gradient
    p0 = model.p0 if true_p0 is None else true_p0
    sent: list[bytes] = []
    for nid, (nx, ny) in enumerate(nodes):
        d = math.hypot(nx - tag_pos[0], ny - tag_pos[1])
        heard = [PathLoss(p0, model.n).rssi(d) + rng.gauss(0, shadow_sigma) for _ in range(advs_per_node)]
        heard = [r for r in heard if r >= sensitivity_dbm]
        if not heard:
            continue
        seen = adv.decode(addr, payload)  # relay parses the advertisement
        s = report.Sighting(seen_ts=int(t), node_id=0x5000 + nid, x=int(nx * 100), y=int(ny * 100), z=0,
                            accuracy_cm=20, rssi=int(round(statistics.median(heard))),
                            tag_status=seen.status_bits)
        env = report.seal(seen.public_key, s)
        if sim.nodes[nid].originate(env, sim.now):
            sent.append(env)
    sim.run(30.0)

    store = ReportStore()
    for env in sim.gateway_deliveries():
        store.add(env)
    keys = keyring.keys_for_window(t - 3600, t + 60)
    found = store.query([k.hash for k in keys])
    recent = latest_window(decrypt_all(keyring, keys, found))
    obs = [r.observation() for r in recent]
    if obs:
        ex, ey, method = estimate(obs, model)
        err = math.hypot(ex - tag_pos[0], ey - tag_pos[1])
        est = (ex, ey)
    else:
        est, method, err = None, "none", math.inf
    delivered = len(set(sim.gateway_deliveries()) & set(sent))
    return BuildingResult(tag_pos, est, method, err, len(sent), delivered, obs, nodes)


