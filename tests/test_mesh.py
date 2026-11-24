import os

import pytest

from meshfind import mesh
from meshfind.mesh import DIST_NONE, DedupCache, Frame, MeshNode, MeshSimulator, NodeConfig, TokenBucket


def _env():
    return bytes([1, 0]) + os.urandom(106)


def test_frame_roundtrip_and_limits():
    e = _env()
    f = Frame(mesh.T_REPORT, 9, 2, mesh.report_msg_id(e), e)
    raw = f.encode()
    assert len(raw) == 120 <= 250
    assert Frame.decode(raw) == f
    b = mesh.make_beacon(3, 77, 1_767_225_600)
    assert mesh.parse_beacon(Frame.decode(b.encode())) == (3, 77, 1_767_225_600)
    for bad in (raw[:11], b"\x00" + raw[1:], raw[:1] + b"\x21" + raw[2:], raw[:-1], raw + b"\x00" * 200):
        with pytest.raises(mesh.FrameError):
            Frame.decode(bad)


def test_should_forward_rule():
    assert mesh.should_forward(False, 1, 2, 5)
    assert not mesh.should_forward(False, 2, 2, 5)  # equal distance: not closer
    assert not mesh.should_forward(False, 3, 2, 5)
    assert not mesh.should_forward(False, 1, 2, 1)  # ttl exhausted
    assert not mesh.should_forward(True, 0, 2, 5)   # gateways deliver, never forward
    assert mesh.should_forward(False, DIST_NONE, DIST_NONE, 5)  # store-and-forward
    assert not mesh.should_forward(False, DIST_NONE, 1, 5)
    assert mesh.should_forward(False, 4, DIST_NONE, 5)


def test_dedup_cache_lru_and_expiry():
    c = DedupCache(capacity=3, lifetime=10)
    assert not c.seen(b"a", 0) and c.seen(b"a", 1)
    for k in (b"b", b"c", b"d"):
        c.seen(k, 2)
    assert len(c) == 3 and not c.seen(b"a", 3)  # evicted
    assert not c.seen(b"b", 20)  # expired


def test_token_bucket():
    b = TokenBucket(rate=2, burst=3)
    assert [b.take(0) for _ in range(4)] == [True, True, True, False]
    assert b.take(0.5) and not b.take(0.5)


def test_origination_rate_limit_per_key():
    n = MeshNode(5, cfg=NodeConfig(origin_min_interval=300))
    e1 = _env()
    e2 = e1[:66] + os.urandom(42)  # same key hash, different report
    assert n.originate(e1, 0)
    assert not n.originate(e2, 100)
    assert n.originate(e2, 301)


def test_line_topology_forwarding_and_passive_ack():
    # 0 (gateway) - 1 - 2 - 3, unit spacing, range 1.5, no loss
    sim = MeshSimulator(positions=[(0, 0), (1, 0), (2, 0), (3, 0)], n_gateways=1, radio_range=1.5, loss=0.0)
    sim.run(5)
    assert [n.dist(sim.now) for n in sim.nodes] == [0, 1, 2, 3]
    e = _env()
    sim.nodes[3].originate(e, sim.now)
    sim.run(5)
    assert sim.gateway_deliveries() == [e]
    # acks (passive or gateway) emptied every queue: no endless retries
    assert all(not n.queue for n in sim.nodes)
    # time sync from beacons
    assert sim.nodes[3].clock_offset is not None


def test_store_and_forward_when_partitioned():
    sim = MeshSimulator(positions=[(0, 0), (1, 0), (2, 0)], n_gateways=1, radio_range=1.5, loss=0.0)
    gw = sim.nodes[0]
    gw.is_gateway = False  # gateway is down: nobody has a route
    sim.run(3)
    e = _env()
    sim.nodes[2].originate(e, sim.now)
    sim.run(5)
    assert not sim.gateway_deliveries()
    assert any(p.frame.msg_id == mesh.report_msg_id(e) for p in sim.nodes[2].queue)
    gw.is_gateway = True  # gateway back: beacons rebuild the gradient, queue drains
    sim._next_beacon = 0
    sim.run(10)
    assert sim.gateway_deliveries() == [e]


@pytest.mark.parametrize("seed,loss", [(1, 0.1), (2, 0.2), (3, 0.3), (4, 0.2)])
def test_random_topology_with_loss_delivers(seed, loss):
    sim = MeshSimulator(n_nodes=40, n_gateways=2, radio_range=45, loss=loss, seed=seed)
    sim.run(30)
    envs = []
    for i, n in enumerate(sim.nodes[2:]):
        e = _env()
        envs.append(e)
        n.originate(e, sim.now + i * 0.1)
    sim.run(60)
    r = sim.result(envs)
    assert r.delivery_ratio >= 0.95, r
    # efficiency: directed flooding should cost far less than a full flood
    full_flood = len(envs) * len(sim.nodes) * NodeConfig().max_retries
    assert r.transmissions < full_flood


def test_ttl_bounds_hops():
    pos = [(i, 0) for i in range(14)]
    sim = MeshSimulator(positions=pos, n_gateways=1, radio_range=1.5, loss=0.0)
    sim.run(20)
    e = _env()
    sim.nodes[13].originate(e, sim.now)  # 13 hops > DEFAULT_TTL (10)
    sim.run(20)
    assert not sim.gateway_deliveries()
    assert sum(n.stats["dropped_ttl"] for n in sim.nodes) >= 1
