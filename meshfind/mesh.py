"""Store-and-forward gradient routing over a broadcast link (ESP-NOW).

Frame layout (12-byte header, little-endian), max 120 bytes, well under the
250-byte ESP-NOW v1 payload limit::

    0  u8   magic 0x4D ('M')
    1  u8   version(4 bits, =1) << 4 | type (1=REPORT, 2=BEACON, 3=ACK)
    2  u8   ttl          (hops left; decremented by each forwarder)
    3  u8   sender_dist  (sender's hop distance to the nearest gateway; 255 = none)
    4  u8[8] msg_id      REPORT: SHA-256(envelope)[:8]   (content-derived, so it
                                 identifies the report, never the relay)
                         BEACON: SHA-256("bcn" | gw_id | seq)[:8]
                         ACK:    msg_id of the delivered report
    12 ..   payload      REPORT: 108-byte envelope
                         BEACON: u32 gw_id | u32 seq | u32 unix_time
                         ACK:    empty

Routing:

* Gateways flood BEACONs; every node keeps ``dist`` = 1 + min sender_dist over
  fresh beacons, i.e. a hop-count gradient towards the closest gateway. Beacons
  also carry wall-clock time, which relays (no RTC/GPS) adopt.
* A REPORT is re-broadcast only by nodes strictly closer to a gateway than the
  sender (``my_dist < sender_dist``) -- a directed flood that needs no
  neighbour tables or addresses.
* Each forwarder keeps the frame until it hears a closer node re-broadcast it
  (passive ack) or a gateway ACK, retrying up to ``max_retries`` times.
* With no gateway route (dist = 255) frames are *stored* and forwarded when a
  beacon arrives -- store-and-forward for partitioned meshes.
* Dedup cache (msg_id, time-bounded), TTL, a token bucket on all transmissions,
  a bounded queue (oldest dropped), and a per-key origination limit protect
  the mesh from loops, storms and floods.
"""

from __future__ import annotations

import hashlib
import math
import random
import struct
from collections import OrderedDict
from dataclasses import dataclass, field

MAGIC = 0x4D
VERSION = 1
T_REPORT, T_BEACON, T_ACK = 1, 2, 3
HDR_LEN = 12
DIST_NONE = 255
DEFAULT_TTL = 10
BEACON_TTL = 16
MAX_FRAME = 250

_HDR = struct.Struct("<BBBB8s")
_BEACON = struct.Struct("<III")


class FrameError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    ftype: int
    ttl: int
    sender_dist: int
    msg_id: bytes
    payload: bytes = b""

    def encode(self) -> bytes:
        if len(self.msg_id) != 8:
            raise FrameError("msg_id must be 8 bytes")
        b = _HDR.pack(MAGIC, (VERSION << 4) | self.ftype, self.ttl, self.sender_dist, self.msg_id) + self.payload
        if len(b) > MAX_FRAME:
            raise FrameError("frame too large")
        return b

    @classmethod
    def decode(cls, b: bytes) -> "Frame":
        if len(b) < HDR_LEN or len(b) > MAX_FRAME:
            raise FrameError("bad frame length")
        magic, vt, ttl, sd, mid = _HDR.unpack(b[:HDR_LEN])
        if magic != MAGIC or vt >> 4 != VERSION:
            raise FrameError("bad magic/version")
        ftype = vt & 0x0F
        payload = b[HDR_LEN:]
        if ftype == T_REPORT and len(payload) != 108:
            raise FrameError("bad report length")
        if ftype == T_BEACON and len(payload) != _BEACON.size:
            raise FrameError("bad beacon length")
        if ftype == T_ACK and payload:
            raise FrameError("bad ack length")
        if ftype not in (T_REPORT, T_BEACON, T_ACK):
            raise FrameError("unknown frame type")
        return cls(ftype, ttl, sd, mid, payload)

    def with_hop(self, ttl: int, sender_dist: int) -> "Frame":
        return Frame(self.ftype, ttl, sender_dist, self.msg_id, self.payload)


def report_msg_id(envelope: bytes) -> bytes:
    return hashlib.sha256(envelope).digest()[:8]


def beacon_msg_id(gw_id: int, seq: int) -> bytes:
    return hashlib.sha256(b"bcn" + struct.pack("<II", gw_id, seq)).digest()[:8]


def make_beacon(gw_id: int, seq: int, unix_time: int) -> Frame:
    return Frame(T_BEACON, BEACON_TTL, 0, beacon_msg_id(gw_id, seq), _BEACON.pack(gw_id, seq, unix_time))


def parse_beacon(f: Frame) -> tuple[int, int, int]:
    return _BEACON.unpack(f.payload)


def should_forward(is_gateway: bool, my_dist: int, sender_dist: int, ttl: int) -> bool:
    """Pure forwarding rule, mirrored by ``mf_mesh_should_forward`` in C.

    Returns True when a non-duplicate REPORT should be queued for forwarding.
    A node with no route (255) still stores the frame (store-and-forward) unless
    the sender is itself routed -- then a routed neighbour will handle it.
    """
    if is_gateway or ttl <= 1:
        return False
    if my_dist == DIST_NONE:
        return sender_dist == DIST_NONE
    return my_dist < sender_dist


class DedupCache:
    """Bounded, time-limited set of recently seen msg_ids (LRU eviction)."""

    def __init__(self, capacity: int = 256, lifetime: float = 600.0):
        self.capacity = capacity
        self.lifetime = lifetime
        self._d: OrderedDict[bytes, float] = OrderedDict()

    def seen(self, mid: bytes, now: float) -> bool:
        """Returns True if already seen; otherwise records it and returns False."""
        t = self._d.get(mid)
        if t is not None and now - t < self.lifetime:
            return True
        self._d[mid] = now
        self._d.move_to_end(mid)
        while len(self._d) > self.capacity:
            self._d.popitem(last=False)
        return False

    def __len__(self) -> int:
        return len(self._d)


class TokenBucket:
    def __init__(self, rate: float, burst: float):
        self.rate, self.burst = rate, burst
        self.tokens = burst
        self.t = 0.0

    def take(self, now: float, n: float = 1.0) -> bool:
        self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


@dataclass
class _Pending:
    frame: Frame
    next_tx: float
    retries_left: int
    queued_at: float
    needs_ack: bool


@dataclass
class NodeConfig:
    tx_rate: float = 20.0          # frames / second (token bucket)
    tx_burst: float = 20.0
    max_retries: int = 5
    retry_interval: float = 0.6    # seconds
    jitter: float = 0.15           # random forwarding delay, also blurs timing
    queue_capacity: int = 64
    max_hold: float = 3600.0       # store-and-forward lifetime
    beacon_stale: float = 35.0     # beacon older than this -> route lost
    origin_min_interval: float = 300.0  # per tag key, per relay


@dataclass
class MeshNode:
    node_id: int
    is_gateway: bool = False
    cfg: NodeConfig = field(default_factory=NodeConfig)
    rng: random.Random = field(default_factory=random.Random)

    def __post_init__(self):
        self.dedup = DedupCache()
        self.bucket = TokenBucket(self.cfg.tx_rate, self.cfg.tx_burst)
        self.queue: list[_Pending] = []
        # gw -> (seq, dist for seq, dist for seq-1, rx_time). Using the min of the
        # last two beacon rounds stops the gradient flapping when a longer path
        # happens to deliver a new beacon first.
        self.routes: dict[int, tuple[int, int, int, float]] = {}
        self.clock_offset: float | None = None
        self.delivered: list[bytes] = []
        self._origin_last: dict[bytes, float] = {}
        self.stats = dict(tx=0, rx=0, dup=0, dropped_queue=0, dropped_ttl=0, rate_limited=0)
        self._beacon_seq = 0

    # -- routing state -----------------------------------------------------
    def dist(self, now: float) -> int:
        if self.is_gateway:
            return 0
        fresh = [min(d, dp) for (_, d, dp, t) in self.routes.values() if now - t <= self.cfg.beacon_stale]
        return min(fresh) if fresh else DIST_NONE

    def _enqueue(self, frame: Frame, now: float, needs_ack: bool, delay: float | None = None):
        if len(self.queue) >= self.cfg.queue_capacity:
            self.queue.pop(0)
            self.stats["dropped_queue"] += 1
        d = self.rng.uniform(0, self.cfg.jitter) if delay is None else delay
        self.queue.append(_Pending(frame, now + d, self.cfg.max_retries if needs_ack else 1, now, needs_ack))

    def _ack(self, mid: bytes):
        self.queue = [p for p in self.queue if not (p.needs_ack and p.frame.msg_id == mid)]

    # -- API -----------------------------------------------------------------
    def emit_beacon(self, now: float, unix_time: int) -> None:
        assert self.is_gateway
        self._beacon_seq += 1
        self._enqueue(make_beacon(self.node_id, self._beacon_seq, unix_time), now, False, 0.0)

    def originate(self, envelope: bytes, now: float) -> bool:
        """Queue a freshly sealed report. Enforces the per-key origination limit."""
        kh = envelope[2:34]
        last = self._origin_last.get(kh)
        if last is not None and now - last < self.cfg.origin_min_interval:
            self.stats["rate_limited"] += 1
            return False
        self._origin_last[kh] = now
        mid = report_msg_id(envelope)
        self.dedup.seen(mid, now)
        if self.is_gateway:
            self.delivered.append(envelope)
            return True
        self._enqueue(Frame(T_REPORT, DEFAULT_TTL, DIST_NONE, mid, envelope), now, True)
        return True

    def on_receive(self, raw: bytes, now: float) -> None:
        try:
            f = Frame.decode(raw)
        except FrameError:
            return
        self.stats["rx"] += 1
        my = self.dist(now)
        if f.ftype == T_BEACON:
            if self.is_gateway:
                return
            gw, seq, ut = parse_beacon(f)
            old = self.routes.get(gw)
            cand = min(DIST_NONE - 1, f.sender_dist + 1)
            if old is None or seq > old[0] or (seq == old[0] and cand < old[1]):
                if old is None or seq > old[0]:
                    prev = old[1] if old is not None and seq == old[0] + 1 else DIST_NONE
                else:
                    prev = old[2]
                self.routes[gw] = (seq, cand, prev, now)
                if ut:  # 0 = gateway has no wall-clock time yet
                    self.clock_offset = ut - now
                if f.ttl > 1:
                    self._enqueue(f.with_hop(f.ttl - 1, cand), now, False)
            return
        if f.ftype == T_ACK:
            self._ack(f.msg_id)
            return
        # REPORT
        if f.sender_dist < my or (my == DIST_NONE and f.sender_dist != DIST_NONE):
            self._ack(f.msg_id)  # passive ack: someone closer carried it on
        if self.dedup.seen(f.msg_id, now):
            self.stats["dup"] += 1
            if self.is_gateway:  # re-ack so the sender stops retrying
                self._enqueue(Frame(T_ACK, 1, 0, f.msg_id), now, False, 0.0)
            return
        if self.is_gateway:
            self.delivered.append(f.payload)
            self._enqueue(Frame(T_ACK, 1, 0, f.msg_id), now, False, 0.0)
            return
        if f.ttl <= 1:
            self.stats["dropped_ttl"] += 1
            return
        if should_forward(False, my, f.sender_dist, f.ttl):
            self._enqueue(f.with_hop(f.ttl - 1, DIST_NONE), now, True)

    def tick(self, now: float) -> list[bytes]:
        """Returns frames to broadcast now."""
        out: list[bytes] = []
        my = self.dist(now)
        keep: list[_Pending] = []
        for p in self.queue:
            if now - p.queued_at > self.cfg.max_hold:
                continue
            if p.next_tx > now:
                keep.append(p)
                continue
            if p.frame.ftype == T_REPORT and my == DIST_NONE:
                keep.append(p)  # store until a route appears
                continue
            if not self.bucket.take(now):
                keep.append(p)
                continue
            sd = my if p.frame.ftype == T_REPORT else p.frame.sender_dist
            out.append(p.frame.with_hop(p.frame.ttl, sd).encode())
            self.stats["tx"] += 1
            p.retries_left -= 1
            if p.retries_left > 0:
                p.next_tx = now + self.cfg.retry_interval * (1 + self.rng.random())
                keep.append(p)
        self.queue = keep
        return out


# --------------------------------------------------------------------------
# Simulator
# --------------------------------------------------------------------------

@dataclass
class SimResult:
    originated: int
    delivered_unique: int
    delivered_total: int
    transmissions: int

    @property
    def delivery_ratio(self) -> float:
        return self.delivered_unique / self.originated if self.originated else 1.0


class MeshSimulator:
    """Discrete-time broadcast simulator: unit-disc radio, i.i.d. per-receiver
    frame loss, no collisions (documented limitation)."""

    def __init__(self, n_nodes: int = 40, n_gateways: int = 2, area=(200.0, 200.0),
                 radio_range: float = 45.0, loss: float = 0.2, seed: int = 1,
                 cfg: NodeConfig | None = None, positions: list[tuple[float, float]] | None = None):
        self.rng = random.Random(seed)
        self.loss = loss
        self.cfg = cfg or NodeConfig()
        if positions is not None:
            n_nodes = len(positions)
        for _ in range(200):
            pos = list(positions) if positions is not None else [
                (self.rng.uniform(0, area[0]), self.rng.uniform(0, area[1])) for _ in range(n_nodes)]
            nbrs = {i: [j for j in range(n_nodes) if j != i and math.dist(pos[i], pos[j]) <= radio_range]
                    for i in range(n_nodes)}
            if self._connected(nbrs, n_nodes):
                break
            if positions is not None:
                raise RuntimeError("given topology is not connected")
        else:
            raise RuntimeError("could not generate a connected topology")
        self.pos, self.nbrs = pos, nbrs
        self.nodes = [MeshNode(i, is_gateway=i < n_gateways, cfg=self.cfg,
                               rng=random.Random(self.rng.random())) for i in range(n_nodes)]
        self.now = 0.0
        self.unix0 = 1_767_225_600  # 2026-01-01T00:00:00Z
        self._inflight: list[tuple[int, bytes]] = []
        self._next_beacon = 0.0

    @staticmethod
    def _connected(nbrs, n) -> bool:
        seen, stack = {0}, [0]
        while stack:
            for j in nbrs[stack.pop()]:
                if j not in seen:
                    seen.add(j)
                    stack.append(j)
        return len(seen) == n

    def hop_distance(self, i: int) -> int:
        gws = {n.node_id for n in self.nodes if n.is_gateway}
        frontier, seen, d = {i}, {i}, 0
        while frontier:
            if frontier & gws:
                return d
            nxt = {j for k in frontier for j in self.nbrs[k]} - seen
            seen |= nxt
            frontier, d = nxt, d + 1
        return -1

    def step(self, dt: float = 0.05) -> None:
        self.now += dt
        inflight, self._inflight = self._inflight, []
        for dst, raw in inflight:
            self.nodes[dst].on_receive(raw, self.now)
        if self.now >= self._next_beacon:
            for n in self.nodes:
                if n.is_gateway:
                    n.emit_beacon(self.now, int(self.unix0 + self.now))
            self._next_beacon = self.now + 10.0
        for n in self.nodes:
            for raw in n.tick(self.now):
                for j in self.nbrs[n.node_id]:
                    if self.rng.random() >= self.loss:
                        self._inflight.append((j, raw))

    def run(self, seconds: float, dt: float = 0.05) -> None:
        for _ in range(int(seconds / dt)):
            self.step(dt)

    def gateway_deliveries(self) -> list[bytes]:
        return [e for n in self.nodes if n.is_gateway for e in n.delivered]

    def result(self, originated: list[bytes]) -> SimResult:
        got = self.gateway_deliveries()
        uniq = set(got) & set(originated)
        return SimResult(len(originated), len(uniq), len(got), sum(n.stats["tx"] for n in self.nodes))
