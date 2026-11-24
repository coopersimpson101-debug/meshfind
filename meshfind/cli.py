"""meshfind command-line interface.

    python -m meshfind tag new tag.json            # create an owner keyring for a tag
    python -m meshfind tag provision tag.json      # sdkconfig lines for the tag firmware
    python -m meshfind tag keys tag.json -n 4      # show upcoming advertised keys
    python -m meshfind tag presence tag.json       # owner-presence beacon payloads
    python -m meshfind server --db reports.db      # run the report store
    python -m meshfind gateway --server URL --serial COM5  # bridge a gateway node
    python -m meshfind gateway --server URL < serial.log   # or replay "MFRPT <hex>" lines
    python -m meshfind query tag.json --server URL --svg map.svg
    python -m meshfind simulate --svg sim.svg      # end-to-end building simulation
    python -m meshfind antistalk scans.jsonl       # unknown-tracker detection
    python -m meshfind vectors > vectors/meshfind_vectors.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request

from . import adv, antistalk, locate, owner, plot, ratchet, vectors
from .ratchet import OwnerKeyring
from .report import Envelope, ReportError


def _load_tag(path: str) -> OwnerKeyring:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    return OwnerKeyring(bytes.fromhex(d["master"]), int(d["epoch0"]), int(d.get("epoch_seconds", 900)))


def cmd_tag(a) -> int:
    if a.action == "new":
        if os.path.exists(a.file) and not a.force:
            print(f"{a.file} exists; use --force to overwrite", file=sys.stderr)
            return 1
        epoch0 = int(a.epoch0 if a.epoch0 is not None else time.time())
        kr = OwnerKeyring.generate(epoch0, a.epoch_seconds)
        with open(a.file, "w", encoding="utf-8") as f:
            json.dump({"master": kr.master.hex(), "epoch0": epoch0, "epoch_seconds": a.epoch_seconds,
                       "name": a.name}, f, indent=1)
        print(f"wrote {a.file} -- this file is the tag's master secret: keep it private and backed up")
        return 0
    kr = _load_tag(a.file)
    if a.action == "provision":
        print("# Paste into firmware/tag/sdkconfig (or `idf.py menuconfig` -> meshfind tag).")
        print("# The tag only receives chain *seeds*, never the master secret.")
        print(f'CONFIG_MESHFIND_TAG_SK0="{ratchet.chain_init(kr.master).hex()}"')
        print(f'CONFIG_MESHFIND_TAG_SEP_SK0="{ratchet.chain_init(kr.master, True).hex()}"')
        print(f'CONFIG_MESHFIND_TAG_PRESENCE_KEY="{ratchet.presence_key(kr.master).hex()}"')
        print(f"CONFIG_MESHFIND_TAG_EPOCH0={kr.epoch0}")
        print(f"CONFIG_MESHFIND_TAG_EPOCH_SECONDS={kr.epoch_seconds}")
        return 0
    if a.action == "presence":
        t = a.at if a.at is not None else time.time()
        i0 = ratchet.epoch_index(t, kr.epoch0, kr.epoch_seconds)
        pk = ratchet.presence_key(kr.master)
        print("# raw advertising data for an owner device (e.g. a second ESP32 or a phone app)")
        for i in range(i0, i0 + a.n):
            print(f"epoch {i:6d}  {adv.encode_presence(ratchet.presence_token(pk, i)).hex()}")
        return 0
    if a.action == "keys":
        t = a.at if a.at is not None else time.time()
        i0 = ratchet.epoch_index(t, kr.epoch0, kr.epoch_seconds)
        for i in range(i0, i0 + a.n):
            k = kr.key(i)
            addr, _ = adv.encode(adv.TagAdvert(k.public))
            start, _ = kr.epoch_window(k)
            print(f"epoch {i:6d}  from {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(start))}Z  "
                  f"addr {':'.join(f'{b:02X}' for b in addr)}  hash {k.hash.hex()[:16]}...")
        return 0
    return 2


def cmd_server(a) -> int:
    from .server import serve
    httpd = serve(a.host, a.port, a.db, a.token or os.environ.get("MESHFIND_UPLOAD_TOKEN"), a.retention_days)
    print(f"meshfind server on http://{a.host}:{a.port} (db={a.db})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_gateway(a) -> int:
    """Reads relay/gateway serial output and uploads reports in batches."""
    port = None
    if a.serial:
        try:
            import serial  # pyserial, optional
        except ImportError:
            print("--serial needs pyserial: pip install pyserial", file=sys.stderr)
            return 1
        port = serial.Serial(a.serial, a.baud, timeout=1)
        src = (raw.decode("utf-8", "replace") for raw in iter(port.readline, None))
    else:
        src = open(a.input, encoding="utf-8", errors="replace") if a.input != "-" else sys.stdin
    token = a.token or os.environ.get("MESHFIND_UPLOAD_TOKEN")
    batch: list[str] = []

    def flush():
        if not batch:
            return
        hdrs = {"Content-Type": "application/json"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(a.server.rstrip("/") + "/v1/reports",
                                     json.dumps({"reports": batch}).encode(), hdrs)
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
            print(json.loads(r.read()))
        batch.clear()

    last_time_push = 0.0
    for line in src:
        if port is not None and time.time() - last_time_push > 60:
            port.write(f"MFTIME {int(time.time())}\n".encode())  # gateway learns wall-clock time
            last_time_push = time.time()
            flush()
        parts = line.strip().split()
        if len(parts) == 2 and parts[0] == "MFRPT":
            try:
                Envelope.parse(bytes.fromhex(parts[1]))
            except (ValueError, ReportError):
                print(f"skipping malformed line: {line.strip()[:40]}", file=sys.stderr)
                continue
            batch.append(parts[1])
            if len(batch) >= a.batch:
                flush()
    flush()
    return 0


def cmd_query(a) -> int:
    kr = _load_tag(a.file)
    now = time.time() if a.now is None else a.now
    keys = kr.keys_for_window(now - a.hours * 3600, now)
    found = owner.fetch(a.server, owner.query_hashes(keys, a.decoys))
    reps = owner.decrypt_all(kr, keys, found)
    if not reps:
        print("no reports found")
        return 1
    for r in reps:
        s = r.sighting
        flag = "" if r.plausible_time else "  [timestamp outside key epoch: ignored]"
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(s.seen_ts))}Z node {s.node_id:#06x} "
              f"pos ({s.x / 100:.1f}, {s.y / 100:.1f}) m  rssi {s.rssi} dBm{flag}")
    recent = owner.latest_window(reps, a.window * 60)
    obs = [r.observation() for r in recent]
    if not obs:
        print("no plausible recent reports")
        return 1
    model = locate.PathLoss(a.p0, a.n)
    x, y, method = locate.estimate(obs, model)
    print(f"estimate ({method}, {len(obs)} reports): x={x:.1f} m y={y:.1f} m")
    if a.svg:
        with open(a.svg, "w", encoding="utf-8") as f:
            f.write(plot.render_svg(obs, (x, y), title=f"meshfind: {method}"))
        print(f"wrote {a.svg}")
    return 0


def cmd_simulate(a) -> int:
    from .scenario import run_building
    import random
    rng = random.Random(a.seed)
    pos = (a.x if a.x is not None else rng.uniform(2, 48), a.y if a.y is not None else rng.uniform(2, 28))
    r = run_building(pos, seed=a.seed, mesh_loss=a.loss)
    print(f"tag at ({pos[0]:.1f}, {pos[1]:.1f}) m; {r.reports_sent} relays heard it; "
          f"{r.reports_delivered} reports reached the gateway over the mesh")
    if r.estimate:
        print(f"owner estimate ({r.method}): ({r.estimate[0]:.1f}, {r.estimate[1]:.1f}) m, error {r.error_m:.2f} m")
    if a.svg:
        with open(a.svg, "w", encoding="utf-8") as f:
            f.write(plot.render_svg(r.observations, r.estimate, pos, r.nodes, "meshfind simulated building"))
        print(f"wrote {a.svg}")
    return 0


def cmd_antistalk(a) -> int:
    events = []
    with open(a.file, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                d = json.loads(line)
                events.append(antistalk.ScanEvent(d["t"], d["x"], d["y"], bytes.fromhex(d["key"]),
                                                  int(d["rssi"]), bool(d.get("separated", False))))
    alerts = antistalk.detect(events)
    for al in alerts:
        print("ALERT:", al.describe())
    if not alerts:
        print("no unknown tracker appears to be travelling with you")
    return 3 if alerts else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="meshfind", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("tag", help="create / inspect / provision a tag keyring")
    t.add_argument("action", choices=["new", "keys", "provision", "presence"])
    t.add_argument("file")
    t.add_argument("--name", default="tag")
    t.add_argument("--epoch0", type=int)
    t.add_argument("--epoch-seconds", type=int, default=ratchet.EPOCH_SECONDS)
    t.add_argument("--at", type=float)
    t.add_argument("-n", type=int, default=4)
    t.add_argument("--force", action="store_true")
    t.set_defaults(fn=cmd_tag)

    s = sub.add_parser("server", help="run the report store HTTP API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--db", default="meshfind.db")
    s.add_argument("--token", help="require this bearer token for uploads (or MESHFIND_UPLOAD_TOKEN)")
    s.add_argument("--retention-days", type=int, default=7)
    s.set_defaults(fn=cmd_server)

    g = sub.add_parser("gateway", help="upload MFRPT lines from a gateway's serial log")
    g.add_argument("--server", required=True)
    g.add_argument("--input", default="-", help="log file to replay, or - for stdin")
    g.add_argument("--serial", help="read the gateway's console UART directly (needs pyserial)")
    g.add_argument("--baud", type=int, default=115200)
    g.add_argument("--token")
    g.add_argument("--batch", type=int, default=50)
    g.set_defaults(fn=cmd_gateway)

    q = sub.add_parser("query", help="fetch, decrypt and locate your tag")
    q.add_argument("file")
    q.add_argument("--server", required=True)
    q.add_argument("--hours", type=float, default=24)
    q.add_argument("--window", type=float, default=15, help="minutes of newest reports used for the fix")
    q.add_argument("--decoys", type=int, default=0)
    q.add_argument("--p0", type=float, default=-59.0)
    q.add_argument("--n", type=float, default=2.2)
    q.add_argument("--now", type=float)
    q.add_argument("--svg")
    q.set_defaults(fn=cmd_query)

    m = sub.add_parser("simulate", help="end-to-end simulated building")
    m.add_argument("--seed", type=int, default=1)
    m.add_argument("--x", type=float)
    m.add_argument("--y", type=float)
    m.add_argument("--loss", type=float, default=0.15)
    m.add_argument("--svg")
    m.set_defaults(fn=cmd_simulate)

    st = sub.add_parser("antistalk", help="detect unknown trackers in a JSONL scan log")
    st.add_argument("file")
    st.set_defaults(fn=cmd_antistalk)

    v = sub.add_parser("vectors", help="print cross-implementation test vectors (JSON)")
    v.set_defaults(fn=lambda a: (sys.stdout.write(vectors.dumps()), 0)[1])

    a = p.parse_args(argv)
    return a.fn(a)
