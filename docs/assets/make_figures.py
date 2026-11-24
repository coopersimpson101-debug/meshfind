#!/usr/bin/env python3
"""Regenerate every image in docs/assets/ from the real meshfind code.

    pip install -e . matplotlib
    python docs/assets/make_figures.py

Outputs (all deterministic, all from the simulator / reference implementation):
    banner.svg             README banner; motif = relay grid + sightings of the seed-3 building run
    sim_map.svg            the owner-side map written by `python -m meshfind simulate --seed 3 --svg`
    simulate_terminal.svg  the captured stdout of that same command, drawn as a terminal window
    byte_layout.svg        31-byte advertisement + 108-byte report envelope, real bytes from adv/report
    mesh_delivery.png      delivery ratio vs per-link loss from mesh.MeshSimulator (40 nodes, 2 gateways)
"""
from __future__ import annotations

import math
import os
import random
import statistics
import subprocess
import sys
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from meshfind import adv, report  # noqa: E402
from meshfind.mesh import MeshSimulator  # noqa: E402
from meshfind.ratchet import TagState, key_hash  # noqa: E402
from meshfind.scenario import UNIX0, run_building  # noqa: E402

ACCENT = "#A78BFA"
BG, FG, MUTED, GRIDC = "#0d1117", "#e6edf3", "#8b949e", "#161b22"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
SEED = 3


def write(name: str, text: str) -> None:
    with open(os.path.join(HERE, name), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("wrote", name, f"({os.path.getsize(os.path.join(HERE, name)) / 1024:.1f} KiB)")


def cli_pos(seed: int) -> tuple[float, float]:
    """Same tag position `python -m meshfind simulate --seed N` picks."""
    rng = random.Random(seed)
    return rng.uniform(2, 48), rng.uniform(2, 28)


# ---------------------------------------------------------------- simulate (map + terminal)
def simulate_cli() -> list[str]:
    cmd = [sys.executable, "-m", "meshfind", "simulate", "--seed", str(SEED), "--svg",
           os.path.join(HERE, "sim_map.svg")]
    out = subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True).stdout
    lines = [ln.rstrip() for ln in out.splitlines() if ln.strip()]
    # the last line echoes the absolute output path; show it repo-relative
    lines = [("wrote docs/assets/sim_map.svg" if ln.startswith("wrote ") else ln) for ln in lines]
    print("simulate:", *lines, sep="\n  ")
    return lines


def terminal_svg(cmd: str, lines: list[str], title: str) -> str:
    w, lh = 980, 22
    h = 70 + lh * (len(lines) + 2)
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">',
         f'<rect width="{w}" height="{h}" rx="10" fill="{BG}" stroke="#30363d"/>',
         f'<rect width="{w}" height="34" rx="10" fill="{GRIDC}"/><rect y="24" width="{w}" height="10" fill="{GRIDC}"/>',
         '<circle cx="20" cy="17" r="6" fill="#ff5f56"/><circle cx="40" cy="17" r="6" fill="#ffbd2e"/>'
         '<circle cx="60" cy="17" r="6" fill="#27c93f"/>',
         f'<text x="{w / 2}" y="22" fill="{MUTED}" font-family="{MONO}" font-size="13" text-anchor="middle">'
         f'{escape(title)}</text>',
         f'<g font-family="{MONO}" font-size="15">',
         f'<text x="20" y="{60 + lh * 0}" fill="{FG}"><tspan fill="{ACCENT}">$</tspan> {escape(cmd)}</text>']
    for i, ln in enumerate(lines, 1):
        col = ACCENT if "error" in ln else FG
        o.append(f'<text x="20" y="{60 + lh * i}" fill="{col}">{escape(ln)}</text>')
    o.append(f'<text x="20" y="{60 + lh * (len(lines) + 1)}" fill="{ACCENT}">$ <tspan fill="{FG}">_</tspan></text>')
    o += ["</g>", "</svg>"]
    return "\n".join(o) + "\n"


# ---------------------------------------------------------------- banner
def banner(res) -> str:
    W, H = 1280, 400
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
         "<defs>",
         f'<pattern id="g" width="32" height="32" patternUnits="userSpaceOnUse">'
         f'<path d="M32 0H0V32" fill="none" stroke="{GRIDC}" stroke-width="1"/></pattern>',
         f'<radialGradient id="glow"><stop offset="0" stop-color="{ACCENT}" stop-opacity="0.35"/>'
         f'<stop offset="1" stop-color="{ACCENT}" stop-opacity="0"/></radialGradient>',
         "</defs>",
         f'<rect width="{W}" height="{H}" fill="{BG}"/><rect width="{W}" height="{H}" fill="url(#g)"/>',
         f'<text x="72" y="190" font-family="{MONO}" font-weight="bold" font-size="104" fill="{FG}">meshfind</text>',
         f'<text x="76" y="242" font-family="{MONO}" font-size="22" fill="{MUTED}">'
         'offline, end-to-end encrypted Find-My</text>',
         f'<text x="76" y="276" font-family="{MONO}" font-size="22" fill="{MUTED}">'
         'for DIY trackers, over an ESP32 mesh</text>',
         f'<rect x="76" y="306" width="420" height="4" rx="2" fill="{ACCENT}"/>',
         f'<text x="76" y="346" font-family="{MONO}" font-size="16" fill="{MUTED}">'
         'X25519 · HKDF ratchet · ChaCha20-Poly1305 · Python + C</text>']
    # motif: the real seed-3 building (50 x 30 m, relays on a 10 m grid)
    x0, y0, s = 720, 50, 10.0  # px per metre
    px = lambda x, y: (x0 + x * s, y0 + (30 - y) * s)  # noqa: E731
    o.append(f'<rect x="{x0 - 14}" y="{y0 - 14}" width="{50 * s + 28}" height="{30 * s + 28}" rx="8" '
             f'fill="none" stroke="#30363d" stroke-dasharray="4 6"/>')
    nodes = res.nodes
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            if math.dist(a, b) <= 10.01:
                (ax, ay), (bx, by) = px(*a), px(*b)
                o.append(f'<line x1="{ax:.1f}" y1="{ay:.1f}" x2="{bx:.1f}" y2="{by:.1f}" '
                         f'stroke="{ACCENT}" stroke-opacity="0.22" stroke-width="1.5"/>')
    tx, ty = px(*res.truth)
    for o_ in res.observations:
        cx, cy = px(o_.x, o_.y)
        a = min(1.0, max(0.08, (o_.rssi + 100) / 50))
        o.append(f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{tx:.1f}" y2="{ty:.1f}" stroke="{ACCENT}" '
                 f'stroke-opacity="{0.55 * a:.2f}" stroke-width="1.2" stroke-dasharray="2 4"/>')
    for nx, ny in nodes:
        cx, cy = px(nx, ny)
        o.append(f'<rect x="{cx - 5:.1f}" y="{cy - 5:.1f}" width="10" height="10" rx="2" fill="{GRIDC}" '
                 f'stroke="{MUTED}" stroke-width="1.2"/>')
    for o_ in res.observations:
        cx, cy = px(o_.x, o_.y)
        a = min(1.0, max(0.08, (o_.rssi + 100) / 50))
        o.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="9" fill="{ACCENT}" fill-opacity="{min(1.0, a + 0.25):.2f}"/>')
    o.append(f'<circle cx="{tx:.1f}" cy="{ty:.1f}" r="46" fill="url(#glow)"/>')
    for r in (14, 26, 38):
        o.append(f'<circle cx="{tx:.1f}" cy="{ty:.1f}" r="{r}" fill="none" stroke="{ACCENT}" '
                 f'stroke-opacity="{0.9 - r / 50:.2f}" stroke-width="1.5"/>')
    o.append(f'<circle cx="{tx:.1f}" cy="{ty:.1f}" r="5" fill="{FG}"/>')
    if res.estimate:
        ex, ey = px(*res.estimate)
        o.append(f'<path d="M{ex - 7:.1f} {ey - 7:.1f}l14 14M{ex + 7:.1f} {ey - 7:.1f}l-14 14" '
                 f'stroke="{FG}" stroke-width="2.5"/>')
    o.append(f'<text x="{x0 - 14}" y="{y0 + 30 * s + 40}" font-family="{MONO}" font-size="13" fill="{MUTED}">'
             f'simulated: {len(res.observations)} relays heard the tag · estimate error '
             f'{res.error_m:.2f} m</text>')
    o.append("</svg>")
    return "\n".join(o) + "\n"


# ---------------------------------------------------------------- byte layout
def byte_layout() -> str:
    master = bytes(range(32))  # fixed demo secret so the figure is reproducible
    tag = TagState.provision(master, UNIX0)
    pub = tag.current_public(UNIX0 + 3600)
    addr, payload = adv.encode(adv.TagAdvert(pub, adv.battery_level(80), False))
    sighting = report.Sighting(seen_ts=UNIX0 + 3600, node_id=0x5007, x=2000, y=1000, z=0,
                               accuracy_cm=20, rssi=-71, tag_status=payload[4] & 0x3F)
    env = report.seal(pub, sighting, eph_secret=bytes([7]) * 32)
    assert len(payload) == adv.ADV_LEN and len(env) == report.ENVELOPE_LEN
    assert env[2:34] == key_hash(pub)

    W, cell = 1180, 34
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="350" viewBox="0 0 {W} 350" '
         f'font-family="{MONO}">', f'<rect width="{W}" height="350" rx="10" fill="{BG}"/>']

    def row(y, title, data, fields, scale):
        o.append(f'<text x="24" y="{y}" fill="{FG}" font-size="17" font-weight="bold">{escape(title)}</text>')
        x = 24
        y += 14
        for name, n, col in fields:
            wpx = max(n * scale, 50)
            chunk = data[:n]
            data = data[n:]
            o.append(f'<rect x="{x}" y="{y}" width="{wpx - 4}" height="{cell}" rx="4" fill="{col}" '
                     f'fill-opacity="0.18" stroke="{col}"/>')
            hx = chunk.hex()
            maxc = int((wpx - 12) / 8.4)
            if len(hx) > maxc:
                hx = hx[:max(maxc - 1, 2)] + "…"
            o.append(f'<text x="{x + 6}" y="{y + 22}" fill="{FG}" font-size="13">{hx}</text>')
            o.append(f'<text x="{x + 2}" y="{y + cell + 18}" fill="{col}" font-size="12">{escape(name)}</text>')
            o.append(f'<text x="{x + 2}" y="{y + cell + 34}" fill="{MUTED}" font-size="11">{n} B</text>')
            x += wpx
        return y + cell + 62

    y = 34
    y = row(y, "BLE address (6 B, static random: top bits 11)", addr,
            [("P[0]|0xC0 ‖ P[1..5]", 6, ACCENT)], 60)
    y = row(y, f"Legacy advertisement payload: {len(payload)} bytes (ADV_NONCONN_IND)", payload,
            [("len", 1, MUTED), ("type", 1, MUTED), ("company", 2, MUTED), ("status", 1, "#f0883e"),
             ("P[6..31]  (rest of the X25519 key)", 26, ACCENT)], 34)
    y = row(y, f"Encrypted report envelope: {len(env)} bytes (relay → mesh → server)", env,
            [("ver", 1, MUTED), ("flg", 1, MUTED), ("SHA-256(P)  index", 32, "#3fb950"),
             ("E  ephemeral X25519", 32, ACCENT), ("ChaCha20 ciphertext (26 B sighting)", 26, "#f0883e"),
             ("Poly1305 tag", 16, "#f778ba")], 9.8)
    o.append(f'<text x="24" y="{y - 10}" fill="{MUTED}" font-size="12">bytes produced by meshfind.adv.encode() '
             'and meshfind.report.seal() for a fixed demo key (docs/assets/make_figures.py)</text>')
    o.append("</svg>")
    return "\n".join(o) + "\n"


# ---------------------------------------------------------------- mesh delivery vs loss
def mesh_delivery(losses=(0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6), seeds=range(1, 21)):
    """Same protocol as tests/test_mesh.py::test_random_topology_with_loss_delivers."""
    rows = []
    for loss in losses:
        ratios = []
        for seed in seeds:
            sim = MeshSimulator(n_nodes=40, n_gateways=2, radio_range=45, loss=loss, seed=seed)
            sim.run(30)
            rng = random.Random(seed)
            envs = []
            for i, n in enumerate(sim.nodes[2:]):
                e = bytes(rng.getrandbits(8) for _ in range(report.ENVELOPE_LEN))
                envs.append(e)
                n.originate(e, sim.now + i * 0.1)
            sim.run(60)
            ratios.append(sim.result(envs).delivery_ratio)
        rows.append((loss, statistics.mean(ratios), min(ratios), max(ratios)))
        print(f"  loss {loss:.0%}: mean {rows[-1][1]:.4f} min {rows[-1][2]:.4f} ({len(ratios)} topologies)")
    return rows


def plot_delivery(rows, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "monospace", "svg.hashsalt": "meshfind"})
    fig, ax = plt.subplots(figsize=(8, 4), dpi=120)
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    L = [r[0] * 100 for r in rows]
    ax.fill_between(L, [r[2] * 100 for r in rows], [r[3] * 100 for r in rows], color=ACCENT, alpha=0.2,
                    label="min–max over 20 random topologies")
    ax.plot(L, [r[1] * 100 for r in rows], "o-", color=ACCENT, lw=2, label="mean delivery")
    for x, r in zip(L, rows):
        ax.annotate(f"{r[1] * 100:.1f}", (x, r[1] * 100), textcoords="offset points", xytext=(0, 8),
                    ha="center", color=FG, fontsize=8)
    ax.set_xlabel("per-link frame loss [%]", color=MUTED)
    ax.set_ylabel("reports delivered to a gateway [%]", color=MUTED)
    ax.set_title("ESP-NOW mesh simulator: 40 nodes, 2 gateways, 38 reports", color=FG, fontsize=11, pad=10)
    ax.tick_params(colors=MUTED)
    for s in ax.spines.values():
        s.set_color("#30363d")
    ax.grid(color=GRIDC)
    lo = min(r[2] for r in rows) * 100
    ax.set_ylim(min(90, math.floor(lo - 2)), 104)
    ax.legend(facecolor=BG, edgecolor="#30363d", labelcolor=FG, fontsize=8, loc="lower left")
    fig.tight_layout()
    fig.savefig(path, facecolor=BG)
    print("wrote", os.path.basename(path), f"({os.path.getsize(path) / 1024:.1f} KiB)")


def main() -> None:
    lines = simulate_cli()
    write("simulate_terminal.svg", terminal_svg(f"python -m meshfind simulate --seed {SEED} --svg "
                                                "docs/assets/sim_map.svg", lines, "meshfind simulate"))
    res = run_building(cli_pos(SEED), seed=SEED, mesh_loss=0.15)
    write("banner.svg", banner(res))
    write("byte_layout.svg", byte_layout())
    plot_delivery(mesh_delivery(), os.path.join(HERE, "mesh_delivery.png"))


if __name__ == "__main__":
    main()
