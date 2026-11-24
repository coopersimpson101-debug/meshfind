"""Dependency-free SVG map of sightings and the position estimate."""

from __future__ import annotations

from xml.sax.saxutils import escape

from .locate import Observation


def render_svg(obs: list[Observation], estimate: tuple[float, float] | None,
               truth: tuple[float, float] | None = None, nodes: list[tuple[float, float]] | None = None,
               title: str = "meshfind", width: int = 720) -> str:
    pts = [(o.x, o.y) for o in obs] + list(nodes or [])
    if estimate:
        pts.append(estimate)
    if truth:
        pts.append(truth)
    if not pts:
        pts = [(0.0, 0.0)]
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    minx, maxx, miny, maxy = min(xs) - 3, max(xs) + 3, min(ys) - 3, max(ys) + 3
    sx = (width - 40) / max(maxx - minx, 1e-6)
    height = int((maxy - miny) * sx) + 70

    def px(x, y):
        return 20 + (x - minx) * sx, 50 + (maxy - y) * sx

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
           f'viewBox="0 0 {width} {height}" font-family="sans-serif" font-size="12">',
           f'<rect width="100%" height="100%" fill="#fafafa"/>',
           f'<text x="20" y="24" font-size="16">{escape(title)}</text>',
           f'<text x="20" y="42" fill="#666">1 m = {sx:.1f} px; circles: relay sightings '
           f'(darker = stronger RSSI); x = estimate; + = truth</text>']
    for nx, ny in nodes or []:
        cx, cy = px(nx, ny)
        out.append(f'<rect x="{cx - 3:.1f}" y="{cy - 3:.1f}" width="6" height="6" fill="#bbb"/>')
    for o in obs:
        cx, cy = px(o.x, o.y)
        a = min(1.0, max(0.1, (o.rssi + 100) / 50))
        out.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="7" fill="#1f6feb" fill-opacity="{a:.2f}">'
                   f'<title>node {o.node_id} rssi {o.rssi:.0f}</title></circle>')
    if truth:
        cx, cy = px(*truth)
        out.append(f'<path d="M{cx - 8:.1f} {cy:.1f}h16M{cx:.1f} {cy - 8:.1f}v16" stroke="#2da44e" stroke-width="3"/>')
    if estimate:
        cx, cy = px(*estimate)
        out.append(f'<path d="M{cx - 7:.1f} {cy - 7:.1f}l14 14M{cx + 7:.1f} {cy - 7:.1f}l-14 14" '
                   f'stroke="#cf222e" stroke-width="3"/>')
    out.append("</svg>")
    return "\n".join(out) + "\n"
