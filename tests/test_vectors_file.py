"""The committed vectors file must match the Python reference exactly, and
every vector must decode/verify with the reference implementation."""

import json
from pathlib import Path

from meshfind import adv, mesh, report, vectors

VEC = Path(__file__).resolve().parents[1] / "vectors" / "meshfind_vectors.json"


def test_committed_vectors_are_current():
    assert VEC.read_text(encoding="utf-8") == vectors.dumps(), \
        "regenerate with: python -m meshfind vectors > vectors/meshfind_vectors.json"


def test_vectors_open_with_reference():
    v = json.loads(VEC.read_text(encoding="utf-8"))
    for r in v["report"]:
        s = report.open_(bytes.fromhex(r["tag_priv"]), bytes.fromhex(r["tag_pub"]), bytes.fromhex(r["envelope"]))
        assert s.pack().hex() == r["plaintext"]
    for a in v["adv"]:
        d = adv.decode(bytes.fromhex(a["addr"]), bytes.fromhex(a["payload"]))
        assert d.public_key.hex() == a["pub"] and d.battery == a["battery"] and d.separated == a["separated"]
    for f in v["mesh_frames"]:
        fr = mesh.Frame.decode(bytes.fromhex(f["encoded"]))
        assert (fr.ftype, fr.ttl, fr.sender_dist, fr.msg_id.hex(), fr.payload.hex()) == (
            f["type"], f["ttl"], f["sender_dist"], f["msg_id"], f["payload"])
