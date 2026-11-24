"""Deterministic cross-implementation test vectors.

``python -m meshfind vectors > vectors/meshfind_vectors.json`` regenerates the
committed file. ``tests/test_vectors_file.py`` asserts the committed file
matches the Python reference; ``firmware/common/test/test_vectors.c`` checks
the C implementation against the same file.
"""

from __future__ import annotations

import json

from . import adv, crypto, mesh, ratchet, report

# Published vectors (RFC 5869 A.1, RFC 7748 5.2/6.1, RFC 8439 2.8.2, FIPS 180 "abc")
RFC_SHA256 = [("616263", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
RFC_HKDF = [dict(
    ikm="0b" * 22, salt="000102030405060708090a0b0c", info="f0f1f2f3f4f5f6f7f8f9", length=42,
    okm="3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
)]
RFC_X25519 = [
    dict(scalar="a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
         u="e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
         out="c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    dict(scalar="77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
         u="0900000000000000000000000000000000000000000000000000000000000000",
         out="8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
    dict(scalar="5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
         u="8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
         out="4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
]
RFC_AEAD_PT = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
               b"for the future, sunscreen would be it.")
RFC_AEAD = dict(key="808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                nonce="070000004041424344454647", aad="50515253c0c1c2c3c4c5c6c7",
                tag="1ae10b594f09e26a7e902ecbd0600691")

MASTER = bytes(range(32))
EPOCH0 = 1_767_225_600


def generate() -> dict:
    v: dict = {"version": 1}
    v["sha256"] = [dict(msg=m, digest=crypto.sha256(bytes.fromhex(m)).hex()) for m, _ in RFC_SHA256]
    v["sha256"].append(dict(msg=("6d65736866696e64" * 20), digest=crypto.sha256(bytes.fromhex("6d65736866696e64" * 20)).hex()))
    v["hkdf"] = []
    for h in RFC_HKDF:
        v["hkdf"].append(dict(h, okm=crypto.hkdf(bytes.fromhex(h["ikm"]), bytes.fromhex(h["salt"]),
                                                   bytes.fromhex(h["info"]), h["length"]).hex()))
    v["hkdf"].append(dict(ikm=MASTER.hex(), salt="", info=b"meshfind/v1/chain-init".hex(), length=32,
                          okm=crypto.hkdf(MASTER, b"", b"meshfind/v1/chain-init", 32).hex()))
    v["x25519"] = [dict(x, out=crypto.x25519(bytes.fromhex(x["scalar"]), bytes.fromhex(x["u"])).hex())
                   for x in RFC_X25519]
    key, nonce, aad = (bytes.fromhex(RFC_AEAD[k]) for k in ("key", "nonce", "aad"))
    ct = crypto.aead_encrypt(key, nonce, RFC_AEAD_PT, aad)
    v["aead"] = [dict(key=key.hex(), nonce=nonce.hex(), aad=aad.hex(), pt=RFC_AEAD_PT.hex(), ct=ct.hex())]
    ct2 = crypto.aead_encrypt(bytes(32), bytes(12), b"", b"")
    v["aead"].append(dict(key="00" * 32, nonce="00" * 12, aad="", pt="", ct=ct2.hex()))

    # Ratchet
    v["ratchet"] = {"master": MASTER.hex(), "epoch0": EPOCH0, "epoch_seconds": ratchet.EPOCH_SECONDS,
                    "presence_key": ratchet.presence_key(MASTER).hex(), "epochs": [], "separated": [],
                    "presence": []}
    kr = ratchet.OwnerKeyring(MASTER, EPOCH0)
    for i in (0, 1, 2, 3, 95, 96, 97, 500):
        k = kr.key(i)
        v["ratchet"]["epochs"].append(dict(index=i, sk=kr._sk(i, False).hex(), priv=k.private.hex(),
                                           pub=k.public.hex(), hash=k.hash.hex()))
    for d in (0, 1, 2, 30):
        k = kr.key(d, separated=True)
        v["ratchet"]["separated"].append(dict(index=d, sk=kr._sk(d, True).hex(), priv=k.private.hex(),
                                              pub=k.public.hex(), hash=k.hash.hex()))
    pk = ratchet.presence_key(MASTER)
    for e in (0, 1, 1000):
        tok = ratchet.presence_token(pk, e)
        v["ratchet"]["presence"].append(dict(epoch=e, token=tok.hex(), adv=adv.encode_presence(tok).hex()))
    v["epoch_index"] = [dict(t=t, epoch0=EPOCH0, seconds=900, index=ratchet.epoch_index(t, EPOCH0))
                        for t in (EPOCH0, EPOCH0 + 899, EPOCH0 + 900, EPOCH0 + 86400 * 3 + 1)]

    # Advertisements
    v["adv"] = []
    for i, (batt, sep) in enumerate([(0, False), (1, False), (2, True), (3, True)]):
        pub = kr.key(i).public
        addr, payload = adv.encode(adv.TagAdvert(pub, batt, sep))
        v["adv"].append(dict(pub=pub.hex(), battery=batt, separated=sep, addr=addr.hex(), payload=payload.hex()))
    v["adv_interval"] = [dict(percent=p, separated=s, ms=adv.adv_interval_ms(p, s))
                         for p in (100, 60, 59, 30, 29, 10, 9, 0) for s in (False, True)]

    # Reports
    v["report"] = []
    for i in range(3):
        k = kr.key(i)
        s = report.Sighting(seen_ts=EPOCH0 + i * 900 + 17, node_id=0x1000 + i, x=-1234 * (i + 1),
                            y=5678 + i, z=300, accuracy_cm=50, rssi=-70 - i, tag_status=0x11 + i)
        eph = crypto.sha256(b"eph" + bytes([i]))
        env = report.seal(k.public, s, eph_secret=eph)
        v["report"].append(dict(tag_pub=k.public.hex(), tag_priv=k.private.hex(), eph_secret=eph.hex(),
                                plaintext=s.pack().hex(), seen_ts=s.seen_ts, node_id=s.node_id, x=s.x, y=s.y,
                                z=s.z, accuracy_cm=s.accuracy_cm, rssi=s.rssi, tag_status=s.tag_status,
                                flags=s.flags, envelope=env.hex()))

    # Mesh
    env0 = bytes.fromhex(v["report"][0]["envelope"])
    mid = mesh.report_msg_id(env0)
    frames = [
        mesh.Frame(mesh.T_REPORT, 10, 3, mid, env0),
        mesh.make_beacon(7, 42, EPOCH0 + 5),
        mesh.Frame(mesh.T_ACK, 1, 0, mid),
    ]
    v["mesh_frames"] = [dict(type=f.ftype, ttl=f.ttl, sender_dist=f.sender_dist, msg_id=f.msg_id.hex(),
                             payload=f.payload.hex(), encoded=f.encode().hex()) for f in frames]
    v["mesh_forward"] = []
    for gw in (False, True):
        for my in (0, 1, 2, 255):
            for sd in (0, 1, 2, 255):
                for ttl in (0, 1, 2):
                    v["mesh_forward"].append(dict(is_gateway=gw, my_dist=my, sender_dist=sd, ttl=ttl,
                                                  forward=mesh.should_forward(gw, my, sd, ttl)))
    return v


def dumps() -> str:
    return json.dumps(generate(), indent=1, sort_keys=True) + "\n"
