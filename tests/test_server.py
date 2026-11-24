import json
import threading
import urllib.error
import urllib.request

import pytest

from meshfind import owner, report
from meshfind.ratchet import OwnerKeyring
from meshfind.server import ReportStore, serve

E0 = 1_767_225_600
kr = OwnerKeyring(bytes(range(32)), E0)


def _sighting(i=0):
    return report.Sighting(E0 + 900 * 5 + 10 + i, 0x42, 100 * i, 200, 0, 10, -60 - i, 0x01)


@pytest.fixture()
def server(tmp_path):
    httpd = serve("127.0.0.1", 0, str(tmp_path / "r.db"), upload_token="s3cret")
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", httpd
    httpd.shutdown()
    httpd.server_close()


def _post(url, path, obj, token=None):
    hdrs = {"Content-Type": "application/json"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url + path, json.dumps(obj).encode(), hdrs)
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def test_store_dedup_and_query():
    st = ReportStore()
    k = kr.key(5)
    env = report.seal(k.public, _sighting())
    assert st.add(env) == "accepted"
    assert st.add(env) == "duplicate"  # replayed upload is idempotent
    assert st.add(env[:-1]) == "rejected"
    assert st.query([k.hash]) == {k.hash: [env]}
    assert st.query([kr.key(6).hash]) == {}


def test_retention():
    st = ReportStore(retention_s=100)
    k = kr.key(5)
    st.add(report.seal(k.public, _sighting()), now=1000)
    st.add(report.seal(k.public, _sighting(1)), now=1200)
    assert st.expire(now=1250) == 1 and st.count() == 1


def test_http_end_to_end(server):
    url, _ = server
    k = kr.key(5)
    envs = [report.seal(k.public, _sighting(i)) for i in range(3)]
    other = report.seal(kr.key(9).public, _sighting())
    with pytest.raises(urllib.error.HTTPError) as ei:
        _post(url, "/v1/reports", {"reports": [e.hex() for e in envs]})
    assert ei.value.code == 401
    res = _post(url, "/v1/reports", {"reports": [e.hex() for e in envs + [other, envs[0]]] + ["00ff"]}, "s3cret")
    assert res == {"accepted": 4, "duplicates": 1, "rejected": 1}

    keys = kr.keys_for_window(E0 + 900 * 5, E0 + 900 * 6)
    found = owner.fetch(url, owner.query_hashes(keys, decoys=20))
    reps = owner.decrypt_all(kr, keys, found)
    assert [r.sighting for r in reps if r.key.index == 5] == [_sighting(i) for i in range(3)]
    assert all(r.plausible_time for r in reps)
    with urllib.request.urlopen(url + "/v1/health") as r:
        assert json.loads(r.read())["reports"] == 4


def test_http_rejects_malformed(server):
    url, _ = server
    for body in ({"key_hashes": ["zz"]}, {"key_hashes": "nope"}, {"key_hashes": ["00" * 31]}):
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post(url, "/v1/query", body)
        assert ei.value.code == 400


def test_owner_flags_implausible_timestamps():
    k = kr.key(5)
    bad = report.Sighting(E0 + 86400 * 30, 1, 0, 0, 0, 0, -50, 1)  # claims a time far outside epoch 5
    found = {k.hash: [report.seal(k.public, bad), report.seal(k.public, _sighting())]}
    reps = owner.decrypt_all(kr, [k], found)
    assert sorted(r.plausible_time for r in reps) == [False, True]
    assert [r.sighting for r in owner.latest_window(reps)] == [_sighting()]
