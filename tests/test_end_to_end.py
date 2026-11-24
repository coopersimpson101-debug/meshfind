"""Full pipeline: tag adverts -> relays -> mesh -> HTTP server -> owner CLI."""

import json
import threading

from meshfind import cli, mesh
from meshfind.scenario import run_building
from meshfind.server import serve


def test_pipeline_through_http_and_cli(tmp_path, capsys):
    r = run_building((23.0, 14.0), seed=5)
    assert r.reports_sent >= 6 and r.reports_delivered == r.reports_sent
    assert r.error_m < 3.0

    httpd = serve("127.0.0.1", 0, str(tmp_path / "db.sqlite"))
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}"
        tagfile = tmp_path / "tag.json"
        assert cli.main(["tag", "new", str(tagfile), "--epoch0", "1767225600"]) == 0
        # emulate the gateway serial log for a few relays, then upload it
        from meshfind import adv, report
        from meshfind.ratchet import OwnerKeyring
        d = json.loads(tagfile.read_text())
        kr = OwnerKeyring(bytes.fromhex(d["master"]), d["epoch0"])
        t = 1767225600 + 7 * 900 + 100
        pub = kr.key(7).public
        addr, payload = adv.encode(adv.TagAdvert(pub))
        seen = adv.decode(addr, payload)
        lines = []
        for nid, (x, y, rssi) in enumerate([(0, 0, -62), (1000, 0, -72), (0, 1000, -74), (1000, 1000, -80)]):
            s = report.Sighting(t, nid, x, y, 0, 10, rssi, seen.status_bits)
            lines.append(f"MFRPT {report.seal(seen.public_key, s).hex()}")
        log = tmp_path / "serial.log"
        log.write_text("boot noise\n" + "\n".join(lines) + "\nMFRPT nothex\n")
        assert cli.main(["gateway", "--server", url, "--input", str(log)]) == 0
        svg = tmp_path / "map.svg"
        rc = cli.main(["query", str(tagfile), "--server", url, "--now", str(t + 60), "--decoys", "8",
                       "--svg", str(svg)])
        out = capsys.readouterr().out
        assert rc == 0, out
        assert "estimate (trilateration, 4 reports)" in out
        assert svg.read_text().startswith("<svg")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_cli_misc(tmp_path, capsys):
    tagfile = tmp_path / "t.json"
    assert cli.main(["tag", "new", str(tagfile), "--epoch0", "1767225600"]) == 0
    assert cli.main(["tag", "new", str(tagfile)]) == 1  # refuses to overwrite a secret
    assert cli.main(["tag", "keys", str(tagfile), "--at", "1767230000", "-n", "2"]) == 0
    assert cli.main(["tag", "provision", str(tagfile)]) == 0
    out = capsys.readouterr().out
    assert "CONFIG_MESHFIND_TAG_SK0=" in out and json.loads(tagfile.read_text())["master"] not in out
    assert cli.main(["simulate", "--seed", "3", "--svg", str(tmp_path / "s.svg")]) == 0
    assert "owner estimate" in capsys.readouterr().out


def test_report_frames_fit_espnow():
    assert mesh.HDR_LEN + 108 <= 250


def test_cli_presence(tmp_path, capsys):
    tagfile = tmp_path / "t.json"
    cli.main(["tag", "new", str(tagfile), "--epoch0", "1767225600"])
    capsys.readouterr()
    assert cli.main(["tag", "presence", str(tagfile), "--at", "1767230000", "-n", "2"]) == 0
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("epoch")]
    assert len(lines) == 2 and all(ln.split()[-1].startswith("14ffffff50") for ln in lines)
