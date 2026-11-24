"""Report store + HTTP API (stdlib only: http.server + sqlite3).

The server is deliberately dumb: it stores opaque 108-byte envelopes indexed
by ``key_hash`` (SHA-256 of the epoch public key) and hands them back to
whoever asks for a hash. It never sees tag keys, owner identities or
plaintext locations.

API (JSON over HTTP; put it behind TLS for anything but a LAN)::

    GET  /v1/health                         -> {"ok": true, "reports": N}
    POST /v1/reports  {"reports": [hex]}    -> {"accepted", "duplicates", "rejected"}
         (optional ``Authorization: Bearer <token>`` if started with a token)
    POST /v1/query    {"key_hashes": [hex], "since": unix?}
                                            -> {"reports": {hash_hex: [hex, ...]}}
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .report import Envelope, ReportError

MAX_BODY = 512 * 1024
MAX_UPLOAD = 1000
MAX_QUERY = 4096
MAX_PER_HASH = 500


class ReportStore:
    def __init__(self, path: str = ":memory:", retention_s: int = 7 * 86400):
        self.retention_s = retention_s
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS reports ("
            " report_id BLOB PRIMARY KEY, key_hash BLOB NOT NULL,"
            " envelope BLOB NOT NULL, received_at INTEGER NOT NULL)"
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_kh ON reports(key_hash, received_at)")
        self.db.commit()

    def add(self, raw: bytes, now: float | None = None) -> str:
        """Returns 'accepted', 'duplicate' or 'rejected'."""
        try:
            env = Envelope.parse(raw)
        except ReportError:
            return "rejected"
        now = int(time.time() if now is None else now)
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO reports VALUES (?,?,?,?)",
                (env.report_id, env.key_hash, raw, now),
            )
            self.db.commit()
        return "accepted" if cur.rowcount == 1 else "duplicate"

    def query(self, key_hashes: list[bytes], since: int = 0) -> dict[bytes, list[bytes]]:
        out: dict[bytes, list[bytes]] = {}
        with self._lock:
            for kh in key_hashes:
                rows = self.db.execute(
                    "SELECT envelope FROM reports WHERE key_hash=? AND received_at>=?"
                    " ORDER BY received_at LIMIT ?",
                    (kh, since, MAX_PER_HASH),
                ).fetchall()
                if rows:
                    out[kh] = [r[0] for r in rows]
        return out

    def expire(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            cur = self.db.execute("DELETE FROM reports WHERE received_at < ?", (int(now - self.retention_s),))
            self.db.commit()
        return cur.rowcount

    def count(self) -> int:
        with self._lock:
            return self.db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]


def _hexlist(v, n_bytes: int | None, limit: int) -> list[bytes]:
    if not isinstance(v, list) or len(v) > limit:
        raise ValueError("expected a bounded list")
    out = []
    for item in v:
        if not isinstance(item, str):
            raise ValueError("expected hex strings")
        b = bytes.fromhex(item)
        if n_bytes is not None and len(b) != n_bytes:
            raise ValueError("wrong length")
        out.append(b)
    return out


def make_handler(store: ReportStore, upload_token: str | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "meshfind/0.1"

        def log_message(self, fmt, *args):  # quiet by default
            pass

        def _send(self, code: int, obj) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_BODY:
                raise ValueError("bad body size")
            return json.loads(self.rfile.read(n))

        def do_GET(self):
            if self.path == "/v1/health":
                return self._send(200, {"ok": True, "reports": store.count()})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                if self.path == "/v1/reports":
                    if upload_token and self.headers.get("Authorization") != f"Bearer {upload_token}":
                        return self._send(401, {"error": "unauthorized"})
                    reps = _hexlist(self._body().get("reports"), None, MAX_UPLOAD)
                    res = {"accepted": 0, "duplicates": 0, "rejected": 0}
                    for r in reps:
                        k = store.add(r)
                        res["duplicates" if k == "duplicate" else k] += 1
                    return self._send(200, res)
                if self.path == "/v1/query":
                    body = self._body()
                    hashes = _hexlist(body.get("key_hashes"), 32, MAX_QUERY)
                    since = int(body.get("since", 0))
                    found = store.query(hashes, since)
                    return self._send(200, {"reports": {k.hex(): [e.hex() for e in v] for k, v in found.items()}})
            except (ValueError, AttributeError, json.JSONDecodeError) as exc:
                return self._send(400, {"error": str(exc)})
            self._send(404, {"error": "not found"})

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8787, db: str = "meshfind.db",
          upload_token: str | None = None, retention_days: int = 7) -> ThreadingHTTPServer:
    store = ReportStore(db, retention_days * 86400)
    httpd = ThreadingHTTPServer((host, port), make_handler(store, upload_token))
    httpd.store = store  # type: ignore[attr-defined]
    return httpd
