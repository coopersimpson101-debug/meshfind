"""Build and run the firmware/common host test with any available C compiler.

Compiler choice: $CC if set, else `python -m ziglang cc` (pip install ziglang),
else `cc`. Exits with the test binary's status.

    python tools/host_test.py
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "firmware" / "common"
SOURCES = ["src/mf_crypto_ref.c", "src/mf_crypto_common.c", "src/mf_proto.c", "src/mf_mesh.c", "test/test_main.c"]
FLAGS = ["-std=c99", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-Wshadow", "-Wconversion",
         "-Wno-sign-conversion"]


def compiler() -> list[str]:
    if os.environ.get("CC"):
        return shlex.split(os.environ["CC"])
    try:
        import ziglang  # noqa: F401
        return [sys.executable, "-m", "ziglang", "cc"]
    except ImportError:
        pass
    for cc in ("cc", "gcc", "clang"):
        if shutil.which(cc):
            return [cc]
    raise SystemExit("no C compiler found (set CC or pip install ziglang)")


def build(out_dir: Path) -> Path:
    exe = out_dir / ("mf_host_test.exe" if os.name == "nt" else "mf_host_test")
    cmd = compiler() + FLAGS + ["-I", str(COMMON / "include"), "-o", str(exe)] + [str(COMMON / s) for s in SOURCES]
    subprocess.run(cmd, check=True)
    return exe


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        exe = build(Path(td))
        return subprocess.run([str(exe), str(ROOT / "vectors" / "meshfind_vectors.json")]).returncode


if __name__ == "__main__":
    sys.exit(main())
