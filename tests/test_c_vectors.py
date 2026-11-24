"""C (firmware/common) vs Python agreement: builds the portable C core on the
host and runs it against vectors/meshfind_vectors.json."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _have_compiler() -> bool:
    if os.environ.get("CC"):
        return True
    try:
        import ziglang  # noqa: F401
        return True
    except ImportError:
        return any(shutil.which(c) for c in ("cc", "gcc", "clang"))


@pytest.mark.skipif(not _have_compiler(), reason="no C compiler (set CC or pip install ziglang)")
def test_c_core_matches_python_vectors():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "host_test.py")], capture_output=True, text=True,
                       timeout=900)
    assert r.returncode == 0, r.stdout + r.stderr
    assert " 0 failures" in r.stdout
