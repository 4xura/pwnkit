# tests/test_io.py
from __future__ import annotations

import os
from pathlib import Path
import pytest

from pwnkit.io import Tube

BIN_CAT = "/bin/cat"
LIBC    = "/usr/lib/libc.so.6"  


@pytest.mark.skipif(not Path(BIN_CAT).exists(), reason="/bin/cat not found")
def test_local_cat_echo_line():
    io = Tube(BIN_CAT).init().alias()
    try:
        msg = b"hello-tube"
        io.sl(msg)
        out = io.r(len(msg) + 1)
        assert out == msg + b"\n"
    finally:
        io.close()  # <— important


def test_alias_required_guard():
    """Using shortcuts before alias() should assert."""
    io = Tube(BIN_CAT).init()
    with pytest.raises(AssertionError):
        io.sl(b"nope")  # alias() not called yet


def test_as_code_representation_local():
    """as_code() should describe a local process launch."""
    io = Tube(BIN_CAT)
    code = io.as_code()
    # e.g., "process('/bin/cat')" or "process('/bin/cat', env={...})"
    assert code.startswith("process(")
    assert BIN_CAT in code


def test_build_env_no_libc_and_empty_env_is_none():
    """Without libc_path and with empty env, build_env() yields None for local."""
    io = Tube(BIN_CAT)
    assert io.build_env() is None


@pytest.mark.skipif(not Path(LIBC).exists(), reason="no libc")
def test_build_env_with_libc_sets_preload_and_libpath():
    """If a local libc_path is provided, build_env() sets LD_PRELOAD/LD_LIBRARY_PATH."""
    assert Path(LIBC).exists(), "libc path invalid for this test"
    io = Tube(BIN_CAT, libc_path=LIBC)
    env = io.build_env()
    assert env is not None
    assert env.get("LD_PRELOAD", "").endswith("libc.so.6")
    assert os.path.isdir(env.get("LD_LIBRARY_PATH", ""))

