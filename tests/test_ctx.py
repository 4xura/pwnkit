from __future__ import annotations

import logging
import pytest
from pwn import context as pwnctx  # pwntools global context
from pwnkit.ctx import Context, TERM


@pytest.fixture(autouse=True)
def save_restore_pwn_context():
    """
    Snapshot the pwntools context and restore after each test,
    so tests don't leak global state across runs.
    """
    snap = {
        "arch": pwnctx.arch,
        "os": pwnctx.os,
        "endian": pwnctx.endian,
        "log_level": pwnctx.log_level,
        "terminal": tuple(pwnctx.terminal) if pwnctx.terminal else None,
    }
    try:
        yield
    finally:
        pwnctx.clear()
        # pwntools expects certain fields to be set explicitly
        if snap["arch"]:
            pwnctx.arch = snap["arch"]
        if snap["os"]:
            pwnctx.os = snap["os"]
        if snap["endian"]:
            pwnctx.endian = snap["endian"]
        if snap["log_level"]:
            pwnctx.log_level = snap["log_level"]
        if snap["terminal"] is not None:
            pwnctx.terminal = list(snap["terminal"])


def test_str_has_all_fields():
    c = Context()
    s = str(c)
    assert "Context(" in s and "arch" in s and "os" in s and "endian" in s
    assert "log_level" in s and "terminal" in s


def test_defaults_and_term_tuple_immutable():
    c1 = Context()
    assert c1.arch == "amd64"
    assert c1.os == "linux"
    assert c1.endian == "little"
    assert c1.log_level == "debug"
    assert tuple(c1.terminal) == TERM
    # tuples are immutable → TypeError on assignment
    with pytest.raises(TypeError):
        TERM[0] = "bash"


def test_push_applies_to_pwntools_context():
    c = Context(arch="i386", os="linux", endian="little",
                log_level="info", terminal=("tmux", "splitw", "-v"))
    c.push()
    assert pwnctx.arch == "i386"
    assert pwnctx.os == "linux"
    assert pwnctx.endian == "little"
    assert pwnctx.log_level == logging.INFO   # <- compare to int level
    assert pwnctx.terminal == ["tmux", "splitw", "-v"]


def test_presets_list_and_fetch_copy():
    names = set(Context.presets())
    assert "linux-amd64-debug" in names
    base = Context.preset("linux-amd64-debug")
    # getting it twice returns distinct objects (shallow copy)
    another = Context.preset("linux-amd64-debug")
    assert base is not another
    # fields look sane
    assert base.arch == "amd64" and base.os == "linux" and base.endian == "little"
    assert base.log_level in ("debug", "info")


def test_unknown_preset_raises():
    with pytest.raises(KeyError):
        Context.preset("does-not-exist-42")


def test_override_preset_then_push():
    c = Context.preset("linux-aarch64-debug")
    c.log_level = "error"
    c.terminal = ("tmux", "splitw", "-h")
    c.push()
    assert pwnctx.arch == "aarch64"
    assert pwnctx.log_level == logging.ERROR  # <- compare to int level
    assert pwnctx.terminal == ["tmux", "splitw", "-h"]

