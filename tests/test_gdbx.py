# tests/test_gdbx.py
from __future__ import annotations

import types
import pytest

from pwnkit.gdbx import ga
from pwnlib.tubes.process import process as PwntoolsProcess  # used only for isinstance check


def _dummy_local_process_instance():
    """Create an instance that passes isinstance(x, PwntoolsProcess) without starting a real process."""
    class _Dummy(PwntoolsProcess):
        pass
    return object.__new__(_Dummy)  # skip __init__, we only need isinstance to be true


class _DummyRemote:
    """Any non-PwntoolsProcess object acts as a 'remote' tube for our tests."""
    pass


def test_ga_local_process_attaches(monkeypatch):
    called = {}

    def fake_attach(target, gdbscript=None):
        called["target"] = target
        called["gdbscript"] = gdbscript

    warnings = []

    monkeypatch.setattr("pwnkit.gdbx.gdb.attach", fake_attach)
    monkeypatch.setattr("pwnkit.gdbx.warn", lambda msg: warnings.append(msg))

    io = _dummy_local_process_instance()
    ga(io, script="b main\nc")

    assert called["target"] is io
    assert called["gdbscript"] == "b main\nc"
    assert warnings == []


def test_ga_remote_with_server_attaches(monkeypatch):
    called = {}

    def fake_attach(target, gdbscript=None):
        called["target"] = target
        called["gdbscript"] = gdbscript

    warnings = []

    monkeypatch.setattr("pwnkit.gdbx.gdb.attach", fake_attach)
    monkeypatch.setattr("pwnkit.gdbx.warn", lambda msg: warnings.append(msg))

    io = _DummyRemote()
    server = ("127.0.0.1", 1337)
    ga(io, script="b *0x401000\nc", server=server)

    assert called["target"] == server              # attaches to (host, port)
    assert called["gdbscript"] == "b *0x401000\nc"
    assert warnings == []


def test_ga_remote_without_server_warns(monkeypatch):
    called = {"attach": False}
    monkeypatch.setattr("pwnkit.gdbx.gdb.attach", lambda *a, **kw: called.__setitem__("attach", True))
    msgs = []
    monkeypatch.setattr("pwnkit.gdbx.warn", lambda m: msgs.append(m))

    io = _DummyRemote()
    ga(io, script="b main")

    assert called["attach"] is False
    assert len(msgs) == 1
    assert "remote tube detected" in msgs[0]


def test_ga_attach_failure_warns(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("no gdb here")

    msgs = []
    monkeypatch.setattr("pwnkit.gdbx.gdb.attach", boom)
    monkeypatch.setattr("pwnkit.gdbx.warn", lambda m: msgs.append(m))

    io = _dummy_local_process_instance()
    ga(io, script="c")

    assert any("GDB attach failed" in m for m in msgs)

