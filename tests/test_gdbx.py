import types
import pytest

# Skip tube-specific test cleanly if pwntools isn't present
pwn = pytest.importorskip("pwn", reason="pwntools required for tube-type test")
pytest.importorskip("pwnlib", reason="pwntools required for tube-type test")

import pwnkit.gdbx import ga


class Sentinel:
    """Unique object to verify return value passthrough."""
    pass


@pytest.fixture
def attach_spy(monkeypatch):
    """
    Patch ga.gdb.attach to a spy that records calls and returns a sentinel.
    """
    calls = {"args": None, "kwargs": None}
    ret = Sentinel()

    def _spy(*args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs
        return ret

    monkeypatch.setattr(ga.gdb, "attach", _spy)
    return calls, ret


def test_exports_ga():
    assert "ga" in getattr(ga, "__all__", []), "__all__ must export 'ga'"


def test_ga_with_pid(attach_spy):
    calls, ret = attach_spy
    out = ga.ga(1337, script="break *main")
    assert out is ret
    # First positional argument should be the target
    assert calls["args"] == (1337,)
    # Script must be passed via 'gdbscript' kwarg
    assert calls["kwargs"] == {"gdbscript": "break *main"}


def test_ga_with_gdbserver_tuple(attach_spy):
    calls, _ = attach_spy
    host_port = ("127.0.0.1", 31337)
    ga.ga(host_port, script="continue")
    assert calls["args"] == (host_port,)
    assert calls["kwargs"] == {"gdbscript": "continue"}


def test_ga_with_default_script_empty(attach_spy):
    calls, _ = attach_spy
    ga.ga(4242)  # no script provided
    assert calls["args"] == (4242,)
    assert calls["kwargs"] == {"gdbscript": ""}


def test_ga_with_pwntools_tube(attach_spy):
    """
    Use a minimal in-memory pipe to stand in for a PwntoolsTube.
    If you prefer, you can import and use process()/remote() directly.
    """
    calls, _ = attach_spy

    # Build a tiny fake that quacks like a pwntools tube
    from pwnlib.tubes.tube import tube as PwntoolsTube

    class DummyTube(PwntoolsTube):
        def __init__(self):
            # Initialize minimal state required by base class
            super().__init__(timeout=None)

        # Implement abstract methods with no-ops for type sanity
        def close(self): pass
        def recv_raw(self, *a, **kw): return b""
        def recv_raw_async(self, *a, **kw): return b""
        def send_raw(self, *a, **kw): return 0
        def connected(self): return True

    t = DummyTube()
    ga.ga(t, script="si")
    assert calls["args"] == (t,)
    assert calls["kwargs"] == {"gdbscript": "si"}

