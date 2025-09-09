import pytest
import pwnkit.gdbx as gdbx  # ← import the MODULE, not the function

class Sentinel: pass

@pytest.fixture
def attach_spy(monkeypatch):
    calls = {"args": None, "kwargs": None}
    ret = Sentinel()

    def _spy(*args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs
        return ret

    # Patch the attach used *inside your module*
    monkeypatch.setattr(gdbx.gdb, "attach", _spy)
    return calls, ret

def test_exports_ga():
    # Prefer module attribute check; __all__ optional across refactors
    assert hasattr(gdbx, "ga"), "module must expose ga()"
    # If you *require* __all__, keep this too:
    assert "ga" in getattr(gdbx, "__all__", []), "__all__ must export 'ga'"

def test_ga_with_pid(attach_spy):
    calls, ret = attach_spy
    out = gdbx.ga(1337, script="break *main")
    assert out is ret
    assert calls["args"] == (1337,)
    assert calls["kwargs"] == {"gdbscript": "break *main"}

def test_ga_with_gdbserver_tuple(attach_spy):
    calls, _ = attach_spy
    target = ("127.0.0.1", 31337)
    gdbx.ga(target, script="continue")
    assert calls["args"] == (target,)
    assert calls["kwargs"] == {"gdbscript": "continue"}

def test_ga_with_default_script_empty(attach_spy):
    calls, _ = attach_spy
    gdbx.ga(4242)
    assert calls["args"] == (4242,)
    assert calls["kwargs"] == {"gdbscript": ""}

def test_ga_with_pwntools_tube(attach_spy):
    pytest.importorskip("pwn", reason="pwntools required")
    pytest.importorskip("pwnlib", reason="pwntools required")
    from pwnlib.tubes.tube import tube as PwntoolsTube

    class DummyTube(PwntoolsTube):
        def __init__(self): super().__init__(timeout=None)
        def close(self): pass
        def recv_raw(self, *a, **kw): return b""
        def recv_raw_async(self, *a, **kw): return b""
        def send_raw(self, *a, **kw): return 0
        def connected(self): return True

    calls, _ = attach_spy
    t = DummyTube()
    gdbx.ga(t, script="si")
    assert calls["args"] == (t,)
    assert calls["kwargs"] == {"gdbscript": "si"}

