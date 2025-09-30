import builtins
import types
import pytest

# simple fake tube implementing the required methods
class FakeTube:
    def __init__(self):
        self.sent = []
        self._recv_buf = b""
    # receiver-like methods
    def recvuntil(self, d, drop=True): return b"OK"
    def recvn(self, n): return b"x" * n
    def recvline(self, keepends=True): return b"line\n"
    def recv(self, n=4096): return b"data"
    # sender-like methods
    def send(self, data): self.sent.append(("send", data)); return len(data)
    def sendafter(self, delim, data): self.sent.append(("sendafter", delim, data)); return len(data)
    def sendline(self, data): self.sent.append(("sendline", data)); return len(data)
    def sendlineafter(self, delim, data): self.sent.append(("sendlineafter", delim, data)); return len(data)

from pwnkit import config as mod

def test_run_attaches_aliases_and_uu64_local(monkeypatch, tmp_path):
    """When running locally, run() should attach short aliases and uu64."""
    fake = FakeTube()

    # monkeypatch pwn.process to return our fake tube
    def fake_process(path, *a, **kw):
        assert str(path).endswith("vuln")  # sanity
        return fake
    monkeypatch.setattr("pwn.process", fake_process, raising=False)

    # Create a Config with a dummy local file path (no actual exec called due to monkeypatch)
    cfg = mod.Config(file_path=str(tmp_path / "vuln"))
    io = cfg.run()

    # verify returned object is our fake tube
    assert io is fake

    # Prepare calls: mapping short-name -> call args (tuple)
    call_map = {
        "ru": (b"\n",),     # recvuntil
        "rn": (10,),        # recvn
        "rl": (),           # recvline (no args -> defaults)
        "r": (4096,),       # recv
        "s": (b"test",),    # send
        "sa": (b"delim", b"test"),   # sendafter(delim, data)
        "sl": (b"line",),   # sendline
        "sla": (b"delim", b"line"),  # sendlineafter(delim, data)
    }

    for short, args in call_map.items():
        assert hasattr(io, short)
        # call them to ensure they don't raise
        getattr(io, short)(*args)

    # uu64 should be attached and compute expected value
    assert hasattr(io, "uu64")
    assert io.uu64(b"\x01\x02") == 0x0201

def test_run_attaches_aliases_and_uu64_remote(monkeypatch):
    """When running remote, remote(...) is called and aliases attached."""
    fake = FakeTube()
    def fake_remote(host, port, *a, **kw):
        assert host == "127.0.0.1"
        assert port == 1234
        return fake
    monkeypatch.setattr("pwn.remote", fake_remote, raising=False)

    cfg = mod.Config(file_path="./vuln", host="127.0.0.1", port=1234)
    io = cfg.run()

    assert io is fake
    assert hasattr(io, "ru")
    assert io.uu64(b"\x01") == 0x01

def test_global_aliases(monkeypatch):
    """Test alias() and global shorthand wrappers (s, sa, sl, etc.)."""
    fake = FakeTube()
    # ensure global alias uses exactly the provided tube
    mod.alias(fake)
    # call a few global helpers that wrap the global io
    mod.s(b"hello")
    mod.sl(b"line")
    mod.sa(b"delim", b"x")
    # check that our fake received the calls recorded earlier
    assert any(entry[0] == "send" and entry[1] == b"hello" for entry in fake.sent)
    assert any(entry[0] == "sendline" and entry[1] == b"line" for entry in fake.sent)

    # uu64 as global wrapper should map to mod.uu64 (which uses pwn.u64)
    assert mod.uu64(b"\x02") == 0x02

