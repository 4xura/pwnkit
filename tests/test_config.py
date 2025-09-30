import types
import pytest

import pwnkit.config as mod


class FakeTube:
    """A lightweight fake 'tube' that behaves like a pwntools tube for testing."""

    def __init__(self):
        self.calls = []

    # receive/send style methods — record args and return simple predictable values
    def recvuntil(self, d, drop=True, timeout=None):
        self.calls.append(("recvuntil", d, drop, timeout))
        return b"until:" + (d if isinstance(d, bytes) else str(d).encode())

    def recvn(self, n, timeout=None):
        self.calls.append(("recvn", n, timeout))
        return b"A" * min(n, 10)  # return up to 10 bytes so we can assert

    def recvline(self, keepends=True):
        self.calls.append(("recvline", keepends))
        return b"aline\n" if keepends else b"aline"

    def recv(self, n=4096):
        self.calls.append(("recv", n))
        return b"R" * min(n, 8)

    def send(self, data):
        self.calls.append(("send", data))
        return len(data) if isinstance(data, (bytes, bytearray)) else len(str(data))

    def sendafter(self, d, x):
        self.calls.append(("sendafter", d, x))
        return True

    def sendline(self, x):
        self.calls.append(("sendline", x))
        return True

    def sendlineafter(self, d, x):
        self.calls.append(("sendlineafter", d, x))
        return True


def test_init_attaches_aliases_and_uu64(monkeypatch):
    """Config.init() must attach instance-level aliases and attach a uu64 helper."""

    # patch Config._open_tube to return our fake tube
    fake = FakeTube()
    monkeypatch.setattr(mod.Config, "_open_tube", lambda self: fake)

    cfg = mod.Config("./vuln")  # file_path is irrelevant; _open_tube is patched
    io = cfg.init()

    # Instance should be exactly our fake object (or the same interface)
    assert io is fake

    # Aliases should exist on the instance and call the underlying method
    assert hasattr(io, "ru"), "ru alias missing"
    assert hasattr(io, "rn"), "rn alias missing"
    assert hasattr(io, "sl"), "sl alias missing"
    assert hasattr(io, "sla"), "sla alias missing"

    # Call aliases and ensure the FakeTube recorded the calls
    out_ru = io.ru(b"\n")
    assert out_ru.startswith(b"until:"), "recvuntil alias did not proxy"
    assert ("recvuntil", b"\n", True, None) in fake.calls

    fake.calls.clear()
    out_rn = io.rn(4)
    assert out_rn == b"AAAA" or out_rn == b"A" * min(4, 10)
    assert ("recvn", 4, None) in fake.calls

    fake.calls.clear()
    assert io.sl(b"cmd") is True
    assert ("sendline", b"cmd") in fake.calls

    fake.calls.clear()
    assert io.s(b"yo") == 2
    assert ("send", b"yo") in fake.calls

    # uu64 helper should be attached and work (1-byte -> 1)
    assert hasattr(io, "uu64")
    assert io.uu64(b"\x01") == 1
    assert io.uu64(b"\x41\x42") == (0x4241)

    # p64 helper (if your module attaches p64) would be similar; skip if not present
    fake.calls.clear()


def test_global_aliases_and_wrappers(monkeypatch):
    """alias() should register the tube globally and module-level helpers should forward."""

    fake = FakeTube()

    # ensure global state is fresh: if your module exposes a reset function, use it.
    # We can't access private _global_io directly here (and shouldn't); alias() sets it.
    mod.alias(fake)

    # Module-level wrappers should forward to fake
    assert mod.s(b"hello") == 5 or mod.s("hello") == 5  # send returns length
    assert ("send", b"hello") in fake.calls or ("send", "hello") in fake.calls

    fake.calls.clear()
    # sendafter wrapper
    assert mod.sa(b":", b"payload") is True or mod.sa(":", "payload") is True
    assert any(c[0] == "sendafter" for c in fake.calls)

    fake.calls.clear()
    assert mod.sl(b"line") is True or mod.sl("line") is True
    assert any(c[0] == "sendline" for c in fake.calls)

    fake.calls.clear()
    # recv wrapper
    out = mod.r(3)
    assert out == b"R" * min(3, 8)
    assert any(c[0] == "recv" for c in fake.calls)

    fake.calls.clear()
    # recvline wrapper
    out = mod.rl(True)
    assert out == b"aline\n"
    assert any(c[0] == "recvline" for c in fake.calls)

    fake.calls.clear()
    # recvuntil wrapper
    out = mod.ru(b".")
    assert out.startswith(b"until:")
    assert any(c[0] == "recvuntil" for c in fake.calls)

    # module-level uu64 should decode correctly
    assert mod.uu64(b"\x02") == 2
    assert mod.uu64(b"\x10\x02") == 0x0210


