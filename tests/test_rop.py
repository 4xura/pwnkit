from __future__ import annotations

from pathlib import Path
import pytest

from pwn import ELF  # type: ignore
from pwnkit.rop import ROPGadgets

CANDIDATE_LIBCS = [
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/lib64/libc.so.6",
    "/usr/lib64/libc.so.6",
    "/usr/lib/libc.so.6",
]

def _find_libc_path() -> Path | None:
    for p in CANDIDATE_LIBCS:
        if Path(p).exists():
            return Path(p)
    return None

@pytest.mark.skipif(_find_libc_path() is None, reason="no known libc path found")
def test_ropgadgets_map_basic():
    libc_path = _find_libc_path()
    assert libc_path is not None

    libc = ELF(str(libc_path))

    # only test amd64 mnemonics; skip other arches
    if libc.arch != "amd64":
        pytest.skip(f"libc arch is {libc.arch}, test expects amd64")

    rop = ROPGadgets(libc)

    expected_keys = {
        "p_rdi_r", "p_rsi_r", "p_rdx_rbx_r", "p_rax_r",
        "p_rsp_r", "leave_r", "ret", "syscall_r",
    }
    assert expected_keys.issubset(set(rop.gadgets.keys()))

    # Values are either None or absolute addresses no lower than base
    for name, addr in rop.gadgets.items():
        if addr is None:
            continue
        assert isinstance(addr, int)
        assert addr >= libc.address  # basic sanity

    # __getitem__ mirrors dict
    assert rop["ret"] == rop.gadgets["ret"]

    # Sanity-read: 'ret' gadget should actually contain a 0xC3 byte
    ret_addr = rop["ret"]
    assert ret_addr is not None
    # Read one byte at the gadget address; pwntools maps VAs relative to ELF base
    b = libc.read(ret_addr, 1)
    assert isinstance(b, (bytes, bytearray)) and len(b) == 1
    assert b == b"\xC3"

