import re
import sys
from typing import Tuple

import pytest
from pwn import context  # type: ignore

# --- Import IOFilePlus from your package --------------------------------------
# Adjust as needed. We try a few common layouts so the test runs out-of-the-box.
try:
    from pwnkit.FILE import IOFilePlus  # your current path
except Exception:
    try:
        from pwnkit.iofile_plus import IOFilePlus  # alt name
    except Exception:
        from iofile_plus import IOFilePlus  # local module fallback


# --- helpers ------------------------------------------------------------------

def set_arch(arch: str) -> None:
    """Reset pwntools context for deterministic packing."""
    if arch == "amd64":
        context.clear(arch="amd64", os="linux", endian="little")
    elif arch == "i386":
        context.clear(arch="i386", os="linux", endian="little")
    else:
        raise ValueError("unsupported arch for test")


def column_slices(ptr_size: int) -> Tuple[slice, slice, slice, slice, slice]:
    """
    Return slices (off, name, sz, hex, dec) matching your dump() column widths.
      OFF(6) | NAME(24) | SZ(2) | HEX(3 + 2*ptr) | DEC(20) | BYTES...
    Columns are separated by two spaces.
    """
    OFF_W, NAME_W, SZ_W = 6, 24, 2
    HEX_W = 3 + 2 * ptr_size   # '-0x' or ' 0x' + digits
    DEC_W = 20

    pos = 0
    off_sl = slice(pos, pos + OFF_W); pos += OFF_W + 2
    name_sl = slice(pos, pos + NAME_W); pos += NAME_W + 2
    sz_sl = slice(pos, pos + SZ_W); pos += SZ_W + 2
    hex_sl = slice(pos, pos + HEX_W); pos += HEX_W + 2
    dec_sl = slice(pos, pos + DEC_W)
    return off_sl, name_sl, sz_sl, hex_sl, dec_sl


# --- AMD64 tests --------------------------------------------------------------

def test_amd64_basic_fields_and_lengths(capsys):
    set_arch("amd64")
    f = IOFilePlus("amd64")

    # size & ptr width
    assert f.ptr_size == 8
    assert len(f.bytes) == 0xE0  # 224

    # set by name
    f.flags = 0xFBAD0000
    f.vtable = 0x4141414141414141
    f.chain = 0x1337
    f.lock = 0x2222

    # set by offset (use the map to be robust)
    vtbl_off = f.offset_of("vtable")
    f.set(vtbl_off, 0x4242424242424242)
    assert f.get("vtable") == 0x4242424242424242

    # signed char handling
    f.vtable_offset = -1
    assert f.vtable_offset == -1
    off = f.offset_of("_vtable_offset")
    assert f.data[off:off+1] == b"\xff"

    # dump without ANSI (stable text), keep zeros
    f.dump(color=False, only_nonzero=False)
    out = capsys.readouterr().out

    # must contain fixed-width HEX for the signed char: zero-extended, not negative hex
    assert " 0x00000000000000ff" in out
    assert "-0x0000000000000001" not in out

    # check column exact widths on the _vtable_offset line
    line = next(l for l in out.splitlines() if "_vtable_offset" in l)
    off_sl, name_sl, sz_sl, hex_sl, dec_sl = column_slices(ptr_size=8)
    # expected hex cell: leading space before 0x to align with negatives
    expected_hex = " 0x" + "0" * 14 + "ff"
    assert line[hex_sl] == expected_hex
    # width sanity: no bleed into next column
    assert len(line[hex_sl]) == 3 + 16
    assert line[sz_sl].strip() == "1"


def test_amd64_get_set_symmetry_and_offsets():
    set_arch("amd64")
    f = IOFilePlus("amd64")

    # name/offset symmetry for a classic pointer field
    name = "_IO_write_ptr"
    off = f.offset_of(name)
    f.set(name, 0xdeadbeefcafebabe)
    assert f.get(off) == 0xdeadbeefcafebabe
    assert f.get(name) == f.get(off)

    # numeric scalar field (u32)
    f.set("_flags", 0x41424344)
    assert f.flags == 0x41424344


def test_amd64_ptr_sentinel_is_not_size_based():
    """
    Ensure pointer-ness comes from the PTR sentinel, not just 'size == ptr_size'.
    Specifically, _offset is 8 bytes but is NOT a pointer.
    """
    set_arch("amd64")
    f = IOFilePlus("amd64")
    # class caches pointer fields in __post_init__ as `_ptr_fields`
    assert hasattr(f, "_ptr_fields")
    ptrs = f._ptr_fields

    # definitely pointers
    assert "_IO_read_ptr" in ptrs
    assert "_IO_write_ptr" in ptrs
    assert "_lock" in ptrs
    assert "vtable" in ptrs

    # 8-byte scalar: should NOT be a pointer
    assert "_offset" not in ptrs
    assert "_old_offset" not in ptrs


def test_amd64_from_bytes_hydration_roundtrip():
    set_arch("amd64")
    f0 = IOFilePlus("amd64")
    # craft a blob: set vtable_offset raw byte to 0xfe (signed = -2)
    blob = bytearray(f0.bytes)
    blob[f0.offset_of("_vtable_offset")] = 0xFE
    f = IOFilePlus.from_bytes(bytes(blob), arch="amd64")
    assert f.vtable_offset == -2
    # mutate & re-emit
    f.vtable = 0x1111222233334444
    out = f.bytes
    assert isinstance(out, bytes)
    assert len(out) == 0xE0


# --- i386 tests ---------------------------------------------------------------

def test_i386_signed_and_hex_padding(capsys):
    set_arch("i386")
    f = IOFilePlus("i386")

    assert f.ptr_size == 4
    assert len(f.bytes) == 0x98

    f.vtable_offset = -1
    f.dump(color=False)
    out = capsys.readouterr().out

    # hex must be zero-extended to 8 digits on i386
    assert " 0x000000ff" in out
    assert "-0x00000001" not in out


def test_i386_name_and_offset_setters():
    set_arch("i386")
    f = IOFilePlus("i386")

    vtbl = 0x8049000
    f.vtable = vtbl
    assert f.get("vtable") == vtbl

    off = f.offset_of("vtable")
    f.set(off, 0x804dead)
    assert f.get("vtable") == 0x804dead

