#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple, Union
from pwn import context, pack, unpack, error  # type: ignore

__all__ = [
    "IOFilePlus",
    "IO_FILE_MAPS",
]

# Glibc IO file structs
# ---------------------------------------------------------------------------
# Each entry: offset -> (name, size_bytes)
PTR = object()  # "pointer-sized"

_IO_FILE_I386: Dict[int, Tuple[str, int | object]] = {
    0x00: ("_flags",         4),
    0x04: ("_IO_read_ptr",   PTR),
    0x08: ("_IO_read_end",   PTR),
    0x0c: ("_IO_read_base",  PTR),
    0x10: ("_IO_write_base", PTR),
    0x14: ("_IO_write_ptr",  PTR),
    0x18: ("_IO_write_end",  PTR),
    0x1c: ("_IO_buf_base",   PTR),
    0x20: ("_IO_buf_end",    PTR),
    0x24: ("_IO_save_base",  PTR),
    0x28: ("_IO_backup_base",PTR),
    0x2c: ("_IO_save_end",   PTR),
    0x30: ("_markers",       PTR),
    0x34: ("_chain",         PTR),
    0x38: ("_fileno",        4),
    0x3c: ("_flags2",        4),
    0x40: ("_old_offset",    4),
    0x44: ("_cur_column",    2),
    0x46: ("_vtable_offset", 1),
    0x47: ("_shortbuf",      1),
    0x48: ("_lock",          PTR),
    0x4c: ("_offset",        8),  # off_t on 32-bit GLIBC is 64-bit
    0x54: ("_codecvt",       PTR),
    0x58: ("_wide_data",     PTR),
    0x5c: ("_freeres_list",  PTR),
    0x60: ("_freeres_buf",   PTR),
    0x64: ("__pad5",         4),
    0x68: ("_mode",          4),  
    0x6c: ("_unused2",       0x20),  # array
    0x94: ("vtable",         PTR),
}

_IO_FILE_AMD64: Dict[int, Tuple[str, int | object]] = {
    0x00: ("_flags",         4),
    0x08: ("_IO_read_ptr",   PTR),
    0x10: ("_IO_read_end",   PTR),
    0x18: ("_IO_read_base",  PTR),
    0x20: ("_IO_write_base", PTR),
    0x28: ("_IO_write_ptr",  PTR),
    0x30: ("_IO_write_end",  PTR),
    0x38: ("_IO_buf_base",   PTR),
    0x40: ("_IO_buf_end",    PTR),
    0x48: ("_IO_save_base",  PTR),
    0x50: ("_IO_backup_base",PTR),
    0x58: ("_IO_save_end",   PTR),
    0x60: ("_markers",       PTR),
    0x68: ("_chain",         PTR),
    0x70: ("_fileno",        4),
    0x74: ("_flags2",        4),
    0x78: ("_old_offset",    8),   # off_t (64-bit)
    0x80: ("_cur_column",    2),
    0x82: ("_vtable_offset", 1),
    0x83: ("_shortbuf",      1),
    0x88: ("_lock",          PTR),
    0x90: ("_offset",        8),
    0x98: ("_codecvt",       PTR),
    0xa0: ("_wide_data",     PTR),
    0xa8: ("_freeres_list",  PTR),
    0xb0: ("_freeres_buf",   PTR),
    0xb8: ("__pad5",         4),
    0xc0: ("_mode",          4), 
    0xc4: ("_unused2",       0x14),  # array
    0xd8: ("vtable",         PTR),
}

IO_FILE_MAPS: Dict[str, Dict[int, Tuple[str, int | object]]] = {
    "i386" : _IO_FILE_I386,
    "amd64": _IO_FILE_AMD64,
}

_DEFAULT_FILE_SIZE = {
    "i386" : 0x98, 
    "amd64": 0xe0,
}

# Instantize an _IO_FILE_plus struct
# ---------------------------------------------------------------------------
from .ctx import Arch   # Arch = Literal["amd64", "i386", "arm", "aarch64"]
Key = Union[str, int]   # field name like "vtable", or byte offset like 0xd8

@dataclass
class IOFilePlus:
    arch: Arch = field(default_factory=lambda: ("amd64") if context.bits == 64 else "i386")
    size: int = field(init=False)
    data: bytearray = field(init=False)
    _map: Dict[int, Tuple[str, int | object]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.arch not in IO_FILE_MAPS:
            error(f"Unsupported arch '{self.arch}'")
        self._map = IO_FILE_MAPS[self.arch]
        self.size = _DEFAULT_FILE_SIZE[self.arch]        
        self.data = bytearray(self.size)

    # - Utilities
    @property
    def ptr_size(self) -> int:
        if self.arch in ("amd64", "aarch64"):
            return 8
        elif self.arch in ("i386", "arm"):
            return 4
        else:
            error(f"Unsupported arch '{self.arch}'")

    def _size_of(self, sz: int | object) -> int:
        return self.ptr_size if sz is PTR else int(sz)

    def fields(self) -> Iterable[Tuple[int, str, int]]:
        for off, (name, sz) in sorted(self._map.items()):
            yield off, name, self._size_of(sz)

    def offset_of(self, field_name: str) -> int:
        for off, (name, _sz) in self._map.items():
            if name == field_name:
                return off
        raise KeyError(f"Unknown field: {field_name}")

    # - Pretty dump print
    def _u(self, off: int, size: int) -> int:
        be = (context.endian == "big")
        return int.from_bytes(self.data[off:off+size], byteorder="big" if be else "little", signed=False)

    def _bytes(self, off: int, size: int) -> bytes:
        return bytes(self.data[off:off+size])

    def dump(
        self,
        *,
        only_nonzero: bool = False,
        show_bytes: bool = True,
        highlight_ptrs: bool = True,
        color: bool = True,
    ) -> None:
        """
        Print a table of (offset, name, size, hex, dec, bytes).
            @only_nonzero   : hide zero-valued fields
            @show_bytes     : include the raw hex bytes column
            @highlight_ptrs : bold pointer-sized fields
            @color          : ANSI colors
        """
        def c(s: str, code: str) -> str:
            if not color: return s
            return f"\x1b[{code}m{s}\x1b[0m"

        BOLD = "1"
        DIM  = "2"
        CYAN = "36"
        MAG  = "35"
        YEL  = "33"

        rows: List[str] = []
        header = f"{c('OFF',BOLD):>6}  {c('NAME',BOLD):<24}  {c('SZ',BOLD):>3}  {c('HEX',BOLD):>18}  {c('DEC',BOLD):>20}"
        if show_bytes:
            header += f"  {c('BYTES',BOLD)}"
        rows.append(header)

        # walk the layout
        for off, (name, desc_sz) in sorted(self._map.items()):
            size = self._size_of(desc_sz)
            chunk = self.data[off:off+size]

            signed = (name == "_vtable_offset" and size == 1)
            be = (context.endian == "big")
            byteorder = "big" if be else "little"
            val = int.from_bytes(chunk, byteorder=byteorder, signed=signed)

            if only_nonzero and val == 0:
                continue

            hexval = f"0x{val:0{size*2}x}" if not signed or val >= 0 else f"-0x{(-val):0{size*2}x}"
            decval = str(val)
            bhex   = chunk.hex()

            shown_name = name
            if highlight_ptrs and size == self.ptr_size:
                shown_name = c(shown_name, BOLD if val else DIM)
            elif val == 0 and color:
                shown_name = c(shown_name, DIM)

            line = f"{off:#06x}  {shown_name:<24}  {size:>3}  {c(hexval, CYAN):>18}  {c(decval, MAG):>20}"
            if show_bytes:
                line += f"  {c(bhex, YEL)}"
            rows.append(line)

        # header/meta up top
        meta = [
            f"{c('arch',BOLD)}: {self.arch}   {c('ptr size',BOLD)}: {self.ptr_size}   {c('size',BOLD)}: {self.size}",
        ]
        print("\n".join(meta + [""] + rows))

    # - Get/set by field 
    def _resolve(self, key: Key) -> Tuple[int, int]:
        """
        Normalize an IO FILE field selector to (offset, size).
        - If key is int: treat as byte offset; look up size from _map.
        - If key is str: look up by field name via offset_of().
        """
        # int → offset
        if isinstance(key, int):
            off = key
            try:
                _name, sz = self._map[off]
            except KeyError:
                raise KeyError(f"Unknown offset 0x{off:x} for arch {self.arch}")
            size = self._size_of(sz)
            return off, size

        # str → field name
        off = self.offset_of(key)
        _name, sz = self._map[off]
        size = self._size_of(sz)
        return off, size

    # Get/Set that accept name or offset
    def set(self, key: Key, value: int) -> "IOFilePlus":
        """Set numeric field (int or pointer) by field name or byte offset."""
        off, size = self._resolve(key)
        self.data[off:off+size] = pack(value, word_size=size*8, endianness=context.endian, sign=False)
        return self

    def get(self, key: Key) -> int:
        """Get numeric field by field name or byte offset."""
        off, size = self._resolve(key)
        return unpack(bytes(self.data[off:off+size]), word_size=size*8, endianness=context.endian, sign=False)

    # - Aliases for common fields
    #   _flags
    @property
    def flags(self) -> int:
        return self.get("_flags")
    @flags.setter
    def flags(self, v: int) -> None:
        self.set("_flags", v)

    #   vtable
    @property
    def vtable(self) -> int:
        return self.get("vtable")
    @vtable.setter
    def vtable(self, addr: int) -> None:
        self.set("vtable", addr)

    #   _vtable_offset
    @property
    def vtable_offset(self) -> int:
        """signed char (-128..127)."""
        return self.get("_vtable_offset")
    @vtable_offset.setter
    def vtable_offset(self, off: int) -> None:
        if not (-128 <= off <= 127):
            raise ValueError("_vtable_offset must fit in signed char (-128..127)")
        self.set("_vtable_offset", off)

    #   _mode
    @property
    def mode(self) -> int:
        return self.get("_mode")
    @mode.setter
    def mode(self, v: int) -> None:
        """_mode is always present as a 32-bit field."""
        if not (0 <= v <= 0xFFFFFFFF):
            error(f"_mode out of range: {hex(v)}")
        self.set("_mode", v)

    #   _chain
    @property
    def chain(self) -> int:
        return self.get("_chain")
    @chain.setter
    def chain(self, addr: int) -> None:
        self.set("_chain", addr)

    #   _lock
    @property
    def lock(self) -> int:
        return self.get("_lock")
    @lock.setter
    def lock(self, addr: int) -> None:
        self.set("_lock", addr)

    #   _fileno
    @property
    def fileno(self) -> int:
        return self.get("_fileno")
    @fileno.setter
    def fileno(self, fd: int) -> None:
        if not (0 <= fd <= 0xFFFFFFFF):
            error(f"_fileno out of range: {hex(fd)}")
        self.set("_fileno", fd)

    #   _markers
    @property
    def markers(self) -> int:
        return self.get("_markers")
    @markers.setter
    def markers(self, addr: int) -> None:
        self.set("_markers", addr)

    #   _wide_data
    @property
    def wide_data(self) -> int:
        return self.get("_wide_data")
    @wide_data.setter
    def wide_data(self, addr: int) -> None:
        self.set("_wide_data", addr)

    #  _IO_read_ptr
    @property
    def read_ptr(self) -> int:
        return self.get("_IO_read_ptr")
    @read_ptr.setter
    def read_ptr(self, addr: int) -> None:
        self.set("_IO_read_ptr", addr)

    #  _IO_read_end
    @property
    def read_end(self) -> int:
        return self.get("_IO_read_end")
    @read_end.setter
    def read_end(self, addr: int) -> None:
        self.set("_IO_read_end", addr)

    #  _IO_read_base
    @property
    def read_base(self) -> int:
        return self.get("_IO_read_base")
    @read_base.setter
    def read_base(self, addr: int) -> None:
        self.set("_IO_read_base", addr)

    #  _IO_write_base
    @property
    def write_base(self) -> int:
        return self.get("_IO_write_base")
    @write_base.setter
    def write_base(self, addr: int) -> None:
        self.set("_IO_write_base", addr)

    #  _IO_write_ptr
    @property
    def write_ptr(self) -> int:
        return self.get("_IO_write_ptr")
    @write_ptr.setter
    def write_ptr(self, addr: int) -> None:
        self.set("_IO_write_ptr", addr)

    #  _IO_write_end
    @property
    def write_end(self) -> int:
        return self.get("_IO_write_end")
    @write_end.setter
    def write_end(self, addr: int) -> None:
        self.set("_IO_write_end", addr)

    #  _IO_buf_base
    @property
    def buf_base(self) -> int:
        return self.get("_IO_buf_base")
    @buf_base.setter
    def buf_base(self, addr: int) -> None:
        self.set("_IO_buf_base", addr)

    #  _IO_buf_end
    @property
    def buf_end(self) -> int:
        return self.get("_IO_buf_end")
    @buf_end.setter
    def buf_end(self, addr: int) -> None:
        self.set("_IO_buf_end", addr)

    # - to/from bytes 
    @classmethod
    def from_bytes(cls, blob: bytes, arch: Arch | None = None) -> "IOFilePlus":
        obj = cls(arch or ("amd64" if context.bits == 64 else "i386"))
        if len(blob) > len(obj.data):
            error(f"Blob too large for IO_FILE({obj.arch}): {len(blob)} > {len(obj.data)}")
        obj.data[:len(blob)] = blob
        return obj

    def bytes(self) -> bytes:
        return bytes(self.data)


