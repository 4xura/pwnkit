#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple, Union, Mapping
from pwn import context, pack, unpack, error  # type: ignore

__all__ = [
    "_IO_FILE_I386", "_IO_FILE_AMD64",
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

SIGNED_FIELDS: set[str] = {"_vtable_offset"}  # signed char (-128..127)

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
    _ptr_fields: Tuple[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.arch not in IO_FILE_MAPS:
            error(f"Unsupported arch '{self.arch}'")
        self.size = _DEFAULT_FILE_SIZE[self.arch]        
        self.data = bytearray(self.size)
        self._map = IO_FILE_MAPS[self.arch]
        self._ptr_fields = {name for _off, (name, spec) in self._map.items() if spec is PTR}

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

    def iter_fields(self) -> Iterable[Tuple[int, str, int]]:
        for off, (name, sz) in sorted(self._map.items()):
            yield off, name, self._size_of(sz)

    @property
    def fields(self) -> list[Tuple[str, int, str]]:
        return list(self.iter_fields())

    def offset_of(self, field_name: str) -> int:
        for off, (name, _sz) in self._map.items():
            if name == field_name:
                return off
        raise KeyError(f"Unknown field: {field_name}")

    def load(
        self,
        items: Union[Mapping[Union[str, int], Union[int, bytes]],
                     Iterable[Tuple[Union[str, int], Union[int, bytes]]]],
        *,
        strict: bool = True,
        stop_on_error: bool = True,
    ) -> None:
        """
        Bulk-assign fields.
        `items` can be a dict {field: value} or an iterable of (field, value).
        - field: str (named/alias) or int (absolute offset)
        - value: int or bytes (size must match)
        - strict: if False, silently ignore unknown fields; if True, raise KeyError
        - stop_on_error: if False, continue after errors (collect them and raise AggregateError at end)
        """
        if isinstance(items, Mapping):
            iterable = items.items()
        else:
            iterable = items

        errors: list[Exception] = []
        for k, v in iterable:
            try:
                self.set(k, v)
            except Exception as e:
                if strict:
                    if stop_on_error:
                        raise
                    errors.append(e)
                # not strict → ignore unknowns / size mismatches silently

        if errors:
            msgs = "; ".join(str(e) for e in errors)
            raise RuntimeError(f"load() encountered {len(errors)} errors: {msgs}")

    # - Pretty dump print
    def _u(self, off: int, size: int) -> int:
        be = (context.endian == "big")
        return int.from_bytes(self.data[off:off+size], byteorder="big" if be else "little", signed=False)

    def _bytes(self, off: int, size: int) -> bytes:
        return bytes(self.data[off:off+size])

    def dump(
        self,
        # *,
        title: str = "IO_FILE_plus dump",
        only_nonzero: bool = False,
        show_bytes: bool = True,
        highlight_ptrs: bool = True,
        color: bool = True,
    ) -> None:
        """
        Fixed-width columns:
          OFF(6) | NAME(24) | SZ(2) | HEX(3 + 2*ptr) | DEC(20) | BYTES(full)
        - HEX is zero-padded to ptr width (16 digits on amd64 / 8 on i386).
        - Handles signed char inside SIGNED_FIELD, e.g, _vtable_offset 
        - Pointers are detected via the PTR sentinel, not by raw size.

            @title          : heading above the table
            @only_nonzero   : hide zero-valued fields
            @show_bytes     : include raw BYTES column (full, no preview)
            @highlight_ptrs : bold pointer-sized fields
            @color          : ANSI colors
        """
        def paint(s: str, code: str) -> str:
            return f"\x1b[{code}m{s}\x1b[0m" if color else s
        def cell(text: str, width: int, align: str = ">") -> str:
            return f"{text:{align}{width}}"

        BOLD, DIM, CYAN, MAG, YEL = "1", "2", "36", "35", "33"

        # widths
        OFF_W, NAME_W, SZ_W = 6, 24, 2
        HEX_DIGITS = self.ptr_size * 2                  # 16 on amd64, 8 on i386
        HEX_W = 3 + HEX_DIGITS                          # '-0x' or ' 0x' + digits
        DEC_W = 20

        be = (context.endian == "big")
        byteorder = "big" if be else "little"

        # title + meta
        bar = "-" * max(8, len(title))
        print(paint(title, BOLD))
        print(bar)
        print(f"{paint('arch',BOLD)}: {self.arch}   {paint('ptr size',BOLD)}: {self.ptr_size}   {paint('size',BOLD)}: {self.size}\n")

        # header
        hdr = "  ".join([
            paint(cell("OFF",  OFF_W, ">"), BOLD),
            paint(cell("NAME", NAME_W, "<"), BOLD),
            paint(cell("SZ",   SZ_W,   ">"), BOLD),
            paint(cell("HEX",  HEX_W,  ">"), BOLD),
            paint(cell("DEC",  DEC_W,  ">"), BOLD),
            *( [paint("BYTES", BOLD)] if show_bytes else [] )
        ])
        print(hdr)

        # rows
        for off, (name, spec) in sorted(self._map.items()):
            size  = self.ptr_size if spec is PTR else int(spec)
            chunk = self.data[off:off+size]

            # compute values for <=8B; blobs keep HEX/DEC narrow
            if size <= 8:
                is_signed = (name == "_vtable_offset" and size == 1)
                uval = int.from_bytes(chunk, byteorder=byteorder, signed=False)
                if is_signed:
                    sval = int.from_bytes(chunk, byteorder=byteorder, signed=True)
                    dec_raw = str(sval)                                 # signed for DEC
                    hex_raw = f" 0x{uval:0{HEX_DIGITS}x}"               # raw byte for HEX (zero-extended)
                    is_zero = (uval == 0)
                else:
                    dec_raw = str(uval)
                    hex_raw = f" 0x{uval:0{HEX_DIGITS}x}"
                    is_zero = (uval == 0)
            else:
                hex_raw = f"[{size}B]"
                dec_raw = "-"
                is_zero = all(b == 0 for b in chunk)

            # name styling: use cached pointer set
            is_ptr = (name in getattr(self, "_ptr_fields", ()))

            if highlight_ptrs and is_ptr:
                # always bold pointers, zero or not
                name_txt = paint(cell(name, NAME_W, "<"), BOLD)
            else:
                # non-pointers: dim zeros, normal otherwise
                name_txt = paint(cell(name, NAME_W, "<"), DIM) if is_zero else cell(name, NAME_W, "<")

            off_cell = cell(f"0x{off:04x}", OFF_W, ">")
            sz_cell  = cell(str(size), SZ_W, ">")
            hex_cell = paint(cell(hex_raw, HEX_W, ">"), CYAN)
            dec_cell = paint(cell(dec_raw, DEC_W, ">"), MAG)

            line = "  ".join([off_cell, name_txt, sz_cell, hex_cell, dec_cell])
            if show_bytes:
                line += "  " + paint(chunk.hex(), YEL)
            print(line)

    # - Get/set by field 
    def _resolve(self, key: Key) -> Tuple[int, int, bool, str]:
        """
        Normalize selector to (offset, size_bytes, signed_flag, field_name).
        - int  -> treat as byte offset (look up name, size)
        - str  -> treat as field name (look up offset, size)
        """
        if isinstance(key, int):
            off = key
            try:
                field_name, sz_spec = self._map[off]
            except KeyError:
                raise KeyError(f"Unknown offset 0x{off:x} for arch {self.arch}")
        else:
            field_name = key
            off = self.offset_of(field_name)
            _field_name, sz_spec = self._map[off]
            # (optional) assert the map name matches
            assert _field_name == field_name

        size   = self._size_of(sz_spec)
        signed = field_name in SIGNED_FIELDS
        return off, size, signed, field_name

    def set(self, key: Key, value: int) -> "IOFilePlus":
        """Set numeric field (int or pointer) by field name or byte offset."""
        off, size, signed, _ = self._resolve(key)
        self.data[off:off+size] = pack(value,
                                       word_size=size * 8,
                                       endianness=context.endian,
                                       sign=signed)
        return self

    def get(self, key: Key) -> int:
        """Get numeric field by field name or byte offset."""
        off, size, signed, _ = self._resolve(key)
        return unpack(bytes(self.data[off:off+size]),
                      word_size=size * 8,
                      endianness=context.endian,
                      sign=signed)

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

    def to_bytes(self) -> bytes:
        return bytes(self.data)
    
    @property
    def bytes(self) -> bytes:
        return self.to_bytes()
