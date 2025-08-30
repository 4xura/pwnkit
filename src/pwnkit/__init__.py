from __future__ import annotations
import importlib as _il

try:
    from ._version import __version__ 
except ImportError:
    __version__ = "0.0.0"

__all__: list[str] = ["__version__"]

_modules = ("io", "encrypt", "rop", "gdbx", "utils", "ctx", "shellcode", "hashpow")

# - Import submodules once, export their public symbols, and expose modules as attributes
for _m in _modules:
    _mod = _il.import_module(f"{__name__}.{_m}")
    # - Re-export each submodule's public API
    for _name in getattr(_mod, "__all__", ()):
        globals()[_name] = getattr(_mod, _name)
        __all__.append(_name)
    # - Make them available as pwnkit.io, pwnkit.utils, ...
    globals()[_m] = _mod
