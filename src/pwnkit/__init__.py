from __future__ import annotations
import importlib as _il

_modules = ("io", "encrypt", "rop", "gdbx", "utils", "ctx")

__all__: list[str] = []

for _m in _modules:
    _mod = _il.import_module(f"{__name__}.{_m}")
    for _name in getattr(_mod, "__all__", ()):
        globals()[_name] = getattr(_mod, _name)
        __all__.append(_name)

# (optional) Set `pwnkit.io` etc. available:
for _m in _modules:
    globals()[_m] = _il.import_module(f"{__name__}.{_m}")

