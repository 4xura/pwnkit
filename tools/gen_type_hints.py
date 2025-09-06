#!/usr/bin/env python3
"""
Generate the TYPE_CHECKING block inside pwnkit/__init__.py by reading
_pkg/_modules and each submodule's __all__.

Works with both repo layouts:
- src/pwnkit/__init__.py
- pwnkit/__init__.py

Usage:
    python tools/gen_type_hints.py
"""
from __future__ import annotations

import importlib
import io
import pathlib
import re
import sys
from textwrap import wrap
from typing import Iterable

PKG = "pwnkit"
BEGIN = "# --- TYPE_CHECKING BEGIN (auto-generated; do not edit) ---"
END   = "# --- TYPE_CHECKING END (auto-generated) ---"
LINE_WIDTH = 100


def find_package() -> tuple[pathlib.Path, pathlib.Path]:
    """Return (repo_root, package_dir) and ensure sys.path has the right root."""
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    candidates = [repo_root / "src", repo_root]
    for root in candidates:
        pkg_dir = root / PKG
        if (pkg_dir / "__init__.py").exists():
            # make imports like 'import pwnkit' work
            sys.path.insert(0, str(root))
            return repo_root, pkg_dir
    raise SystemExit(
        f"[!] Could not find {PKG}/__init__.py under {repo_root}/src or {repo_root}.\n"
        f"    Checked: {[str((c / PKG).resolve()) for c in candidates]}"
    )


def collect_exports(module) -> list[str]:
    names = getattr(module, "__all__", None)
    if names is None:
        # fallback: visible public names
        names = [n for n in dir(module) if not n.startswith("_")]
    # uniquify + sort for stable output
    return sorted(set(names))


def format_import_line(submodule: str, symbols: list[str]) -> str:
    head = f"from .{submodule} import "
    if len(symbols) == 1:
        return head + symbols[0]

    # multiple symbols → wrap in parentheses with trailing comma
    body = ", ".join(symbols) + ","
    chunks = wrap(
        body,
        width=LINE_WIDTH - 4,
        break_long_words=False,
        break_on_hyphens=False,
    )
    lines = [head + "("]
    for ch in chunks:
        lines.append("    " + ch)
    lines.append(")")
    return "\n".join(lines)


def main() -> None:
    repo_root, pkg_dir = find_package()
    init_path = pkg_dir / "__init__.py"

    # Import the package so we can read _modules
    pkg = importlib.import_module(PKG)
    modules: Iterable[str] = getattr(pkg, "_modules", ())
    if not modules:
        raise SystemExit(f"[!] {PKG}._modules is empty or missing.")

    # Build the TYPE_CHECKING block
    buf = io.StringIO()
    buf.write("from typing import TYPE_CHECKING\n\n")
    buf.write("if TYPE_CHECKING:\n")
    for m in modules:
        sub = importlib.import_module(f"{PKG}.{m}")
        exports = collect_exports(sub)
        if not exports:
            continue
        line = format_import_line(m, exports)
        for i, l in enumerate(line.splitlines()):
            buf.write("    " + l + "\n")
    block = f"{BEGIN}\n{buf.getvalue().rstrip()}\n{END}"

    # Replace between markers
    text = init_path.read_text(encoding="utf-8")
    pattern = re.compile(rf"{re.escape(BEGIN)}.*?{re.escape(END)}", flags=re.DOTALL)
    if not pattern.search(text):
        raise SystemExit(
            f"[!] Markers not found in {init_path.relative_to(repo_root)}.\n"
            f"    Add these two lines to your __init__.py where the block should live:\n"
            f"    {BEGIN}\n    {END}"
        )

    new_text = pattern.sub(block, text)
    if new_text != text:
        init_path.write_text(new_text + ("" if new_text.endswith("\n") else "\n"), encoding="utf-8")
        print(f"[+] Updated TYPE_CHECKING block in {init_path.relative_to(repo_root)}")
    else:
        print("[=] No changes (already up-to-date)")


if __name__ == "__main__":
    main()

