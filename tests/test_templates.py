import os
from pathlib import Path
import pytest

from pwnkit.__main__ import (
    _bundled_templates,
    load_template,
    render_format,
    ENV_TPL_DIR,
)

def test_bundled_template_names_nonempty_and_contains_known():
    names = _bundled_templates()
    assert isinstance(names, list) and names, "no bundled templates found"
    # sanity: at least one of these must be bundled in your repo
    assert any(n in names for n in {"default", "minimal", "ret2libc", "heap"})

def test_load_bundled_by_name_and_render_minimal_ctx():
    names = _bundled_templates()
    name = names[0]
    tpl, origin = load_template(name)
    assert origin.startswith("pkg:"), f"expected pkg origin, got {origin}"
    assert isinstance(tpl, str) and len(tpl) > 10
    # it should be format()-style; prove we can at least render a tiny subset
    # we don't know all fields the template expects, so render only a trivial template here
    # (render_format itself is tested below)
    assert "{" in tpl and "}" in tpl  # has placeholders

def test_load_from_explicit_path(tmp_path: Path, monkeypatch):
    p = tmp_path / "explicit.py.tpl"
    p.write_text("hello {who}", encoding="utf-8")
    tpl, origin = load_template(str(p))
    assert origin.startswith("fs:"), origin
    out = render_format(tpl, {"who": "world"})
    assert out == "hello world"

def test_load_from_env_dir_by_name(tmp_path: Path, monkeypatch):
    # create a custom template in an env dir
    envdir = tmp_path / "tpls"
    envdir.mkdir()
    (envdir / "custom.py.tpl").write_text("# custom\nHi {name}!", encoding="utf-8")
    monkeypatch.setenv(ENV_TPL_DIR, str(envdir))

    tpl, origin = load_template("custom")
    assert origin.startswith("env:"), origin
    out = render_format(tpl, {"name": "Ax"})
    assert out.strip().endswith("Hi Ax!")

def test_render_format_missing_keys_raises():
    tpl = "A: {a}, B: {b!r}, Chex: {c:02x}"
    # 'b' and 'c' missing → ValueError
    with pytest.raises(ValueError):
        render_format(tpl, {"a": 1})

    # now provide all:
    rendered = render_format(tpl, {"a": 1, "b": "x", "c": 0x7})
    assert rendered == "A: 1, B: 'x', Chex: 07"

