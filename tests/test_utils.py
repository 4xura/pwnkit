import io
import logging
import re
import pytest
from pwnkit.utils import leak, pa, itoa, init_pr, pr_debug, pr_info, pr_warn, pr_error, pr_critical, pr_exception

HEX = r"0x[0-9a-fA-F]+"
ANSI = "\x1b["

def _capture_pwnlib_logs():
    """
    Temporarily attach a StreamHandler to 'pwnlib' logger to capture success() output,
    bypassing the global silencer in conftest.py.
    """
    logger = logging.getLogger("pwnlib")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    # snapshot existing state
    prev_level = logger.level
    prev_handlers = list(logger.handlers)
    prev_prop = logger.propagate
    # install our capture handler
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger, handler, stream, prev_level, prev_handlers, prev_prop

def _restore_logger(logger, prev_level, prev_handlers, prev_prop):
    logger.setLevel(prev_level)
    logger.handlers = prev_handlers
    logger.propagate = prev_prop

def test_leak_prints_with_var_name_and_hex(monkeypatch):
    messages = []

    # Patch the symbol used by our module (pwnkit.utils.success)
    monkeypatch.setattr("pwnkit.utils.success", lambda msg: messages.append(str(msg)))

    buf = 0xdeadbeefcafebabe
    leak(buf)

    # now we assert on our captured messages, independent of logging handlers
    assert any("Leak buf" in m for m in messages)
    assert any(re.search(HEX, m) for m in messages)


def test_pa_alias_matches_leak(monkeypatch):
    messages = []
    monkeypatch.setattr("pwnkit.utils.success", lambda msg: messages.append(str(msg)))

    val = 0x4141414142424242
    pa(val)

    assert any("Leak val" in m for m in messages)
    assert any(re.search(HEX, m) for m in messages)


def test_itoa_basic():
    assert itoa(0) == b"0"
    assert itoa(1337) == b"1337"


def test_init_pr_colors_and_levels(capsys):
    init_pr(level="debug", fmt="%(levelname)s %(message)s", datefmt="%H:%M:%S")
    pr_debug("dbg"); pr_info("info"); pr_warn("warn"); pr_error("err"); pr_critical("crit")
    err = capsys.readouterr().err
    for msg in ("dbg","info","warn","err","crit"):
        assert msg in err
    assert ANSI in err


def test_pr_exception_includes_traceback(capsys):
    init_pr(level="error", fmt="%(levelname)s %(message)s")
    try:
        raise ValueError("boom")
    except ValueError:
        pr_exception("oops")
    err = capsys.readouterr().err
    assert "oops" in err and "ValueError: boom" in err

