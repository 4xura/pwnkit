import pytest
import sys
import re
from typing import Optional, Tuple

from pwnkit import utils

utils.re = re


# ---------------------------
# load_argv tests (core)
# ---------------------------
@pytest.mark.parametrize(
    "argv,expected",
    [
        ([], (None, None)),                      # no args -> local
        (["127.0.0.1", "31337"], ("127.0.0.1", 31337)),   # two args
        (["example.com:1337"], ("example.com", 1337)),    # host:port single arg
    ],
)
def test_load_argv_ok(argv, expected: Tuple[Optional[str], Optional[int]]):
    """load_argv should parse empty / two-arg / host:port correctly."""
    assert utils.load_argv(list(argv)) == expected


@pytest.mark.parametrize(
    "bad_argv",
    [
        (["bad:port"]),        # non-numeric port after colon -> usage exit
        (["host", "notnum"]),  # second arg non-digit -> usage exit
        (["a", "b", "c"]),     # too many args -> usage exit
        (["::1::2"]),          # malformed colon count -> usage exit
    ],
)
def test_load_argv_bad_input_exits(bad_argv):
    """Invalid argv forms should call _usage() which exits (SystemExit)."""
    with pytest.raises(SystemExit):
        utils.load_argv(list(bad_argv))


# ---------------------------
# small transformer tests
# ---------------------------
def test_itoa_and_i2a():
    assert utils.itoa(123) == b"123"
    assert utils.i2a(0) == b"0"


def test_bytex_various_inputs():
    # bytes stays bytes
    assert utils.bytex(b"abc") == b"abc"
    # bytearray -> bytes
    assert utils.bytex(bytearray(b"xyz")) == b"xyz"
    # memoryview -> bytes
    assert utils.bytex(memoryview(b"hey")) == b"hey"
    # str -> bytes (utf-8 default)
    assert utils.bytex("hello") == b"hello"
    # int -> ascii bytes
    assert utils.bytex(42) == b"42"


def test_hex2b_and_b2hex_roundtrip():
    # simple hex with 0x prefix
    assert utils.hex2b("0x6162") == b"ab"
    # hex with spaces and non-hex separators
    assert utils.hex2b("61 62:63") == b"abc"
    # odd-length string auto-left-pads with 0
    assert utils.hex2b("f") == b"\x0f"
    # b2hex produces 0x...
    assert utils.b2hex(b"\x61\x62\x63") == "0x616263"


def test_hex2b_invalid_behavior():
    # Current implementation strips non-hex characters then unhexlifies;
    # for an all-invalid input like "zzzz" that becomes '' -> b''
    assert utils.hex2b("zzzz") == b""


def test_url_qs_rfc3986_and_plus():
    params = {"q": "a b", "tag": ["x/y", "z"]}
    qs_rfc = utils.url_qs(params, rfc3986=True)
    # must encode space as %20 in rfc3986 mode
    assert "q=a%20b" in qs_rfc
    assert "tag=x%2Fy" in qs_rfc and "tag=z" in qs_rfc

    qs_plus = utils.url_qs(params, rfc3986=False)
    # plus encoding uses '+' for spaces
    assert "q=a+b" in qs_plus


# ---------------------------
# printing helpers smoke tests
# ---------------------------
def test_print_data_str_and_bytes_and_int(capsys):
    # string branch: check it doesn't raise and prints expected markers
    utils.print_data("hi", name="test_str")
    out = capsys.readouterr().out
    assert "Print data:" in out and "test_str" in out

    # bytes branch
    utils.print_data(b"\x01\x02", name="test_bytes")
    out = capsys.readouterr().out
    assert "memoryview" in out or "hex" in out

    # int branch: check numeric lines present
    utils.print_data(0x4142, name="test_int")
    out = capsys.readouterr().out
    assert "hex" in out and "dec" in out


# ---------------------------
# helper: _get_caller_varname should return '<expr>' when not found
# ---------------------------
def test__get_caller_varname_no_match():
    # private utility; verify fallback doesn't crash
    res = utils._get_caller_varname(object(), depth=1)
    assert isinstance(res, str)


# ---------------------------
# ensure aliases present
# ---------------------------
def test_aliases_exist():
    assert utils.pa is utils.print_addr
    assert utils.leak is utils.print_addr
    assert utils.pd is utils.print_data

