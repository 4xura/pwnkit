import ipaddress
import pytest

from pwnkit.shellcode import (
    SHELLCODESTORE,
    ShellcodeStore,
    Shellcode,
    ShellcodeBuilder,
    hex_shellcode,
    build_sockaddr_in,
)
from pwnkit.ctx import Arch  # Arch = Literal["amd64", "i386", "arm", "aarch64"]


def test_hex_shellcode_bytes_and_str():
    assert hex_shellcode(b"\x90\xcc") == "\\x90\\xcc"
    assert hex_shellcode("AB") == "\\x41\\x42"


@pytest.mark.parametrize(
    "ip,port,expected_prefix",
    [
        ("127.0.0.1", 4444, b"\x02\x00\x11\x5c\x7f\x00\x00\x01"),
        ("10.11.12.13", 31337, b"\x02\x00\x7a\x69\x0a\x0b\x0c\x0d"),
    ],
)
def test_build_sockaddr_in(ip, port, expected_prefix):
    buf = build_sockaddr_in(ip, port)
    assert isinstance(buf, (bytes, bytearray))
    assert len(buf) == 16
    # AF_INET (2, little-endian) + port (big-endian) + addr (big-endian)
    assert buf[:8] == expected_prefix
    # trailing zero padding
    assert buf[8:] == b"\x00" * 8


def test_registry_has_minimum_entries():
    # sanity: a few well-known names exist
    names_amd64 = set(SHELLCODESTORE.names("amd64"))
    assert "execve_bin_sh" in names_amd64
    assert "cat_flag" in names_amd64
    names_i386 = set(SHELLCODESTORE.names("i386"))
    assert "execve_bin_sh_21" in names_i386


def test_registry_get_returns_shellcode():
    sc = SHELLCODESTORE.get("amd64", "execve_bin_sh")
    assert isinstance(sc.blob, (bytes, bytearray))
    assert len(sc.blob) > 0
    assert sc.arch == "amd64"
    assert sc.name == "execve_bin_sh"


def test_registry_duplicate_rejected():
    store = ShellcodeStore()
    sc = Shellcode("demo", "amd64", b"\x90", "noop")
    store.register(sc)
    with pytest.raises(ValueError):
        store.register(sc)  # duplicate


def test_registry_missing_raises_keyerror():
    store = ShellcodeStore()
    with pytest.raises(KeyError):
        store.get("amd64", "does_not_exist")


def test_builder_alpha_amd64_seeds():
    b = ShellcodeBuilder("amd64")
    # different registers should change the first byte (seed), payload suffix stays same length
    s_rax = b.build_alpha_shellcode("rax")
    s_rbx = b.build_alpha_shellcode("rbx")
    assert isinstance(s_rax, (bytes, bytearray))
    assert isinstance(s_rbx, (bytes, bytearray))
    assert s_rax != s_rbx
    # both are ASCII-only
    assert all(32 <= c <= 126 for c in s_rax)
    assert all(32 <= c <= 126 for c in s_rbx)


def test_builder_alpha_i386_not_implemented():
    b = ShellcodeBuilder("i386")
    with pytest.raises(NotImplementedError):
        b.build_alpha_shellcode("eax")  # any value should raise for now


@pytest.mark.parametrize(
    "ip,port",
    [("127.0.0.1", 4444), ("8.8.8.8", 80)],
)
def test_builder_reverse_tcp_connect_amd64(ip, port):
    b = ShellcodeBuilder("amd64")
    blob = b.build_reverse_tcp_connect(ip, port)
    assert isinstance(blob, (bytes, bytearray))
    assert len(blob) > 0
    # Verify the encoded IP:PORT are present (big-endian network order)
    ip_be = ipaddress.IPv4Address(ip).packed
    port_be = port.to_bytes(2, "big")
    assert port_be + ip_be in blob


def test_builder_reverse_tcp_shell_amd64_contains_markers():
    b = ShellcodeBuilder("amd64")
    blob = b.build_reverse_tcp_shell("127.0.0.1", 4444)
    assert isinstance(blob, (bytes, bytearray))
    assert len(blob) > 0
    # Contains '/bin/sh\\x00' immediate used in payload
    assert b"/bin/sh\x00" in blob


def test_builders_not_available_on_i386():
    b = ShellcodeBuilder("i386")
    with pytest.raises(NotImplementedError):
        b.build_reverse_tcp_connect("127.0.0.1", 4444)
    with pytest.raises(NotImplementedError):
        b.build_reverse_tcp_shell("127.0.0.1", 4444)

