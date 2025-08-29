from pwnkit.encrypt import PointerGuard, SafeLinking

def test_pointer_guard():
    print(f"[*] Testing PointerGuard...")
    pg = PointerGuard(guard=0xdeadbeefcafebabe)
    print(f"    guard       : {guard}")
    ptr = 0x4141414142424242
    print(f"    pointer     : {ptr}")
    enc = pg.mangle(ptr)
    print(f"    encrypted   : {enc}")
    dec = pg.demangle(enc)
    print(f"    decrypted   : {dec}")
    assert dec == enc

def test_safelinking():
    print(f"[*] Testing SafeLinking...")
    heap_base=0x555555000000
    s = SafeLinking(heap_base=heap_base)
    print(f"    heap base   : {heap_base}")
    fd = 0xdeadbeefcafebabe
    print(f"    fd          : {fd}")
    enc = s.encrypt(fd)
    print(f"    encrypted   : {enc}")
    dec = s.decrypt_progressive(enc)
    print(f"    decrypted   : {dec}")
    # progressive returns a lower-bound reconstruction; at least top bits must match
    assert dec >> 12 == fd >> 12
