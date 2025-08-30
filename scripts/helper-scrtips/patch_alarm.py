from pwn import *

context.clear()
context.arch = 'amd64'
context.os = 'linux'
context.binary = './pwn'
elf = context.binary

# PIE binary — patch the file assuming offset is 0x137f
# .text section starts at offset 0, so this offset is fine

"""
.text:000000000000137F                 mov     edi, 30h ; '0'  ; seconds
.text:0000000000001384                 mov     eax, 0
.text:0000000000001389                 call    _alarm

pwndbg> x/10i 0x55555555537f
   0x55555555537f:      mov    edi,0x30
   0x555555555384:      mov    eax,0x0
   0x555555555389:      call   0x555555555180 <alarm@plt>
   
pwndbg> distance 0x555555555389 0x55555555537f
0x555555555389->0x55555555537f is -0xa bytes (-0x2 words)
"""

"""
Patch
"""
patch_offset = 0x137f
# patch = asm('nop') * 11  # patch mov edi; mov eax; call alarm
patch = asm('xor eax, eax') + asm('nop') * 8  # 2 + 8 = 10 bytes

with open('./pwn', 'rb') as f:
    data = bytearray(f.read())

data[patch_offset:patch_offset + len(patch)] = patch

with open('./pwn_patch', 'wb') as f:
    f.write(data)

print(f"[+] Patched binary saved to ./pwn_patch")

