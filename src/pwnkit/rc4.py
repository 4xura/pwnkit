#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable

__all__ = [
	"rc4",
    "rc4_encrypt", "rc4_decrypt",
]

def _ksa(key: bytes) -> list[int]:
    """
    Key-Scheduling Algorithm (KSA).
    Input: secret key bytes.
    Output: initialized permutation state S.
    """
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]  # swap
    return S

def _prga(S: list[int]) -> Iterable[int]:
    """
    Pseudo-Random Generation Algorithm (PRGA).
    Produces the keystream, one byte at a time.
    """
    i = 0
    j = 0
    while True:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) & 0xFF]

def rc4(key: bytes, data: bytes, drop_n: int = 0) -> bytes:
    """
    Encrypt or decrypt data with RC4.
        @key:   secret key (bytes)
        @data:  plaintext or ciphertext
        @drop_n: discard first N keystream bytes (RC4-dropN variant)
    Returns: transformed bytes
    """
    if not key:
        raise ValueError("Key must not be empty")

    # Step 1: initialize state with KSA
    S = _ksa(key)

    # Step 2: generate keystream with PRGA
    keystream = _prga(S)

    # Step 3: optionally discard biased keystream prefix
    for _ in range(drop_n):
        next(keystream)

    # Step 4: XOR keystream with data
    return bytes(b ^ next(keystream) for b in data)

# Aliases (encrypt == decrypt in stream ciphers)
rc4_encrypt = rc4
rc4_decrypt = rc4
