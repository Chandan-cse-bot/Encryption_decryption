


#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64, hashlib, os

BLOCK_SIZE = 32

def _derive_key(passphrase: str, salt: bytes, length: int) -> bytes:
    seed = hashlib.sha256(passphrase.encode('utf-8') + salt).digest()
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        counter_bytes = counter.to_bytes(8, 'big')
        block = hashlib.sha256(seed + counter_bytes).digest()
        keystream.extend(block)
        counter += 1
    return bytes(keystream[:length])

def _xor_bytes(data: bytes, mask: bytes) -> bytes:
    return bytes(d ^ m for d, m in zip(data, mask))

def encrypt(plaintext: str, passphrase: str) -> str:
    salt = os.urandom(16)
    pt_bytes = plaintext.encode('utf-8')
    ks = _derive_key(passphrase, salt, len(pt_bytes))
    ct = _xor_bytes(pt_bytes, ks)
    return base64.b64encode(salt + ct).decode('utf-8')

def decrypt(b64_ciphertext: str, passphrase: str) -> str:
    packed = base64.b64decode(b64_ciphertext.encode('utf-8'))
    salt, ct = packed[:16], packed[16:]
    ks = _derive_key(passphrase, salt, len(ct))
    pt_bytes = _xor_bytes(ct, ks)
    return pt_bytes.decode('utf-8')

# ---------------- INTERACTIVE PART ----------------
if __name__ == "__main__":
    print("=== Simple Encryption/Decryption Demo ===")
    mode = input("Choose mode (enc/dec): ").strip().lower()
    key = input("Enter your key (numbers/symbols/words allowed): ").strip()

    if mode == "enc":
        text = input("Enter text to encrypt: ").strip()
        cipher = encrypt(text, key)
        print("\nEncrypted Base64:\n", cipher)
    elif mode == "dec":
        cipher = input("Enter Base64 ciphertext: ").strip()
        try:
            plain = decrypt(cipher, key)
            print("\nDecrypted text:\n", plain)
        except Exception as e:
            print("Error:", e)
    else:
        print("Invalid mode! Use 'enc' or 'dec'.")
