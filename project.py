# David,Regev,204813323
# Python 3.8

import Crypto.Cipher.AES as AES
from functools import reduce
from operator import xor

BLOCK_SIZE = 16


def cbc_custom_decrypt(k, n, cipher):
    decipher = AES.new(k, AES.MODE_ECB)
    decrypt_message = bytearray()
    for i in range(1, n + 1):
        c_i = cipher[BLOCK_SIZE * i: BLOCK_SIZE * (i + 1)]
        former_c = bytearray(cipher[BLOCK_SIZE * (i - 1): BLOCK_SIZE * i])
        dec_block = decrypt_block(k, c_i, former_c, decipher)
        decrypt_message += dec_block
    return bytes(decrypt_message)


def make_blocks(cipher):
    return [cipher[i: i + BLOCK_SIZE] for i in range(0, len(cipher), BLOCK_SIZE)]


def cbc_flip_fix(k, n, cipher):
    decipher = AES.new(k, AES.MODE_ECB)
    dec_cipher = cbc_custom_decrypt(k, n, cipher)
    dec_blocks = make_blocks(dec_cipher)
    for i, block in enumerate(reversed(dec_blocks)):
        mask = reduce(xor, block)
        if mask:
            corrupted_byte_index = next(i for i, byte in enumerate(block) if block.count(byte) == 1)
            idx = BLOCK_SIZE * (n - i - 1) + corrupted_byte_index
            fixed_cipher = cipher[: idx] + bytes([cipher[idx] ^ mask]) + cipher[idx + 1:]
            fixed_cipher_blocks = make_blocks(fixed_cipher)
            return decrypt_block(k, fixed_cipher_blocks[n - i - 1], fixed_cipher_blocks[n - i - 2], decipher)


def decrypt_block(k, cipher, former_cipher, decipher):
    cipher_decrypt = decipher.decrypt(cipher)
    return bytes(map(xor, cipher_decrypt, former_cipher))
