import unittest

from Crypto.Cipher import AES

from project import cbc_custom_decrypt, cbc_flip_fix

def flip(i, byte):
    return bytes([ord(byte) ^ (1 << i)])

class MyTestCase(unittest.TestCase):
    def test_cbc_custom_decrypt(self):
        k = b'\x81\x0ff\t\x04\xb6\xcf\x1f.\x10\x8frd\xb4E\x19'
        cipher = b'e|\x92\xd0\x8b\xd9\x00\xc8X\xf2Noi\xa1\x155\x8b\xa5\xb7\xdcka\xaa\x94=a_!x\x1a\xcf\xf4'
        n = 1
        assert len(cipher) == 32
        iv = b'e|\x92\xd0\x8b\xd9\x00\xc8X\xf2Noi\xa1\x155'
        cipher_text = AES.new(k, AES.MODE_CBC, iv)
        assert cipher_text.decrypt(cipher[16:]) == cbc_custom_decrypt(k, n, cipher)

        k = b'\x81\x0ff\t\x04\xb6\xcf\x1f.\x10\x8frd\xb4E\x19'
        iv = b'9193470938756473'
        cipher = iv + b'93746483900993873765345729285341'
        n = 2
        assert len(cipher) == 48
        cipher_text = AES.new(k, AES.MODE_CBC, iv)
        assert cipher_text.decrypt(cipher[16:]) == cbc_custom_decrypt(k, n, cipher)

        k = b'3939378487348557'
        iv = b'8870123765252522'
        cipher = iv + b'937464839009938737653457292853411010109394847645'
        n = 3
        assert len(cipher) == 64
        cipher_text = AES.new(k, AES.MODE_CBC, iv)
        assert cipher_text.decrypt(cipher[16:]) == cbc_custom_decrypt(k, n, cipher)

    def test_cbc_flip_fix(self):
        k = b'\x81\x0ff\t\x04\xb6\xcf\x1f.\x10\x8frd\xb4E\x19'
        iv = b'e|\x92\xd0\x8b\xd9\x00\xc8X\xf2Noi\xa1\x155'
        plain_text = b'2222222222222222hhhhhhhhhhhhhhhhZZZZZZZZZZZZZZZZrrrrrrrrrrrrrrrr'
        cipher = AES.new(k, AES.MODE_CBC, iv=iv)
        cipher_text = cipher.encrypt(plain_text)
        t = cipher_text[31]
        assert cbc_flip_fix(k, 4, iv + cipher_text[:31] + flip(3, bytes([cipher_text[31]])) + cipher_text[32:]) == b'hhhhhhhhhhhhhhhh'
        assert cbc_flip_fix(k, 4, iv + cipher_text[:32] + flip(6, bytes([cipher_text[32]])) + cipher_text[33:]) == b'ZZZZZZZZZZZZZZZZ'


if __name__ == '__main__':
    unittest.main()
