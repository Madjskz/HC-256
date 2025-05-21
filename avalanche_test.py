import unittest
import os
import random
from hc256 import HC256


def hamming_distance(b1: bytes, b2: bytes) -> int:
    # Считает количество отличающихся битов между двумя байтовыми строками
    return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))


def flip_bit(data: bytearray) -> bytearray:
    # Возвращает копию с одним перевёрнутым случайным битом
    result = bytearray(data)
    idx = random.randrange(len(result))
    result[idx] ^= 1 << random.randrange(8)
    return result


class TestHC256Avalanche(unittest.TestCase):
    # Допустимый диапазон изменения бит
    LOWER = 0.4
    UPPER = 0.6  
    
    def setUp(self):
        self.key = bytearray(os.urandom(16))
        self.iv = bytearray(os.urandom(16))
        self.plaintext = b"A" * 256

    def run_avalanche(self, original_bytes, modified_bytes, description: str):
        cipher1 = HC256(key=self.key, iv=self.iv, is_crypt=True)
        ct1 = cipher1.crypt(self.plaintext)
        cipher2 = HC256(key=original_bytes, iv=modified_bytes, is_crypt=True)
        ct2 = cipher2.crypt(self.plaintext)

        dist = hamming_distance(ct1, ct2)
        total = len(ct1) * 8
        ratio = dist / total
        print(f"{description}: {dist}/{total} бит изменено ({ratio:.1%})")

        self.assertTrue(self.LOWER <= ratio <= self.UPPER,
                        f"{description} вне диапазона: {ratio:.1%}")

    def test_avalanche_on_key(self):
        flipped_key = flip_bit(self.key)
        self.run_avalanche(flipped_key, self.iv, "Изменение ключа")

    def test_avalanche_on_iv(self):
        flipped_iv = flip_bit(self.iv)
        self.run_avalanche(self.key, flipped_iv, "Изменение IV")


if __name__ == '__main__':
    unittest.main(verbosity=2)
