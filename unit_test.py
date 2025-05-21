import unittest
import logging
from hc256 import HC256

class TestHC256(unittest.TestCase):
    def test_HC256_rotr(self):
        # Тестирование циклического сдвига вправо
        self.assertEqual(HC256.rotr(0x80000000, 1), 0x40000000)
        self.assertEqual(HC256.rotr(0x00000001, 1), 0x80000000)
        self.assertEqual(HC256.rotr(0x12345678, 4), 0x81234567)
        self.assertEqual(HC256.rotr(0xFFFFFFFF, 8), 0xFFFFFFFF)

    def test_known_vector(self):
        key = bytes.fromhex(
            "0053a6f94c9ff24598eb3e91e4378add3083d6297ccf2275c81b6ec11467ba0d"
        )
        iv = bytes.fromhex(
            "0d74db42a91077de45ac137ae148af167de44bb21980e74eb51c83ea51b81f86"
        )
        data = bytes(64)
        expected = bytes.fromhex(
            "23d9e70a45eb0127884d66d9f6f23c01d1f88afd629270127247256c1fff91e9"
            "1a797bd98add23ae15bee6eea3cefdbfa3ed6d22d9c4f459db10c40cdf4f4dff"
        )

        cipher_enc = HC256(key, iv, is_crypt=True)
        result = cipher_enc.crypt(data)
        self.assertEqual(result, expected)

        cipher_dec = HC256(key, iv, is_crypt=True)
        recovered = cipher_dec.crypt(result)
        self.assertEqual(recovered, data)

    def test_basic_vectors(self):
        test_cases = [
            {
                "key": b"\x00",
                "iv": b"\x00",
                "expect": bytes([
                    0x5b, 0x07, 0x89, 0x85, 0xd8, 0xf6, 0xf3, 0x0d,
                    0x42, 0xc5, 0xc0, 0x2f, 0xa6, 0xb6, 0x79, 0x51,
                    0x53, 0xf0, 0x65, 0x34, 0x80, 0x1f, 0x89, 0xf2,
                    0x4e, 0x74, 0x24, 0x8b, 0x72, 0x0b, 0x48, 0x18
                ])
            },
            {
                "key": b"\x00",
                "iv": b"\x01",
                "expect": bytes([
                    0xaf, 0xe2, 0xa2, 0xbf, 0x4f, 0x17, 0xce, 0xe9,
                    0xfe, 0xc2, 0x05, 0x8b, 0xd1, 0xb1, 0x8b, 0xb1,
                    0x5f, 0xc0, 0x42, 0xee, 0x71, 0x2b, 0x31, 0x01,
                    0xdd, 0x50, 0x1f, 0xc6, 0x0b, 0x08, 0x2a, 0x50
                ])
            },
            {
                "key": b"\x55",
                "iv": b"\x00",
                "expect": bytes([
                    0x1c, 0x40, 0x4a, 0xfe, 0x4f, 0xe2, 0x5f, 0xed,
                    0x95, 0x8f, 0x9a, 0xd1, 0xae, 0x36, 0xc0, 0x6f,
                    0x88, 0xa6, 0x5a, 0x3c, 0xc0, 0xab, 0xe2, 0x23,
                    0xae, 0xb3, 0x90, 0x2f, 0x42, 0x0e, 0xd3, 0xa8
                ])
            }
        ]

        for i, test in enumerate(test_cases):
            with self.subTest(test_case=i):
                key = test["key"]
                iv = test["iv"]

                cipher_enc = HC256(key, iv, is_crypt=True)
                plaintext = b"\x00" * 32
                output = cipher_enc.crypt(plaintext)
                self.assertEqual(
                    output,
                    test["expect"],
                    f"Test case {i} failed encryption: {output.hex()} vs {test['expect'].hex()}"
                )

                cipher_dec = HC256(key, iv, is_crypt=True)
                recovered = cipher_dec.crypt(output)
                self.assertEqual(
                    recovered,
                    plaintext,
                    f"Test case {i} failed decryption: {recovered.hex()} vs {plaintext.hex()}"
                )

if __name__ == '__main__':
    unittest.main()
