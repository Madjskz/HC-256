import logging

class HC256:
    MASK8BIT = 0xFF
    MASK10BIT = 0x3FF
    MASK11BIT = 0x7FF
    MASK32BIT = 0xFFFFFFFF

    def __init__(
            self, 
            key: bytearray, 
            iv: bytearray, 
            is_crypt: bool = True,
            log_level=logging.NOTSET
        ):

        logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s')
        self.log = logging.getLogger(__name__)
        self.log.setLevel(log_level)

        self.is_crypt = is_crypt

        key = key.ljust(32, b"\x00")
        iv = iv.ljust(32, b"\x00")
        self.log.debug(f'Ключ: {key.hex()}')
        self.log.debug(f'IV:   {iv.hex()}')

        key_words = [int.from_bytes(key[i:i+4], 'little') for i in range(0, 32, 4)]
        iv_words  = [int.from_bytes(iv[i:i+4], 'little') for i in range(0, 32, 4)]

        self.log.debug(f'Слова ключа: {key_words}')
        self.log.debug(f'Слова IV:   {iv_words}')

        W = [0] * 2560
        W[:8], W[8:16] = key_words, iv_words

        for i in range(16, 2560):
            # W[i] = f[2](W[i-2]) + W[i-7] + f[1](W[i-15]) + W[i-16] + i
            f1 = HC256.f1(W[i - 15])
            f2 = HC256.f2(W[i - 2])
            W[i] = (W[i - 16] + f1 + W[i - 7] + f2 + i) & HC256.MASK32BIT

        self.P = W[512:1536]
        self.Q = W[1536:2560]

        self.counter = 0

        for _ in range(4096):
            self.__generate_keystream_word()

    @staticmethod
    def rotr(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & HC256.MASK32BIT

    @staticmethod
    def f1(x: int) -> int:
        # f1(x) = (x >>> 7) ⊕ (x >>> 18) ⊕ (x >>> 3)
        return (HC256.rotr(x, 7) ^ HC256.rotr(x, 18) ^ (x >> 3)) & HC256.MASK32BIT

    @staticmethod
    def f2(x: int) -> int:
        # f2(x) = (x >>> 17) ⊕ (x >>> 19) ⊕ (x >>> 10)
        return (HC256.rotr(x, 17) ^ HC256.rotr(x, 19) ^ (x >> 10)) & HC256.MASK32BIT

    @staticmethod
    def g1(x: int, y: int, Q: list[int]) -> int:
        # g1(x,y) = (x>>>10 ⊕ y>>>23) + Q[(x⊕y) mod 1024]
        a = HC256.rotr(x, 10) ^ HC256.rotr(y, 23)
        idx = (x ^ y) & HC256.MASK10BIT
        return (a + Q[idx]) & HC256.MASK32BIT

    @staticmethod
    def g2(x: int, y: int, P: list[int]) -> int:
        # g2(x,y) = (x>>>10 ⊕ y>>>23) + P[(x⊕y) mod 1024]
        a = HC256.rotr(x, 10) ^ HC256.rotr(y, 23)
        idx = (x ^ y) & HC256.MASK10BIT
        return (a + P[idx]) & HC256.MASK32BIT

    @staticmethod
    def h1(x: int, Q: list[int]) -> int:
        # h1(x) = Q[x0] + Q[256+x1] + Q[512+x2] + Q[768+x3]
        return (
            Q[(x & HC256.MASK8BIT)] +
            Q[256 + ((x>>8) & HC256.MASK8BIT)] +
            Q[512 + ((x>>16) & HC256.MASK8BIT)] +
            Q[768 + ((x>>24) & HC256.MASK8BIT)]
        ) & HC256.MASK32BIT

    @staticmethod
    def h2(x: int, P: list[int]) -> int:
        # h2(x) = P[x0] + P[256+x1] + P[512+x2] + P[768+x3]
        return (
            P[(x & HC256.MASK8BIT)] +
            P[256 + ((x>>8) & HC256.MASK8BIT)] +
            P[512 + ((x>>16) & HC256.MASK8BIT)] +
            P[768 + ((x>>24) & HC256.MASK8BIT)]
        ) & HC256.MASK32BIT

    @staticmethod
    def format_bytes_as_hex_table(data: bytes, width: int = 32) -> str:
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            line = '   '.join(f"{b:02x}" for b in chunk)
            lines.append(f"   {line}")
        return '\n'.join(lines)

    def __generate_keystream_word(self) -> int:
        j = self.counter & HC256.MASK10BIT
        jm3 = (j - 3) & HC256.MASK10BIT
        jm10 = (j - 10) & HC256.MASK10BIT
        jm12 = (j - 12) & HC256.MASK10BIT
        jm1023 = (j - 1023) & HC256.MASK10BIT

        if self.counter < 1024:
            state, alt = self.P, self.Q
            temp = HC256.g1(state[jm3], state[jm1023], alt)
        else:
            state, alt = self.Q, self.P
            temp = HC256.g2(state[jm3], state[jm1023], alt)

        state[j] = (state[j] + state[jm10] + temp) & HC256.MASK32BIT

        idx = state[jm12]
        if self.counter < 1024:
            ks = HC256.h1(idx, self.Q) ^ state[j]
        else:
            ks = HC256.h2(idx, self.P) ^ state[j]

        self.counter = (self.counter + 1) & HC256.MASK11BIT
        return ks & HC256.MASK32BIT

    def crypt(self, data):
        self.log.debug(f'Данные = {data}')
        self.log.debug(f'Длина данных = {len(data)}')

        if self.is_crypt and isinstance(data, str):
            data = data.encode('utf-8')

        res = bytearray(data)
        i = 0
        keystream_bytes = bytearray()

        while i < len(res):
            w = self.__generate_keystream_word()

            for _ in range(4):
                if i >= len(res):
                    break

                keystream_bytes.append(w & HC256.MASK8BIT)
                res[i] ^= w & HC256.MASK8BIT
                w >>= 8
                i += 1

        self.log.debug(f'Ключевой поток:\n{HC256.format_bytes_as_hex_table(keystream_bytes)}\n')
        self.log.debug(f'Результат шифрования:\n{HC256.format_bytes_as_hex_table(res)}\n')

        if self.is_crypt:
            return bytes(res)
        return res.decode()