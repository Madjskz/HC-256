import os
import time
import math
from multiprocessing import Pool, cpu_count
from hc256 import HC256
from tqdm import tqdm


def try_key_byte(key_byte_and_ct):
    key_byte, ciphertext, message = key_byte_and_ct
    key = bytes([key_byte])
    for iv_byte in range(256):
        iv = bytes([iv_byte])
        test = HC256(key=key, iv=iv, is_crypt=False)
        try:
            pt = test.crypt(ciphertext)
        except Exception:
            continue
        if pt == message:
            return key_byte, iv_byte
    return None


def main() -> None:
    message = '''
    In 1833, Faraday’s experimentation with electrolysis indicated a natural unit 
    of electrical charge, thus pointing to a discrete rather than continuous 
    charge. (to a discrete rather than continuous charge is also a phrase.)
    '''
    true_key = os.urandom(1)
    true_iv  = os.urandom(1)
    cipher = HC256(key=true_key, iv=true_iv, is_crypt=True)
    ciphertext = cipher.crypt(message)

    print(f"Истинный ключ: {true_key.hex():>02}")
    print(f"Истинный IV:  {true_iv.hex():>02}\n")

    # 2) Брутфорс 1-байтных ключа и IV
    start = time.perf_counter()
    total = 256
    kv_iterable = ((kb, ciphertext, message) for kb in range(total))

    with Pool(processes=cpu_count()) as pool:
        for res in tqdm(pool.imap_unordered(try_key_byte, kv_iterable),
                        total=total,
                        desc="Bruteforce key/IV"):
            if res is not None:
                found_key, found_iv = res
                elapsed = time.perf_counter() - start
                print(f"\nНайдено: key=0x{found_key:02x}, iv=0x{found_iv:02x}")
                print(f"Время поиска (1 байт key/iv): {elapsed:.2f} сек")
                pool.terminate()
                break
        else:
            print("\nКлюч и IV не найдены.")
            exit(1)

    seconds_per_year = 3600 * 24 * 365
    full_seconds = elapsed * (2 ** 496)
    full_years = full_seconds / seconds_per_year
    print(f"\nОценочное время брутфорса: {full_years:.3e} лет")


if __name__ == '__main__':
    main()