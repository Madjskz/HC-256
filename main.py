import os
import logging
from hc256 import HC256


def main() -> None:
    key, iv = os.urandom(32), os.urandom(32)
    
    cipher_to_crypt = HC256(key, iv, is_crypt=True, log_level=logging.DEBUG)
    cipher_to_decrypt = HC256(key, iv, is_crypt=False, log_level=logging.DEBUG)
    
    message = '''
    In 1833, Faraday’s experimentation with electrolysis indicated a natural unit 
    of electrical charge, thus pointing to a discrete rather than continuous 
    charge. (to a discrete rather than continuous charge is also a phrase.)
    '''
    crypt_message = cipher_to_crypt.crypt(message)
    encrypt_message = cipher_to_decrypt.crypt(crypt_message)
    print(encrypt_message)

    message = '''
    Сложно сказать, почему базовые сценарии поведения пользователей, инициированные исключительно 
    синтетически, в равной степени предоставлены сами себе. Следует отметить, что выбранный нами 
    инновационный путь способствует повышению качества дальнейших направлений развития. Для современного 
    мира понимание сути ресурсосберегающих технологий однозначно определяет каждого участника как способного 
    принимать собственные решения касаемо новых принципов формирования материально-технической и кадровой 
    базы.
    '''
    crypt_message = cipher_to_crypt.crypt(message)
    encrypt_message = cipher_to_decrypt.crypt(crypt_message)
    print(encrypt_message)


if __name__ == '__main__':
    main()