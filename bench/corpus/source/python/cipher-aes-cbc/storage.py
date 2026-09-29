from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encryptor(key, iv):
    return Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
