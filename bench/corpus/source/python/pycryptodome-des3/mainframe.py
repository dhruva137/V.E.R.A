from Crypto.Cipher import DES3


def wrap(key, iv, block):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(block)
