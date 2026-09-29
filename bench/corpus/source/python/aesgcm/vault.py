import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
box = AESGCM(key)
sealed = box.encrypt(os.urandom(12), b"secret", None)
