import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

def file_checksum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def checksum(data: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, data).hexdigest()

REPORT_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
