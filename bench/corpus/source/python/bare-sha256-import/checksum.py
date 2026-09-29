from hashlib import sha256


def checksum(blob: bytes) -> str:
    return sha256(blob).hexdigest()
