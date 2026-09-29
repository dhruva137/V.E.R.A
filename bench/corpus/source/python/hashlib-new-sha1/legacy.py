import hashlib

digest = hashlib.new("sha1", b"payload").hexdigest()
