from cryptography.hazmat.primitives.asymmetric import ec

signing_key = ec.generate_private_key(ec.SECP256R1())
