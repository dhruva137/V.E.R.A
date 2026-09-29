import jwt


def issue(claims, private_pem):
    return jwt.encode(claims, private_pem, algorithm="RS256")
