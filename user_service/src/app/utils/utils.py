import secrets

def generate_2fa_code(length: int = 4) -> str:
    return ''.join(secrets.choice("0123456789") for _ in range(length))