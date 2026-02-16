from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone

class KeyManager:
    def __init__(self):
        self.keys = {}

    def generate_key(self, kid: str, expires_in_minutes: int = 10):
        """Generate a new RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)

        self.keys[kid] = {
            "private_key": private_key,
            "public_key": public_key,
            "expiry": expiry_time
        }

    def get_public_keys(self):
        """Return keys in JWKS format."""
        jwks = []
        for kid, key_info in self.keys.items():
            public_key = key_info["public_key"]
            public_numbers = public_key.public_numbers()
            e = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")
            n = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
            jwks.append({
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": int.from_bytes(n, "big"),
                "e": int.from_bytes(e, "big")
            })
        return jwks

