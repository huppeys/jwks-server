"""
key_manager.py - RSA key generation and JWK conversion for the JWKS server.

Private keys are serialized to PKCS1 PEM format before saving to SQLite,
and deserialized back when read from the DB.
n and e are base64url-encoded as required by RFC 7517.
"""

import base64
import time
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

import db


def generate_and_store_key(expires_in_seconds: int) -> int:
    """
    Generate a 2048-bit RSA key pair and persist it to the database.

    The private key is serialized to PKCS1 PEM format (no encryption)
    before being stored.  Pass a negative value for ``expires_in_seconds``
    to create a key that is already expired (useful for testing).

    Args:
        expires_in_seconds: Number of seconds from now until the key
            expires.  Use a negative value for an already-expired key.

    Returns:
        int: The auto-incremented ``kid`` assigned to the stored key.
    """
    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    pem: str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    exp: int = int(time.time()) + expires_in_seconds
    return db.insert_key(pem, exp)


def deserialize_private_key(pem: str) -> RSAPrivateKey:
    """
    Convert a PEM string retrieved from the database into an RSA private key.

    Args:
        pem: A PKCS1 PEM-encoded RSA private key string.

    Returns:
        RSAPrivateKey: The deserialized RSA private key object.
    """
    return serialization.load_pem_private_key(
        pem.encode("utf-8"),
        password=None,
        backend=default_backend(),
    )


def _int_to_base64url(value: int) -> str:
    """
    Convert a large integer (RSA modulus or exponent) to a base64url string.

    This encoding is required by the JWKS standard (RFC 7517).  Raw integers
    are not accepted by JWT verifiers — they must be base64url-encoded byte
    sequences with no padding.

    Args:
        value: A non-negative integer (typically the RSA ``n`` or ``e``).

    Returns:
        str: The base64url-encoded, unpadded representation of *value*.
    """
    byte_length: int = (value.bit_length() + 7) // 8
    raw_bytes: bytes = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("utf-8")


def public_key_to_jwk(kid: int, private_key: RSAPrivateKey) -> dict[str, Any]:
    """
    Build a JWK (JSON Web Key) dict from the public component of an RSA key.

    All fields required by RFC 7517 are included: ``kty``, ``kid``,
    ``use``, ``alg``, ``n``, and ``e``.

    Args:
        kid: The integer key ID stored in the database (used as the
            ``kid`` claim in JWTs and the JWKS response).
        private_key: The RSA private key whose public component will be
            exported.

    Returns:
        dict[str, Any]: A JWK-compliant dictionary ready to be included
            in a JWKS ``keys`` array.
    """
    pub_numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": str(kid),
        "use": "sig",
        "alg": "RS256",
        "n": _int_to_base64url(pub_numbers.n),
        "e": _int_to_base64url(pub_numbers.e),
    }
