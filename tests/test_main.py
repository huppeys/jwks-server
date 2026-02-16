# tests/test_main.py

from datetime import datetime, timedelta, timezone
import pytest
from jose import jwt, JWTError
from main import key_manager, decode_jwt


def test_decode_jwt_valid():
    # Pick the first key from key_manager
    kid, key_info = list(key_manager.keys.items())[0]
    private_key = key_info["private_key"]

    # Create a valid token (5 minutes in the future)
    token = jwt.encode(
        {"sub": "user", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )

    # Decode the token
    payload = decode_jwt(token)
    assert payload["sub"] == "user"


def test_decode_jwt_expired():
    # Pick the first key from key_manager
    kid, key_info = list(key_manager.keys.items())[0]
    private_key = key_info["private_key"]

    # Create an expired token (5 minutes in the past)
    token = jwt.encode(
        {"sub": "user", "exp": datetime.now(timezone.utc) - timedelta(minutes=5)},
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )

    # Decoding should raise JWTError
    with pytest.raises(JWTError):
        decode_jwt(token)

