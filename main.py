"""
main.py - FastAPI JWKS server (Project 2).

Endpoints:
    GET  /.well-known/jwks.json  Returns all valid (non-expired) public keys
                                  in JWKS format.
    POST /auth                   Issues a signed JWT using a key from the DB.
                                  Add ?expired=true to sign with an expired key.

Database:
    totally_not_my_privateKeys.db (SQLite, created automatically on startup).
    Keys are stored as PKCS1 PEM strings with Unix expiry timestamps.
    All SQL uses parameterized queries (?) to prevent SQL injection.
"""

import time
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

import db
import key_manager

app = FastAPI(title="JWKS Server", version="2.0.0")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
def startup() -> None:
    """
    Initialize the server on startup.

    Performs two tasks:
        1. Creates the SQLite database file and ``keys`` table if they do
           not already exist.
        2. Seeds one already-expired key and one key valid for one hour so
           that both ``POST /auth`` code paths can always be exercised.
    """
    db.initialize_db()
    key_manager.generate_and_store_key(expires_in_seconds=-1)
    key_manager.generate_and_store_key(expires_in_seconds=3600)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get(
    "/.well-known/jwks.json",
    summary="Return all valid public keys as JWKS",
    response_class=JSONResponse,
)
def get_jwks() -> JSONResponse:
    """
    Retrieve all non-expired public keys from the database and return them
    in standard JWKS (JSON Web Key Set) format.

    Expired keys are excluded.  The ``n`` and ``e`` values are
    base64url-encoded per RFC 7517.

    Returns:
        JSONResponse: A JSON object with a single ``keys`` array containing
            one JWK dict per valid key.
    """
    rows = db.get_all_valid_keys()
    keys: list[dict[str, Any]] = []
    for row in rows:
        private_key = key_manager.deserialize_private_key(row["key"])
        jwk = key_manager.public_key_to_jwk(row["kid"], private_key)
        keys.append(jwk)
    return JSONResponse(content={"keys": keys})


@app.post(
    "/auth",
    summary="Issue a signed JWT (mock authentication)",
    response_class=JSONResponse,
)
async def authenticate(expired: bool = Query(False)) -> JSONResponse:
    """
    Issue a JWT signed with an RSA private key retrieved from the database.

    By default a valid (non-expired) key is used.  When the ``expired``
    query parameter is ``true``, an already-expired key is used instead,
    producing a JWT that will fail signature verification by design.

    Accepts HTTP Basic Auth or a JSON body with ``username`` / ``password``
    fields.  Credentials are not validated — this is a mock authentication
    endpoint for testing purposes only.

    Args:
        expired: When ``True``, sign the JWT with an expired key.

    Returns:
        JSONResponse: A JSON object containing a single ``token`` field
            with the signed JWT string.

    Raises:
        HTTPException 404: If no key of the requested type exists in the DB.
    """
    if expired:
        row = db.get_expired_key()
        if row is None:
            raise HTTPException(status_code=404, detail="No expired key found in DB")
    else:
        row = db.get_valid_key()
        if row is None:
            raise HTTPException(status_code=404, detail="No valid key found in DB")

    private_key = key_manager.deserialize_private_key(row["key"])
    pem_bytes: bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    now: int = int(time.time())
    payload: dict[str, Any] = {
        "sub": "userABC",
        "iat": now,
        "exp": row["exp"],
    }
    token: str = pyjwt.encode(
        payload,
        pem_bytes,
        algorithm="RS256",
        headers={"kid": str(row["kid"])},
    )
    return JSONResponse(content={"token": token})
