from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from key_manager import KeyManager
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

app = FastAPI()
key_manager = KeyManager()

# Generate demo keys
key_manager.generate_key("example_key_1")  # Valid key
key_manager.generate_key("example_key_2", expires_in_minutes=0)  # Expired key

# ==============================
# JWKS Endpoint
# ==============================
@app.get("/.well-known/jwks.json")
def get_jwks():
    keys = key_manager.get_public_keys()
    return JSONResponse(content={"keys": keys})

# ==============================
# Authentication Endpoint
# ==============================
@app.post("/auth")
def authenticate(expired: bool = Query(False)):
    for kid, key_info in key_manager.keys.items():
        private_key = key_info["private_key"]
        if expired:
            token = jwt.encode(
                {
                    "sub": "user",
                    "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
                },
                private_key,
                algorithm="RS256",
                headers={"kid": kid},
            )
            return {"token": token}

        # Valid token
        token = jwt.encode(
            {
                "sub": "user",
                "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            },
            private_key,
            algorithm="RS256",
            headers={"kid": kid},
        )
        return {"token": token}

    raise HTTPException(status_code=404, detail="No available keys")

# ==============================
# Protected Endpoint
# ==============================
@app.get("/protected")
def protected_route(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authentication scheme")

        # Extract kid from token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if kid not in key_manager.keys:
            raise JWTError("Invalid key ID")

        public_key = key_manager.keys[kid]["public_key"]
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        return {"message": "Access granted", "user": decoded["sub"]}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# ==============================
# Helper function for testing
# ==============================
def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode JWT and return payload."""
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if kid not in key_manager.keys:
            raise JWTError("Invalid key ID")

        public_key = key_manager.keys[kid]["public_key"]
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        return decoded
    except JWTError as e:
        raise e

