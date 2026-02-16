import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_auth_valid():
    resp = client.post("/auth")
    assert resp.status_code == 200
    assert "token" in resp.json()

def test_auth_expired():
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    token = resp.json()["token"]
    # Try accessing protected route with expired token
    headers = {"Authorization": f"Bearer {token}"}
    resp2 = client.get("/protected", headers=headers)
    assert resp2.status_code == 401 or "Invalid" in resp2.json()["detail"]

def test_jwks_keys():
    resp = client.get("/.well-known/jwks.json")
    keys = resp.json()["keys"]
    # Ensure keys have kid, n, e, exp
    for k in keys:
        assert "kid" in k and "n" in k and "e" in k and "exp" in k

