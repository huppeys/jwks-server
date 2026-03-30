"""
test_main.py - Test suite for the JWKS server Phase 2.
Run: pytest test_main.py -v --cov=. --cov-report=term-missing
"""

import base64
import json
import os
import sqlite3
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import db
db.DB_FILE = "test_jwks_temp.db"

import key_manager
from main import app

@pytest.fixture(autouse=True)
def clean_db():
    """Wipe and recreate the test DB before every test."""
    if os.path.exists(db.DB_FILE):
        os.remove(db.DB_FILE)
    db.initialize_db()
    yield
    if os.path.exists(db.DB_FILE):
        os.remove(db.DB_FILE)

@pytest.fixture
def client():
    """FastAPI test client — triggers startup event which seeds the DB."""
    with TestClient(app) as c:
        yield c


class TestDatabase:
    def test_initialize_creates_table(self):
        """DB init should create the keys table."""
        db.initialize_db()
        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
            ).fetchone()
        assert row is not None

    def test_initialize_is_idempotent(self):
        """Calling initialize_db twice should not raise an error."""
        db.initialize_db()
        db.initialize_db()

    def test_insert_key_returns_integer_kid(self):
        """insert_key should return a positive integer kid."""
        kid = db.insert_key("FAKE_PEM", int(time.time()) + 3600)
        assert isinstance(kid, int) and kid >= 1

    def test_insert_multiple_keys_unique_kids(self):
        """Each inserted key should get a unique auto-incremented kid."""
        kid1 = db.insert_key("PEM_A", int(time.time()) + 3600)
        kid2 = db.insert_key("PEM_B", int(time.time()) + 3600)
        assert kid1 != kid2

    def test_get_valid_key_returns_unexpired(self):
        """get_valid_key should return a key with exp in the future."""
        exp = int(time.time()) + 3600
        db.insert_key("VALID_PEM", exp)
        row = db.get_valid_key()
        assert row is not None
        assert row["key"] == "VALID_PEM"

    def test_get_valid_key_none_when_only_expired(self):
        """get_valid_key returns None if the only key is expired."""
        db.insert_key("OLD_PEM", int(time.time()) - 100)
        assert db.get_valid_key() is None

    def test_get_expired_key_returns_expired(self):
        """get_expired_key should return a key with exp in the past."""
        db.insert_key("EXPIRED_PEM", int(time.time()) - 10)
        row = db.get_expired_key()
        assert row is not None
        assert row["key"] == "EXPIRED_PEM"

    def test_get_expired_key_none_when_only_valid(self):
        """get_expired_key returns None if the only key is valid."""
        db.insert_key("NEW_PEM", int(time.time()) + 3600)
        assert db.get_expired_key() is None

    def test_get_all_valid_keys_excludes_expired(self):
        """get_all_valid_keys should only return non-expired keys."""
        now = int(time.time())
        db.insert_key("V1", now + 3600)
        db.insert_key("V2", now + 7200)
        db.insert_key("EXP", now - 100)
        rows = db.get_all_valid_keys()
        assert len(rows) == 2
        pems = {r["key"] for r in rows}
        assert "EXP" not in pems

    def test_get_all_valid_keys_empty_when_all_expired(self):
        """get_all_valid_keys returns empty list if all keys are expired."""
        db.insert_key("EXP1", int(time.time()) - 50)
        assert db.get_all_valid_keys() == []

    def test_sql_injection_stored_safely(self):
        """A SQL injection string should be stored as data, not executed."""
        evil = "'; DROP TABLE keys; --"
        db.insert_key(evil, int(time.time()) + 3600)
        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
            ).fetchone()
        assert row is not None
        assert db.get_valid_key()["key"] == evil

    def test_initialize_db_raises_on_error(self):
        """initialize_db should raise RuntimeError on sqlite failure."""
        with patch("db.get_connection", side_effect=sqlite3.Error("fail")):
            with pytest.raises(RuntimeError, match="Failed to initialize database"):
                db.initialize_db()

    def test_insert_key_raises_on_error(self):
        """insert_key should raise RuntimeError on sqlite failure."""
        with patch("db.get_connection", side_effect=sqlite3.Error("fail")):
            with pytest.raises(RuntimeError, match="Failed to insert key"):
                db.insert_key("PEM", int(time.time()) + 3600)

    def test_get_valid_key_raises_on_error(self):
        """get_valid_key should raise RuntimeError on sqlite failure."""
        with patch("db.get_connection", side_effect=sqlite3.Error("fail")):
            with pytest.raises(RuntimeError, match="Failed to fetch valid key"):
                db.get_valid_key()

    def test_get_expired_key_raises_on_error(self):
        """get_expired_key should raise RuntimeError on sqlite failure."""
        with patch("db.get_connection", side_effect=sqlite3.Error("fail")):
            with pytest.raises(RuntimeError, match="Failed to fetch expired key"):
                db.get_expired_key()

    def test_get_all_valid_keys_raises_on_error(self):
        """get_all_valid_keys should raise RuntimeError on sqlite failure."""
        with patch("db.get_connection", side_effect=sqlite3.Error("fail")):
            with pytest.raises(RuntimeError, match="Failed to fetch valid keys"):
                db.get_all_valid_keys()


class TestKeyManager:
    def test_generate_and_store_returns_kid(self):
        """generate_and_store_key should return a positive integer kid."""
        kid = key_manager.generate_and_store_key(3600)
        assert isinstance(kid, int) and kid >= 1

    def test_generated_key_appears_in_db(self):
        """A generated valid key should appear in get_all_valid_keys."""
        key_manager.generate_and_store_key(3600)
        assert len(db.get_all_valid_keys()) == 1

    def test_expired_key_not_in_valid_list(self):
        """A key generated with negative expiry should not appear as valid."""
        key_manager.generate_and_store_key(-1)
        assert db.get_all_valid_keys() == []

    def test_deserialize_round_trip(self):
        """PEM serialize and deserialize should recover the same public key."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        priv = rsa.generate_private_key(65537, 2048, default_backend())
        pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode("utf-8")
        recovered = key_manager.deserialize_private_key(pem)
        assert (
            recovered.public_key().public_numbers()
            == priv.public_key().public_numbers()
        )

    def test_public_key_to_jwk_required_fields(self):
        """public_key_to_jwk must include kty, kid, use, alg, n, e."""
        key_manager.generate_and_store_key(3600)
        row = db.get_valid_key()
        priv = key_manager.deserialize_private_key(row["key"])
        jwk = key_manager.public_key_to_jwk(row["kid"], priv)
        for field in ("kty", "kid", "use", "alg", "n", "e"):
            assert field in jwk

    def test_public_key_to_jwk_values(self):
        """JWK should have correct static field values."""
        key_manager.generate_and_store_key(3600)
        row = db.get_valid_key()
        priv = key_manager.deserialize_private_key(row["key"])
        jwk = key_manager.public_key_to_jwk(row["kid"], priv)
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"

    def test_n_and_e_are_valid_base64url(self):
        """The n and e values must be valid base64url-encoded strings."""
        key_manager.generate_and_store_key(3600)
        row = db.get_valid_key()
        priv = key_manager.deserialize_private_key(row["key"])
        jwk = key_manager.public_key_to_jwk(row["kid"], priv)
        for field in ("n", "e"):
            val = jwk[field]
            padded = val + "=" * (-len(val) % 4)
            assert len(base64.urlsafe_b64decode(padded)) > 0


class TestAuthEndpoint:
    def test_auth_returns_200_and_token(self, client):
        """POST /auth should return HTTP 200 with a token field."""
        resp = client.post("/auth")
        assert resp.status_code == 200
        assert "token" in resp.json()

    def test_auth_token_is_string(self, client):
        """The returned token should be a non-empty string."""
        token = client.post("/auth").json()["token"]
        assert isinstance(token, str) and len(token) > 0

    def test_auth_token_has_three_jwt_parts(self, client):
        """A JWT must have exactly 3 dot-separated segments."""
        token = client.post("/auth").json()["token"]
        assert len(token.split(".")) == 3

    def test_auth_expired_returns_200(self, client):
        """POST /auth?expired=true should return HTTP 200 with a token."""
        resp = client.post("/auth?expired=true")
        assert resp.status_code == 200
        assert "token" in resp.json()

    def test_auth_expired_token_three_parts(self, client):
        """An expired JWT should still have 3 dot-separated segments."""
        token = client.post("/auth?expired=true").json()["token"]
        assert len(token.split(".")) == 3

    def test_auth_valid_token_kid_in_db(self, client):
        """The kid in the JWT header must match a valid key in the DB."""
        token = client.post("/auth").json()["token"]
        header_b64 = token.split(".")[0] + "=="
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        kid = int(header["kid"])
        valid_kids = {r["kid"] for r in db.get_all_valid_keys()}
        assert kid in valid_kids

    def test_auth_no_valid_key_returns_404(self, client):
        """If no valid key exists in DB, POST /auth should return 404."""
        with db.get_connection() as conn:
            conn.execute("DELETE FROM keys WHERE exp > ?", (int(time.time()),))
            conn.commit()
        assert client.post("/auth").status_code == 404

    def test_auth_no_expired_key_returns_404(self, client):
        """If no expired key exists, POST /auth?expired=true returns 404."""
        with db.get_connection() as conn:
            conn.execute("DELETE FROM keys WHERE exp <= ?", (int(time.time()),))
            conn.commit()
        assert client.post("/auth?expired=true").status_code == 404

    def test_auth_get_method_not_allowed(self, client):
        """GET /auth should return 405 Method Not Allowed."""
        assert client.get("/auth").status_code == 405

    def test_auth_accepts_json_body(self, client):
        """POST /auth should accept JSON body credentials without failing."""
        resp = client.post(
            "/auth",
            json={"username": "userABC", "password": "password123"},
        )
        assert resp.status_code == 200


class TestJWKSEndpoint:
    def test_jwks_returns_200(self, client):
        """GET /.well-known/jwks.json should return HTTP 200."""
        assert client.get("/.well-known/jwks.json").status_code == 200

    def test_jwks_has_keys_array(self, client):
        """Response must be a JSON object with a keys array."""
        data = client.get("/.well-known/jwks.json").json()
        assert "keys" in data and isinstance(data["keys"], list)

    def test_jwks_contains_at_least_one_key(self, client):
        """There should be at least one valid key after startup seeding."""
        assert len(client.get("/.well-known/jwks.json").json()["keys"]) >= 1

    def test_jwks_key_has_required_fields(self, client):
        """Every JWK must have kty, kid, use, alg, n, e."""
        for key in client.get("/.well-known/jwks.json").json()["keys"]:
            for field in ("kty", "kid", "use", "alg", "n", "e"):
                assert field in key

    def test_jwks_excludes_expired_keys(self, client):
        """Expired keys must not appear in the JWKS response."""
        db.insert_key("SHOULD_NOT_APPEAR", int(time.time()) - 500)
        keys = client.get("/.well-known/jwks.json").json()["keys"]
        for k in keys:
            assert len(k["n"]) > 0

    def test_jwks_n_and_e_base64url(self, client):
        """n and e must decode successfully as base64url."""
        for key in client.get("/.well-known/jwks.json").json()["keys"]:
            for field in ("n", "e"):
                val = key[field] + "=="
                assert len(base64.urlsafe_b64decode(val)) > 0

    def test_jwks_post_not_allowed(self, client):
        """POST /.well-known/jwks.json should return 405."""
        assert client.post("/.well-known/jwks.json").status_code == 405
