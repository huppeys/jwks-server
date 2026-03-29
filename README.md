# JWKS Server (Project 2)

A FastAPI-based JWKS server with SQLite-backed private key storage, JWT issuance,
and SQL injection protection via parameterized queries.

## Features

- SQLite database (`totally_not_my_privateKeys.db`) for persistent RSA key storage
- RSA private keys serialized as PKCS1 PEM strings in the database
- JWKS endpoint (`/.well-known/jwks.json`) — returns all valid (non-expired) public keys
- Auth endpoint (`/auth`) — issues a signed JWT; supports `?expired=true` query parameter
- Accepts HTTP Basic Auth or JSON body credentials (mocked authentication)
- All SQL queries use parameterized statements (`?`) to prevent SQL injection
- 40 unit tests with 99% code coverage

## Project Structure
```
jwks-server/
├── main.py              # FastAPI app, startup seeding, endpoints
├── db.py                # SQLite layer (create, insert, query keys)
├── key_manager.py       # RSA key generation, PEM serialization, JWK conversion
├── test_main.py         # Full test suite (pytest + coverage)
├── setup.cfg            # pytest and coverage configuration
├── screenshots/         # Gradebot output and test coverage screenshots
└── README.md
```

## Database Schema
```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
```

- `kid` — auto-incremented key ID, used as the JWT `kid` header
- `key` — RSA private key stored as a PKCS1 PEM string
- `exp` — Unix timestamp for key expiry

## Setup
```bash
git clone https://github.com/huppeys/jwks-server.git
cd jwks-server
python3 -m venv venv
source venv/bin/activate
pip install fastapi "uvicorn[standard]" cryptography pyjwt pytest pytest-cov httpx
uvicorn main:app --port 8080
```

On startup, the server automatically creates the database and seeds one expired key and one valid key (expires in 1 hour).

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/jwks.json` | Returns all valid public keys in JWKS format |
| `POST` | `/auth` | Issues a signed JWT using a valid key |
| `POST` | `/auth?expired=true` | Issues a JWT signed with an expired key |

## Running Tests
```bash
pytest test_main.py -v --cov=. --cov-report=term-missing
```

Results: 40 passed, 99% coverage (Python 3.9.6, pytest 8.4.2)
```
Name             Stmts   Miss  Cover
--------------------------------------
db.py               51      0   100%
key_manager.py      22      0   100%
main.py             38      0   100%
test_main.py       202      1    99%
--------------------------------------
TOTAL              313      1    99%
```
