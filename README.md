# JWKS Server

This repository contains a FastAPI server demonstrating JWT authentication with JWKS (JSON Web Key Set).

## Features

- Generates demo RSA keys (valid and expired)
- Provides a JWKS endpoint (`/.well-known/jwks.json`)
- Issues JWT tokens (`/auth`)
- Protected endpoint requiring valid JWT (`/protected`)
- Unit tests for JWT encoding/decoding

## Setup

```bash
# Clone the repo
git clone https://github.com/huppeys/jwks-server.git
cd jwks-server

# Create virtual environment and install dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run server
uvicorn main:app --reload
