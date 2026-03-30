"""
db.py - SQLite database layer for the JWKS server.

Creates and manages the totally_not_my_privateKeys.db file.
All queries use parameterized statements (?) to prevent SQL injection.
"""

import sqlite3
import time
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:
    """Central configuration for the database layer."""
    DB_FILE: str = "totally_not_my_privateKeys.db"


# Keep a module-level alias so tests can override it easily.
DB_FILE = Config.DB_FILE

CREATE_TABLE_SQL: str = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    """
    Open and return a connection to the SQLite database.

    Returns:
        sqlite3.Connection: An open connection with Row factory enabled
            so columns can be accessed by name.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Schema initialization
# ---------------------------------------------------------------------------

def initialize_db() -> None:
    """
    Create the database file and keys table if they do not already exist.

    This function is idempotent — calling it multiple times is safe.

    Raises:
        sqlite3.Error: If the database cannot be created or the table
            statement fails for any reason other than it already existing.
    """
    try:
        with get_connection() as conn:
            conn.execute(CREATE_TABLE_SQL)
            conn.commit()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to initialize database: {exc}") from exc


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------

def insert_key(pem: str, exp: int) -> int:
    """
    Insert a PEM-encoded private key with its expiry Unix timestamp.

    Uses a parameterized query (?) to prevent SQL injection.

    Args:
        pem: RSA private key serialized as a PKCS1 PEM string.
        exp: Unix timestamp (seconds since epoch) at which the key expires.

    Returns:
        int: The auto-incremented ``kid`` assigned to the new row.

    Raises:
        RuntimeError: If the insert fails at the database level.
    """
    sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    try:
        with get_connection() as conn:
            cursor = conn.execute(sql, (pem, exp))
            conn.commit()
            return cursor.lastrowid
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to insert key: {exc}") from exc


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------

def get_valid_key() -> Optional[sqlite3.Row]:
    """
    Return one unexpired key row from the database.

    A key is considered valid when its ``exp`` timestamp is strictly
    greater than the current Unix time.

    Returns:
        sqlite3.Row | None: A row with columns ``kid``, ``key``, and
            ``exp``, or ``None`` if no valid keys exist.

    Raises:
        RuntimeError: If the query fails at the database level.
    """
    now = int(time.time())
    sql = "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1"
    try:
        with get_connection() as conn:
            return conn.execute(sql, (now,)).fetchone()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to fetch valid key: {exc}") from exc


def get_expired_key() -> Optional[sqlite3.Row]:
    """
    Return one expired key row from the database.

    A key is considered expired when its ``exp`` timestamp is less than
    or equal to the current Unix time.

    Returns:
        sqlite3.Row | None: A row with columns ``kid``, ``key``, and
            ``exp``, or ``None`` if no expired keys exist.

    Raises:
        RuntimeError: If the query fails at the database level.
    """
    now = int(time.time())
    sql = "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1"
    try:
        with get_connection() as conn:
            return conn.execute(sql, (now,)).fetchone()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to fetch expired key: {exc}") from exc


def get_all_valid_keys() -> list:
    """
    Return all unexpired key rows from the database.

    Expired keys are excluded from the result set.

    Returns:
        list[sqlite3.Row]: A (possibly empty) list of rows, each with
            columns ``kid``, ``key``, and ``exp``.

    Raises:
        RuntimeError: If the query fails at the database level.
    """
    now = int(time.time())
    sql = "SELECT kid, key, exp FROM keys WHERE exp > ?"
    try:
        with get_connection() as conn:
            return conn.execute(sql, (now,)).fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to fetch valid keys: {exc}") from exc
