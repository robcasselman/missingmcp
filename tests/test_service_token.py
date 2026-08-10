"""Service tokens are ordinary access_tokens rows with expires_at = NULL.

The point of these tests is that minting one requires NO change to
proxy.authenticate(): the token validates through the same hash lookup as a
browser-issued one, survives the expiry sweep, and stays revocable.
"""
import subprocess
import sys
from pathlib import Path

import pytest

from missingmcp import store

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mint_service_token.py"


def run(db_path, *args):
    return subprocess.run([sys.executable, str(SCRIPT), "--db", str(db_path), *args],
                          capture_output=True, text=True)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "gateway.db"
    conn = store.init_db(str(path))
    conn.execute("INSERT INTO accounts (adapter, account_key, blob_enc) "
                 "VALUES ('garmin', 'rob@example.com', 'x')")
    conn.commit()
    conn.close()
    return path


def token_from(stdout: str) -> str:
    """The script prints the token alone on its own indented line."""
    return next(line.strip() for line in stdout.splitlines()
                if line.startswith("  ") and len(line.strip()) > 32 and " " not in line.strip())


def test_mint_creates_a_token_that_authenticates(db):
    r = run(db, "--account", "rob@example.com", "--label", "garmin-insights")
    assert r.returncode == 0, r.stderr
    token = token_from(r.stdout)

    conn = store.init_db(str(db))
    assert store.account_key_for_token_hash(conn, store.hash_token(token)) == (
        "garmin", "rob@example.com")
    conn.close()


def test_mint_never_expires_and_survives_the_sweep(db):
    r = run(db, "--account", "rob@example.com", "--label", "garmin-insights")
    token = token_from(r.stdout)
    conn = store.init_db(str(db))
    hashed = store.hash_token(token)

    assert conn.execute("SELECT expires_at FROM access_tokens WHERE token_hash=?",
                        (hashed,)).fetchone()["expires_at"] is None
    store.cleanup_expired_tokens(conn)
    assert store.account_key_for_token_hash(conn, hashed) is not None
    conn.close()


def test_mint_refuses_an_account_that_never_connected(db):
    r = run(db, "--account", "nobody@example.com", "--label", "x")
    assert r.returncode != 0
    assert "No connected account" in r.stdout + r.stderr
    conn = store.init_db(str(db))
    assert conn.execute("SELECT COUNT(*) FROM access_tokens").fetchone()[0] == 0
    conn.close()


def test_account_key_is_normalized_like_the_oauth_path(db):
    r = run(db, "--account", "  ROB@Example.com  ", "--label", "garmin-insights")
    assert r.returncode == 0, r.stdout + r.stderr
    conn = store.init_db(str(db))
    assert store.account_key_for_token_hash(
        conn, store.hash_token(token_from(r.stdout))) == ("garmin", "rob@example.com")
    conn.close()


def test_revoke_removes_the_token(db):
    token = token_from(run(db, "--account", "rob@example.com",
                           "--label", "garmin-insights").stdout)
    conn = store.init_db(str(db))
    assert store.account_key_for_token_hash(conn, store.hash_token(token)) is not None
    conn.close()

    r = run(db, "--revoke", "garmin-insights")
    assert r.returncode == 0
    conn = store.init_db(str(db))
    assert store.account_key_for_token_hash(conn, store.hash_token(token)) is None
    conn.close()


def test_list_reports_the_label_without_leaking_the_token(db):
    token = token_from(run(db, "--account", "rob@example.com",
                           "--label", "garmin-insights").stdout)
    r = run(db, "--list")
    assert "garmin-insights" in r.stdout
    assert "garmin:rob@example.com" in r.stdout
    assert token not in r.stdout
