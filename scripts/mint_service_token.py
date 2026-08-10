#!/usr/bin/env python3
"""Mint a non-expiring service token for an unattended consumer of the gateway.

A service token is an ordinary row in access_tokens with expires_at = NULL, so
it needs NO new code in proxy.authenticate(): the existing hash lookup accepts
it, the existing per-token rate-limit bucket governs it, and revoke.py can kill
it. The only thing that makes it "service" is (a) it never expires — NULL
expires_at is skipped by both account_key_for_token_hash() and
cleanup_expired_tokens() — and (b) its client_id is "service:<label>" rather
than a DCR-registered client, which is how --list finds it again later.

This exists because unattended jobs (the garmin-insights daily cron) cannot run
the interactive OAuth flow: authorize requires a browser and the upstream
password. The token inherits the account's stored upstream credentials, so it is
exactly as powerful as that user's MCP connection — treat it like a password.

Usage:
  python scripts/mint_service_token.py --list
  python scripts/mint_service_token.py --account me@x.cz --label garmin-insights
  python scripts/mint_service_token.py --revoke garmin-insights

The token is printed ONCE. Only its SHA-256 hash is stored, so a lost token
cannot be recovered — mint a new one and revoke the old.

DB path resolves like status.py: $DB_PATH, $DATA_DIR/gateway.db, /data, ./.localdata.
On Railway: railway ssh --service missingmcp \
              "python3 /app/scripts/mint_service_token.py --account <email> --label garmin-insights"
"""
from __future__ import annotations
import argparse
import hashlib
import os
import secrets
import sqlite3
import sys

DEFAULT_ADAPTER = "garmin"
CLIENT_PREFIX = "service:"


def resolve_db() -> str:
    if os.environ.get("DB_PATH"):
        return os.environ["DB_PATH"]
    if os.environ.get("DATA_DIR"):
        return os.path.join(os.environ["DATA_DIR"], "gateway.db")
    for cand in ("/data/gateway.db", "./.localdata/gateway.db"):
        if os.path.exists(cand):
            return cand
    return "/data/gateway.db"


def parse_account(value: str) -> tuple[str, str]:
    """'whoop:me@x.cz' -> ('whoop', 'me@x.cz'); a bare key defaults to garmin.
    Keys are stored lowercased (oauth._finish), so normalize here too."""
    adapter, sep, key = value.partition(":")
    if not sep:
        return DEFAULT_ADAPTER, adapter.strip().lower()
    return adapter.strip().lower(), key.strip().lower()


def main():
    p = argparse.ArgumentParser(description="Mint a non-expiring service token.")
    p.add_argument("--db", default=None, help="SQLite DB path (default: auto-resolve)")
    p.add_argument("--label", default=None,
                   help="name of the consuming job, e.g. garmin-insights "
                        "(stored as client_id 'service:<label>')")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true", help="list existing service tokens")
    g.add_argument("--account", metavar="[ADAPTER:]KEY",
                   help="account the token acts as (bare key = garmin)")
    g.add_argument("--revoke", metavar="LABEL",
                   help="revoke the service token(s) with this label")
    args = p.parse_args()

    db_path = args.db or resolve_db()
    if not os.path.exists(db_path):
        sys.exit(f"DB not found: {db_path}\nSet --db, DB_PATH or DATA_DIR.")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    if args.list:
        rows = conn.execute(
            "SELECT token_hash, adapter, account_key, client_id, created_at, last_used "
            "FROM access_tokens WHERE client_id LIKE ? ORDER BY created_at",
            (CLIENT_PREFIX + "%",),
        ).fetchall()
        if not rows:
            print("No service tokens.")
            return
        for r in rows:
            label = r["client_id"][len(CLIENT_PREFIX):]
            print(f"  {label:<24} {r['adapter']}:{r['account_key']:<32} "
                  f"{r['token_hash'][:8]}…  created: {r['created_at']}  "
                  f"last used: {r['last_used'] or '—'}")
        return

    if args.revoke:
        cur = conn.execute("DELETE FROM access_tokens WHERE client_id=?",
                           (CLIENT_PREFIX + args.revoke.strip(),))
        conn.commit()
        print(f"Revoked {cur.rowcount} service token(s) labelled {args.revoke!r}.")
        return

    if not args.label:
        p.error("--account requires --label (names the job that will hold the token)")
    label = args.label.strip()
    if not label:
        p.error("--label must not be empty")
    adapter, key = parse_account(args.account)

    # Refuse to mint against an account that has never connected: the token would
    # authenticate fine and then fail at forward time with a confusing 401, because
    # there are no stored upstream credentials to act on.
    if conn.execute("SELECT 1 FROM accounts WHERE adapter=? AND account_key=?",
                    (adapter, key)).fetchone() is None:
        known = [f"{r['adapter']}:{r['account_key']}" for r in conn.execute(
            "SELECT adapter, account_key FROM accounts ORDER BY adapter, account_key")]
        sys.exit(f"No connected account {adapter}:{key}.\n"
                 f"That account must sign in through the normal OAuth flow first.\n"
                 + ("Known accounts: " + ", ".join(known) if known
                    else "No accounts are connected yet."))

    client_id = CLIENT_PREFIX + label
    existing = conn.execute("SELECT COUNT(*) FROM access_tokens WHERE client_id=?",
                            (client_id,)).fetchone()[0]

    # Same shape as oauth._token: secrets.token_urlsafe(32) hashed with SHA-256.
    # ttl is deliberately absent -> expires_at stays NULL -> never expires, never swept.
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO access_tokens "
        "(token_hash, adapter, account_key, client_id, last_used, expires_at) "
        "VALUES (?, ?, ?, ?, datetime('now'), NULL)",
        (hashlib.sha256(token.encode()).hexdigest(), adapter, key, client_id),
    )
    conn.commit()

    if existing:
        print(f"Note: {existing} other token(s) already carry the label {label!r}. "
              f"Revoke them with --revoke {label} once the new one is in place.\n")
    print(f"Service token for {adapter}:{key}  (label: {label})\n")
    print(f"  {token}\n")
    print("Shown once — only its SHA-256 hash is stored. It never expires; it grants\n"
          f"full {adapter} MCP access as {key}. Store it as a secret env var and\n"
          f"revoke with: python scripts/mint_service_token.py --revoke {label}")


if __name__ == "__main__":
    main()
