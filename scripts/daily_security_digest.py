#!/usr/bin/env python3
"""Daily security digest -> email, sent ONLY when something changed.

Reads the gateway's last ~24h of Railway logs (same GraphQL API and log-parsing
machinery as hourly_digest.py, imported from it directly to avoid duplicating
that logic) and looks for the signals that matter for a single-operator
deployment: account/token/client count changes (the gateway only ever emits a
`stats` event when one of those counts actually changes, so its mere presence
in the window IS the "something changed" signal), completed logins
(`token-issued`, which carries the account_key), and the same anomaly counting
hourly_digest.py already does (5xx / error / critical rows, re-auth self-heals
excluded). If none of that fired in the window, the script prints why and exits
without sending anything -- no daily "all clear" noise.

Standalone (httpx + stdlib only, does not import the missingmcp package), so it
runs in GitHub Actions without installing the gateway's dependencies.

Email delivery is via the Resend HTTP API (https://resend.com) rather than SMTP —
one POST, mirrors report.py's post_slack() shape, no mail-account credential
needed. RESEND_API_KEY is a Resend account, not a mail account, so it can't be
used to send-as you anywhere else. DIGEST_EMAIL_FROM can stay the shared
onboarding@resend.dev sender (works out of the box, no setup) or point at a
domain you've verified with Resend for a branded From: address.

Env:
  RAILWAY_API_TOKEN       account/workspace or project token (Bearer)  [required]
  RAILWAY_SERVICE_ID      gateway service uuid                         [required]
  RAILWAY_ENVIRONMENT_ID  environment uuid                             [required]
  GATEWAY_URL             liveness-probe target (default https://missingmcp.com)
  DIGEST_EMAIL_TO         recipient address                [required unless --dry-run]
  DIGEST_EMAIL_FROM       From: address (default: onboarding@resend.dev)
  RESEND_API_KEY          Resend API key                   [required unless --dry-run]
  ANOMALY_MIN             min problem rows before the subject line reads
                          "anomaly" instead of "activity" (default 3)

Usage: python scripts/daily_security_digest.py [--dry-run] [--window-hours 24]
On Railway/GitHub Actions this needs no gateway access -- it only reads Railway
logs and sends mail.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hourly_digest as hd  # noqa: E402 - reuse Railway log fetch/parse, not duplicate it

RESEND_API = "https://api.resend.com/emails"


def _decode(v):
    try:
        return json.loads(v)
    except (ValueError, TypeError):
        return v

# stats field -> human label, in display order.
_STATS_FIELDS = [
    ("accounts", "accounts"),
    ("tokens", "tokens"),
    ("people_with_token", "people with a token"),
    ("clients", "OAuth clients"),
    ("active_workers", "active workers"),
]


# --- pure log processing (unit-tested) --------------------------------------

def stats_snapshots(rows: list[dict]) -> list[dict]:
    """Every `stats` event in the window, in the order Railway returned them,
    as {field: value} dicts (missing fields omitted). The gateway only emits
    `stats` on startup and whenever one of its counts changes (see store.py /
    app.py), so each entry here already represents a real change -- there is
    no need to diff against a prior run's state. parse_row() collapses
    attributes down to a fixed shape that drops the stats-specific fields, so
    this decodes each row's attributes directly instead."""
    out = []
    for row in rows:
        raw = {a["key"]: _decode(a["value"]) for a in (row.get("attributes") or [])}
        if raw.get("event") != "stats":
            continue
        snap = {key: int(raw[key]) for key, _label in _STATS_FIELDS if key in raw}
        if snap:
            snap["_timestamp"] = row.get("timestamp")
            out.append(snap)
    return out


def token_issuances(rows: list[dict]) -> list[dict]:
    """Every `token-issued` event in the window as {timestamp, account_key}."""
    out = []
    for row in rows:
        raw = {a["key"]: _decode(a["value"]) for a in (row.get("attributes") or [])}
        if raw.get("event") != "token-issued":
            continue
        out.append({"timestamp": row.get("timestamp"), "account_key": raw.get("account_key")})
    return out


def should_alert(summary: dict, n_stats: int, n_logins: int, probe_ok: bool) -> bool:
    """True when the digest is worth sending at all -- an account/token/client
    count changed, a login completed, an anomaly occurred, or the liveness
    probe failed. False (silent) on a quiet day."""
    return bool(n_stats or n_logins or summary["problems"] or summary["critical"]
                or not probe_ok)


def render_email(summary: dict, stats: list[dict], logins: list[dict],
                 probe_ok: bool, window_hours: int, gateway_url: str,
                 anomaly_min: int) -> tuple[str, str]:
    """Returns (subject, plain-text body)."""
    loud = summary["problems"] >= anomaly_min or summary["critical"] > 0 or not probe_ok
    if not probe_ok:
        subject = "[MissingMCP] gateway DOWN -- security digest"
    elif loud:
        subject = f"[MissingMCP] anomaly -- security digest ({summary['problems']} problem(s))"
    else:
        subject = "[MissingMCP] account activity -- security digest"

    lines = [
        f"MissingMCP security digest -- last {window_hours}h",
        f"Liveness probe ({gateway_url}): {'OK' if probe_ok else 'FAILED'}",
        "",
    ]

    if stats:
        latest = stats[-1]
        lines.append(f"Account/token counts changed {len(stats)} time(s) in this window.")
        lines.append("Latest counts:")
        for key, label in _STATS_FIELDS:
            if key in latest:
                lines.append(f"  - {label}: {latest[key]}")
    else:
        lines.append("Account/token counts: no change.")
    lines.append("")

    if logins:
        lines.append(f"Logins completed ({len(logins)}):")
        for entry in logins:
            lines.append(f"  - {entry['timestamp']}  account={entry['account_key']}")
    else:
        lines.append("Logins completed: none.")
    lines.append("")

    lines.append("Anomalies:")
    lines.append(f"  - 5xx responses: {summary['http_5xx']}")
    lines.append(f"  - error/critical rows (excl. routine re-auth): {summary['err_rows']}")
    lines.append(f"  - critical: {summary['critical']}")
    lines.append(f"  - re-auth self-heals (routine, not counted above): {summary['reauth']}")
    lines.append("")
    lines.append(f"({summary['requests']} requests, {summary['rows']} log rows scanned)")

    return subject, "\n".join(lines)


# --- I/O ---------------------------------------------------------------------

def send_email(api_key: str, to_addr: str, from_addr: str, subject: str, body: str) -> None:
    """One POST to the Resend API. Raises on failure, mirroring report.py's
    post_slack() shape."""
    resp = httpx.post(
        RESEND_API,
        headers={"Authorization": f"Bearer {api_key}"},
        json={"from": from_addr, "to": [to_addr], "subject": subject, "text": body},
        timeout=15.0,
    )
    if resp.status_code >= 300:
        raise RuntimeError(f"resend post rejected: HTTP {resp.status_code} {resp.text}")


def _need(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        sys.exit(f"missing required env var: {name}")
    return v


def main():
    p = argparse.ArgumentParser(description="Daily gateway security digest -> email.")
    p.add_argument("--dry-run", action="store_true", help="print, don't send")
    p.add_argument("--window-hours", type=int, default=24, help="log window in hours")
    p.add_argument("--test-email", action="store_true",
                   help="send one canned test message via Resend and exit, skipping "
                        "Railway/change-detection entirely -- verifies RESEND_API_KEY "
                        "and DIGEST_EMAIL_TO are wired correctly on their own")
    args = p.parse_args()

    if args.test_email:
        send_email(
            _need("RESEND_API_KEY"),
            _need("DIGEST_EMAIL_TO"),
            os.environ.get("DIGEST_EMAIL_FROM", "onboarding@resend.dev"),
            "[MissingMCP] test email -- daily security digest",
            "This is a one-off test message from scripts/daily_security_digest.py "
            "--test-email. If you got this, RESEND_API_KEY and DIGEST_EMAIL_TO are "
            "wired correctly; the real digest only sends when something changed.",
        )
        print("[sent] test email")
        return

    token = _need("RAILWAY_API_TOKEN")
    service_id = _need("RAILWAY_SERVICE_ID")
    environment_id = _need("RAILWAY_ENVIRONMENT_ID")
    gateway_url = os.environ.get("GATEWAY_URL", "https://missingmcp.com")
    anomaly_min = int(os.environ.get("ANOMALY_MIN", "3"))

    now = datetime.now(timezone.utc)
    start_iso = (now - timedelta(hours=args.window_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    deployment_id = hd.resolve_deployment_id(token, service_id, environment_id)
    rows = hd.fetch_logs(token, deployment_id, start_iso, end_iso, limit=10000)
    summary = hd.summarize(rows)
    stats = stats_snapshots(rows)
    logins = token_issuances(rows)
    probe_ok = hd.probe(gateway_url)

    alert = should_alert(summary, len(stats), len(logins), probe_ok)
    subject, body = render_email(summary, stats, logins, probe_ok,
                                 args.window_hours, gateway_url, anomaly_min)
    print(f"[alert={alert}] {subject}")
    print(body)

    if not alert:
        print("[silent] nothing changed in the window -- no email sent.")
        return
    if args.dry_run:
        print("[dry-run] not sending.")
        return

    send_email(
        _need("RESEND_API_KEY"),
        _need("DIGEST_EMAIL_TO"),
        os.environ.get("DIGEST_EMAIL_FROM", "onboarding@resend.dev"),
        subject, body,
    )
    print("[sent]")


if __name__ == "__main__":
    main()
