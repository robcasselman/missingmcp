"""Daily security digest -- the pure log-processing + alert logic (the I/O
functions that hit Railway/SMTP are exercised manually via --dry-run)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import daily_security_digest as dsd  # noqa: E402


def _stats_row(accounts=1, tokens=1, people_with_token=1, clients=1, active_workers=0,
               ts="2026-08-07T08:00:00Z"):
    return {"timestamp": ts, "severity": "info", "message": "",
            "attributes": [
                {"key": "event", "value": '"stats"'},
                {"key": "accounts", "value": str(accounts)},
                {"key": "tokens", "value": str(tokens)},
                {"key": "people_with_token", "value": str(people_with_token)},
                {"key": "clients", "value": str(clients)},
                {"key": "active_workers", "value": str(active_workers)},
            ]}


def _login_row(account_key="rob@metalevels.net", ts="2026-08-07T08:05:00Z"):
    return {"timestamp": ts, "severity": "info", "message": "",
            "attributes": [
                {"key": "event", "value": '"token-issued"'},
                {"key": "account_key", "value": f'"{account_key}"'},
            ]}


def _other_row(event="mcp-request", ts="2026-08-07T08:01:00Z"):
    return {"timestamp": ts, "severity": "info", "message": "",
            "attributes": [{"key": "event", "value": f'"{event}"'}]}


def test_stats_snapshots_extracts_only_stats_events():
    rows = [_other_row(), _stats_row(accounts=2), _other_row(event="mcp-response")]
    snaps = dsd.stats_snapshots(rows)
    assert len(snaps) == 1
    assert snaps[0]["accounts"] == 2 and snaps[0]["clients"] == 1


def test_stats_snapshots_empty_when_no_stats_events():
    assert dsd.stats_snapshots([_other_row(), _other_row(event="mcp-response")]) == []


def test_stats_snapshots_preserves_order_and_multiple_entries():
    rows = [_stats_row(accounts=1, ts="t1"), _stats_row(accounts=2, ts="t2")]
    snaps = dsd.stats_snapshots(rows)
    assert [s["accounts"] for s in snaps] == [1, 2]


def test_token_issuances_extracts_account_key():
    rows = [_other_row(), _login_row(account_key="rob@metalevels.net")]
    logins = dsd.token_issuances(rows)
    assert len(logins) == 1
    assert logins[0]["account_key"] == "rob@metalevels.net"


def test_token_issuances_empty_when_none():
    assert dsd.token_issuances([_other_row(), _stats_row()]) == []


def _quiet_summary():
    return dsd.hd.summarize([_other_row(), _other_row(event="mcp-response")])


def test_should_alert_silent_on_a_quiet_day():
    s = _quiet_summary()
    assert not dsd.should_alert(s, n_stats=0, n_logins=0, probe_ok=True)


def test_should_alert_on_stats_change():
    s = _quiet_summary()
    assert dsd.should_alert(s, n_stats=1, n_logins=0, probe_ok=True)


def test_should_alert_on_login():
    s = _quiet_summary()
    assert dsd.should_alert(s, n_stats=0, n_logins=1, probe_ok=True)


def test_should_alert_on_probe_failure():
    s = _quiet_summary()
    assert dsd.should_alert(s, n_stats=0, n_logins=0, probe_ok=False)


def test_should_alert_on_anomaly():
    rows = [{"timestamp": "t", "severity": "error", "message": "",
             "attributes": [{"key": "event", "value": '"local-forward-error"'},
                            {"key": "account", "value": '"a@x"'}]}]
    s = dsd.hd.summarize(rows)
    assert dsd.should_alert(s, n_stats=0, n_logins=0, probe_ok=True)


def test_render_email_reports_stats_change_and_login():
    stats = dsd.stats_snapshots([_stats_row(accounts=1, clients=2)])
    logins = dsd.token_issuances([_login_row(account_key="rob@metalevels.net")])
    s = _quiet_summary()
    subject, body = dsd.render_email(s, stats, logins, probe_ok=True, window_hours=24,
                                     gateway_url="https://garmin.metalevels.net",
                                     anomaly_min=3)
    assert "activity" in subject
    assert "OAuth clients: 2" in body
    assert "rob@metalevels.net" in body


def test_render_email_no_changes_is_still_renderable():
    s = _quiet_summary()
    subject, body = dsd.render_email(s, [], [], probe_ok=True, window_hours=24,
                                     gateway_url="https://garmin.metalevels.net",
                                     anomaly_min=3)
    assert "no change" in body.lower()
    assert "none" in body.lower()


def test_render_email_down_probe_subject():
    s = _quiet_summary()
    subject, _body = dsd.render_email(s, [], [], probe_ok=False, window_hours=24,
                                      gateway_url="https://garmin.metalevels.net",
                                      anomaly_min=3)
    assert "DOWN" in subject


def test_render_email_anomaly_subject_at_threshold():
    rows = [{"timestamp": "t", "severity": "error", "message": "",
             "attributes": [{"key": "event", "value": '"local-forward-error"'},
                            {"key": "account", "value": f'"{i}@x"'}]}
            for i in range(3)]
    s = dsd.hd.summarize(rows)
    subject, _body = dsd.render_email(s, [], [], probe_ok=True, window_hours=24,
                                      gateway_url="https://garmin.metalevels.net",
                                      anomaly_min=3)
    assert "anomaly" in subject
