"""Daily security digest -- the pure log-processing + alert logic (the I/O
functions that hit Railway/SMTP/the state file are exercised manually via
--dry-run / --test-email)."""
import os
import sys
import tempfile

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


# --- diff_stats: the actual fix for the restart false-positive ------------

def test_diff_stats_no_baseline_never_alerts():
    # First run ever (no persisted state): nothing to compare against, so a
    # `stats` event -- however it got there -- must not be reported as a change.
    latest = dsd.stats_snapshots([_stats_row(accounts=1, clients=1)])[-1]
    assert dsd.diff_stats(latest, {}) == {}


def test_diff_stats_no_stats_event_is_empty():
    assert dsd.diff_stats(None, {"accounts": 1}) == {}


def test_diff_stats_restart_with_unchanged_values_is_not_a_diff():
    # The exact bug this fixes: a stats line exists (e.g. from a restart) but
    # every value matches the baseline -- must NOT be reported as a change.
    latest = dsd.stats_snapshots([_stats_row(accounts=1, tokens=2, clients=1)])[-1]
    baseline = {"accounts": 1, "tokens": 2, "clients": 1, "people_with_token": 1,
                "active_workers": 0}
    assert dsd.diff_stats(latest, baseline) == {}


def test_diff_stats_reports_only_changed_fields():
    latest = dsd.stats_snapshots([_stats_row(accounts=1, tokens=3, clients=2)])[-1]
    baseline = {"accounts": 1, "tokens": 2, "clients": 1}
    diffs = dsd.diff_stats(latest, baseline)
    assert diffs == {"tokens": (2, 3), "clients": (1, 2)}
    assert "accounts" not in diffs


def test_load_state_missing_file_is_empty():
    assert dsd.load_state("/nonexistent/path/digest-state.json") == {}


def test_load_state_corrupt_file_is_empty():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("not json")
        path = f.name
    try:
        assert dsd.load_state(path) == {}
    finally:
        os.unlink(path)


def test_save_state_then_load_state_round_trips():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        path = f.name
    try:
        dsd.save_state(path, {"accounts": 1, "tokens": 2})
        assert dsd.load_state(path) == {"accounts": 1, "tokens": 2}
    finally:
        os.unlink(path)


def _quiet_summary():
    return dsd.hd.summarize([_other_row(), _other_row(event="mcp-response")])


def test_should_alert_silent_on_a_quiet_day():
    s = _quiet_summary()
    assert not dsd.should_alert(s, n_diffs=0, n_logins=0, probe_ok=True)


def test_should_alert_on_real_stats_diff():
    s = _quiet_summary()
    assert dsd.should_alert(s, n_diffs=1, n_logins=0, probe_ok=True)


def test_should_alert_on_login():
    s = _quiet_summary()
    assert dsd.should_alert(s, n_diffs=0, n_logins=1, probe_ok=True)


def test_should_alert_on_probe_failure():
    s = _quiet_summary()
    assert dsd.should_alert(s, n_diffs=0, n_logins=0, probe_ok=False)


def test_should_alert_on_anomaly():
    rows = [{"timestamp": "t", "severity": "error", "message": "",
             "attributes": [{"key": "event", "value": '"local-forward-error"'},
                            {"key": "account", "value": '"a@x"'}]}]
    s = dsd.hd.summarize(rows)
    assert dsd.should_alert(s, n_diffs=0, n_logins=0, probe_ok=True)


def test_render_email_reports_diffs_and_login():
    latest = dsd.stats_snapshots([_stats_row(accounts=1, clients=2)])[-1]
    diffs = {"clients": (1, 2)}
    logins = dsd.token_issuances([_login_row(account_key="rob@metalevels.net")])
    s = _quiet_summary()
    subject, body = dsd.render_email(s, latest, diffs, logins, probe_ok=True,
                                     window_hours=24,
                                     gateway_url="https://garmin.metalevels.net",
                                     anomaly_min=3)
    assert "activity" in subject
    assert "OAuth clients: 1 -> 2" in body
    assert "rob@metalevels.net" in body


def test_render_email_no_diffs_but_stats_fired_explains_restart_case():
    latest = dsd.stats_snapshots([_stats_row(accounts=1)])[-1]
    s = _quiet_summary()
    _subject, body = dsd.render_email(s, latest, {}, [], probe_ok=True, window_hours=24,
                                      gateway_url="https://garmin.metalevels.net",
                                      anomaly_min=3)
    assert "no change since last known state" in body.lower()


def test_render_email_no_stats_event_at_all():
    s = _quiet_summary()
    _subject, body = dsd.render_email(s, None, {}, [], probe_ok=True, window_hours=24,
                                      gateway_url="https://garmin.metalevels.net",
                                      anomaly_min=3)
    assert "account/token counts: no change." in body.lower()
    assert "none" in body.lower()


def test_render_email_down_probe_subject():
    s = _quiet_summary()
    subject, _body = dsd.render_email(s, None, {}, [], probe_ok=False, window_hours=24,
                                      gateway_url="https://garmin.metalevels.net",
                                      anomaly_min=3)
    assert "DOWN" in subject


def test_render_email_anomaly_subject_at_threshold():
    rows = [{"timestamp": "t", "severity": "error", "message": "",
             "attributes": [{"key": "event", "value": '"local-forward-error"'},
                            {"key": "account", "value": f'"{i}@x"'}]}
            for i in range(3)]
    s = dsd.hd.summarize(rows)
    subject, _body = dsd.render_email(s, None, {}, [], probe_ok=True, window_hours=24,
                                      gateway_url="https://garmin.metalevels.net",
                                      anomaly_min=3)
    assert "anomaly" in subject
