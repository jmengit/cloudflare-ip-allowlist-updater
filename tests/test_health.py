import time

from cf_allowlist_updater.health import (
    HealthConfig,
    evaluate,
    read_state,
    run_health_check,
    success_ips,
    write_state,
)


def test_state_roundtrip_replaces_atomically(tmp_path):
    path = str(tmp_path / "nested" / "state.json")
    write_state(path, {"last_success_at": 1.0, "consecutive_failures": 0})
    assert read_state(path)["last_success_at"] == 1.0

    write_state(path, {"last_success_at": 2.0, "consecutive_failures": 1})
    state = read_state(path)
    assert state == {"last_success_at": 2.0, "consecutive_failures": 1}
    # no temp files left behind
    assert [p.name for p in (tmp_path / "nested").iterdir()] == ["state.json"]


def test_read_state_returns_none_for_missing_or_corrupt(tmp_path):
    missing = str(tmp_path / "absent.json")
    assert read_state(missing) is None

    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert read_state(str(bad)) is None

    not_object = tmp_path / "list.json"
    not_object.write_text("[1, 2, 3]")
    assert read_state(str(not_object)) is None


def test_max_age_defaults_to_one_interval_plus_slack():
    assert HealthConfig().max_age_for(3600) == 4200
    # a short interval still leaves ten minutes of slack
    assert HealthConfig().max_age_for(60) == 660
    # explicit override wins
    assert HealthConfig(max_age_seconds=900).max_age_for(3600) == 900


def test_missing_state_is_unhealthy():
    healthy, message = evaluate(
        None, now=1000.0, max_age_seconds=4200, start_grace_seconds=300
    )
    assert healthy is False
    assert "no health state" in message


def test_disabled_updater_is_healthy():
    healthy, message = evaluate(
        {"disabled": True}, now=1000.0, max_age_seconds=4200, start_grace_seconds=300
    )
    assert healthy is True
    assert "disabled" in message


def test_waiting_for_first_cycle_is_healthy_inside_start_grace():
    state = {"started_at": 900.0, "last_success_at": None}
    healthy, message = evaluate(
        state, now=1100.0, max_age_seconds=4200, start_grace_seconds=300
    )
    assert healthy is True
    assert "waiting for first update cycle" in message


def test_no_success_after_start_grace_is_unhealthy_with_error():
    state = {"started_at": 100.0, "last_success_at": None, "last_error": "ValueError: bad token"}
    healthy, message = evaluate(
        state, now=1000.0, max_age_seconds=4200, start_grace_seconds=300
    )
    assert healthy is False
    assert "bad token" in message


def test_fresh_success_is_healthy_and_names_the_policy():
    state = {
        "last_success_at": 1000.0,
        "last_success_ips": ["203.0.113.7/32"],
        "policy_id": "policy-1",
    }
    healthy, message = evaluate(
        state, now=1300.0, max_age_seconds=4200, start_grace_seconds=300
    )
    assert healthy is True
    assert "203.0.113.7/32" in message
    assert "policy-1" in message


def test_stale_success_is_unhealthy_and_reports_failures():
    state = {
        "last_success_at": 1000.0,
        "consecutive_failures": 3,
        "last_error": "CloudflareAPIError: 403",
    }
    healthy, message = evaluate(
        state, now=1000.0 + 4201, max_age_seconds=4200, start_grace_seconds=300
    )
    assert healthy is False
    assert "exceeds 70m limit" in message
    assert "consecutive failures: 3" in message
    assert "403" in message


def test_success_ips_reads_all_result_shapes():
    assert success_ips({"policy_result": {"include": [{"ip": {"ip": "198.51.100.9"}}]}}) == [
        "198.51.100.9"
    ]
    assert success_ips({"policy": {"include": [{"ip": {"ip": "198.51.100.10"}}, {"email": {}}]}}) == [
        "198.51.100.10"
    ]
    assert success_ips({"ip": "198.51.100.11/32"}) == ["198.51.100.11/32"]
    assert success_ips({"mode": "policy"}) == []


def test_run_health_check_exit_codes(tmp_path, capsys):
    path = str(tmp_path / "state.json")
    write_state(
        path,
        {
            "last_success_at": time.time(),
            "max_age_seconds": 4200,
            "last_success_ips": ["203.0.113.7/32"],
            "policy_id": "p1",
        },
    )
    assert run_health_check(HealthConfig(state_file=path)) == 0
    assert capsys.readouterr().out.startswith("ok:")

    write_state(
        path,
        {
            "last_success_at": time.time() - 7200,
            "max_age_seconds": 4200,
            "consecutive_failures": 2,
            "last_error": "CloudflareAPIError: 403",
        },
    )
    assert run_health_check(HealthConfig(state_file=path)) == 1
    out = capsys.readouterr().out
    assert out.startswith("unhealthy:")
    assert "403" in out


def test_health_flag_runs_without_cloudflare_configuration(tmp_path, monkeypatch, capsys):
    from cf_allowlist_updater import cli

    path = str(tmp_path / "state.json")
    write_state(path, {"last_success_at": time.time(), "max_age_seconds": 4200})
    monkeypatch.setenv("HEALTH_STATE_FILE", path)
    for name in ("CF_API_TOKEN", "CF_ACCOUNT_ID", "CF_POLICY_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["cf-allowlist-updater", "--health"])

    assert cli.main() == 0
    assert capsys.readouterr().out.startswith("ok:")


def test_restart_keeps_last_success_for_the_same_policy(tmp_path, monkeypatch):
    from cf_allowlist_updater import cli
    from cf_allowlist_updater.core import CloudflareAPIError

    path = str(tmp_path / "state.json")
    old_success = time.time() - 7300
    write_state(
        path,
        {
            "policy_id": "policy",
            "last_success_at": old_success,
            "last_success_ips": ["203.0.113.7"],
        },
    )
    monkeypatch.setenv("HEALTH_STATE_FILE", path)
    monkeypatch.setenv("CF_API_TOKEN", "token")
    monkeypatch.setenv("CF_ACCOUNT_ID", "account")
    monkeypatch.setenv("CF_POLICY_ID", "policy")
    monkeypatch.setenv("ONCE", "true")
    monkeypatch.setattr(cli.sys, "argv", ["cf-allowlist-updater"])

    def boom(_cfg):
        raise CloudflareAPIError("403 forbidden")

    monkeypatch.setattr(cli, "run_once", boom)
    assert cli.main() == 1

    state = read_state(path)
    assert state["last_success_at"] == old_success
    assert state["last_success_ips"] == ["203.0.113.7"]
    assert state["consecutive_failures"] == 1


def test_restart_does_not_carry_success_across_a_policy_change(tmp_path, monkeypatch):
    from cf_allowlist_updater import cli

    path = str(tmp_path / "state.json")
    write_state(path, {"policy_id": "old-policy", "last_success_at": time.time() - 100})
    monkeypatch.setenv("HEALTH_STATE_FILE", path)
    monkeypatch.setenv("CF_API_TOKEN", "token")
    monkeypatch.setenv("CF_ACCOUNT_ID", "account")
    monkeypatch.setenv("CF_POLICY_ID", "new-policy")
    monkeypatch.setenv("ONCE", "true")
    monkeypatch.setattr(cli.sys, "argv", ["cf-allowlist-updater"])
    monkeypatch.setattr(cli, "run_once", lambda _cfg: {"mode": "policy"})
    assert cli.main() == 0

    state = read_state(path)
    assert state["policy_id"] == "new-policy"
    assert state["last_success_ips"] == []


def test_loop_records_success_and_failure_in_state(tmp_path, monkeypatch):
    from cf_allowlist_updater import cli
    from cf_allowlist_updater.core import CloudflareAPIError

    path = str(tmp_path / "state.json")
    monkeypatch.setenv("HEALTH_STATE_FILE", path)
    monkeypatch.setenv("CF_API_TOKEN", "token")
    monkeypatch.setenv("CF_ACCOUNT_ID", "account")
    monkeypatch.setenv("CF_POLICY_ID", "policy")
    monkeypatch.setenv("ONCE", "true")
    monkeypatch.setenv("UPDATE_INTERVAL_MINUTES", "60")
    monkeypatch.setattr(cli.sys, "argv", ["cf-allowlist-updater"])

    def boom(_cfg):
        raise CloudflareAPIError("403 forbidden")

    monkeypatch.setattr(cli, "run_once", boom)
    assert cli.main() == 1
    state = read_state(path)
    assert state["consecutive_failures"] == 1
    assert "403 forbidden" in state["last_error"]
    assert state["last_success_at"] is None
    assert state["max_age_seconds"] == 4200

    monkeypatch.setattr(
        cli,
        "run_once",
        lambda _cfg: {
            "mode": "policy",
            "policy_id": "policy",
            "policy_result": {"include": [{"ip": {"ip": "203.0.113.7"}}]},
        },
    )
    assert cli.main() == 0
    state = read_state(path)
    assert state["consecutive_failures"] == 0
    assert state["last_error"] is None
    assert state["last_success_ips"] == ["203.0.113.7"]
    assert state["last_success_at"] is not None
