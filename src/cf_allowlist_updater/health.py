"""Health state for the updater loop.

The updater has no network surface, so Docker's ``HEALTHCHECK`` runs a second
process in the same container (``cf-allowlist-updater --health``).  The two
processes share progress through a small JSON state file that the loop rewrites
after every attempt.

The signal is deliberately *functional*: healthy means "a real Cloudflare
update succeeded recently", not "the process is still running".  A revoked API
token, a deleted policy or a wedged loop all leave the process alive while the
policy silently goes stale; only the success age catches those.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
from dataclasses import dataclass
from typing import Any

DEFAULT_STATE_FILE = "/tmp/cf-allowlist-updater/state.json"
DEFAULT_START_GRACE_SECONDS = 300
# Extra room on top of one interval so a slow cycle is not called stale early.
MAX_AGE_SLACK_SECONDS = 600


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class HealthConfig:
    """Health settings, read without validating the Cloudflare configuration."""

    state_file: str = DEFAULT_STATE_FILE
    # 0 means "derive from the update interval" (see max_age_for).
    max_age_seconds: int = 0
    start_grace_seconds: int = DEFAULT_START_GRACE_SECONDS

    @classmethod
    def from_env(cls) -> "HealthConfig":
        return cls(
            state_file=os.getenv("HEALTH_STATE_FILE", DEFAULT_STATE_FILE),
            max_age_seconds=_int_env("HEALTH_MAX_AGE_SECONDS", 0),
            start_grace_seconds=_int_env(
                "HEALTH_START_GRACE_SECONDS", DEFAULT_START_GRACE_SECONDS
            ),
        )

    def max_age_for(self, interval_seconds: int) -> int:
        """Maximum age of the last successful update before reporting unhealthy."""
        if self.max_age_seconds > 0:
            return self.max_age_seconds
        return int(interval_seconds) + MAX_AGE_SLACK_SECONDS


def write_state(path: str, state: dict[str, Any]) -> None:
    """Atomically replace the state file so a reader never sees a partial write."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".state-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def read_state(path: str) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def success_ips(result: dict[str, Any]) -> list[str]:
    """Extract the IP entries a successful run wrote, for the health message."""
    entries: Any = None
    if isinstance(result.get("policy_result"), dict):
        entries = result["policy_result"].get("include")
    elif isinstance(result.get("policy"), dict):
        entries = result["policy"].get("include")
    ips: list[str] = []
    if isinstance(entries, list):
        for entry in entries:
            value = entry.get("ip", {}).get("ip") if isinstance(entry, dict) else None
            if value and value not in ips:
                ips.append(value)
    elif isinstance(result.get("ip"), str):
        ips.append(result["ip"])
    return ips


def evaluate(
    state: dict[str, Any] | None,
    *,
    now: float,
    max_age_seconds: int,
    start_grace_seconds: int,
) -> tuple[bool, str]:
    """Return (healthy, one-line reason) for a state snapshot."""
    if state is None:
        return False, "no health state file: the updater has not completed a cycle"

    if state.get("disabled"):
        return True, "updater is disabled by configuration (DISABLED=true)"

    last_success = state.get("last_success_at")
    if not last_success:
        started_at = float(state.get("started_at") or now)
        age = max(0.0, now - started_at)
        if age <= start_grace_seconds:
            return True, f"waiting for first update cycle ({age:.0f}s since start)"
        last_error = state.get("last_error") or "no successful update yet"
        return False, (
            f"no successful update in {age / 60:.1f}m since start: {last_error}"
        )

    age = max(0.0, now - float(last_success))
    if age <= max_age_seconds:
        ips = state.get("last_success_ips") or []
        ip_text = ",".join(ips) if ips else "n/a"
        policy = state.get("policy_id") or "n/a"
        return True, (
            f"last successful update {age:.0f}s ago (ips {ip_text}, policy {policy})"
        )

    failures = state.get("consecutive_failures", 0)
    last_error = state.get("last_error") or "no error recorded"
    return False, (
        f"last successful update {age / 60:.1f}m ago exceeds "
        f"{max_age_seconds / 60:.0f}m limit; consecutive failures: {failures}; "
        f"last error: {last_error}"
    )


def run_health_check(health: HealthConfig | None = None) -> int:
    """Entry point for ``--health``: print one line and return a Docker exit code."""
    health = health or HealthConfig.from_env()
    state = read_state(health.state_file)
    default_interval = _int_env("UPDATE_INTERVAL_MINUTES", 5) * 60
    max_age = int(
        (state or {}).get("max_age_seconds") or health.max_age_for(default_interval)
    )
    healthy, message = evaluate(
        state,
        now=time.time(),
        max_age_seconds=max_age,
        start_grace_seconds=health.start_grace_seconds,
    )
    print(f"{'ok' if healthy else 'unhealthy'}: {message}", flush=True)
    return 0 if healthy else 1
