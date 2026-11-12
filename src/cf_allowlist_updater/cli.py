from __future__ import annotations

import json
import sys
import time
from typing import Any

from .config import Config
from .core import CloudflareAPIError, run_once
from .health import HealthConfig, read_state, run_health_check, success_ips, write_state


def _redact(result: dict[str, Any]) -> dict[str, Any]:
    safe = dict(result)
    # Dry-run item values are not secrets, but keeping logs compact is nicer for Unraid.
    if "items" in safe and isinstance(safe["items"], list):
        safe["items"] = f"{len(safe['items'])} item(s)"
    return safe


class _StateWriter:
    """Keep the Docker health state file current without ever failing the loop."""

    def __init__(self, health: HealthConfig, cfg: Config) -> None:
        self.path = health.state_file
        previous = read_state(self.path) or {}
        # Carry the last success across a process restart (same container) so a
        # crash-loop cannot reset the health clock to "waiting for first cycle".
        carry = (
            previous.get("policy_id") == cfg.policy_id
            and previous.get("last_success_at")
        )
        self.state: dict[str, Any] = {
            "version": 1,
            "started_at": time.time(),
            "interval_seconds": cfg.interval_seconds,
            "max_age_seconds": health.max_age_for(cfg.interval_seconds),
            "policy_id": cfg.policy_id,
            "dry_run": cfg.dry_run,
            "disabled": cfg.disabled,
            "last_attempt_at": None,
            "last_success_at": previous.get("last_success_at") if carry else None,
            "last_success_ips": (previous.get("last_success_ips") or []) if carry else [],
            "consecutive_failures": 0,
            "last_error": None,
        }
        self._warned = False
        self.flush()

    def flush(self) -> None:
        try:
            write_state(self.path, self.state)
        except OSError as exc:
            if not self._warned:
                print(
                    f"WARNING: cannot write health state {self.path}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
                self._warned = True

    def attempt(self) -> None:
        self.state["last_attempt_at"] = time.time()
        self.flush()

    def success(self, result: dict[str, Any]) -> None:
        now = time.time()
        self.state["last_attempt_at"] = now
        self.state["last_success_at"] = now
        self.state["last_success_ips"] = success_ips(result)
        self.state["consecutive_failures"] = 0
        self.state["last_error"] = None
        self.flush()

    def failure(self, exc: BaseException) -> None:
        self.state["last_attempt_at"] = time.time()
        self.state["consecutive_failures"] = (
            int(self.state.get("consecutive_failures") or 0) + 1
        )
        self.state["last_error"] = f"{type(exc).__name__}: {exc}"
        self.flush()


def main() -> int:
    if "--health" in sys.argv[1:]:
        # Runs as a second process under Docker HEALTHCHECK; reads the state file
        # only, so a broken Cloudflare configuration cannot hide the result.
        return run_health_check()
    try:
        cfg = Config.from_env()
        writer = _StateWriter(HealthConfig.from_env(), cfg)
        if cfg.disabled:
            print(
                "cf-allowlist-updater is disabled; set DISABLED=false and fill Cloudflare env vars to enable.",
                flush=True,
            )
            while not cfg.once:
                time.sleep(cfg.interval_seconds)
            return 0
        last_exit_code = 0
        last_success = time.monotonic()
        while True:
            writer.attempt()
            try:
                result = run_once(cfg)
                print(json.dumps(_redact(result), sort_keys=True), flush=True)
                writer.success(result)
                last_success = time.monotonic()
                last_exit_code = 0
            except (CloudflareAPIError, ValueError) as exc:
                writer.failure(exc)
                print(f"ERROR: {exc}", file=sys.stderr, flush=True)
                skip = {
                    "error": str(exc),
                    "mode": "skip",
                    "wait_seconds": cfg.interval_seconds,
                }
                print(json.dumps(skip, sort_keys=True), flush=True)
                last_exit_code = 1
                elapsed = time.monotonic() - last_success
                if elapsed >= cfg.failure_window_seconds:
                    print(
                        f"FATAL: no successful update in {elapsed / 3600:.1f}h "
                        f"(limit {cfg.failure_window_seconds / 3600:.0f}h). Exiting.",
                        file=sys.stderr,
                        flush=True,
                    )
                    return 1
            if cfg.once:
                return last_exit_code
            time.sleep(cfg.interval_seconds)
    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
