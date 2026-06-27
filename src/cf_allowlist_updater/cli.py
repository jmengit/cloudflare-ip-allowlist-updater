from __future__ import annotations

import json
import sys
import time
from typing import Any

from .config import Config
from .core import CloudflareAPIError, run_once


def _redact(result: dict[str, Any]) -> dict[str, Any]:
    safe = dict(result)
    # Dry-run item values are not secrets, but keeping logs compact is nicer for Unraid.
    if "items" in safe and isinstance(safe["items"], list):
        safe["items"] = f"{len(safe['items'])} item(s)"
    return safe


def main() -> int:
    try:
        cfg = Config.from_env()
        if cfg.disabled:
            print(
                "cf-allowlist-updater is disabled; set DISABLED=false and fill Cloudflare env vars to enable.",
                flush=True,
            )
            while not cfg.once:
                time.sleep(cfg.interval_seconds)
            return 0
        last_exit_code = 0
        while True:
            try:
                result = run_once(cfg)
                print(json.dumps(_redact(result), sort_keys=True), flush=True)
                last_exit_code = 0
            except (CloudflareAPIError, ValueError) as exc:
                print(f"ERROR: {exc}", file=sys.stderr, flush=True)
                skip = {
                    "error": str(exc),
                    "mode": "skip",
                    "wait_seconds": cfg.interval_seconds,
                }
                print(json.dumps(skip, sort_keys=True), flush=True)
                last_exit_code = 1
            if cfg.once:
                return last_exit_code
            time.sleep(cfg.interval_seconds)
    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
