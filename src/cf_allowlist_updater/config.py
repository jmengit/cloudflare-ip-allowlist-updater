from __future__ import annotations

import os
from dataclasses import dataclass

_TRUE = {"1", "true", "yes", "y", "on"}


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in _TRUE


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


@dataclass(frozen=True)
class Config:
    api_token: str
    account_id: str
    list_id: str | None = None
    list_name: str | None = None
    public_ip_url: str = "https://api64.ipify.org"
    comment: str = "managed-by=cf-ip-allowlist-updater"
    managed_comment_prefix: str = "managed-by=cf-ip-allowlist-updater"
    replace_all: bool = False
    dry_run: bool = False
    disabled: bool = False
    once: bool = False
    interval_seconds: int = 300
    wait_for_completion: bool = True
    operation_poll_seconds: float = 2.0
    operation_poll_attempts: int = 15
    request_timeout_seconds: int = 30
    api_base_url: str = "https://api.cloudflare.com/client/v4"

    def validate(self) -> None:
        if self.disabled:
            return
        missing = []
        if not self.api_token:
            missing.append("CF_API_TOKEN")
        if not self.account_id:
            missing.append("CF_ACCOUNT_ID")
        if not self.list_id and not self.list_name:
            missing.append("CF_LIST_ID or CF_LIST_NAME")
        if missing:
            raise ValueError("Missing required environment/config values: " + ", ".join(missing))
        if self.interval_seconds < 30:
            raise ValueError("CHECK_INTERVAL_SECONDS must be at least 30")

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls(
            api_token=os.getenv("CF_API_TOKEN", ""),
            account_id=os.getenv("CF_ACCOUNT_ID", ""),
            list_id=os.getenv("CF_LIST_ID") or None,
            list_name=os.getenv("CF_LIST_NAME") or os.getenv("CF_ALLOWLIST_NAME") or None,
            public_ip_url=os.getenv("PUBLIC_IP_URL", "https://api64.ipify.org"),
            comment=os.getenv("CF_LIST_ITEM_COMMENT", "managed-by=cf-ip-allowlist-updater"),
            managed_comment_prefix=os.getenv(
                "MANAGED_COMMENT_PREFIX", "managed-by=cf-ip-allowlist-updater"
            ),
            replace_all=_bool_env("REPLACE_ALL", False),
            dry_run=_bool_env("DRY_RUN", False),
            disabled=_bool_env("DISABLED", False),
            once=_bool_env("ONCE", False),
            interval_seconds=_int_env("CHECK_INTERVAL_SECONDS", 300),
            wait_for_completion=_bool_env("WAIT_FOR_COMPLETION", True),
            operation_poll_seconds=float(os.getenv("OPERATION_POLL_SECONDS", "2.0")),
            operation_poll_attempts=_int_env("OPERATION_POLL_ATTEMPTS", 15),
            request_timeout_seconds=_int_env("REQUEST_TIMEOUT_SECONDS", 30),
            api_base_url=os.getenv("CF_API_BASE_URL", "https://api.cloudflare.com/client/v4"),
        )
        cfg.validate()
        return cfg
