from __future__ import annotations

import os
from dataclasses import dataclass, field

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


def _csv_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [part.strip() for part in value.split(",") if part.strip()]


def _public_ip_urls_from_env() -> list[str]:
    """Return ordered public IP lookup URLs from env.

    PUBLIC_IP_URLS is an optional comma-separated override for environments
    that want to control the fallback order.  PUBLIC_IP_URL remains the
    single-primary legacy setting.
    """
    urls = _csv_env("PUBLIC_IP_URLS")
    if urls:
        return urls
    single = os.getenv("PUBLIC_IP_URL", "").strip()
    if single:
        return [single]
    return []


@dataclass(frozen=True)
class Config:
    api_token: str
    account_id: str
    # Preferred mode: update a Cloudflare Zero Trust Access policy directly.
    policy_id: str | None = None
    extra_ip_ranges: list[str] = field(default_factory=list)
    dns_names: list[str] = field(default_factory=list)
    ip_lookup_enabled: bool = True
    policy_replace_all: bool = False
    # Legacy mode: update a Cloudflare account Rules List of kind='ip'.
    list_id: str | None = None
    list_name: str | None = None
    public_ip_url: str = "https://api64.ipify.org"
    public_ip_urls: list[str] = field(default_factory=list)
    ip_lookup_retries: int = 3
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
    failure_window_seconds: int = 86400

    def validate(self) -> None:
        if self.disabled:
            return
        missing = []
        if not self.api_token:
            missing.append("CF_API_TOKEN/CLOUDFLARE_API_KEY")
        if not self.account_id:
            missing.append("CF_ACCOUNT_ID/CLOUDFLARE_ACCOUNT_ID")
        if not self.policy_id and not self.list_id and not self.list_name:
            missing.append("CF_POLICY_ID/CLOUDFLARE_POLICY_ID or CF_LIST_ID/CF_LIST_NAME")
        if not self.ip_lookup_enabled and not self.extra_ip_ranges and not self.dns_names:
            missing.append("at least one IP source: IP lookup, IP_RANGE, or IP_FROM_DNS")
        if missing:
            raise ValueError("Missing required environment/config values: " + ", ".join(missing))
        if self.interval_seconds < 30:
            raise ValueError("CHECK_INTERVAL_SECONDS must be at least 30")

    @classmethod
    def from_env(cls) -> "Config":
        interval = os.getenv("CHECK_INTERVAL_SECONDS")
        update_minutes = os.getenv("UPDATE_INTERVAL_MINUTES")
        if (interval is None or interval.strip() == "") and update_minutes and update_minutes.strip():
            interval_seconds = int(update_minutes) * 60
        else:
            interval_seconds = _int_env("CHECK_INTERVAL_SECONDS", 300)

        cfg = cls(
            api_token=os.getenv("CF_API_TOKEN") or os.getenv("CLOUDFLARE_API_KEY", ""),
            account_id=os.getenv("CF_ACCOUNT_ID") or os.getenv("CLOUDFLARE_ACCOUNT_ID", ""),
            policy_id=os.getenv("CF_POLICY_ID") or os.getenv("CLOUDFLARE_POLICY_ID") or None,
            extra_ip_ranges=_csv_env("IP_RANGE") or _csv_env("EXTRA_IP_RANGES"),
            dns_names=_csv_env("IP_FROM_DNS") or _csv_env("DNS_NAMES"),
            ip_lookup_enabled=_bool_env("IP_LOOKUP_ENABLED", True),
            policy_replace_all=_bool_env("POLICY_REPLACE_ALL", False),
            list_id=os.getenv("CF_LIST_ID") or None,
            list_name=os.getenv("CF_LIST_NAME") or os.getenv("CF_ALLOWLIST_NAME") or None,
            public_ip_url=os.getenv("PUBLIC_IP_URL", "https://api64.ipify.org"),
            public_ip_urls=_public_ip_urls_from_env(),
            ip_lookup_retries=_int_env("IP_LOOKUP_RETRIES", 3),
            comment=os.getenv("CF_LIST_ITEM_COMMENT", "managed-by=cf-ip-allowlist-updater"),
            managed_comment_prefix=os.getenv(
                "MANAGED_COMMENT_PREFIX", "managed-by=cf-ip-allowlist-updater"
            ),
            replace_all=_bool_env("REPLACE_ALL", False),
            dry_run=_bool_env("DRY_RUN", False),
            disabled=_bool_env("DISABLED", False),
            once=_bool_env("ONCE", False),
            interval_seconds=interval_seconds,
            wait_for_completion=_bool_env("WAIT_FOR_COMPLETION", True),
            operation_poll_seconds=float(os.getenv("OPERATION_POLL_SECONDS", "2.0")),
            operation_poll_attempts=_int_env("OPERATION_POLL_ATTEMPTS", 15),
            request_timeout_seconds=_int_env("REQUEST_TIMEOUT_SECONDS", 30),
            api_base_url=os.getenv("CF_API_BASE_URL", "https://api.cloudflare.com/client/v4"),
            failure_window_seconds=_int_env("FAILURE_WINDOW_HOURS", 24) * 3600,
        )
        cfg.validate()
        return cfg
