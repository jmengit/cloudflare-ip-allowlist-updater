import pytest

from cf_allowlist_updater.config import Config
from cf_allowlist_updater.core import compute_replacement_items, normalize_ip_for_list, run_once


def test_normalize_ipv4_adds_32_cidr():
    assert normalize_ip_for_list("203.0.113.7") == "203.0.113.7/32"


def test_normalize_ipv6_adds_128_cidr():
    assert normalize_ip_for_list("2001:db8::1") == "2001:db8::1/128"


def test_compute_replacement_items_preserves_unmanaged_and_replaces_managed():
    existing = [
        {"id": "a", "ip": "198.51.100.10/32", "comment": "static office"},
        {"id": "b", "ip": "198.51.100.20/32", "comment": "managed-by=cf-ip-allowlist-updater old"},
    ]

    result = compute_replacement_items(
        existing,
        current_ip="203.0.113.7/32",
        comment="managed-by=cf-ip-allowlist-updater home",
        managed_comment_prefix="managed-by=cf-ip-allowlist-updater",
        replace_all=False,
    )

    assert result == [
        {"ip": "198.51.100.10/32", "comment": "static office"},
        {"ip": "203.0.113.7/32", "comment": "managed-by=cf-ip-allowlist-updater home"},
    ]


def test_compute_replacement_items_replace_all_drops_unmanaged():
    existing = [{"id": "a", "ip": "198.51.100.10/32", "comment": "static office"}]

    result = compute_replacement_items(
        existing,
        current_ip="203.0.113.7/32",
        comment="home",
        managed_comment_prefix="managed-by=cf-ip-allowlist-updater",
        replace_all=True,
    )

    assert result == [{"ip": "203.0.113.7/32", "comment": "home"}]


class FakeCloudflare:
    def __init__(self):
        self.updated = None

    def get_public_ip(self, endpoint):
        assert endpoint == "https://example.test/ip"
        return "203.0.113.7"

    def resolve_list_id(self, list_id, list_name):
        assert list_id is None
        assert list_name == "home_allowlist"
        return "list-123"

    def get_list_items(self, list_id):
        assert list_id == "list-123"
        return [{"id": "old", "ip": "198.51.100.20/32", "comment": "managed-by=cf-ip-allowlist-updater old"}]

    def update_all_list_items(self, list_id, items):
        assert list_id == "list-123"
        self.updated = items
        return "op-123"

    def get_bulk_operation(self, operation_id):
        assert operation_id == "op-123"
        return {"status": "completed"}


def test_run_once_updates_cloudflare_list_when_ip_changes():
    client = FakeCloudflare()
    cfg = Config(
        api_token="token",
        account_id="acct",
        list_name="home_allowlist",
        public_ip_url="https://example.test/ip",
        comment="managed-by=cf-ip-allowlist-updater home",
        wait_for_completion=True,
    )

    result = run_once(cfg, client=client)

    assert result["ip"] == "203.0.113.7/32"
    assert result["operation_id"] == "op-123"
    assert client.updated == [{"ip": "203.0.113.7/32", "comment": "managed-by=cf-ip-allowlist-updater home"}]


def test_run_once_dry_run_does_not_update():
    client = FakeCloudflare()
    cfg = Config(
        api_token="token",
        account_id="acct",
        list_name="home_allowlist",
        public_ip_url="https://example.test/ip",
        dry_run=True,
    )

    result = run_once(cfg, client=client)

    assert result["dry_run"] is True
    assert client.updated is None


def test_disabled_config_allows_missing_cloudflare_credentials():
    cfg = Config(api_token="", account_id="", disabled=True)

    cfg.validate()
