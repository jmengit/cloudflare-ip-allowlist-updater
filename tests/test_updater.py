import pytest

from cf_allowlist_updater.config import Config
from cf_allowlist_updater.core import (
    build_policy_include,
    compute_replacement_items,
    normalize_ip_for_list,
    normalize_ip_for_policy,
    public_ip_lookup_urls,
    run_once,
)


def test_normalize_ipv4_adds_32_cidr():
    assert normalize_ip_for_list("203.0.113.7") == "203.0.113.7/32"


def test_normalize_ipv6_adds_128_cidr():
    assert normalize_ip_for_list("2001:db8::1") == "2001:db8::1/128"


def test_normalize_ip_for_policy_keeps_plain_ip_like_tiippex():
    assert normalize_ip_for_policy("203.0.113.7") == "203.0.113.7"
    assert normalize_ip_for_policy("203.0.113.0/24") == "203.0.113.0/24"


def test_public_ip_lookup_urls_supports_env_order_and_builtin_fallbacks():
    cfg = Config(
        api_token="token",
        account_id="acct",
        list_name="home_allowlist",
        public_ip_url="https://legacy.example/ip",
        public_ip_urls=["https://primary.example/ip", "https://checkip.amazonaws.com/"],
    )

    assert public_ip_lookup_urls(cfg)[:4] == [
        "https://primary.example/ip",
        "https://checkip.amazonaws.com",
        "https://api64.ipify.org",
        "https://api.ipify.org",
    ]


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


def test_build_policy_include_preserves_non_ip_rules_and_replaces_ip_rules():
    existing_include = [
        {"email": {"email": "me@example.com"}},
        {"ip": {"ip": "198.51.100.20"}},
        {"everyone": {}},
    ]

    result = build_policy_include(
        existing_include,
        ip_ranges=["203.0.113.7", "203.0.113.0/24"],
        replace_all=False,
    )

    assert result == [
        {"email": {"email": "me@example.com"}},
        {"everyone": {}},
        {"ip": {"ip": "203.0.113.7"}},
        {"ip": {"ip": "203.0.113.0/24"}},
    ]


def test_build_policy_include_replace_all_matches_direct_policy_only_mode():
    existing_include = [{"email": {"email": "me@example.com"}}]

    result = build_policy_include(existing_include, ip_ranges=["203.0.113.7"], replace_all=True)

    assert result == [{"ip": {"ip": "203.0.113.7"}}]


class FakeCloudflare:
    def __init__(self):
        self.updated = None

    def get_public_ip(self, endpoint, fallback_urls=None):
        assert endpoint == "https://example.test/ip"
        assert fallback_urls is not None
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

    assert result["mode"] == "list"
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


class FakePolicyCloudflare:
    def __init__(self):
        self.updated_policy = None

    def get_public_ip(self, endpoint, fallback_urls=None):
        assert endpoint == "https://example.test/ip"
        assert fallback_urls is not None
        return "203.0.113.7"

    def resolve_dns_to_ips(self, name):
        assert name == "vpn.example.test"
        return ["198.51.100.9"]

    def get_access_policy(self, policy_id):
        assert policy_id == "policy-123"
        return {
            "id": "policy-123",
            "name": "Home IP bypass",
            "decision": "bypass",
            "include": [
                {"email": {"email": "me@example.com"}},
                {"ip": {"ip": "198.51.100.20"}},
            ],
        }

    def update_access_policy(self, policy_id, policy):
        assert policy_id == "policy-123"
        self.updated_policy = policy
        return {"id": "policy-123"}


def test_run_once_updates_access_policy_like_tiippex_but_preserves_non_ip_rules():
    client = FakePolicyCloudflare()
    cfg = Config(
        api_token="token",
        account_id="acct",
        policy_id="policy-123",
        public_ip_url="https://example.test/ip",
        extra_ip_ranges=["203.0.113.0/24"],
        dns_names=["vpn.example.test"],
    )

    result = run_once(cfg, client=client)

    assert result["mode"] == "policy"
    assert result["ip_ranges"] == ["203.0.113.7", "203.0.113.0/24", "198.51.100.9"]
    assert client.updated_policy["include"] == [
        {"email": {"email": "me@example.com"}},
        {"ip": {"ip": "203.0.113.7"}},
        {"ip": {"ip": "203.0.113.0/24"}},
        {"ip": {"ip": "198.51.100.9"}},
    ]


def test_disabled_config_allows_missing_cloudflare_credentials():
    cfg = Config(api_token="", account_id="", disabled=True)

    cfg.validate()
