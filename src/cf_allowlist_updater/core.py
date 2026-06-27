from __future__ import annotations

import ipaddress
import json
import random
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .config import Config


class CloudflareAPIError(RuntimeError):
    pass


DEFAULT_PUBLIC_IP_URLS = [
    "https://api64.ipify.org",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
]


class CloudflareClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.base_url = cfg.api_base_url.rstrip("/")

    def _request(self, method: str, path_or_url: str, payload: Any | None = None) -> Any:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            url = path_or_url
        else:
            url = f"{self.base_url}/{path_or_url.lstrip('/')}"

        body = None
        headers = {
            "Authorization": f"Bearer {self.cfg.api_token}",
            "Accept": "application/json",
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.request_timeout_seconds) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise CloudflareAPIError(f"Cloudflare API HTTP {exc.code}: {raw}") from exc
        except urllib.error.URLError as exc:
            raise CloudflareAPIError(f"Cloudflare API connection error: {exc}") from exc

        if not raw:
            return None
        data = json.loads(raw)
        if isinstance(data, dict) and data.get("success") is False:
            raise CloudflareAPIError(f"Cloudflare API error: {data.get('errors') or data}")
        return data

    def get_public_ip(self, endpoint: str, fallback_urls: list[str] | None = None) -> str:
        """Fetch public IP with retry + fallback endpoints.

        Tries *endpoint* with up to cfg.ip_lookup_retries exponential-backoff
        attempts.  If all fail, tries each URL in *fallback_urls* (or
        DEFAULT_PUBLIC_IP_URLS minus *endpoint*) once.  Raises
        CloudflareAPIError only when every attempt on every URL has failed.
        """
        primary = endpoint.rstrip("/")
        fallbacks = fallback_urls or [
            u for u in DEFAULT_PUBLIC_IP_URLS if u.rstrip("/") != primary
        ]
        candidates: list[tuple[str, int]] = [(primary, self.cfg.ip_lookup_retries)]
        candidates.extend((fb, 1) for fb in fallbacks)

        errors: list[str] = []
        for url, max_attempts in candidates:
            for attempt in range(1, max_attempts + 1):
                try:
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "cf-allowlist-updater/0.2"}
                    )
                    with urllib.request.urlopen(
                        req, timeout=self.cfg.request_timeout_seconds
                    ) as resp:
                        ip = resp.read().decode("utf-8").strip()
                        if ip:
                            return ip
                        errors.append(f"{url}: empty response")
                except urllib.error.URLError as exc:
                    msg = f"{url}: {exc}"
                    errors.append(msg)
                    if attempt < max_attempts:
                        delay = min(2**attempt + random.uniform(0, 1), 15)
                        print(
                            f"  retry {attempt}/{max_attempts} after {delay:.1f}s — {exc}",
                            flush=True,
                        )
                        time.sleep(delay)

        raise CloudflareAPIError(
            f"Public IP lookup failed after {len(candidates)} endpoint(s): "
            f"{'; '.join(errors)}"
        )

    def resolve_dns_to_ips(self, name: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise CloudflareAPIError(f"Failed to resolve DNS {name!r}: {exc}") from exc
        ips: list[str] = []
        for info in infos:
            ip = str(info[4][0])
            if ip not in ips:
                ips.append(ip)
        return ips

    def get_access_policy(self, policy_id: str) -> dict[str, Any]:
        account = urllib.parse.quote(self.cfg.account_id, safe="")
        policy = urllib.parse.quote(policy_id, safe="")
        data = self._request("GET", f"/accounts/{account}/access/policies/{policy}")
        return data.get("result", data)

    def update_access_policy(self, policy_id: str, policy: dict[str, Any]) -> dict[str, Any]:
        account = urllib.parse.quote(self.cfg.account_id, safe="")
        policy_part = urllib.parse.quote(policy_id, safe="")
        data = self._request("PUT", f"/accounts/{account}/access/policies/{policy_part}", policy)
        return data.get("result", data)

    def resolve_list_id(self, list_id: str | None, list_name: str | None) -> str:
        if list_id:
            return list_id
        encoded = urllib.parse.quote(self.cfg.account_id, safe="")
        data = self._request("GET", f"/accounts/{encoded}/rules/lists")
        matches = [item for item in data.get("result", []) if item.get("name") == list_name]
        if not matches:
            raise CloudflareAPIError(f"No Cloudflare account rules list named {list_name!r} found")
        if len(matches) > 1:
            raise CloudflareAPIError(f"Multiple Cloudflare lists named {list_name!r}; use CF_LIST_ID")
        if matches[0].get("kind") != "ip":
            raise CloudflareAPIError(f"Cloudflare list {list_name!r} is not kind='ip'")
        return str(matches[0]["id"])

    def get_list_items(self, list_id: str) -> list[dict[str, Any]]:
        account = urllib.parse.quote(self.cfg.account_id, safe="")
        list_part = urllib.parse.quote(list_id, safe="")
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            path = f"/accounts/{account}/rules/lists/{list_part}/items?per_page=500"
            if cursor:
                path += "&cursor=" + urllib.parse.quote(cursor, safe="")
            data = self._request("GET", path)
            items.extend(data.get("result", []))
            result_info = data.get("result_info") or {}
            cursor = result_info.get("cursors", {}).get("after")
            if not cursor:
                return items

    def update_all_list_items(self, list_id: str, items: list[dict[str, str]]) -> str | None:
        account = urllib.parse.quote(self.cfg.account_id, safe="")
        list_part = urllib.parse.quote(list_id, safe="")
        data = self._request("PUT", f"/accounts/{account}/rules/lists/{list_part}/items", items)
        result = data.get("result") if isinstance(data, dict) else None
        if isinstance(result, dict):
            return result.get("operation_id") or result.get("id")
        return None

    def get_bulk_operation(self, operation_id: str) -> dict[str, Any]:
        account = urllib.parse.quote(self.cfg.account_id, safe="")
        operation = urllib.parse.quote(operation_id, safe="")
        data = self._request("GET", f"/accounts/{account}/rules/lists/bulk_operations/{operation}")
        return data.get("result", data)


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        value = value.strip()
        if value and value not in result:
            result.append(value)
    return result


def normalize_ip_for_list(ip: str) -> str:
    ip = ip.strip()
    if "/" in ip:
        return ip
    if ":" in ip:
        return f"{ip}/128"
    return f"{ip}/32"


def normalize_ip_for_policy(ip: str) -> str:
    ip = ip.strip()
    if not ip:
        raise ValueError("empty IP/range")
    try:
        if "/" in ip:
            return str(ipaddress.ip_network(ip, strict=False))
        return str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise ValueError(f"Invalid IP/range {ip!r}") from exc


def build_policy_include(
    existing_include: list[dict[str, Any]], *, ip_ranges: list[str], replace_all: bool
) -> list[dict[str, Any]]:
    new_ip_rules = [{"ip": {"ip": normalize_ip_for_policy(ip)}} for ip in _dedupe(ip_ranges)]
    if replace_all:
        return new_ip_rules
    preserved = [rule for rule in existing_include if "ip" not in rule]
    return preserved + new_ip_rules


def collect_policy_ip_ranges(cfg: Config, client: CloudflareClient) -> list[str]:
    ranges: list[str] = []
    if cfg.ip_lookup_enabled:
        ranges.append(normalize_ip_for_policy(client.get_public_ip(cfg.public_ip_url)))
    ranges.extend(normalize_ip_for_policy(ip) for ip in cfg.extra_ip_ranges)
    for dns_name in cfg.dns_names:
        ranges.extend(normalize_ip_for_policy(ip) for ip in client.resolve_dns_to_ips(dns_name))
    return _dedupe(ranges)


def compute_replacement_items(
    existing: list[dict[str, Any]],
    *,
    current_ip: str,
    comment: str,
    managed_comment_prefix: str,
    replace_all: bool,
) -> list[dict[str, str]]:
    replacement: list[dict[str, str]] = []
    if not replace_all:
        for item in existing:
            existing_comment = str(item.get("comment") or "")
            if existing_comment.startswith(managed_comment_prefix):
                continue
            ip = item.get("ip")
            if ip:
                replacement.append({"ip": str(ip), "comment": existing_comment})

    replacement.append({"ip": current_ip, "comment": comment})
    return replacement


def wait_for_operation(cfg: Config, client: CloudflareClient, operation_id: str) -> dict[str, Any]:
    last: dict[str, Any] = {}
    for _ in range(cfg.operation_poll_attempts):
        last = client.get_bulk_operation(operation_id)
        status = str(last.get("status") or "").lower()
        if status in {"completed", "failed"}:
            return last
        time.sleep(cfg.operation_poll_seconds)
    return last


def run_policy_once(cfg: Config, client: CloudflareClient) -> dict[str, Any]:
    if not cfg.policy_id:
        raise ValueError("policy mode requires CF_POLICY_ID/CLOUDFLARE_POLICY_ID")
    ip_ranges = collect_policy_ip_ranges(cfg, client)
    policy = client.get_access_policy(cfg.policy_id)
    existing_include = policy.get("include") or []
    if not isinstance(existing_include, list):
        raise CloudflareAPIError("Cloudflare policy include field is not a list")
    updated_policy = dict(policy)
    updated_policy["include"] = build_policy_include(
        existing_include,
        ip_ranges=ip_ranges,
        replace_all=cfg.policy_replace_all,
    )

    result: dict[str, Any] = {
        "mode": "policy",
        "policy_id": cfg.policy_id,
        "ip_ranges": ip_ranges,
        "include_count": len(updated_policy["include"]),
        "dry_run": cfg.dry_run,
    }
    if cfg.dry_run:
        result["policy"] = updated_policy
        return result
    result["policy_result"] = client.update_access_policy(cfg.policy_id, updated_policy)
    return result


def run_list_once(cfg: Config, client: CloudflareClient) -> dict[str, Any]:
    raw_ip = client.get_public_ip(cfg.public_ip_url)
    current_ip = normalize_ip_for_list(raw_ip)
    list_id = client.resolve_list_id(cfg.list_id, cfg.list_name)
    existing = client.get_list_items(list_id)
    replacement = compute_replacement_items(
        existing,
        current_ip=current_ip,
        comment=cfg.comment,
        managed_comment_prefix=cfg.managed_comment_prefix,
        replace_all=cfg.replace_all,
    )

    result: dict[str, Any] = {
        "mode": "list",
        "ip": current_ip,
        "list_id": list_id,
        "existing_count": len(existing),
        "replacement_count": len(replacement),
        "dry_run": cfg.dry_run,
    }
    if cfg.dry_run:
        result["items"] = replacement
        return result

    operation_id = client.update_all_list_items(list_id, replacement)
    result["operation_id"] = operation_id
    if operation_id and cfg.wait_for_completion:
        result["operation"] = wait_for_operation(cfg, client, operation_id)
    return result


def run_once(cfg: Config, client: CloudflareClient | None = None) -> dict[str, Any]:
    cfg.validate()
    client = client or CloudflareClient(cfg)
    if cfg.policy_id:
        return run_policy_once(cfg, client)
    return run_list_once(cfg, client)
