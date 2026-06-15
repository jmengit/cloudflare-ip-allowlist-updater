from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .config import Config


class CloudflareAPIError(RuntimeError):
    pass


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

    def get_public_ip(self, endpoint: str) -> str:
        req = urllib.request.Request(endpoint, headers={"User-Agent": "cf-allowlist-updater/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.request_timeout_seconds) as resp:
                return resp.read().decode("utf-8").strip()
        except urllib.error.URLError as exc:
            raise CloudflareAPIError(f"Public IP lookup failed: {exc}") from exc

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


def normalize_ip_for_list(ip: str) -> str:
    ip = ip.strip()
    if "/" in ip:
        return ip
    if ":" in ip:
        return f"{ip}/128"
    return f"{ip}/32"


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


def run_once(cfg: Config, client: CloudflareClient | None = None) -> dict[str, Any]:
    cfg.validate()
    client = client or CloudflareClient(cfg)
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
