# Cloudflare IP Allowlist Updater

Small Dockerized updater that detects the container's current public IP and writes it into a Cloudflare account **Rules List** of kind `ip`.

This is useful for Cloudflare Access / WAF policies that trust a named IP list, while your home WAN IP changes over time.

## What it does

1. Reads the current public IP from `PUBLIC_IP_URL`.
2. Resolves a Cloudflare account IP list by `CF_LIST_ID` or `CF_LIST_NAME`.
3. Fetches existing list items.
4. Removes only previously managed entries whose comment starts with `MANAGED_COMMENT_PREFIX`.
5. Adds the current IP as `/32` for IPv4 or `/128` for IPv6.
6. Updates the list through Cloudflare's `PUT /accounts/{account_id}/rules/lists/{list_id}/items` API.

By default, unmanaged entries are preserved. Set `REPLACE_ALL=true` only if this container should own the entire list.

## Cloudflare token permissions

Create a Cloudflare API token with permission to manage account rules lists. In Cloudflare's API token UI this is typically an account-level token with Rules Lists read/edit permission for the target account. Keep the token secret.

Required env vars:

| Variable | Required | Example | Notes |
| --- | --- | --- | --- |
| `CF_API_TOKEN` | yes | `...` | Cloudflare API token. |
| `CF_ACCOUNT_ID` | yes | `012345...` | Cloudflare account ID. |
| `CF_LIST_ID` | one of list id/name | `abcd...` | Prefer ID if known. |
| `CF_LIST_NAME` / `CF_ALLOWLIST_NAME` | one of list id/name | `home_allowlist` | Must refer to a Cloudflare account Rules List of kind `ip`. |

Optional env vars:

| Variable | Default | Notes |
| --- | --- | --- |
| `PUBLIC_IP_URL` | `https://api64.ipify.org` | Endpoint returning a plain IP string. |
| `CF_LIST_ITEM_COMMENT` | `managed-by=cf-ip-allowlist-updater` | Comment attached to the managed item. |
| `MANAGED_COMMENT_PREFIX` | `managed-by=cf-ip-allowlist-updater` | Existing list entries with this prefix are replaced. |
| `CHECK_INTERVAL_SECONDS` | `300` | Poll interval; minimum 30 seconds. |
| `ONCE` | `false` | Run once and exit. |
| `DRY_RUN` | `false` | Fetch and compute but do not update Cloudflare. |
| `DISABLED` | `false` | Keep the container alive without calling Cloudflare; useful for Unraid placeholder setup. |
| `REPLACE_ALL` | `false` | If true, replace the entire list with the detected IP. Dangerous if humans also manage the list. |
| `WAIT_FOR_COMPLETION` | `true` | Poll Cloudflare bulk operation status. |

## Docker

```bash
docker run --rm \
  -e CF_API_TOKEN='...' \
  -e CF_ACCOUNT_ID='...' \
  -e CF_LIST_NAME='home_allowlist' \
  -e CF_LIST_ITEM_COMMENT='managed-by=cf-ip-allowlist-updater home' \
  ghcr.io/jmengit/cloudflare-ip-allowlist-updater:latest
```

For a first run, use:

```bash
-e DRY_RUN=true -e ONCE=true
```

## Docker Compose

```yaml
services:
  cloudflare-ip-allowlist-updater:
    image: ghcr.io/jmengit/cloudflare-ip-allowlist-updater:latest
    container_name: cloudflare-ip-allowlist-updater
    restart: unless-stopped
    environment:
      CF_API_TOKEN: ${CF_API_TOKEN}
      CF_ACCOUNT_ID: ${CF_ACCOUNT_ID}
      CF_LIST_NAME: home_allowlist
      CF_LIST_ITEM_COMMENT: managed-by=cf-ip-allowlist-updater home
      CHECK_INTERVAL_SECONDS: "300"
      REPLACE_ALL: "false"
```

## Unraid native Docker setup

Use the Unraid Docker UI with:

- Repository: `ghcr.io/jmengit/cloudflare-ip-allowlist-updater:latest`
- Network Type: `bridge`
- Console shell command: `Shell`
- Restart policy: `unless-stopped`
- Add environment variables listed above.
- No ports or volumes are required.

Start with `DRY_RUN=true` and `ONCE=true` until the token/list settings are correct, then remove or set both to `false` for continuous updates.

For placeholder creation before you add Cloudflare credentials, set `DISABLED=true`. When ready, fill in `CF_API_TOKEN`, `CF_ACCOUNT_ID`, and `CF_LIST_NAME`/`CF_LIST_ID`, then set `DISABLED=false`.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest -q
```

## Safety notes

- This tool never logs the API token.
- It rewrites the Cloudflare list items endpoint, but by default it preserves any entries not marked with the managed comment prefix.
- Use a dedicated list for this automation if possible.
