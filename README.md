# Cloudflare Access Policy IP Updater

Small Dockerized updater that keeps a Cloudflare Zero Trust **Access Policy** current with the public IP of the machine/network where the container runs.

This is intended for the pattern: create one reusable Access policy such as `Home IP Bypass`, let this container update that policy's IP include rules, then apply that policy to whichever Cloudflare Access apps/tunnels you want.

## What it does

Preferred v0.2+ policy mode:

1. Reads the current public IP from `PUBLIC_IP_URL`, default `https://api64.ipify.org`.
2. Optionally adds extra static IPs/CIDRs from `IP_RANGE`.
3. Optionally resolves DNS names from `IP_FROM_DNS` and adds their resolved IPs.
4. Fetches the Cloudflare Access policy identified by `CF_POLICY_ID` / `CLOUDFLARE_POLICY_ID`.
5. Replaces the policy's IP include rules with the current IP set.
6. Preserves non-IP include rules by default. Set `POLICY_REPLACE_ALL=true` if this policy should contain only the generated IP rules.
7. Updates the Access policy through Cloudflare's `/accounts/{account_id}/access/policies/{policy_id}` API.

Legacy v0.1 list mode is still available if you provide `CF_LIST_ID` or `CF_LIST_NAME` and no policy ID, but policy mode is now the intended mode.

## Why this instead of Tiippex's container?

This repo now implements the same core idea as `Tiippex/cloudflare-access-policy-ip-updater`: update a Cloudflare Access policy directly from the current public IP.

Things borrowed from that design:

- direct Access Policy update mode
- static `IP_RANGE` support
- DNS resolution support via `IP_FROM_DNS`
- `UPDATE_INTERVAL_MINUTES` compatibility
- `CLOUDFLARE_*` env var compatibility

Differences/improvements here:

- test coverage for policy/list behavior
- no third-party Python runtime dependency; uses stdlib only
- safe `DISABLED=true` mode for placeholder Unraid setup
- `DRY_RUN=true` support
- preserves non-IP include rules by default instead of overwriting the entire `include` array
- still supports the prior Cloudflare Rules List updater mode

## Cloudflare token permissions

For policy mode, create a Cloudflare API token with:

- **Account** > **Access: Apps and Policies** > **Edit**

Scope it to the target account when possible.

## Environment variables — policy mode

| Variable | Required | Example | Notes |
| --- | --- | --- | --- |
| `CF_API_TOKEN` / `CLOUDFLARE_API_KEY` | yes | `...` | Cloudflare API token. |
| `CF_ACCOUNT_ID` / `CLOUDFLARE_ACCOUNT_ID` | yes | `012345...` | Cloudflare account ID. |
| `CF_POLICY_ID` / `CLOUDFLARE_POLICY_ID` | yes | `abcd...` | Access Policy ID to update. |
| `IP_RANGE` | no | `203.0.113.0/24,198.51.100.10` | Extra static IPs/CIDRs. |
| `IP_FROM_DNS` | no | `home.example.com` | DNS names to resolve and include. |
| `IP_LOOKUP_ENABLED` | no, default `true` | `true` | Add the container's current public IP. |
| `PUBLIC_IP_URL` | no | `https://api64.ipify.org` | Primary plain-text IP endpoint. |
| `PUBLIC_IP_URLS` | no | `https://api64.ipify.org,https://api.ipify.org,https://checkip.amazonaws.com` | Comma-separated public IP endpoints tried in order; built-in fallbacks are appended and duplicates removed. Overrides `PUBLIC_IP_URL`. |
| `UPDATE_INTERVAL_MINUTES` | no | `15` | Tiippex-compatible interval. If unset, `CHECK_INTERVAL_SECONDS` is used. |
| `CHECK_INTERVAL_SECONDS` | no, default `300` | `300` | Poll interval; minimum 30 seconds. |
| `POLICY_REPLACE_ALL` | no, default `false` | `false` | If true, replace entire `include` with generated IP rules. |
| `DRY_RUN` | no, default `false` | `true` | Compute but do not update Cloudflare. |
| `DISABLED` | no, default `false` | `true` | Keep the container alive without calling Cloudflare. |
| `ONCE` | no, default `false` | `true` | Run once and exit. |

## Docker

```bash
docker run --rm \
  -e CF_API_TOKEN='***' \
  -e CF_ACCOUNT_ID='...' \
  -e CF_POLICY_ID='...' \
  -e IP_RANGE='203.0.113.0/24' \
  -e UPDATE_INTERVAL_MINUTES='15' \
  ghcr.io/jmengit/cloudflare-ip-allowlist-updater:latest
```

For a first run, use:

```bash
-e DRY_RUN=true -e ONCE=true -e DISABLED=false
```

Then set:

```bash
-e DRY_RUN=false -e ONCE=false -e DISABLED=false
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
      CF_POLICY_ID: ${CF_POLICY_ID}
      IP_LOOKUP_ENABLED: "true"
      IP_RANGE: ${IP_RANGE:-}
      IP_FROM_DNS: ${IP_FROM_DNS:-}
      UPDATE_INTERVAL_MINUTES: "15"
      POLICY_REPLACE_ALL: "false"
      DISABLED: "false"
```

## Unraid native Docker setup

Use the Unraid Docker UI with:

- Repository: `ghcr.io/jmengit/cloudflare-ip-allowlist-updater:latest`
- Network Type: `bridge`
- Restart policy: `unless-stopped`
- No ports or volumes are required.
- Add the policy-mode environment variables above.

For placeholder creation before credentials exist, set `DISABLED=true`. When ready, fill in `CF_API_TOKEN`, `CF_ACCOUNT_ID`, and `CF_POLICY_ID`, then set `DISABLED=false`.

## Legacy Rules List mode

If you omit `CF_POLICY_ID` and provide `CF_LIST_ID` or `CF_LIST_NAME`, the container updates an account Rules List of kind `ip` as in v0.1. This mode preserves unmanaged list entries by default and replaces entries whose comment starts with `MANAGED_COMMENT_PREFIX`.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest -q
```

## Safety notes

- This tool never logs the API token.
- In policy mode, non-IP include rules are preserved by default.
- Use a dedicated Access policy for this automation if possible.
