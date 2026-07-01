# OpenClaw Gmail Proxy

[![CI](https://github.com/vrwarp/openclaw-gmail-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/vrwarp/openclaw-gmail-proxy/actions/workflows/ci.yml)
[![Docker](https://github.com/vrwarp/openclaw-gmail-proxy/actions/workflows/docker.yml/badge.svg)](https://github.com/vrwarp/openclaw-gmail-proxy/actions/workflows/docker.yml)
[![Docker Hub](https://img.shields.io/docker/pulls/vrwarp/openclaw-gmail-proxy?label=docker%20hub)](https://hub.docker.com/r/vrwarp/openclaw-gmail-proxy)

A **category-scoped Gmail proxy** for [OpenClaw](https://openclaw.ai/). Give an
autonomous OpenClaw agent access to **only** the parts of your mailbox you
choose — specific Gmail categories (Promotions, Social, Updates, Forums,
Primary), specific labels, or both, with a blocklist that overrides everything —
and nothing else. The proxy holds your real Gmail OAuth token; the agent only
ever sees a narrow, audited tool surface over MCP.

> **Why a proxy?** Gmail's OAuth scopes are **account-wide** — there is *no*
> scope that limits access to a category or label. So the only place scoping can
> be enforced is a trusted layer between the agent and Gmail. That is this proxy.
> See [`DESIGN.md`](DESIGN.md) for the full rationale and threat model.

![Admin dashboard](docs/screenshots/dashboard.png)

## How it fits together

```
┌── VM (untrusted) ─────────┐        ┌── Docker host (trusted) ──────────────┐
│ OpenClaw agent            │  MCP    │ gmail-proxy container                 │
│  + "gmail-categories"     │ stream- │  • holds Gmail OAuth token (encrypted)│
│    skill                  │ http +  │  • POLICY ENGINE (scope sandbox)      │──► Gmail API
│  • sees only proxy tools  │ bearer  │  • audit log + kill switch            │
│                           │  auth   │  • admin web UI (localhost only)      │
└───────────────────────────┘         └───────────────────────────────────────┘
```

- **Two pieces:** (1) the proxy server (this repo, runs in Docker outside the
  VM), and (2) the OpenClaw side — an MCP-server registration plus a `SKILL.md`
  (see [`openclaw-plugin/`](openclaw-plugin/)).
- **Enforcement lives in the proxy**, because OpenClaw is untrusted: it reads
  attacker-controlled email and can be prompt-injected. The agent-side
  `tools.allow` is only defense-in-depth.

## What the agent can and cannot do

**Can:** list/search/read messages in scope, mark read/unread, star, archive
(remove from inbox), apply user labels, trash (if you enable it), get unread
counts.

**Cannot (by construction):** read anything out of scope, send/reply/forward,
create drafts, permanently delete, add/remove `CATEGORY_*`/`SPAM`/`TRASH` labels,
change settings, or ever touch the OAuth token.

The MCP tools: `gmail_list_messages`, `gmail_get_message`, `gmail_get_thread`,
`gmail_modify_labels`, `gmail_archive_message`, `gmail_trash_message`,
`gmail_list_labels`, `gmail_counts`, `gmail_get_profile`.

## Scoping

Scope is defined in `policy.yaml` (and editable live in the admin UI):

```yaml
allowed_categories: [promotions, social]   # any of primary/social/promotions/updates/forums
allowed_labels: [Newsletters]              # user labels that also grant access
blocked_labels: [Private]                  # deny — supersedes both allowlists
```

A message is in scope if it matches an allowed category **or** an allowed label —
**unless** it carries a blocked label (which always wins). Labels used for
scoping are made immutable to the agent so it can't relabel messages into or out
of scope.

## Quick start — local demo (no Google account needed)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
ADMIN_TOKEN=demo GMAIL_BACKEND=mock gmail-proxy
```

- Admin UI: <http://127.0.0.1:8081/> (log in with `demo`)
- MCP endpoint: `http://127.0.0.1:8443/mcp`

Issue an agent token on the **Credentials** page, then point an MCP client at
the endpoint with `Authorization: Bearer <token>`.

## Production (real Gmail)

The **entire Gmail bootstrap happens in the admin UI** — no CLI, no
`client_secret.json` on disk, and no pre-baked token.

1. **Google Cloud:** create a project, enable the **Gmail API**, and create an
   OAuth **Web application** client. Register one redirect URI —
   `http://localhost:8081/setup/gmail/callback` (the Setup page shows the exact
   value to paste back).
2. **Configure & run:** `cp .env.example .env` (optionally set `ADMIN_TOKEN` to
   pin your own admin login), then `docker compose up -d`. If you leave
   `ADMIN_TOKEN` blank, a random one is generated on first start and printed to
   the logs — grab it with `docker compose logs gmail-proxy`.
3. **Open the admin UI:** tunnel in with `ssh -L 8081:127.0.0.1:8081 host`, then
   browse to <http://127.0.0.1:8081/> and open the **Setup** page.
4. **Connect Gmail** on the Setup page:
   - paste the OAuth client **id + secret** and save it;
   - click **Connect Gmail** and approve access in Google. The proxy stores an
     **encrypted refresh token** in its data volume. It requests the
     `gmail.modify` scope (read + labels/archive, **no permanent delete**).
5. **Set scope** on the **Configuration** page. (Enabling **Primary** grants
   near full-mailbox read/modify — the UI flags this.)
6. **Register with OpenClaw:** issue a credential on the **Credentials** page,
   merge
   [`openclaw-plugin/mcp-registration.json`](openclaw-plugin/mcp-registration.json)
   into `~/.openclaw/openclaw.json`, install
   [`openclaw-plugin/SKILL.md`](openclaw-plugin/SKILL.md), and set the agent's
   `GMAIL_PROXY_TOKEN` to that credential. The Setup page prints the exact
   registration snippet to copy.

> **Network:** keep the MCP port (`8443`) reachable only from the VM (host
> firewall / private docker network); keep the admin UI (`8081`) on `127.0.0.1`
> and reach it via an SSH tunnel. mTLS is recommended over bearer tokens in
> production.
>
> **Advanced:** a CLI alternative,
> [`scripts/oauth_bootstrap.py`](scripts/oauth_bootstrap.py), can mint the token
> out-of-band (write it to the mapped data volume as `token.json`). The web-UI
> flow above is the supported path.

## Persistence

All mutable state lives in **one Docker volume plus the policy file** — map
these two and the container is fully stateful across restarts and image
upgrades. `docker-compose.yml` already declares both:

| Host mapping           | Container path      | Holds                                                                                             |
| ---------------------- | ------------------- | ------------------------------------------------------------------------------------------------- |
| `proxy-data` volume    | `/data`             | encrypted Gmail token, OAuth client config, agent credentials, encryption/HMAC keys, audit log, kill-switch |
| `./policy.yaml` (bind) | `/app/policy.yaml`  | the scope policy — **writable**, because the admin UI edits it live                                |

Inside `/data`:

- `token.json` — the Gmail refresh token, **encrypted at rest**
- `gmail_oauth.json` — the Google OAuth client id/secret (entered on Setup)
- `credentials.json` — issued agent bearer tokens (stored hashed)
- `keys/` — auto-generated Fernet (token), HMAC (audit), and sender-hash keys,
  plus `admin_token` when `ADMIN_TOKEN` was left unset
- `audit.log` — tamper-evident, hash-chained allow/deny log
- `FROZEN` — present only while the kill-switch is engaged

Back up the `proxy-data` volume to preserve the Gmail connection and audit
trail. If you set `TOKEN_ENCRYPTION_KEY` out-of-band the token is encrypted with
that; otherwise a key is generated once and kept in `keys/token_fernet.key` —
losing it just means reconnecting on the Setup page.

### NAS / Synology — locked-down bind mount

To keep the data off a Docker named volume and inside a shared folder that only
a dedicated user can read, bind-mount that folder and tell the container which
host user to run as. The image honours **`PUID`/`PGID`** (the LinuxServer.io
convention): on startup it remaps its runtime user to those ids, chowns `/data`,
then drops privileges before running the app.

1. In DSM create a non-admin `docker_user` (+ `docker_group`) and grant it
   **Read/Write** on the shared folder you'll mount; set **Everyone → No
   access**. Find its ids with `id docker_user` (or a Task Scheduler `id` job).
2. Set `PUID`/`PGID` to those numbers and bind-mount the folder to **`/data`**
   (the container's data dir — not `/app/data`):

   ```yaml
   environment:
     PUID: "1026"   # uid from `id docker_user`
     PGID: "100"    # gid from `id docker_user`
   volumes:
     - /volume1/docker/openclaw-gmail-proxy/data:/data
     - /volume1/docker/openclaw-gmail-proxy/policy.yaml:/app/policy.yaml
   ```

   In Container Manager's GUI, add `PUID`/`PGID` on the **Environment** tab and
   the folder on the **Volume** tab with mount path `/data`.

Because the container runs as `docker_user`, it can read/write the folder while
every other NAS user is blocked. (Prefer Docker's native `user:` directive
instead? Set it and the entrypoint skips the remap — but then you must make the
mounted folder writable by that uid yourself; `PUID`/`PGID` do the chown for
you.)

## Admin web UI (config + debugging)

Dashboard · Configuration · Audit log (allow/deny + reason, tamper-evident) ·
Policy explain (why a given message is/ isn't in scope) · Tool tester ·
Credentials (issue/rotate/revoke) · Cache stats · Kill-switch. Screenshots in
[`docs/screenshots/`](docs/screenshots/).

- **Authentication:** a signed session gated on `ADMIN_TOKEN`, or optional
  **"Sign in with Google"** (OIDC) restricted to the proxied account, with the
  token kept as a break-glass fallback. The UI stays localhost-only regardless.
- **Caching:** an immutable message-body cache plus short, configurable TTLs for
  labels/lists cut real Gmail API calls; responses are tainted `cached` when
  served from cache and read tools accept `fresh=true` to force a live fetch.

## Container images

Prebuilt images are published to **GHCR** and **[Docker Hub](https://hub.docker.com/r/vrwarp/openclaw-gmail-proxy)**:

```bash
docker pull ghcr.io/vrwarp/openclaw-gmail-proxy:latest   # GitHub Container Registry
docker pull vrwarp/openclaw-gmail-proxy:latest           # Docker Hub
```

To deploy the published image, set
`image: vrwarp/openclaw-gmail-proxy:latest` (or the `ghcr.io/...` equivalent) in
`docker-compose.yml` and remove the `build:` line. Tags: `latest`, semver
(`v1.2.3`), branch, and `sha`.

## Development

```bash
pip install -e '.[dev]'
pytest        # policy engine, query/mutation guards, tools vs a mock Gmail,
              # auth, audit, caching, live MCP, and admin UI
```

The Playwright admin e2e test skips automatically when no Chromium is available.
CI runs ruff + pytest on Python 3.11 and 3.12. Notes on releasing images and
CI/CD supply-chain hardening are in [`docs/ci-security.md`](docs/ci-security.md).

## Repository layout

```
src/gmail_proxy/        proxy server
  policy/               is_eligible(), query sanitizer, mutation guards  (the crux)
  gmail/                backend interface + mock + real googleapis client + token store
  tools.py              the category-scoped tools + dispatch (freeze/rate-limit/audit)
  mcp_server.py         MCP Streamable-HTTP endpoint + per-agent bearer auth
  admin/                FastAPI admin UI
  cache.py              caching backend
openclaw-plugin/        SKILL.md + example MCP registration
scripts/oauth_bootstrap.py   optional CLI alternative to the web-UI connect
tests/                  pytest suite (+ Playwright e2e)
DESIGN.md               full design & threat model
```
