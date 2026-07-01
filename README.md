# OpenClaw Gmail Proxy

[![CI](https://github.com/vrwarp/openclaw-gmail-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/vrwarp/openclaw-gmail-proxy/actions/workflows/ci.yml)
[![Docker](https://github.com/vrwarp/openclaw-gmail-proxy/actions/workflows/docker.yml/badge.svg)](https://github.com/vrwarp/openclaw-gmail-proxy/actions/workflows/docker.yml)

A **category-scoped Gmail proxy** for [OpenClaw](https://openclaw.ai/). It lets
you give an autonomous OpenClaw agent access to **only** the Gmail categories
you choose (Promotions, Social, Updates, Forums, and/or Primary) — and,
optionally, **any messages you tag with specific labels** (with an optional
**blocklist** that overrides everything) — and nothing else.
The proxy holds your real Gmail OAuth token; OpenClaw only ever sees a narrow,
audited, scoped tool surface over MCP.

> **Why a proxy?** Gmail's OAuth scopes are **account-wide** — there is *no*
> scope that limits access to a category or label. So the only place category
> scoping can be enforced is a trusted layer between the agent and Gmail. That
> is this proxy. See [`DESIGN.md`](DESIGN.md) for the full rationale and threat
> model.

![Admin dashboard](docs/screenshots/dashboard.png)

## How it fits together

```
┌── VM (untrusted) ─────────┐        ┌── Docker host (trusted) ──────────────┐
│ OpenClaw agent            │  MCP    │ gmail-proxy container                 │
│  + "gmail-categories"     │ stream- │  • holds Gmail OAuth token (encrypted)│
│    skill                  │ http +  │  • POLICY ENGINE (category sandbox)   │──► Gmail API
│  • sees only proxy tools  │ bearer  │  • audit log + kill switch            │
│                           │  auth   │  • admin web UI (localhost only)      │
└───────────────────────────┘         └───────────────────────────────────────┘
```

- **Two pieces**, as intended: (1) the proxy server (this repo, runs in Docker
  outside the VM), and (2) the OpenClaw side — an MCP-server registration plus a
  `SKILL.md` (see [`openclaw-plugin/`](openclaw-plugin/)).
- **Enforcement lives in the proxy**, because OpenClaw is untrusted (it reads
  attacker-controlled email and can be prompt-injected). The agent-side
  `tools.allow` is only defense-in-depth.

## What the agent can and cannot do

**Can:** list/search/read messages in allowed categories, mark read/unread,
star, archive (remove from inbox), apply user labels, trash (if you enable it),
get unread counts.

**Cannot (by construction):** read any other category, send/reply/forward,
create drafts, permanently delete, add/remove `CATEGORY_*`/`SPAM`/`TRASH`
labels, change settings, or ever touch the OAuth token.

The nine MCP tools: `gmail_list_messages`, `gmail_get_message`,
`gmail_get_thread`, `gmail_modify_labels`, `gmail_archive_message`,
`gmail_trash_message`, `gmail_list_labels`, `gmail_counts`, `gmail_get_profile`.

## Quick start — local demo (no Google account needed)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
ADMIN_TOKEN=demo GMAIL_BACKEND=mock gmail-proxy
```

- Admin UI: <http://127.0.0.1:8081/> (log in with `demo`)
- MCP endpoint: `http://127.0.0.1:8443/mcp`

Issue an agent token in the **Credentials** page, then point an MCP client at
the endpoint with `Authorization: Bearer <token>`.

## Production (real Gmail)

1. **Google Cloud:** create a project, enable the Gmail API, create a **Desktop
   OAuth client**, download `client_secret.json` into `./secrets/`.
2. **Keys:** `cp .env.example .env` and fill in `TOKEN_ENCRYPTION_KEY`,
   `GOOGLE_CLIENT_ID`, `ADMIN_TOKEN` (the file has generation commands).
3. **Bootstrap the token** (one time, opens a browser):
   ```bash
   python scripts/oauth_bootstrap.py --client-secret ./secrets/client_secret.json \
       --out ./secrets/token.json --encryption-key "$TOKEN_ENCRYPTION_KEY"
   ```
   Uses the `gmail.modify` scope (read + labels/archive, **no permanent delete**).
   Add `--readonly` for a read-only deployment.
4. **Run:** `docker compose up -d --build`
5. **Configure scope** in the admin UI (Configuration page): toggle which
   categories the agent may access. (Enabling **Primary** grants near
   full-mailbox read/modify — see the warning there.)
6. **Register with OpenClaw:** merge [`openclaw-plugin/mcp-registration.json`](openclaw-plugin/mcp-registration.json)
   into `~/.openclaw/openclaw.json`, install the skill from
   [`openclaw-plugin/SKILL.md`](openclaw-plugin/SKILL.md), and set the agent's
   `GMAIL_PROXY_TOKEN` secret to a credential issued from the admin UI.

> **Network:** keep port `8443` reachable only from the VM (host firewall /
> private docker network); keep the admin UI (`8081`) on `127.0.0.1` and reach
> it via an SSH tunnel. mTLS is recommended over bearer tokens in production.

## Admin web UI (config + debugging)

Dashboard · Configuration · Audit log (allow/deny + reason, hash-chain
integrity) · Policy explain (why a given message id is/ isn't in scope) ·
Dry-run tester (invoke any tool with full policy enforcement) · Credentials
(issue/rotate/revoke) · Kill-switch. Screenshots in
[`docs/screenshots/`](docs/screenshots/).

**Caching (fewer real Gmail API calls).** A `CachingGmailBackend` fronts Gmail
with: a durable **content cache** (LRU, default 1000 messages — message bodies
are immutable, so this is safe with no TTL and eliminates repeat full fetches),
and short **TTL caches** for labels/list/profile. The labels/eligibility TTL
defaults to **0 (always fresh)** because labels drive the eligibility decision;
raising it is an explicit freshness-vs-calls tradeoff and every entry is
invalidated on mutation. All knobs live under `cache:` in `policy.yaml` and on
the Configuration page; live hit/miss stats and "API calls saved" are on the
**Cache** page.

**Admin authentication.** By default, a signed session cookie gated on
`ADMIN_TOKEN`. Optionally enable **"Sign in with Google"** (OIDC), restricted to
the proxied account — set `ADMIN_OAUTH_CLIENT_ID`/`ADMIN_OAUTH_CLIENT_SECRET`
(a separate OAuth *Web application* client) and register the redirect URI. Only
the proxied mailbox's own Google account can log in; `ADMIN_TOKEN` remains as a
break-glass fallback. The UI stays localhost-only regardless.

## Tests

```bash
pip install -e '.[dev]'
pytest            # 80+ tests: policy engine, query sanitizer, mutation guards,
                  # tool integration vs a mock Gmail, auth, audit, live MCP, admin
```

The Playwright admin e2e test (`tests/e2e/`) skips automatically if no Chromium
is available.

## CI / images

- **CI** (`.github/workflows/ci.yml`) runs ruff + the full pytest suite on
  Python 3.11 and 3.12 for every push and pull request.
- **Docker** (`.github/workflows/docker.yml`) builds the image on every push and
  PR, and **publishes to GHCR** on pushes/merges and tags:
  `ghcr.io/vrwarp/openclaw-gmail-proxy` (tagged by branch, `sha`, semver, and
  `latest` on the default branch). To run the published image instead of
  building locally, set `image: ghcr.io/vrwarp/openclaw-gmail-proxy:latest` in
  `docker-compose.yml` and drop the `build:` line.

## Layout

```
src/gmail_proxy/        proxy server
  policy/               is_eligible(), query sanitizer, mutation guards  (the crux)
  gmail/                backend interface + mock + real googleapis client + token store
  tools.py              the 9 category-scoped tools + dispatch (freeze/rate-limit/audit)
  mcp_server.py         MCP Streamable-HTTP endpoint + per-agent bearer auth
  admin/                FastAPI admin UI (templates + static)
openclaw-plugin/        SKILL.md + example MCP registration
scripts/oauth_bootstrap.py
tests/                  pytest suite (+ e2e)
DESIGN.md               full design & threat model
```
