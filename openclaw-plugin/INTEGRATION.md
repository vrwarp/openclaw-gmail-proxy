# Connecting OpenClaw to the proxy

The proxy side is finished once the **Setup** page shows Gmail connected and
you've issued a credential on the **Credentials** page. The rest is OpenClaw-side
wiring — the part that eats an afternoon when it's under-specified. Placeholders
below: `PROXY_HOST:PORT` (the proxy's VM-facing address + host-mapped MCP port)
and the credential from the admin Credentials page.

> Verified against an OpenClaw gateway around **2026.6.10**. Exact config keys
> and CLI flags can drift across versions — sanity-check against your gateway
> (`openclaw config get …`) before trusting a step.

## 1 · Register the MCP server

Either merge [`mcp-registration.json`](mcp-registration.json) into
`~/.openclaw/openclaw.json`, or use the CLI:

```bash
openclaw mcp add gmail-proxy \
  --url http://PROXY_HOST:PORT/mcp \
  --transport streamable-http \
  --header 'Authorization=Bearer ${GMAIL_PROXY_TOKEN}' \
  --no-probe        # the save-time probe runs CLI-side and 401s without the
                    # token in the CLI env — verify with a real call (step 3)
```

- Keep the **single quotes** so `${GMAIL_PROXY_TOKEN}` is stored as a reference,
  not the literal secret.
- Name the server **exactly `gmail-proxy`**. The skill's `requiresTools`
  (`gmail-proxy__gmail_list_messages`) hard-codes it — OpenClaw namespaces MCP
  tools as `<server>__<tool>`, so a different server name makes the skill show as
  *unavailable* even though the tools are live. If you must rename it, edit
  `SKILL.md` to match.
- Use `http://` unless you front the proxy with a TLS-terminating reverse proxy
  (see [TLS](#tls-optional-reverse-proxy)).

## 2 · Wire the token (the step the docs used to skip)

`${GMAIL_PROXY_TOKEN}` in the header is resolved by the **gateway process**, not
by the CLI you type into — so the credential has to be in the gateway's
environment:

```bash
# 1) credential in a mode-600 file the gateway can read
umask 077; cat > ~/.openclaw/gmail.env <<'EOF'
GMAIL_PROXY_TOKEN=ocgp_your_agent_credential_here
EOF

# 2) inject it into the gateway (systemd user-service drop-in)
mkdir -p ~/.config/systemd/user/openclaw-gateway.service.d
cat > ~/.config/systemd/user/openclaw-gateway.service.d/gmail-env.conf <<'EOF'
[Service]
EnvironmentFile=%h/.openclaw/gmail.env
EOF
systemctl --user daemon-reload
systemctl --user restart openclaw-gateway.service
```

> **Expected, not broken:** every `openclaw` CLI command now prints
> `missing env var "GMAIL_PROXY_TOKEN" …`. That's cosmetic — the *gateway* has
> the value; the CLI process doesn't. For a clean CLI probe, load the env first:
> `set -a; . ~/.openclaw/gmail.env; set +a`.

## 3 · Verify — ground truth, no model in the loop

A model will claim a tool call succeeded whether or not it made one. Confirm
against the proxy directly, then compare with what the agent reports:

```bash
set -a; . ~/.openclaw/gmail.env; set +a
curl -s http://PROXY_HOST:PORT/mcp \
  -H "Authorization: Bearer $GMAIL_PROXY_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"gmail_get_profile","arguments":{}}}'
# → the scoped account + allowed categories. Ask the agent the same thing;
#   if the answers differ, the agent bluffed and never called the tool.
```

## 4 · Install the skill + restrict the agent

Install [`SKILL.md`](SKILL.md) so the agent knows the tool surface and the
untrusted-content rules. As defense-in-depth (the proxy is the real enforcer),
restrict the agent to the proxy's tools via `agents.defaults`:

```json
"agents": { "defaults": { "tools": { "allow": ["gmail-proxy__*"] } } }
```

The key is `agents.defaults` (**plural**) — `agents.default` (singular) is not a
recognized path and is silently ignored, so the restriction never applies. With
`tools.profile=full`, MCP tools are auto-exposed, so this list acts as a
*restriction* (it also hides every non-proxy tool from that agent).

## TLS (optional reverse proxy)

If you front the proxy with a TLS terminator and register an `https://` URL,
OpenClaw verifies the cert by default. The cert's **SAN must include the exact
hostname** in the URL (a wildcard or apex-only cert isn't enough) or you'll get
`SSL: no alternative certificate subject name matches target hostname`. Reissue
with that SAN, or set `sslVerify: false`
(`openclaw mcp configure <name> --ssl-verify false`) as a stopgap. TLS validates
the hostname, not the IP — so an `/etc/hosts` pin (below) is fine.

## Troubleshooting

| You see | It means | Do |
| --- | --- | --- |
| `401 unauthorized` | token not resolving (or wrong) | ensure the **gateway** env has `GMAIL_PROXY_TOKEN`; for CLI probes, source the env file first |
| `421` · `Invalid Host header` (plain text) | old image — the MCP SDK's localhost-only guard | upgrade to an image with the `mcp_allowed_hosts` host-allow-list behavior |
| `421` · `{"reason":"host_not_allowed"}` | your `mcp_allowed_hosts` excludes the connecting host | add it on the admin **Configuration** page, or clear the allow-list |
| TLS `wrong version number` | pointed `https://` at the plain-HTTP endpoint | use `http://`, or front with a TLS reverse proxy |
| TLS `no alternative certificate subject name` | reverse-proxy cert doesn't cover the URL host | reissue the cert with that SAN, or `sslVerify: false` |
| `connection refused` (same LAN) | NAT hairpin — the WAN IP is unreachable from inside the LAN | pin the domain to the proxy's LAN IP in `/etc/hosts` on the agent box |

> **Same-LAN NAT hairpin:** if the agent box and the proxy sit on the same LAN
> and you use a public domain that resolves to the site's WAN IP, the agent box
> may not reach it (many routers don't hairpin). Point the domain at the proxy's
> LAN IP in `/etc/hosts` on the agent box; TLS still verifies because it checks
> the hostname, not the IP.

> **Don't** try to satisfy `mcp_allowed_hosts` by adding a `Host` header in
> OpenClaw's MCP config — its `fetch` client drops `Host`. Control it via the URL
> host or the reverse proxy instead.
