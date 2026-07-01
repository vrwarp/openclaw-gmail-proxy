"""FastAPI admin application (config + debugging)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

import yaml
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import errors, tools
from ..config import Policy
from ..context import AppContext
from ..gmail import oauth as gmail_oauth
from ..gmail.oauth import OAuthClient
from .google_auth import GoogleOIDC, new_pkce, random_token

_HERE = Path(__file__).parent
_ALL_CATEGORY_NAMES = ["primary", "social", "promotions", "updates", "forums"]

# Argument specs for the tool tester (tool -> [(field, kind)]).
_PLAYGROUND = {
    "gmail_list_messages": [("category", "text"), ("unread_only", "bool"),
                            ("from", "text"), ("subject", "text"), ("newer_than", "text"),
                            ("max_results", "int"), ("fresh", "bool")],
    "gmail_get_message": [("id", "text"), ("fresh", "bool")],
    "gmail_get_thread": [("id", "text"), ("fresh", "bool")],
    "gmail_modify_labels": [("id", "text"), ("add_labels", "csv"), ("remove_labels", "csv")],
    "gmail_archive_message": [("id", "text")],
    "gmail_trash_message": [("id", "text")],
    "gmail_list_labels": [("fresh", "bool")],
    "gmail_counts": [("category", "text"), ("fresh", "bool")],
    "gmail_get_profile": [("fresh", "bool")],
}


def _session_key(ctx: AppContext) -> bytes:
    # build_context() always resolves a real token (env value or a generated,
    # persisted one), so there is no insecure shared default here.
    return hashlib.sha256((ctx.settings.admin_token or "").encode()).digest()


def _sign(ctx: AppContext) -> str:
    return hmac.new(_session_key(ctx), b"admin-session", hashlib.sha256).hexdigest()


def _seal(ctx: AppContext, payload: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    mac = hmac.new(_session_key(ctx), raw.encode(), hashlib.sha256).hexdigest()
    return raw + "." + mac


def _unseal(ctx: AppContext, cookie: str | None) -> dict | None:
    if not cookie or "." not in cookie:
        return None
    raw, mac = cookie.rsplit(".", 1)
    expected = hmac.new(_session_key(ctx), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(raw))
    except (ValueError, json.JSONDecodeError):
        return None


def build_admin_app(ctx: AppContext) -> FastAPI:
    app = FastAPI(title="OpenClaw Gmail Proxy — Admin")
    app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")
    templates = Jinja2Templates(directory=str(_HERE / "templates"))

    # --- Google login (optional) -----------------------------------------
    s = ctx.settings
    oidc = (
        GoogleOIDC(s.admin_oauth_client_id, s.admin_oauth_secret(), s.admin_oauth_redirect_uri)
        if s.google_login_enabled else None
    )
    # Pin the account allowed into the admin UI: explicit config, else the
    # proxied mailbox's own address.
    allowed_email = (s.admin_allowed_email or "").lower()
    if not allowed_email:
        try:
            allowed_email = (ctx.backend.get_profile().get("emailAddress") or "").lower()
        except Exception:  # noqa: BLE001
            allowed_email = ""
    allowed_sub = s.admin_allowed_sub or ""

    def authed(request: Request) -> bool:
        cookie = request.cookies.get("admin_session")
        return bool(cookie) and hmac.compare_digest(cookie, _sign(ctx))

    def page(request: Request, name: str, **kw) -> HTMLResponse:
        ctx_data = {"frozen": ctx.killswitch.is_frozen(),
                    "backend": ctx.settings.gmail_backend, "nav": name}
        ctx_data.update(kw)
        return templates.TemplateResponse(request, name, ctx_data)

    # --- auth -------------------------------------------------------------
    def _login_ctx(error: str | None = None) -> dict:
        return {"error": error, "google_enabled": oidc is not None,
                "allowed_email": allowed_email}

    def _grant_session(to: str = "/") -> RedirectResponse:
        resp = RedirectResponse(to, status_code=303)
        # SameSite=Lax (not Strict): the Gmail OAuth callback is a top-level GET
        # navigation coming from accounts.google.com, and a Strict cookie would
        # not be sent — so the callback's auth guard would bounce to /login.
        # Lax still withholds the cookie on cross-site POST/subresource requests.
        resp.set_cookie("admin_session", _sign(ctx), httponly=True, samesite="lax")
        return resp

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return templates.TemplateResponse(request, "login.html", _login_ctx())

    @app.post("/login")
    def login(request: Request, token: str = Form("")):
        # Break-glass token login (works even if Google is unreachable). The
        # token is always set by build_context (env value or a generated one);
        # an empty expected token rejects every login rather than allowing "".
        expected = ctx.settings.admin_token or ""
        if not expected or not hmac.compare_digest(token, expected):
            return templates.TemplateResponse(
                request, "login.html", _login_ctx("Invalid admin token"), status_code=401
            )
        return _grant_session()

    @app.post("/logout")
    def logout():
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie("admin_session")
        return resp

    # --- Google OIDC login (restricted to the proxied account) ------------
    @app.get("/auth/google")
    def auth_google():
        if oidc is None:
            return RedirectResponse("/login", status_code=303)
        state, nonce = random_token(), random_token()
        verifier, challenge = new_pkce()
        resp = RedirectResponse(oidc.authorization_url(state, nonce, challenge), status_code=303)
        # SameSite=Lax so the tx cookie survives the top-level redirect back from Google.
        resp.set_cookie("oauth_tx", _seal(ctx, {"state": state, "nonce": nonce, "verifier": verifier}),
                        httponly=True, samesite="lax", max_age=600)
        return resp

    @app.get("/auth/callback", response_class=HTMLResponse)
    def auth_callback(request: Request, code: str | None = None, state: str | None = None,
                      error: str | None = None):
        if oidc is None:
            return RedirectResponse("/login", status_code=303)
        tx = _unseal(ctx, request.cookies.get("oauth_tx"))

        def deny(msg: str, sc: int = 403):
            r = templates.TemplateResponse(request, "login.html", _login_ctx(msg), status_code=sc)
            r.delete_cookie("oauth_tx")
            return r

        if error or not code or not state or not tx \
                or not hmac.compare_digest(state, tx.get("state", "")):
            return deny("Google sign-in failed or was cancelled.")
        try:
            claims = oidc.exchange_and_verify(code, tx["verifier"], tx["nonce"])
        except Exception:  # noqa: BLE001
            return deny("Could not verify Google identity.")
        email = (claims.get("email") or "").lower()
        if not claims.get("email_verified") or (allowed_email and email != allowed_email):
            return deny("This Google account is not authorized for the proxied mailbox.")
        if allowed_sub and claims.get("sub") != allowed_sub:
            return deny("This Google account is not authorized for the proxied mailbox.")
        resp = _grant_session()
        resp.delete_cookie("oauth_tx")
        return resp

    def guard(request: Request):
        if not authed(request):
            return RedirectResponse("/login", status_code=303)
        return None

    # --- dashboard --------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        if (r := guard(request)):
            return r
        try:
            profile = ctx.backend.get_profile()
            email = profile.get("emailAddress")
        except Exception:  # noqa: BLE001
            email = "(unavailable)"
        recent = ctx.audit.tail(8)
        return page(request, "dashboard.html", policy=ctx.policy, email=email,
                    creds=ctx.credentials.list(), recent=recent,
                    chain_ok=ctx.audit.verify_chain(),
                    kill=ctx.killswitch.status())

    # --- config -----------------------------------------------------------
    @app.get("/config", response_class=HTMLResponse)
    def config_view(request: Request, saved: str | None = None, error: str | None = None):
        if (r := guard(request)):
            return r
        return page(request, "config.html", policy=ctx.policy,
                    all_categories=_ALL_CATEGORY_NAMES, saved=saved, error=error,
                    raw_yaml=Path(ctx.settings.policy_path).read_text())

    @app.post("/config")
    async def config_save(request: Request):
        if (r := guard(request)):
            return r
        form = await request.form()
        cats = form.getlist("allowed_categories")
        data = {
            "version": ctx.policy.version,
            "mode": form.get("mode", "read_write"),
            "allowed_categories": cats,
            "allowed_labels": [s.strip() for s in form.get("allowed_labels", "").split(",") if s.strip()],
            "blocked_labels": [s.strip() for s in form.get("blocked_labels", "").split(",") if s.strip()],
            "mutable_labels": [s.strip() for s in form.get("mutable_labels", "").split(",") if s.strip()],
            "allow_user_label_mutations": form.get("allow_user_label_mutations") == "on",
            "allow_trash": form.get("allow_trash") == "on",
            "allow_attachments": form.get("allow_attachments") == "on",
            "redact_sender_address": form.get("redact_sender_address") == "on",
            "max_body_bytes": int(form.get("max_body_bytes", 65536)),
            "max_results_cap": int(form.get("max_results_cap", 50)),
            "rate_limits": {
                "per_minute": int(form.get("per_minute", 60)),
                "per_day": int(form.get("per_day", 5000)),
            },
            "cache": {
                "content": {
                    "enabled": form.get("cache_content_enabled") == "on",
                    "max_messages": int(form.get("cache_content_max", 1000)),
                },
                "metadata_ttl_s": int(form.get("cache_metadata_ttl", 0)),
                "list_ttl_s": int(form.get("cache_list_ttl", 0)),
                "labels_ttl_s": int(form.get("cache_labels_ttl", 60)),
                "profile_ttl_s": ctx.policy.cache.profile_ttl_s,
            },
        }
        try:
            Policy.model_validate(data)  # validate before writing
            Path(ctx.settings.policy_path).write_text(yaml.safe_dump(data, sort_keys=False))
            ctx.reload_policy()
        except Exception as e:  # noqa: BLE001
            return RedirectResponse(f"/config?error={type(e).__name__}", status_code=303)
        return RedirectResponse("/config?saved=1", status_code=303)

    # --- setup / onboarding ----------------------------------------------
    @app.get("/setup", response_class=HTMLResponse)
    def setup_view(request: Request, error: str | None = None, connected: str | None = None):
        if (r := guard(request)):
            return r
        client = ctx.oauth_client_store().load()
        default_redirect = str(request.base_url).rstrip("/") + "/setup/gmail/callback"
        return page(request, "setup.html", status=ctx.gmail_status(), client=client,
                    default_redirect=default_redirect, mcp_port=ctx.settings.mcp_port,
                    creds=ctx.credentials.list(), error=error, connected=connected,
                    policy=ctx.policy)

    @app.post("/setup/gmail/client")
    async def setup_client(request: Request):
        if (r := guard(request)):
            return r
        form = await request.form()
        cid, sec = form.get("client_id", "").strip(), form.get("client_secret", "").strip()
        redir = form.get("redirect_uri", "").strip()
        # Keep the existing secret if the field was left blank on re-save.
        if not sec and (existing := ctx.oauth_client_store().load()):
            sec = existing.client_secret
        if not (cid and sec and redir):
            return RedirectResponse("/setup?error=client_id, secret and redirect are required", 303)
        ctx.oauth_client_store().save(OAuthClient(cid, sec, redir))
        ctx.rebuild_backend()
        return RedirectResponse("/setup", 303)

    @app.get("/setup/gmail/connect")
    def setup_connect(request: Request):
        if (r := guard(request)):
            return r
        client = ctx.oauth_client_store().load()
        if client is None:
            return RedirectResponse("/setup?error=configure the OAuth client first", 303)
        state = random_token()
        verifier, challenge = gmail_oauth.new_pkce()
        scope = gmail_oauth.SCOPE_READONLY if ctx.policy.mode == "read_only" else gmail_oauth.SCOPE_MODIFY
        resp = RedirectResponse(gmail_oauth.authorization_url(client, state, challenge, scope), 303)
        resp.set_cookie("gmail_tx", _seal(ctx, {"state": state, "verifier": verifier}),
                        httponly=True, samesite="lax", max_age=600)
        return resp

    @app.get("/setup/gmail/callback", response_class=HTMLResponse)
    def setup_callback(request: Request, code: str | None = None, state: str | None = None,
                       error: str | None = None):
        if (r := guard(request)):
            return r
        tx = _unseal(ctx, request.cookies.get("gmail_tx"))

        def back(msg: str):
            resp = RedirectResponse(f"/setup?error={msg}", 303)
            resp.delete_cookie("gmail_tx")
            return resp

        if error or not code or not state or not tx \
                or not hmac.compare_digest(state, tx.get("state", "")):
            return back("Google authorization failed or was cancelled")
        client = ctx.oauth_client_store().load()
        try:
            token = gmail_oauth.exchange_code(client, code, tx["verifier"])
        except Exception:  # noqa: BLE001
            return back("could not obtain a refresh token — revoke prior access and retry")
        ctx.connect_gmail(token)
        # The token exchange can succeed while the first real Gmail call fails
        # (e.g. the Gmail API is not enabled). Verify before claiming success so
        # the actual reason is shown instead of a silent "not connected".
        to = "/setup?connected=1" if ctx.gmail_status().get("connected") else "/setup"
        resp = RedirectResponse(to, 303)
        resp.delete_cookie("gmail_tx")
        return resp

    @app.post("/setup/gmail/disconnect")
    def setup_disconnect(request: Request):
        if (r := guard(request)):
            return r
        ctx.disconnect_gmail()
        return RedirectResponse("/setup", 303)

    # --- audit ------------------------------------------------------------
    @app.get("/audit", response_class=HTMLResponse)
    def audit_view(request: Request, decision: str | None = None):
        if (r := guard(request)):
            return r
        rows = ctx.audit.tail(300)
        if decision in ("allow", "deny"):
            rows = [r for r in rows if r.get("decision") == decision]
        return page(request, "audit.html", rows=rows, chain_ok=ctx.audit.verify_chain(),
                    decision=decision)

    # --- policy explain ---------------------------------------------------
    @app.get("/explain", response_class=HTMLResponse)
    def explain_view(request: Request, id: str | None = None):
        if (r := guard(request)):
            return r
        result = None
        if id:
            from ..policy.engine import eligibility_reason, is_eligible
            try:
                meta = ctx.backend.get_message_metadata(id)
                allowed = ctx.policy.allowed_category_ids()
                allowed_lbls = tools._allowed_label_ids(ctx)
                blocked_lbls = tools._blocked_label_ids(ctx)
                result = {"id": id, "labels": meta.label_ids,
                          "eligible": is_eligible(meta.label_ids, allowed, allowed_lbls, blocked_lbls),
                          "reason": eligibility_reason(meta.label_ids, allowed, allowed_lbls, blocked_lbls),
                          "subject": meta.header("Subject")}
            except KeyError:
                result = {"id": id, "error": "message id not found"}
        return page(request, "explain.html", result=result, id=id or "")

    # --- tool tester -----------------------------------------------------
    @app.get("/playground", response_class=HTMLResponse)
    def playground_view(request: Request, tool: str | None = None):
        if (r := guard(request)):
            return r
        # Selecting a tool just reveals its argument fields (no run) — the tool
        # only executes when the Run button POSTs.
        if tool not in _PLAYGROUND:
            tool = None
        return page(request, "playground.html", specs=_PLAYGROUND, result=None, tool=tool)

    @app.post("/playground", response_class=HTMLResponse)
    async def playground_run(request: Request):
        if (r := guard(request)):
            return r
        form = await request.form()
        tool = form.get("tool", "")
        args: dict = {}
        for field, kind in _PLAYGROUND.get(tool, []):
            raw = form.get(field, "")
            if kind == "bool":
                args[field] = form.get(field) == "on"
            elif kind == "int" and raw:
                args[field] = int(raw)
            elif kind == "csv" and raw:
                args[field] = [s.strip() for s in raw.split(",") if s.strip()]
            elif raw:
                args[field] = raw
        try:
            result = tools.call_tool(ctx, "admin:tester", ctx.policy.mode, tool, args,
                                     enforce_runtime=False)
        except errors.ProxyError as e:
            result = {"error": e.to_public(), "detail": e.detail}
        return page(request, "playground.html", specs=_PLAYGROUND, result=result, tool=tool)

    # --- cache stats ------------------------------------------------------
    @app.get("/cache", response_class=HTMLResponse)
    def cache_view(request: Request):
        if (r := guard(request)):
            return r
        stats = ctx.backend.stats() if hasattr(ctx.backend, "stats") else None
        return page(request, "cache.html", stats=stats, cfg=ctx.policy.cache)

    @app.post("/cache/reset")
    def cache_reset(request: Request):
        if (r := guard(request)):
            return r
        if hasattr(ctx.backend, "reset_stats"):
            ctx.backend.reset_stats()
        return RedirectResponse("/cache", status_code=303)

    @app.post("/cache/clear")
    def cache_clear(request: Request):
        if (r := guard(request)):
            return r
        if hasattr(ctx.backend, "clear"):
            ctx.backend.clear()
        return RedirectResponse("/cache", status_code=303)

    # --- credentials ------------------------------------------------------
    @app.get("/credentials", response_class=HTMLResponse)
    def creds_view(request: Request, new_token: str | None = None):
        if (r := guard(request)):
            return r
        return page(request, "credentials.html", creds=ctx.credentials.list(),
                    new_token=new_token)

    @app.post("/credentials/issue")
    def creds_issue(request: Request, name: str = Form("agent"), mode: str = Form("read_write")):
        if (r := guard(request)):
            return r
        _, token = ctx.credentials.issue(name, mode=mode)
        return RedirectResponse(f"/credentials?new_token={token}", status_code=303)

    @app.post("/credentials/revoke")
    def creds_revoke(request: Request, cred_id: str = Form(...)):
        if (r := guard(request)):
            return r
        ctx.credentials.revoke(cred_id)
        return RedirectResponse("/credentials", status_code=303)

    @app.post("/credentials/rotate")
    def creds_rotate(request: Request, cred_id: str = Form(...)):
        if (r := guard(request)):
            return r
        token = ctx.credentials.rotate(cred_id)
        return RedirectResponse(f"/credentials?new_token={token or ''}", status_code=303)

    # --- kill switch ------------------------------------------------------
    @app.post("/freeze")
    def freeze(request: Request):
        if (r := guard(request)):
            return r
        ctx.killswitch.freeze("admin UI")
        return RedirectResponse("/", status_code=303)

    @app.post("/unfreeze")
    def unfreeze(request: Request):
        if (r := guard(request)):
            return r
        ctx.killswitch.unfreeze()
        return RedirectResponse("/", status_code=303)

    # --- health (unauthenticated, minimal) --------------------------------
    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "frozen": ctx.killswitch.is_frozen(),
                "backend": ctx.settings.gmail_backend}

    return app
