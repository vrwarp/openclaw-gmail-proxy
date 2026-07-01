"""FastAPI admin application (config + debugging)."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

import yaml
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import errors, tools
from ..categories import CATEGORY_ID_BY_NAME
from ..config import Policy, load_policy
from ..context import AppContext

_HERE = Path(__file__).parent
_ALL_CATEGORY_NAMES = ["primary", "social", "promotions", "updates", "forums"]

# Argument specs for the dry-run playground (tool -> [(field, kind)]).
_PLAYGROUND = {
    "gmail_list_messages": [("category", "text"), ("unread_only", "bool"),
                            ("from", "text"), ("subject", "text"), ("newer_than", "text"),
                            ("max_results", "int")],
    "gmail_get_message": [("id", "text")],
    "gmail_get_thread": [("id", "text")],
    "gmail_modify_labels": [("id", "text"), ("add_labels", "csv"), ("remove_labels", "csv")],
    "gmail_archive_message": [("id", "text")],
    "gmail_trash_message": [("id", "text")],
    "gmail_list_labels": [],
    "gmail_counts": [("category", "text")],
    "gmail_get_profile": [],
}


def _session_key(ctx: AppContext) -> bytes:
    return hashlib.sha256((ctx.settings.admin_token or "dev-insecure").encode()).digest()


def _sign(ctx: AppContext) -> str:
    return hmac.new(_session_key(ctx), b"admin-session", hashlib.sha256).hexdigest()


def build_admin_app(ctx: AppContext) -> FastAPI:
    app = FastAPI(title="OpenClaw Gmail Proxy — Admin")
    app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")
    templates = Jinja2Templates(directory=str(_HERE / "templates"))

    def authed(request: Request) -> bool:
        cookie = request.cookies.get("admin_session")
        return bool(cookie) and hmac.compare_digest(cookie, _sign(ctx))

    def page(request: Request, name: str, **kw) -> HTMLResponse:
        ctx_data = {"frozen": ctx.killswitch.is_frozen(),
                    "backend": ctx.settings.gmail_backend, "nav": name}
        ctx_data.update(kw)
        return templates.TemplateResponse(request, name, ctx_data)

    # --- auth -------------------------------------------------------------
    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return templates.TemplateResponse(request, "login.html", {"error": None})

    @app.post("/login")
    def login(request: Request, token: str = Form("")):
        expected = ctx.settings.admin_token or "dev-insecure"
        if not hmac.compare_digest(token, expected):
            return templates.TemplateResponse(
                request, "login.html", {"error": "Invalid admin token"}, status_code=401
            )
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie("admin_session", _sign(ctx), httponly=True, samesite="strict")
        return resp

    @app.post("/logout")
    def logout():
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie("admin_session")
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
            "allowed_categories": cats or ["promotions"],
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
        }
        try:
            Policy.model_validate(data)  # validate before writing
            Path(ctx.settings.policy_path).write_text(yaml.safe_dump(data, sort_keys=False))
            ctx.reload_policy()
        except Exception as e:  # noqa: BLE001
            return RedirectResponse(f"/config?error={type(e).__name__}", status_code=303)
        return RedirectResponse("/config?saved=1", status_code=303)

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
                result = {"id": id, "labels": meta.label_ids,
                          "eligible": is_eligible(meta.label_ids, allowed),
                          "reason": eligibility_reason(meta.label_ids, allowed),
                          "subject": meta.header("Subject")}
            except KeyError:
                result = {"id": id, "error": "message id not found"}
        return page(request, "explain.html", result=result, id=id or "")

    # --- dry-run playground ----------------------------------------------
    @app.get("/playground", response_class=HTMLResponse)
    def playground_view(request: Request):
        if (r := guard(request)):
            return r
        return page(request, "playground.html", specs=_PLAYGROUND, result=None, tool=None)

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
            result = tools.call_tool(ctx, "admin:dryrun", ctx.policy.mode, tool, args,
                                     enforce_runtime=False)
        except errors.ProxyError as e:
            result = {"error": e.to_public(), "detail": e.detail}
        return page(request, "playground.html", specs=_PLAYGROUND, result=result, tool=tool)

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
