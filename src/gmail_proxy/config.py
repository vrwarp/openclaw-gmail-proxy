"""Policy config (``policy.yaml``) and runtime settings (env).

The policy file is the single authoritative description of what the agent may
do.  It is validated with Pydantic and **rejects unknown keys** (default-deny
config): a typo can never silently widen access.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .categories import ALL_CATEGORY_ID_SET, CATEGORY_ID_BY_NAME, category_id_for_name

# Labels that may NEVER be added/removed via the label tool, regardless of
# config.  Mutating a CATEGORY_* label would move a message in/out of scope
# (smuggling); SPAM/TRASH have dedicated, separately-gated paths.
IMMUTABLE_LABELS: frozenset[str] = ALL_CATEGORY_ID_SET | frozenset({"SPAM", "TRASH"})


class RateLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    per_minute: int = Field(60, ge=1)
    per_day: int = Field(5000, ge=1)


class ContentCache(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Message CONTENT (headers/body/snippet) is immutable in Gmail, so this
    # cache is durable (no TTL). It never carries the eligibility decision.
    enabled: bool = True
    max_messages: int = Field(1000, ge=0)


class CacheConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: ContentCache = Field(default_factory=ContentCache)
    # Labels are MUTABLE and drive eligibility. 0 = always fetch fresh (safest,
    # default). A positive TTL trades a small time-of-check/use window for fewer
    # calls; the entry is invalidated whenever the message is mutated.
    metadata_ttl_s: int = Field(0, ge=0)
    # list/search results (new mail won't appear until the TTL expires).
    list_ttl_s: int = Field(0, ge=0)
    # labels.list (labels change rarely; invalidated on label mutations).
    labels_ttl_s: int = Field(60, ge=0)
    profile_ttl_s: int = Field(300, ge=0)


class Policy(BaseModel):
    """Validated representation of ``policy.yaml``."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    # read_only forbids every mutating tool; read_write permits the configured
    # label mutations + (optionally) trash.
    mode: Literal["read_only", "read_write"] = "read_write"

    # Which Gmail categories the agent may see/act on.  Default: all five.
    allowed_categories: list[str] = Field(
        default_factory=lambda: ["primary", "social", "promotions", "updates", "forums"]
    )

    # System labels the agent may toggle.  INBOX here means archive/unarchive is
    # allowed (removing INBOX == archive).  CATEGORY_*/SPAM/TRASH are rejected.
    mutable_labels: list[str] = Field(default_factory=lambda: ["UNREAD", "STARRED", "INBOX"])

    # Allow adding/removing arbitrary *user* (non-system) labels.
    allow_user_label_mutations: bool = True

    allow_trash: bool = False
    allow_attachments: bool = False

    # Header allowlist returned to the agent.  Everything else is dropped.
    return_headers: list[str] = Field(default_factory=lambda: ["From", "Subject", "Date"])
    # If true, the From address is replaced by a stable per-run token.
    redact_sender_address: bool = False

    max_body_bytes: int = Field(65536, ge=1024)
    max_results_cap: int = Field(50, ge=1, le=500)

    rate_limits: RateLimits = Field(default_factory=RateLimits)

    cache: CacheConfig = Field(default_factory=CacheConfig)

    # --- validation -------------------------------------------------------
    @field_validator("allowed_categories")
    @classmethod
    def _known_categories(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("allowed_categories must not be empty")
        for name in v:
            if name.strip().lower() not in CATEGORY_ID_BY_NAME:
                raise ValueError(f"unknown category: {name!r}")
        return [n.strip().lower() for n in v]

    @model_validator(mode="after")
    def _mutable_not_immutable(self) -> "Policy":
        for label in self.mutable_labels:
            if label in IMMUTABLE_LABELS:
                raise ValueError(
                    f"label {label!r} may never be listed in mutable_labels "
                    "(CATEGORY_*/SPAM/TRASH are immutable)"
                )
        return self

    # --- derived ----------------------------------------------------------
    def allowed_category_ids(self) -> set[str]:
        return {category_id_for_name(n) for n in self.allowed_categories}  # type: ignore[misc]

    def includes_primary(self) -> bool:
        return "primary" in self.allowed_categories or "personal" in self.allowed_categories


def load_policy(path: str | os.PathLike[str]) -> Policy:
    """Load and validate ``policy.yaml``."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("policy.yaml must be a mapping")
    return Policy.model_validate(data)


class Settings(BaseModel):
    """Runtime settings, populated from the environment."""

    model_config = ConfigDict(extra="ignore")

    policy_path: str = "policy.yaml"

    # Where per-agent credentials and audit log live.
    data_dir: str = "./data"

    # Gmail backend: "mock" (in-memory, for tests/demo) or "google".
    gmail_backend: Literal["mock", "google"] = "mock"

    # Token store (google backend only).
    token_store_path: str = "./secrets/token.json"
    # Fernet key for encrypting the refresh token at rest (base64).  When unset,
    # the token is stored in plaintext and a loud warning is emitted (dev only).
    token_encryption_key: str | None = None

    google_client_id: str | None = None
    google_client_secret_file: str | None = None

    # Bind addresses / ports.
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8443
    admin_host: str = "127.0.0.1"
    admin_port: int = 8081

    # Admin UI credential (bearer / basic).  Break-glass fallback when Google
    # login is enabled; required otherwise.
    admin_token: str | None = None

    # Admin UI "Sign in with Google" (OIDC). When a client id + secret are set,
    # the login page offers Google sign-in restricted to the proxied account.
    admin_oauth_client_id: str | None = None
    admin_oauth_client_secret: str | None = None
    admin_oauth_client_secret_file: str | None = None
    admin_oauth_redirect_uri: str = "http://localhost:8081/auth/callback"
    # The Google account allowed into the admin UI. If unset, it is pinned at
    # startup to the proxied account's own address (users.getProfile).
    admin_allowed_email: str | None = None
    admin_allowed_sub: str | None = None

    @property
    def google_login_enabled(self) -> bool:
        return bool(self.admin_oauth_client_id and self.admin_oauth_secret())

    def admin_oauth_secret(self) -> str | None:
        if self.admin_oauth_client_secret:
            return self.admin_oauth_client_secret
        if self.admin_oauth_client_secret_file:
            from pathlib import Path as _P

            p = _P(self.admin_oauth_client_secret_file)
            if p.exists():
                return p.read_text().strip()
        return None

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "Settings":
        env = dict(os.environ if environ is None else environ)

        def get(key: str, default=None):
            return env.get(key, default)

        return cls(
            policy_path=get("POLICY_PATH", "policy.yaml"),
            data_dir=get("DATA_DIR", "./data"),
            gmail_backend=get("GMAIL_BACKEND", "mock"),  # type: ignore[arg-type]
            token_store_path=get("TOKEN_STORE_PATH", "./secrets/token.json"),
            token_encryption_key=get("TOKEN_ENCRYPTION_KEY"),
            google_client_id=get("GOOGLE_CLIENT_ID"),
            google_client_secret_file=get("GOOGLE_CLIENT_SECRET_FILE"),
            mcp_host=get("MCP_HOST", "127.0.0.1"),
            mcp_port=int(get("MCP_PORT", "8443")),
            admin_host=get("ADMIN_HOST", "127.0.0.1"),
            admin_port=int(get("ADMIN_PORT", "8081")),
            admin_token=get("ADMIN_TOKEN"),
            admin_oauth_client_id=get("ADMIN_OAUTH_CLIENT_ID"),
            admin_oauth_client_secret=get("ADMIN_OAUTH_CLIENT_SECRET"),
            admin_oauth_client_secret_file=get("ADMIN_OAUTH_CLIENT_SECRET_FILE"),
            admin_oauth_redirect_uri=get("ADMIN_OAUTH_REDIRECT_URI",
                                         "http://localhost:8081/auth/callback"),
            admin_allowed_email=get("ADMIN_ALLOWED_EMAIL"),
            admin_allowed_sub=get("ADMIN_ALLOWED_SUB"),
        )
