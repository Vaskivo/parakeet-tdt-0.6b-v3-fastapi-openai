# coding=utf-8
# SPDX-License-Identifier: Apache-2.0
"""Unified authentication for the Parakeet TDT API.

Any combination of credentials may be configured via environment variables:

* ``API_KEY`` — accepted via ``Authorization: Bearer <key>``
  and ``X-API-Key: <key>`` (programmatic clients).
* ``UI_USER`` + ``UI_PASSWORD`` — accepted via
  ``Authorization: Basic <base64(user:password)>`` (browsers, via the
  native login dialog).

Auth is **enabled** when at least one credential is configured. When enabled,
every protected route accepts ANY of the configured credentials:

* If a credential is presented, it is validated against the store that
  matches its scheme (Bearer/X-API-Key -> API_KEY; Basic -> UI_USER/PASSWORD).
* A presented credential with no matching store is invalid (no fallback).
* No credential presented -> 401.

When NO credential is configured (local/dev default), authentication is
DISABLED and all routes are open — existing deployments keep working.

``AuthMiddleware`` (see below) enforces credentials on EVERY HTTP route,
including FastAPI's built-in docs (``/docs``, ``/redoc``, ``/openapi.json``)
and any mounted sub-app, none of which are covered by router-level
dependencies. ``/health`` and ``/healthz`` are always left unauthenticated
(orchestrators and the Docker HEALTHCHECK must reach them without
credentials).

Comparisons use :func:`hmac.compare_digest` for constant-time equality to
avoid timing side channels. Error responses use the OpenAI error shape used
elsewhere in this server.
"""
from __future__ import annotations

import base64
import hmac
import logging
import os
from typing import Callable, Optional

from fastapi import Header, HTTPException, status
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)


def _env(name: str) -> Optional[str]:
    raw = os.getenv(name, "")
    raw = raw.strip()
    return raw or None


# --- Credential store (read once at import time) ---------------------------
_API_KEY: Optional[str] = _env("API_KEY")
_UI_USER: Optional[str] = _env("UI_USER")
_UI_PASSWORD: Optional[str] = _env("UI_PASSWORD")

# Basic auth requires BOTH a user and a password to be meaningful.
_UI_BASIC_ENABLED: bool = _UI_USER is not None and _UI_PASSWORD is not None
if _UI_USER is not None and not _UI_BASIC_ENABLED:
    logger.warning(
        "UI_USER is set but UI_PASSWORD is empty — HTTP Basic auth is "
        "DISABLED. Set both UI_USER and UI_PASSWORD to enable browser login."
    )

_AUTH_ENABLED: bool = _API_KEY is not None or _UI_BASIC_ENABLED

# Paths that stay unauthenticated even when auth is enabled. These are
# health probes used by orchestrators, load balancers, and the Docker
# HEALTHCHECK (which hits /healthz) — they must not require credentials.
PUBLIC_PATHS: frozenset = frozenset({"/health", "/healthz"})

if _AUTH_ENABLED:
    enabled_parts = []
    if _API_KEY is not None:
        enabled_parts.append("API_KEY (Bearer/X-API-Key)")
    if _UI_BASIC_ENABLED:
        enabled_parts.append(f"UI_USER/UI_PASSWORD (Basic, user='{_UI_USER}')")
    logger.info("Authentication enabled: %s", ", ".join(enabled_parts))
else:
    logger.warning(
        "No credentials configured (API_KEY / UI_USER+UI_PASSWORD) — "
        "authentication is DISABLED. All routes are open. Set credentials to "
        "require authentication on all routes except /health and /healthz."
    )


def is_auth_enabled() -> bool:
    """Return True if authentication is currently enforced."""
    return _AUTH_ENABLED


# ---------------------------------------------------------------------------
# Shared 401 helpers
# ---------------------------------------------------------------------------

# Advertise all configured schemes so browsers/clients know what to send.
_CHALLENGE_SCHEMES = []
if _UI_BASIC_ENABLED:
    _CHALLENGE_SCHEMES.append('Basic realm="Parakeet TDT API"')
if _API_KEY is not None:
    _CHALLENGE_SCHEMES.append("Bearer")
_WWW_AUTHENTICATE = ", ".join(_CHALLENGE_SCHEMES) if _CHALLENGE_SCHEMES else None


def _unauthorized_exc(detail: str) -> HTTPException:
    headers = {"WWW-Authenticate": _WWW_AUTHENTICATE} if _WWW_AUTHENTICATE else None
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "invalid_credentials",
            "message": detail,
            "type": "invalid_request_error",
        },
        headers=headers,
    )


def _unauthorized_response(detail: str) -> JSONResponse:
    headers = {"WWW-Authenticate": _WWW_AUTHENTICATE} if _WWW_AUTHENTICATE else None
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": "invalid_credentials",
            "message": detail,
            "type": "invalid_request_error",
        },
        headers=headers,
    )


_MISSING_CREDENTIALS_MSG = (
    "Missing credentials. Authenticate via one of: "
    "'Authorization: Bearer <key>' (when API_KEY is set), "
    "'X-API-Key: <key>' (when API_KEY is set), or "
    "'Authorization: Basic <base64(user:password)>' (when UI_USER/UI_PASSWORD "
    "are set)."
)


# ---------------------------------------------------------------------------
# Credential validation (shared by the FastAPI dependency and the ASGI wrapper)
# ---------------------------------------------------------------------------

def _eq(a: Optional[str], b: Optional[str]) -> bool:
    """Constant-time string equality, None-safe."""
    if a is None or b is None:
        return False
    return hmac.compare_digest(a, b)


def _validate_authorization_header(value: Optional[str]) -> bool:
    """Validate an ``Authorization`` header value.

    Handles both ``Bearer <key>`` and ``Basic <base64>`` forms. Returns True
    if the presented credential is valid against a configured store.
    """
    if not value:
        return False
    parts = value.split(" ", 1)
    if len(parts) != 2:
        return False
    scheme, payload = parts[0].strip(), parts[1].strip()
    scheme_l = scheme.lower()

    if scheme_l == "bearer":
        if _API_KEY is None:
            return False  # no API key configured -> bearer not accepted
        return _eq(payload, _API_KEY)

    if scheme_l == "basic":
        if not _UI_BASIC_ENABLED:
            return False  # basic not configured -> not accepted
        try:
            decoded = base64.b64decode(payload, validate=True).decode("utf-8")
        except Exception:
            return False
        if ":" not in decoded:
            return False
        user, _, password = decoded.partition(":")
        # Validate BOTH user and password to avoid a user-only timing shortcut
        # that could leak which username is valid.
        return _eq(user, _UI_USER) and _eq(password, _UI_PASSWORD)

    return False  # unknown scheme


def _validate_request(authorization: Optional[str], x_api_key: Optional[str]) -> bool:
    """Validate a request's credentials from its headers.

    Returns True if any presented credential is valid. A request with no
    credentials returns False (callers raise 401).
    """
    # X-API-Key only applies to the API_KEY store.
    if x_api_key:
        if _API_KEY is None:
            return False
        return _eq(x_api_key.strip(), _API_KEY)

    if authorization:
        return _validate_authorization_header(authorization)

    return False


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

async def require_auth(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> None:
    """FastAPI dependency enforcing configured credentials on protected routes.

    When auth is disabled (no credentials configured), this is a no-op.
    Otherwise, the request must present a valid credential via
    ``Authorization: Bearer``, ``Authorization: Basic``, or ``X-API-Key``.
    """
    if not _AUTH_ENABLED:
        return  # Local/dev: open by default.

    if _validate_request(authorization, x_api_key):
        return

    # Distinguish "no credentials" from "invalid credentials" in the message
    # without leaking which store matched; both are 401.
    presented = bool(authorization or x_api_key)
    detail = "Invalid credentials." if presented else _MISSING_CREDENTIALS_MSG
    raise _unauthorized_exc(detail)


# Backward-compatible alias for callers that referenced the previous name.
require_api_key = require_auth


# ---------------------------------------------------------------------------
# ASGI wrapper for gating mounted sub-applications (StaticFiles, etc.)
# ---------------------------------------------------------------------------
# FastAPI/Starlette route-level ``dependencies`` do NOT apply to routes added
# via ``app.mount(...)`` — mounted ASGI sub-apps bypass the router. To gate
# static assets (and any other mounted sub-app) behind the same credentials,
# we wrap the sub-app in a tiny ASGI middleware that runs the check on every
# request before delegating to the wrapped app.

def _validate_scope(scope) -> bool:
    """Validate credentials from a raw ASGI HTTP scope."""
    headers = dict(scope.get("headers") or [])
    auth = headers.get(b"authorization")
    auth_s = auth.decode("latin-1") if auth else None
    x_key = headers.get(b"x-api-key")
    x_key_s = x_key.decode("latin-1") if x_key else None
    return _validate_request(auth_s, x_key_s)


def gated_asgi_app(wrapped_app) -> Callable:
    """Wrap an ASGI app so every HTTP request requires valid credentials.

    Use to gate ``StaticFiles`` and other mounted sub-applications that bypass
    FastAPI's route-level ``dependencies``::

        app.mount("/static", gated_asgi_app(StaticFiles(directory=...)))

    When auth is disabled, the wrapper is a pass-through.
    """

    async def _asgi(scope, receive, send):
        # Only gate HTTP request lifetimes; websocket/lifespan pass through.
        if scope.get("type") != "http" or not _AUTH_ENABLED:
            await wrapped_app(scope, receive, send)
            return

        if _validate_scope(scope):
            await wrapped_app(scope, receive, send)
            return

        presented = bool(
            (scope.get("headers") and b"authorization" in dict(scope["headers"]))
            or (b"x-api-key" in dict(scope.get("headers") or []))
        )
        detail = "Invalid credentials." if presented else _MISSING_CREDENTIALS_MSG
        await _unauthorized_response(detail)(scope, receive, send)

    return _asgi


# ---------------------------------------------------------------------------
# ASGI middleware: protect EVERY HTTP route (including FastAPI built-in docs)
# ---------------------------------------------------------------------------
# FastAPI's interactive docs (/docs, /redoc, /openapi.json) and any mounted
# sub-app are NOT covered by router-level ``dependencies``. This pure-ASGI
# middleware runs before routing and enforces credentials on every HTTP path
# except those in :data:`PUBLIC_PATHS`. It is a no-op when auth is disabled.
#
# Add it FIRST (before any other middleware that might short-circuit) so the
# 401 is returned with the OpenAI error shape and the ``WWW-Authenticate``
# header advertising all configured schemes::
#
#     app.add_middleware(AuthMiddleware)
#
# Because it is added as middleware (outermost layer), it also protects
# /docs, /redoc, /openapi.json, and StaticFiles mounts without per-route deps.

class AuthMiddleware:
    """Gate every HTTP request behind configured credentials.

    Routes in :data:`PUBLIC_PATHS` (``/health``, ``/healthz``) always pass.
    Non-HTTP scopes (websocket, lifespan) always pass. When auth is disabled,
    the middleware is a pass-through.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or not _AUTH_ENABLED:
            await self.app(scope, receive, send)
            return

        path = scope.get("path") or ""
        # Normalize: strip a trailing slash (but keep "/" itself) so "/health/"
        # is treated like "/health". Query strings are not part of scope["path"].
        normalized = path[:-1] if len(path) > 1 and path.endswith("/") else path
        if normalized in PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return

        if _validate_scope(scope):
            await self.app(scope, receive, send)
            return

        presented = bool(
            (scope.get("headers") and b"authorization" in dict(scope["headers"]))
            or (b"x-api-key" in dict(scope.get("headers") or []))
        )
        detail = "Invalid credentials." if presented else _MISSING_CREDENTIALS_MSG
        await _unauthorized_response(detail)(scope, receive, send)
