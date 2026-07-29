"""OAuth 2.0 client-credentials grant (RFC 6749 §4.4) for machine auth.

A single confidential client exchanges its own credentials for a delegated,
path-scoped access token acting as a fixed bot principal — no browser, no
per-user consent, no device flow. This is the machine-to-machine path a
driver / integration uses to act on the sessions API on behalf of a service
identity.

Endpoint (mounted at the app root):

- ``POST /oauth/token`` — handles ONLY ``grant_type=client_credentials``.
  On success returns ``{access_token, token_type, expires_in}``. Any other
  grant type is ``unsupported_grant_type``; a bad / absent / mismatched
  client is ``401 invalid_client``; when no machine client is configured the
  grant answers cleanly as unavailable rather than 500.

Mounted in the cookie-based auth modes (``oidc`` and ``accounts``): it needs
only the HS256 ``cookie_secret`` both configs expose, which is also the key
the minted token is validated against. It is NOT the accounts-only device
router (which hard-raises outside accounts mode); since it owns
``POST /oauth/token`` it is not mounted alongside the device grant, which
already claims that path in accounts mode.

The confidential client is a single env-configured registry entry — no
database, no migration:

- ``OMNIGENT_M2M_CLIENT_ID`` — the client identifier.
- ``OMNIGENT_M2M_CLIENT_SECRET_HASH`` — the client secret, stored only as
  its :func:`hash_secret` digest (HMAC-SHA256 keyed by ``cookie_secret``),
  never the raw secret. Verified in constant time.
- ``OMNIGENT_M2M_SUB`` — the bot principal the minted token acts as.
- ``OMNIGENT_M2M_TOKEN_TTL`` — access-token lifetime in seconds
  (default 3600). Kept short; the client re-mints rather than refreshing —
  there is no refresh token and no store-backed per-token revocation in this
  model (that is the store-backed delegated grant's job).

The minted token reuses the delegated JWT shape
(:func:`omnigent.server.routes.device_auth.mint_delegated_token`) with the
``scope`` claim set and no ``grant_id``: the auth layer confines it to the
delegated path allowlist and, seeing no ``grant_id``, skips the
revocation-denylist lookup.

That allowlist is a PATH confinement only. It does NOT limit the token's
privilege within an allowlisted path: the ``is_admin → LEVEL_OWNER`` override
inside /v1/sessions keys off the token's identity, so an admin ``sub`` would
own every tenant's session despite the allowlist. The bot ``sub`` must
therefore be a distinct, non-admin principal — refused at mount when the
permission store reports it as an admin.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
import os
import secrets
from dataclasses import dataclass

from fastapi import APIRouter, Request
from starlette.datastructures import FormData
from starlette.responses import JSONResponse, Response

from omnigent.server.auth import (
    RESERVED_USER_LOCAL,
    RESERVED_USER_PUBLIC,
    UnifiedAuthProvider,
)
from omnigent.server.device_grant_store import hash_secret
from omnigent.server.routes.device_auth import mint_delegated_token
from omnigent.stores.permission_store import PermissionStore

_logger = logging.getLogger(__name__)

_CLIENT_CREDENTIALS_GRANT = "client_credentials"
_DEFAULT_TOKEN_TTL_SECONDS = 3600

_CLIENT_ID_ENV = "OMNIGENT_M2M_CLIENT_ID"
_CLIENT_SECRET_HASH_ENV = "OMNIGENT_M2M_CLIENT_SECRET_HASH"
_SUB_ENV = "OMNIGENT_M2M_SUB"
_TOKEN_TTL_ENV = "OMNIGENT_M2M_TOKEN_TTL"


def _oauth_error(error: str, status_code: int = 400) -> JSONResponse:
    """Return an RFC 6749-shaped OAuth error response."""
    return JSONResponse(status_code=status_code, content={"error": error})


@dataclass(frozen=True)
class M2MClientConfig:
    """The single confidential machine client, read from the environment.

    :param client_id: The client identifier presented at the token endpoint.
    :param secret_hash: The client secret's :func:`hash_secret` digest — the
        stored form, never the raw secret.
    :param sub: The bot principal the minted token acts as (``sub`` claim).
    :param token_ttl_seconds: Minted access-token lifetime in seconds.
    """

    client_id: str
    secret_hash: str
    sub: str
    token_ttl_seconds: int

    @staticmethod
    def from_env() -> M2MClientConfig | None:
        """Build the machine-client config, or ``None`` when disabled.

        The grant is enabled only when the client id, secret hash, and bot
        principal are all present. A partial config disables it (and warns)
        rather than half-activating; a reserved principal disables it too —
        a bot must be a real, distinct identity, never the ``local`` /
        ``__public__`` sentinels. Never raises: an unconfigured or
        misconfigured machine client is a clean "off", not a startup crash.
        """
        client_id = os.environ.get(_CLIENT_ID_ENV, "").strip()
        secret_hash = os.environ.get(_CLIENT_SECRET_HASH_ENV, "").strip()
        sub = os.environ.get(_SUB_ENV, "").strip()
        if not (client_id and secret_hash and sub):
            if client_id or secret_hash or sub:
                _logger.warning(
                    "client-credentials: partial %s/%s/%s config; the grant "
                    "stays disabled until all three are set",
                    _CLIENT_ID_ENV,
                    _CLIENT_SECRET_HASH_ENV,
                    _SUB_ENV,
                )
            return None
        if sub in (RESERVED_USER_LOCAL, RESERVED_USER_PUBLIC):
            _logger.warning(
                "client-credentials: %s=%r is a reserved identity; the grant "
                "stays disabled (the bot principal must be a distinct user)",
                _SUB_ENV,
                sub,
            )
            return None

        token_ttl = _DEFAULT_TOKEN_TTL_SECONDS
        raw_ttl = os.environ.get(_TOKEN_TTL_ENV, "").strip()
        if raw_ttl:
            try:
                parsed = int(raw_ttl)
            except ValueError:
                _logger.warning(
                    "client-credentials: invalid %s=%r; using default %ds",
                    _TOKEN_TTL_ENV,
                    raw_ttl,
                    _DEFAULT_TOKEN_TTL_SECONDS,
                )
            else:
                if parsed > 0:
                    token_ttl = parsed
                else:
                    _logger.warning(
                        "client-credentials: %s=%r must be positive; using default %ds",
                        _TOKEN_TTL_ENV,
                        raw_ttl,
                        _DEFAULT_TOKEN_TTL_SECONDS,
                    )

        return M2MClientConfig(
            client_id=client_id,
            secret_hash=secret_hash,
            sub=sub,
            token_ttl_seconds=token_ttl,
        )


def _presented_client(request: Request, form: FormData) -> tuple[str, str] | None:
    """Resolve the presented ``(client_id, client_secret)`` pair, or ``None``.

    RFC 6749 §2.3.1: a confidential client may authenticate with HTTP Basic
    (``Authorization: Basic base64(client_id:client_secret)``) or with
    ``client_id`` / ``client_secret`` form fields. Basic takes precedence
    when present. Returns ``None`` when neither carries a usable pair, which
    the caller maps to ``invalid_client``.
    """
    header = request.headers.get("Authorization", "")
    if header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None
        client_id, sep, secret = decoded.partition(":")
        if not sep:
            return None
        return (client_id, secret)
    client_id = str(form.get("client_id") or "")
    secret = str(form.get("client_secret") or "")
    if client_id and secret:
        return (client_id, secret)
    return None


def _client_matches(
    client_id: str,
    secret: str,
    config: M2MClientConfig,
    cookie_secret: bytes,
) -> bool:
    """Constant-time check of a presented client id + secret against config.

    The secret is compared as its :func:`hash_secret` digest (the raw secret
    is never stored). Both the id and the secret-digest comparisons run and
    are combined without short-circuiting, so a mismatch reveals nothing
    through timing about which half was wrong.
    """
    id_ok = hmac.compare_digest(client_id.encode("utf-8"), config.client_id.encode("utf-8"))
    presented_hash = hash_secret(secret, cookie_secret)
    secret_ok = hmac.compare_digest(
        presented_hash.encode("utf-8"), config.secret_hash.encode("utf-8")
    )
    return id_ok and secret_ok


def _sub_is_admin(permission_store: PermissionStore | None, sub: str) -> bool:
    """Return True when the bot *sub* would inherit the admin→OWNER override.

    The path allowlist confines a bot token to the session APIs but does not
    limit its privilege there: /v1/sessions grants ``LEVEL_OWNER`` to any
    ``is_admin`` identity, so an admin ``sub`` would own every tenant's
    session. Enabling such a client is a misconfiguration, refused at mount.

    With no permission store the store-backed override cannot fire, so the sub
    is treated as safe. A store error fails closed (treated as admin) — a
    machine client we cannot vet is never mounted.
    """
    if permission_store is None:
        return False
    try:
        return permission_store.is_admin(sub)
    except Exception:
        _logger.exception(
            "client-credentials: could not verify whether %s=%r is an admin; "
            "failing closed and refusing the grant",
            _SUB_ENV,
            sub,
        )
        return True


def _warn_if_sub_exists(permission_store: PermissionStore | None, sub: str) -> None:
    """Warn (best-effort) when the bot *sub* collides with an existing user.

    A machine client should be its own dedicated, fresh identity; reusing a
    human's principal muddies audit and risks inheriting that human's grants.
    Best-effort: a store error is swallowed (the grant still mounts).
    """
    if permission_store is None:
        return
    try:
        exists = any(account.id == sub for account in permission_store.list_users())
    except Exception:  # noqa: BLE001 — advisory warning must never break the mount
        return
    if exists:
        _logger.warning(
            "client-credentials: %s=%r matches an existing principal; a bot "
            "should use a fresh, dedicated identity to keep audit clean",
            _SUB_ENV,
            sub,
        )


def create_client_credentials_router(
    auth_provider: UnifiedAuthProvider,
    permission_store: PermissionStore | None,
) -> APIRouter:
    """Build the ``POST /oauth/token`` client-credentials router.

    :param auth_provider: The active provider. Must be a cookie-based mode
        (``oidc`` or ``accounts``); its cookie config supplies the HS256
        signing key.
    :param permission_store: The session-permission store, used at mount to
        refuse an admin ``sub`` (see :func:`_sub_is_admin`). ``None`` when the
        deploy has no store — the store-backed OWNER override cannot fire then.
    :returns: An ``APIRouter`` to mount at the app root.
    :raises RuntimeError: If *auth_provider* is not a cookie-based mode.
    """
    if auth_provider._source not in ("oidc", "accounts"):
        raise RuntimeError(
            "create_client_credentials_router requires oidc or accounts auth "
            f"(got {auth_provider._source!r})"
        )
    cookie_config = (
        auth_provider._oidc_config
        if auth_provider._source == "oidc"
        else auth_provider._accounts_config
    )
    assert cookie_config is not None, "cookie-based mode must have a cookie config"
    cookie_secret = cookie_config.cookie_secret
    provider_name = auth_provider._source

    config = M2MClientConfig.from_env()
    if config is not None and _sub_is_admin(permission_store, config.sub):
        _logger.error(
            "client-credentials: %s=%r is an admin principal; refusing to enable "
            "the machine grant. The path allowlist does NOT cover the "
            "is_admin→OWNER override in /v1/sessions, so an admin bot would own "
            "every session. Point %s at a distinct, non-admin identity.",
            _SUB_ENV,
            config.sub,
            _SUB_ENV,
        )
        config = None
    if config is not None:
        _warn_if_sub_exists(permission_store, config.sub)
        if permission_store is None:
            _logger.warning(
                "client-credentials: no permission store wired — the admin-sub "
                "guard could not run for %s=%r (store-backed OWNER override is "
                "inert without a store)",
                _SUB_ENV,
                config.sub,
            )
        _logger.info(
            "client-credentials: /oauth/token enabled for client_id=%s (bot=%s)",
            config.client_id,
            config.sub,
        )
        # cookie_secret is the shared root of trust: it keys the
        # OMNIGENT_M2M_CLIENT_SECRET_HASH check AND signs issued tokens.
        # Rotating it invalidates the stored hash match and every live bot token.
        _logger.info(
            "client-credentials: cookie_secret keys both %s verification and "
            "token signing; rotating it invalidates the stored hash and all "
            "issued bot tokens",
            _CLIENT_SECRET_HASH_ENV,
        )
    else:
        _logger.info("client-credentials: /oauth/token mounted but no active machine client")

    router = APIRouter()

    @router.post("/oauth/token")
    async def token(request: Request) -> Response:
        """Exchange machine client credentials for a delegated bot token.

        Handles only ``grant_type=client_credentials``. Order matters: the
        grant type is checked first (so any other grant is cleanly
        ``unsupported_grant_type`` regardless of whether the machine client
        is configured), then the disabled case, then client authentication.
        """
        form = await request.form()
        grant_type = str(form.get("grant_type") or "")
        if grant_type != _CLIENT_CREDENTIALS_GRANT:
            return _oauth_error("unsupported_grant_type")
        if config is None:
            # Grant not active here. A stable 400 (not 503) so a conformant
            # client fails fast instead of retry-looping; a distinct code from
            # unsupported_grant_type keeps the operator signal in the log clear.
            _logger.warning(
                "oauth/token: client_credentials requested but no machine client "
                "is active (%s/%s/%s unset or refused)",
                _CLIENT_ID_ENV,
                _CLIENT_SECRET_HASH_ENV,
                _SUB_ENV,
            )
            return _oauth_error("invalid_request", status_code=400)

        presented = _presented_client(request, form)
        if presented is None:
            return _oauth_error("invalid_client", status_code=401)
        client_id, secret = presented
        if not _client_matches(client_id, secret, config, cookie_secret):
            return _oauth_error("invalid_client", status_code=401)

        access_token = mint_delegated_token(
            config.sub,
            cookie_secret,
            config.token_ttl_seconds,
            provider_name,
            client_id=config.client_id,
            jti=secrets.token_urlsafe(16),
        )
        _logger.info(
            "oauth/token: issued client-credentials token for client_id=%s (bot=%s)",
            config.client_id,
            config.sub,
        )
        return JSONResponse(
            status_code=200,
            content={
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": config.token_ttl_seconds,
            },
        )

    return router
