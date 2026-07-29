"""Unit tests for the OAuth 2.0 client-credentials (machine-auth) grant.

Three layers, all network-free:

1. :class:`M2MClientConfig` env parsing — enabled / disabled / partial /
   reserved-principal / TTL handling.
2. The ``POST /oauth/token`` router on a minimal OIDC-mode app — the token
   shape, and every error shape (invalid_client, unsupported_grant_type,
   the disabled response).
3. The ``UnifiedAuthProvider._check_cookie`` scope gate — a scope-carrying
   token is confined to the delegated path allowlist, never cached (so a
   prior allowed call can't let a later disallowed path through), and the
   revocation denylist still fires for device tokens that carry a grant_id.
"""

from __future__ import annotations

import base64
import time
from unittest.mock import MagicMock

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.datastructures import FormData

from omnigent.entities import Account
from omnigent.server.auth import UnifiedAuthProvider
from omnigent.server.device_grant_store import hash_secret
from omnigent.server.oidc import OIDCConfig, mint_session_token
from omnigent.server.routes.client_credentials import (
    M2MClientConfig,
    _client_matches,
    _presented_client,
    create_client_credentials_router,
)
from omnigent.server.routes.device_auth import mint_delegated_token

_COOKIE_SECRET = b"c" * 32
_CLIENT_ID = "svc-omnigent"
_CLIENT_SECRET = "top-secret-machine-key"
_SECRET_HASH = hash_secret(_CLIENT_SECRET, _COOKIE_SECRET)
_BOT_SUB = "bot@sei.io"


class _FakeStore:
    """Duck-typed permission store: only the mount-time guard methods.

    The router touches the store only at mount, via ``is_admin`` (the
    admin-sub refusal) and ``list_users`` (the collision warning), so a
    minimal stand-in avoids implementing the whole ABC.
    """

    def __init__(self, *, admins: tuple[str, ...] = (), users: tuple[str, ...] = ()) -> None:
        self._admins = frozenset(admins)
        self._users = users

    def is_admin(self, user_id: str) -> bool:
        return user_id in self._admins

    def list_users(self, *, limit: int = 1000) -> list[Account]:
        return [
            Account(
                id=u,
                is_admin=u in self._admins,
                created_at=None,
                last_login_at=None,
                has_password=False,
            )
            for u in self._users
        ]


# ── Fixtures / helpers ────────────────────────────────────────────


def _make_oidc_provider() -> UnifiedAuthProvider:
    """A GitHub-flavoured OIDC provider (no discovery fetch, no network)."""
    config = OIDCConfig(
        issuer="https://github.com",
        client_id="oidc-client",
        client_secret="oidc-secret",
        redirect_uri="http://localhost:8000/auth/callback",
        cookie_secret=_COOKIE_SECRET,
        scopes="read:user user:email",
        session_ttl_hours=8,
        logout_redirect_uri=None,
        allowed_domains=None,
        provider_type="github",
        authorization_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        jwks_uri=None,
        userinfo_endpoint="https://api.github.com/user",
        allow_invites=False,
    )
    return UnifiedAuthProvider(source="oidc", oidc_config=config)


def _configure(monkeypatch: pytest.MonkeyPatch, *, ttl: str | None = None) -> None:
    monkeypatch.setenv("OMNIGENT_M2M_CLIENT_ID", _CLIENT_ID)
    monkeypatch.setenv("OMNIGENT_M2M_CLIENT_SECRET_HASH", _SECRET_HASH)
    monkeypatch.setenv("OMNIGENT_M2M_SUB", _BOT_SUB)
    if ttl is not None:
        monkeypatch.setenv("OMNIGENT_M2M_TOKEN_TTL", ttl)
    else:
        monkeypatch.delenv("OMNIGENT_M2M_TOKEN_TTL", raising=False)


def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "OMNIGENT_M2M_CLIENT_ID",
        "OMNIGENT_M2M_CLIENT_SECRET_HASH",
        "OMNIGENT_M2M_SUB",
        "OMNIGENT_M2M_TOKEN_TTL",
    ):
        monkeypatch.delenv(var, raising=False)


def _client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    configure: bool = True,
    ttl: str | None = None,
    store: _FakeStore | None = None,
):
    """Build a minimal app with only the client-credentials router mounted.

    Env must be set BEFORE the router is created — the machine-client config
    is read once at mount, matching how the other auth env vars behave. The
    store defaults to one where the bot sub is a fresh, non-admin identity.
    """
    _clear(monkeypatch)
    if configure:
        _configure(monkeypatch, ttl=ttl)
    if store is None:
        store = _FakeStore()
    app = FastAPI()
    app.include_router(create_client_credentials_router(_make_oidc_provider(), store))
    return TestClient(app)


# ── M2MClientConfig.from_env ──────────────────────────────────────


def test_config_enabled_reads_all_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, ttl="900")
    config = M2MClientConfig.from_env()
    assert config is not None
    assert config.client_id == _CLIENT_ID
    assert config.secret_hash == _SECRET_HASH
    assert config.sub == _BOT_SUB
    assert config.token_ttl_seconds == 900


def test_config_disabled_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    assert M2MClientConfig.from_env() is None


def test_config_disabled_on_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    """A half-config (id without secret) disables rather than half-activating."""
    _clear(monkeypatch)
    monkeypatch.setenv("OMNIGENT_M2M_CLIENT_ID", _CLIENT_ID)
    assert M2MClientConfig.from_env() is None


@pytest.mark.parametrize("reserved", ["local", "__public__"])
def test_config_disabled_for_reserved_principal(
    monkeypatch: pytest.MonkeyPatch, reserved: str
) -> None:
    """The bot principal must be a distinct identity, never a sentinel."""
    _configure(monkeypatch)
    monkeypatch.setenv("OMNIGENT_M2M_SUB", reserved)
    assert M2MClientConfig.from_env() is None


def test_config_default_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    config = M2MClientConfig.from_env()
    assert config is not None and config.token_ttl_seconds == 3600


@pytest.mark.parametrize("bad", ["not-an-int", "0", "-5"])
def test_config_bad_ttl_falls_back_to_default(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    _configure(monkeypatch, ttl=bad)
    config = M2MClientConfig.from_env()
    assert config is not None and config.token_ttl_seconds == 3600


# ── Credential presentation + verification ────────────────────────


def _basic(client_id: str, secret: str) -> str:
    raw = base64.b64encode(f"{client_id}:{secret}".encode()).decode("ascii")
    return f"Basic {raw}"


def test_presented_client_from_form() -> None:
    request = MagicMock()
    request.headers = {}
    form = FormData([("client_id", _CLIENT_ID), ("client_secret", _CLIENT_SECRET)])
    assert _presented_client(request, form) == (_CLIENT_ID, _CLIENT_SECRET)


def test_presented_client_from_basic_header_takes_precedence() -> None:
    request = MagicMock()
    request.headers = {"Authorization": _basic("basic-id", "basic-secret")}
    form = FormData([("client_id", _CLIENT_ID), ("client_secret", _CLIENT_SECRET)])
    assert _presented_client(request, form) == ("basic-id", "basic-secret")


def test_presented_client_none_when_secret_absent() -> None:
    request = MagicMock()
    request.headers = {}
    form = FormData([("client_id", _CLIENT_ID)])
    assert _presented_client(request, form) is None


def test_presented_client_none_on_malformed_basic() -> None:
    request = MagicMock()
    request.headers = {"Authorization": "Basic !!!not-base64!!!"}
    assert _presented_client(request, FormData([])) is None


def test_client_matches_true_for_correct_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    config = M2MClientConfig.from_env()
    assert config is not None
    assert _client_matches(_CLIENT_ID, _CLIENT_SECRET, config, _COOKIE_SECRET) is True


def test_client_matches_false_for_wrong_secret_or_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    config = M2MClientConfig.from_env()
    assert config is not None
    assert _client_matches(_CLIENT_ID, "wrong", config, _COOKIE_SECRET) is False
    assert _client_matches("wrong-id", _CLIENT_SECRET, config, _COOKIE_SECRET) is False


# ── /oauth/token route: success + token shape ─────────────────────


def test_token_form_credentials_succeed(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, ttl="1800")
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 1800

    claims = jwt.decode(body["access_token"], _COOKIE_SECRET, algorithms=["HS256"])
    assert claims["sub"] == _BOT_SUB
    assert claims["scope"] == "sessions"
    assert claims["act"] == {"client_id": _CLIENT_ID}
    # Rotation-model MVP: a client-credentials token carries NO grant_id.
    assert "grant_id" not in claims
    assert claims["exp"] - claims["iat"] == 1800


def test_token_basic_auth_credentials_succeed(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch)
    resp = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": _basic(_CLIENT_ID, _CLIENT_SECRET)},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["token_type"] == "Bearer"


# ── /oauth/token route: error shapes ──────────────────────────────


def test_token_wrong_secret_is_invalid_client(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch)
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": "wrong",
        },
    )
    assert resp.status_code == 401 and resp.json()["error"] == "invalid_client"


def test_token_absent_credentials_is_invalid_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(monkeypatch)
    resp = client.post("/oauth/token", data={"grant_type": "client_credentials"})
    assert resp.status_code == 401 and resp.json()["error"] == "invalid_client"


def test_token_wrong_client_id_is_invalid_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(monkeypatch)
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "someone-else",
            "client_secret": _CLIENT_SECRET,
        },
    )
    assert resp.status_code == 401 and resp.json()["error"] == "invalid_client"


def test_token_other_grant_type_is_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch)
    resp = client.post(
        "/oauth/token",
        data={"grant_type": "password", "username": "x", "password": "y"},
    )
    assert resp.status_code == 400 and resp.json()["error"] == "unsupported_grant_type"


def test_token_disabled_returns_clean_response_not_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No machine client configured: the endpoint answers cleanly, never 500.

    A wrong grant type is still ``unsupported_grant_type``; a genuine
    client_credentials request gets a stable 400 (an RFC 6749 token-endpoint
    error, not a 503) so a conformant client fails fast rather than
    retry-looping.
    """
    client = _client(monkeypatch, configure=False)
    other = client.post("/oauth/token", data={"grant_type": "password"})
    assert other.status_code == 400 and other.json()["error"] == "unsupported_grant_type"

    disabled = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
        },
    )
    assert disabled.status_code == 400
    assert disabled.json()["error"] == "invalid_request"


def test_admin_sub_disables_grant_at_mount(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BLOCKING guard: an admin bot ``sub`` refuses to enable the grant.

    The path allowlist confines the token to the session APIs but not its
    privilege there — /v1/sessions' ``is_admin → LEVEL_OWNER`` override would
    make an admin bot OWNER of every tenant's session. So a ``sub`` the
    permission store reports as admin must NOT mount an active grant: the
    endpoint exists but answers as disabled (400 invalid_request).
    """
    admin_store = _FakeStore(admins=(_BOT_SUB,))
    with caplog.at_level("ERROR"):
        client = _client(monkeypatch, store=admin_store)
    assert any("admin principal" in r.message for r in caplog.records)

    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
        },
    )
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_request"


def test_non_admin_sub_enables_grant(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-admin bot ``sub`` mounts an active grant and mints a token."""
    client = _client(monkeypatch, store=_FakeStore(admins=("someone-else@sei.io",)))
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
        },
    )
    assert resp.status_code == 200, resp.text


def test_existing_sub_warns_but_still_enables(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A bot ``sub`` colliding with an existing (non-admin) user warns, not refuses."""
    store = _FakeStore(users=(_BOT_SUB,))
    with caplog.at_level("WARNING"):
        client = _client(monkeypatch, store=store)
    assert any("existing principal" in r.message for r in caplog.records)
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
        },
    )
    assert resp.status_code == 200, resp.text


def test_store_error_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the admin check raises at mount, fail closed — the grant stays off."""

    class _BrokenStore(_FakeStore):
        def is_admin(self, user_id: str) -> bool:
            raise RuntimeError("store down")

    client = _client(monkeypatch, store=_BrokenStore())
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
        },
    )
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_request"


def test_router_rejects_non_cookie_mode() -> None:
    """The grant needs the HS256 cookie secret, so header mode can't mount it."""
    with pytest.raises(RuntimeError, match="oidc or accounts"):
        create_client_credentials_router(UnifiedAuthProvider(source="header"), None)


# ── _check_cookie: scope allowlist + cache-bypass close ────────────


def _req(path: str, *, bearer: str) -> MagicMock:
    mock = MagicMock()
    mock.cookies = {}
    mock.headers = {"Authorization": f"Bearer {bearer}"}
    mock.url.path = path
    return mock


def _m2m_token() -> str:
    return mint_delegated_token(
        _BOT_SUB,
        _COOKIE_SECRET,
        3600,
        "oidc",
        client_id=_CLIENT_ID,
        jti="jti-1",
    )


def test_scope_token_allowed_on_allowlisted_path() -> None:
    provider = _make_oidc_provider()
    assert provider._check_cookie(_req("/v1/sessions", bearer=_m2m_token())) == _BOT_SUB
    assert provider._check_cookie(_req("/v1/sessions/abc/events", bearer=_m2m_token())) == _BOT_SUB


def test_scope_token_rejected_on_non_allowlisted_path() -> None:
    provider = _make_oidc_provider()
    assert provider._check_cookie(_req("/auth/users", bearer=_m2m_token())) is None
    assert provider._check_cookie(_req("/v1/me", bearer=_m2m_token())) is None


def test_scope_token_never_cached_so_no_path_bypass() -> None:
    """A prior allowed call must NOT let a later disallowed path through.

    The credential cache is keyed by token, not path; caching a scope token
    would let a replay on a non-allowlisted path skip the allowlist. The
    scope branch returns before the cache, so every request re-checks.
    """
    provider = _make_oidc_provider()
    token = _m2m_token()
    # Allowed path first — this must not populate the cache.
    assert provider._check_cookie(_req("/v1/sessions", bearer=token)) == _BOT_SUB
    assert provider._cookie_cache == {}
    # Same token, disallowed path: still rejected (allowlist re-runs).
    assert provider._check_cookie(_req("/auth/users", bearer=token)) is None
    assert provider._cookie_cache == {}


def test_plain_session_token_still_cached_and_path_agnostic() -> None:
    """Regression: a non-scoped session token is cached and works anywhere."""
    provider = _make_oidc_provider()
    token = mint_session_token("alice@example.com", _COOKIE_SECRET, 3600, "google")
    assert provider._check_cookie(_req("/auth/users", bearer=token)) == "alice@example.com"
    assert len(provider._cookie_cache) == 1
    # A second call on any path is served identically.
    assert provider._check_cookie(_req("/v1/me", bearer=token)) == "alice@example.com"


def test_grant_id_token_still_hits_revocation_denylist() -> None:
    """Device tokens (scope + grant_id) still consult the revocation check."""
    provider = _make_oidc_provider()
    provider.set_grant_revocation_check(lambda grant_id: grant_id == "revoked-1")

    revoked = mint_delegated_token(
        _BOT_SUB, _COOKIE_SECRET, 3600, "oidc", grant_id="revoked-1", client_id="slack", jti="a"
    )
    live = mint_delegated_token(
        _BOT_SUB, _COOKIE_SECRET, 3600, "oidc", grant_id="live-1", client_id="slack", jti="b"
    )
    assert provider._check_cookie(_req("/v1/sessions", bearer=revoked)) is None
    assert provider._check_cookie(_req("/v1/sessions", bearer=live)) == _BOT_SUB


def test_expired_scope_token_rejected() -> None:
    provider = _make_oidc_provider()
    payload = {
        "sub": _BOT_SUB,
        "iat": int(time.time()) - 7200,
        "exp": int(time.time()) - 1,
        "provider": "oidc",
        "scope": "sessions",
        "act": {"client_id": _CLIENT_ID},
    }
    token = jwt.encode(payload, _COOKIE_SECRET, algorithm="HS256")
    assert provider._check_cookie(_req("/v1/sessions", bearer=token)) is None
