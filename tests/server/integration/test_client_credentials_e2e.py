"""End-to-end integration for the client-credentials machine-auth grant.

Drives a production-shaped FastAPI app (accounts mode, device grant OFF so
the machine grant owns ``POST /oauth/token``) with the machine client
configured, and proves the whole path:

- a valid client mints a bearer token;
- that token authenticates the delegated session APIs (``/v1/sessions*``,
  ``/v1/agents``) but is rejected on a non-allowlisted admin path;
- the minted bot principal — a brand-new identity — can create a session
  (``ensure_user`` + owner grant), operate it (post events, resolve an
  elicitation), and delete it (the owner path);
- a scope token allowed on one path is NOT then accepted on a disallowed
  path (the token-keyed credential cache can't bypass the allowlist).

Network-free: accounts mode needs no IdP discovery.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from omnigent.server.auth import LEVEL_OWNER
from omnigent.server.device_grant_store import hash_secret
from tests.server.helpers import build_agent_bundle

_COOKIE_SECRET_HEX = "ab" * 32
_COOKIE_SECRET = bytes.fromhex(_COOKIE_SECRET_HEX)
_CLIENT_ID = "svc-omnigent"
_CLIENT_SECRET = "top-secret-machine-key"
_BOT_SUB = "omnigent-bot@sei.io"


def _build_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    monkeypatch.delenv("OMNIGENT_OIDC_ISSUER", raising=False)
    monkeypatch.setenv("OMNIGENT_AUTH_PROVIDER", "accounts")
    monkeypatch.setenv("OMNIGENT_ACCOUNTS_COOKIE_SECRET", _COOKIE_SECRET_HEX)
    monkeypatch.setenv("OMNIGENT_ACCOUNTS_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("OMNIGENT_ACCOUNTS_INIT_ADMIN_PASSWORD", "admin-pw-12345")
    monkeypatch.setenv("OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("OMNIGENT_ADMIN_CREDENTIALS_PATH", str(tmp_path / "admin-creds"))
    monkeypatch.setenv("OMNIGENT_ACCOUNTS_AUTO_OPEN", "0")
    # Device grant OFF: the machine grant then owns POST /oauth/token.
    monkeypatch.delenv("OMNIGENT_DEVICE_GRANT_ENABLED", raising=False)
    # Machine client — the secret is stored only as its keyed hash.
    monkeypatch.setenv("OMNIGENT_M2M_CLIENT_ID", _CLIENT_ID)
    monkeypatch.setenv(
        "OMNIGENT_M2M_CLIENT_SECRET_HASH", hash_secret(_CLIENT_SECRET, _COOKIE_SECRET)
    )
    monkeypatch.setenv("OMNIGENT_M2M_SUB", _BOT_SUB)
    monkeypatch.setenv("OMNIGENT_M2M_TOKEN_TTL", "1800")

    db_url = f"sqlite:///{tmp_path}/test.db"
    from omnigent.db.utils import get_or_create_engine
    from omnigent.runtime import init as init_runtime
    from omnigent.runtime import telemetry
    from omnigent.runtime.agent_cache import AgentCache
    from omnigent.runtime.caps import RuntimeCaps
    from omnigent.server.accounts_store import SqlAlchemyAccountStore
    from omnigent.server.app import create_app
    from omnigent.server.auth import create_auth_provider
    from omnigent.stores.agent_store.sqlalchemy_store import SqlAlchemyAgentStore
    from omnigent.stores.artifact_store.local import LocalArtifactStore
    from omnigent.stores.comment_store.sqlalchemy_store import SqlAlchemyCommentStore
    from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore
    from omnigent.stores.file_store.sqlalchemy_store import SqlAlchemyFileStore
    from omnigent.stores.host_store import HostStore
    from omnigent.stores.permission_store.sqlalchemy_store import SqlAlchemyPermissionStore

    get_or_create_engine(db_url)
    telemetry.init()
    permission_store = SqlAlchemyPermissionStore(db_url)
    agent_store = SqlAlchemyAgentStore(db_url)
    conversation_store = SqlAlchemyConversationStore(db_url)
    file_store = SqlAlchemyFileStore(db_url)
    comment_store = SqlAlchemyCommentStore(db_url)
    host_store = HostStore(db_url)
    artifact_store = LocalArtifactStore(str(tmp_path / "artifacts"))
    agent_cache = AgentCache(artifact_store=artifact_store, cache_dir=tmp_path / "cache")
    init_runtime(
        agent_cache=agent_cache,
        caps=RuntimeCaps(),
        agent_store=agent_store,
        file_store=file_store,
        conversation_store=conversation_store,
        artifact_store=artifact_store,
        comment_store=comment_store,
    )
    auth_provider = create_auth_provider()
    account_store = SqlAlchemyAccountStore(db_url)
    app = create_app(
        agent_store=agent_store,
        file_store=file_store,
        conversation_store=conversation_store,
        artifact_store=artifact_store,
        agent_cache=agent_cache,
        comment_store=comment_store,
        permission_store=permission_store,
        host_store=host_store,
        auth_provider=auth_provider,
        account_store=account_store,
    )
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, db_url=db_url, permission_store=permission_store)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    yield from _build_app(tmp_path, monkeypatch)


def _mint_bot_token(client: TestClient) -> str:
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
    return body["access_token"]


def test_token_authenticates_session_apis_and_rejects_admin(env: SimpleNamespace) -> None:
    """The bot token reaches the delegated session APIs, not admin surfaces."""
    token = _mint_bot_token(env.client)
    auth = {"Authorization": f"Bearer {token}"}

    assert env.client.get("/v1/sessions", headers=auth).status_code == 200
    assert env.client.get("/v1/agents", headers=auth).status_code == 200
    # /auth/users is not on the delegated allowlist → rejected at the door.
    assert env.client.get("/auth/users", headers=auth).status_code in (401, 403)


def test_bad_client_is_rejected(env: SimpleNamespace) -> None:
    bad = env.client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": "wrong",
        },
    )
    assert bad.status_code == 401 and bad.json()["error"] == "invalid_client"

    other = env.client.post("/oauth/token", data={"grant_type": "password"})
    assert other.status_code == 400 and other.json()["error"] == "unsupported_grant_type"


def test_bot_owns_and_operates_its_own_session(env: SimpleNamespace) -> None:
    """The brand-new bot principal can create, operate, and delete its session.

    Create runs ``ensure_user`` + an owner grant, so the bot is LEVEL_OWNER
    on the session it made and passes every owner/edit gate that follows.
    """
    token = _mint_bot_token(env.client)
    auth = {"Authorization": f"Bearer {token}"}

    # Create (multipart bundled create) as the bot — the ensure_user +
    # LEVEL_OWNER-on-create path. The bot has never been seen before.
    bundle = build_agent_bundle(name="cc-bot-agent")
    created = env.client.post(
        "/v1/sessions",
        data={"metadata": "{}"},
        files={"bundle": ("agent.tar.gz", bundle, "application/gzip")},
        headers=auth,
    )
    assert created.status_code == 201, created.text
    session_id = created.json()["session_id"]

    # ensure_user + owner grant actually landed for the bot principal.
    grant = env.permission_store.get(_BOT_SUB, session_id)
    assert grant is not None and grant.level >= LEVEL_OWNER

    # Owner can read its own session's agent.
    assert env.client.get(f"/v1/sessions/{session_id}/agent", headers=auth).status_code == 200

    # Post an event (owner satisfies the LEVEL_EDIT gate — not rejected).
    posted = env.client.post(
        f"/v1/sessions/{session_id}/events",
        json={"type": "interrupt", "data": {}},
        headers=auth,
    )
    assert posted.status_code not in (401, 403), posted.text

    # Resolve an elicitation (owner passes the gate; a missing elicitation
    # degrades gracefully rather than being an authz failure).
    resolved = env.client.post(
        f"/v1/sessions/{session_id}/elicitations/{secrets.token_hex(8)}/resolve",
        json={"action": "cancel"},
        headers=auth,
    )
    assert resolved.status_code not in (401, 403), resolved.text

    # Delete its own session (the owner-only path).
    deleted = env.client.delete(f"/v1/sessions/{session_id}", headers=auth)
    assert deleted.status_code == 200, deleted.text


# Seam 2 (tracked follow-up): the machine token's scope="sessions" inherits
# the device grant's broad path allowlist, which also covers /v1/agents,
# /v1/hosts, and /v1/runners. Confining the machine scope to /v1/sessions* +
# /health would rework the shared delegated_path_allowed contract and change
# the bot's capability surface — deferred. This snapshot guards the surface in
# the meantime: a NEW route under these prefixes fails the test, forcing a
# conscious decision on whether the bot should reach it (and to owner-gate it
# if not) before updating the snapshot.
_MACHINE_REACHABLE_PREFIXES = ("/v1/agents", "/v1/hosts", "/v1/runners")
_EXPECTED_ROUTES_UNDER_MACHINE_PREFIXES = frozenset(
    {
        ("GET", "/v1/agents"),
        ("GET", "/v1/hosts"),
        ("GET", "/v1/hosts/{host_id}"),
        ("GET", "/v1/hosts/{host_id}/credentials/detected"),
        ("GET", "/v1/hosts/{host_id}/filesystem"),
        ("GET", "/v1/hosts/{host_id}/filesystem/{path:path}"),
        ("GET", "/v1/hosts/{host_id}/harnesses/{harness}/model-options"),
        ("GET", "/v1/hosts/{host_id}/worktrees"),
        ("GET", "/v1/runners"),
        ("GET", "/v1/runners/{runner_id}/status"),
        ("POST", "/v1/hosts/{host_id}/directories"),
        ("POST", "/v1/hosts/{host_id}/harnesses/{harness}/credential"),
        ("POST", "/v1/hosts/{host_id}/harnesses/{harness}/install"),
        ("POST", "/v1/hosts/{host_id}/runners"),
        ("POST", "/v1/runners/{runner_id}/token"),
        ("WS", "/v1/hosts/{host_id}/tunnel"),
        ("WS", "/v1/runners/{runner_id}/tunnel"),
    }
)


def test_machine_reachable_route_surface_is_frozen(env: SimpleNamespace) -> None:
    """Guard the delegated allowlist surface the machine token inherits.

    See the module-level Seam 2 note. Fails when a route is added or removed
    under /v1/agents|hosts|runners so the change can't silently become
    bot-reachable without an owner-gating review + a snapshot update.
    """
    actual: set[tuple[str, str]] = set()
    for route in env.client.app.routes:
        path = getattr(route, "path", None)
        if not path or not any(
            path == p or path.startswith(p + "/") for p in _MACHINE_REACHABLE_PREFIXES
        ):
            continue
        methods = getattr(route, "methods", None) or {"WS"}
        for method in methods:
            actual.add((method, path))

    assert actual == set(_EXPECTED_ROUTES_UNDER_MACHINE_PREFIXES), (
        "Route surface under the machine-token path allowlist changed. A "
        "scope='sessions' bot token can reach these prefixes; confirm any new "
        "route is owner/admin-gated (a non-admin bot must not escalate through "
        "it), then update _EXPECTED_ROUTES_UNDER_MACHINE_PREFIXES.\n"
        f"added={actual - set(_EXPECTED_ROUTES_UNDER_MACHINE_PREFIXES)}\n"
        f"removed={set(_EXPECTED_ROUTES_UNDER_MACHINE_PREFIXES) - actual}"
    )


def test_scope_token_cache_does_not_bypass_allowlist(env: SimpleNamespace) -> None:
    """A prior allowed call must not let a later disallowed path through.

    End-to-end mirror of the unit cache-bypass test: the credential cache is
    keyed by token, so caching a scope token would skip the allowlist on a
    replay. The same token, same process, must still be refused on
    ``/auth/users`` after succeeding on ``/v1/sessions``.
    """
    token = _mint_bot_token(env.client)
    auth = {"Authorization": f"Bearer {token}"}

    assert env.client.get("/v1/sessions", headers=auth).status_code == 200
    assert env.client.get("/auth/users", headers=auth).status_code in (401, 403)
    # And once more, to be sure repetition never warms a bypassing cache entry.
    assert env.client.get("/auth/users", headers=auth).status_code in (401, 403)
    assert env.client.get("/v1/sessions", headers=auth).status_code == 200
