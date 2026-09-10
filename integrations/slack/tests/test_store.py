from pathlib import Path

import aiosqlite
from omnigent_slack.models import ThreadKey, UserConfig
from omnigent_slack.store import SQLiteStore


async def test_store_persists_thread_session(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "store.sqlite3")
    await store.initialize()

    key = ThreadKey(team_id="T1", channel_id="C1", thread_ts="100.1")
    assert await store.get_session(key) is None

    await store.upsert_session(
        key,
        "conv_1",
        "title",
        owner_user_id="U1",
        host_id="host_a",
    )
    record = await store.get_session(key)
    assert record is not None
    assert record.session_id == "conv_1"
    assert record.owner_user_id == "U1"
    assert record.host_id == "host_a"

    await store.upsert_session(key, "conv_2", "title", owner_user_id="U1")
    record = await store.get_session(key)
    assert record is not None
    assert record.session_id == "conv_2"


async def test_store_user_config_round_trip(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "store.sqlite3")
    await store.initialize()

    assert await store.get_user_config("T1", "U1") is None

    config = UserConfig(
        agent_id="ag_1",
        agent_name="Helper",
        workspace="/home/me/project",
        host_id="host_a",
        host_name="Host A",
    )
    await store.upsert_user_config("T1", "U1", config)
    assert await store.get_user_config("T1", "U1") == config

    # Upsert overwrites and host may be cleared back to "any".
    updated = UserConfig(
        agent_id="ag_2",
        agent_name="Other",
        workspace="/tmp/ws",
    )
    await store.upsert_user_config("T1", "U1", updated)
    assert await store.get_user_config("T1", "U1") == updated
    # A different user in the same workspace is isolated.
    assert await store.get_user_config("T1", "U2") is None


async def test_store_round_trips_managed_host_type(tmp_path: Path) -> None:
    # A managed session carries no host id and no workspace path — the server
    # chooses both — so host_type is the only record of where it runs.
    store = SQLiteStore(tmp_path / "store.sqlite3")
    await store.initialize()

    config = UserConfig(agent_id="ag_1", agent_name="Helper", workspace="", host_type="managed")
    await store.upsert_user_config("T1", "U1", config)
    assert await store.get_user_config("T1", "U1") == config

    key = ThreadKey(team_id="T1", channel_id="C1", thread_ts="100.1")
    await store.upsert_session(key, "conv_1", "t", owner_user_id="U1", host_type="managed")
    record = await store.get_session(key)
    assert record is not None
    assert record.host_type == "managed"
    assert record.host_id is None

    # Switching a user back to their own host is recorded as external again.
    await store.upsert_user_config(
        "T1", "U1", UserConfig("ag_1", "Helper", "/home/me", host_id="h1")
    )
    reread = await store.get_user_config("T1", "U1")
    assert reread is not None and reread.host_type == "external"


async def test_store_adds_host_type_to_a_pre_existing_database(tmp_path: Path) -> None:
    # A store written before host_type existed keeps the old table shape, and
    # every query naming the column would fail. initialize() must add it in place
    # and read existing rows as "external" — the behavior they were saved with.
    path = tmp_path / "store.sqlite3"
    async with aiosqlite.connect(path) as db:
        await db.execute(
            """
            CREATE TABLE user_configs (
                team_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                workspace TEXT,
                host_id TEXT,
                host_name TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (team_id, user_id)
            )
            """
        )
        await db.execute(
            "INSERT INTO user_configs VALUES ('T1','U1','ag_1','Helper','/ws','h1','H',1,1)"
        )
        await db.commit()

    store = SQLiteStore(path)
    await store.initialize()

    config = await store.get_user_config("T1", "U1")
    assert config is not None
    assert config.host_type == "external"
    assert config.host_id == "h1"
    # Idempotent: a second initialize on the upgraded file must not fail.
    await store.initialize()
    assert await store.get_user_config("T1", "U1") == config


async def test_store_claim_event_dedupes(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "store.sqlite3")
    await store.initialize()

    assert await store.claim_event("Ev1") is True
    assert await store.claim_event("Ev1") is False
    assert await store.claim_event(None) is True


async def test_store_unclaim_event_allows_reclaim(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "store.sqlite3")
    await store.initialize()

    assert await store.claim_event("Ev1") is True
    # Releasing the claim lets the same event id be processed again.
    await store.unclaim_event("Ev1")
    assert await store.claim_event("Ev1") is True
    # A no-op without an id, and harmless on an unknown id.
    await store.unclaim_event(None)
    await store.unclaim_event("never-seen")


async def test_store_thread_marks_only_ever_move_forward(tmp_path: Path) -> None:
    # The marks are how a thread catches up across mentions. Moving one BACKWARDS
    # re-opens ground a later turn already covered, so the mention after that
    # re-quotes the whole span; an unconditional UPDATE does exactly that when a
    # delayed mention commits after a newer one.
    store = SQLiteStore(tmp_path / "store.sqlite3")
    await store.initialize()
    key = ThreadKey(team_id="T1", channel_id="C1", thread_ts="100.1")
    await store.upsert_session(key, "conv_1", "title", owner_user_id="U1")

    record = await store.get_session(key)
    assert record is not None
    # A session predating the marks: NULL, which reads as "no floor".
    assert (record.context_read_ts, record.context_delivered_ts) == (None, None)

    await store.advance_thread_marks(key, read_ts="100.3000", delivered_ts="100.3000")
    await store.advance_thread_marks(key, read_ts="100.2000", delivered_ts="100.2000")
    record = await store.get_session(key)
    assert record is not None
    assert (record.context_read_ts, record.context_delivered_ts) == ("100.3000", "100.3000")

    # Ordered as timestamps, not as strings: "1000000000.1" is NEWER than
    # "999999999.9" even though it sorts earlier.
    await store.advance_thread_marks(key, read_ts="999999999.900000")
    await store.advance_thread_marks(key, read_ts="1000000000.100000")
    await store.advance_thread_marks(key, read_ts="999999999.900000")
    record = await store.get_session(key)
    assert record is not None
    assert record.context_read_ts == "1000000000.100000"

    # Each mark moves on its own; ``None`` leaves the other alone.
    await store.advance_thread_marks(key, delivered_ts="1000000001.000000")
    record = await store.get_session(key)
    assert record is not None
    assert record.context_read_ts == "1000000000.100000"
    assert record.context_delivered_ts == "1000000001.000000"


async def test_store_thread_marks_survive_a_session_upsert(tmp_path: Path) -> None:
    # A thread whose session is replaced (a re-created session on the same
    # thread) must keep its read position, or the new session re-quotes the
    # whole thread from the top.
    store = SQLiteStore(tmp_path / "store.sqlite3")
    await store.initialize()
    key = ThreadKey(team_id="T1", channel_id="C1", thread_ts="100.1")
    await store.upsert_session(key, "conv_1", "title", owner_user_id="U1")
    await store.advance_thread_marks(key, read_ts="100.5", delivered_ts="100.5")

    await store.upsert_session(key, "conv_2", "title", owner_user_id="U1")
    record = await store.get_session(key)
    assert record is not None
    assert record.session_id == "conv_2"
    assert (record.context_read_ts, record.context_delivered_ts) == ("100.5", "100.5")


async def test_store_advancing_marks_on_an_unknown_thread_is_a_no_op(tmp_path: Path) -> None:
    # A logout between the read and the acceptance deletes the row. Committing
    # must not resurrect it as a session-less mark holder, and must not raise.
    store = SQLiteStore(tmp_path / "store.sqlite3")
    await store.initialize()
    key = ThreadKey(team_id="T1", channel_id="C1", thread_ts="100.1")

    await store.advance_thread_marks(key, read_ts="100.5", delivered_ts="100.5")

    assert await store.get_session(key) is None


async def test_store_adds_thread_marks_to_a_pre_existing_database(tmp_path: Path) -> None:
    # A store written before the marks existed keeps the old table shape, and
    # every query naming them would fail. They must be added in place, read as
    # NULL on existing rows — the bounded window, never a backfill of the whole
    # thread — and adding them must be idempotent.
    path = tmp_path / "store.sqlite3"
    async with aiosqlite.connect(path) as db:
        await db.execute(
            """
            CREATE TABLE thread_sessions (
                team_id TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                thread_ts TEXT NOT NULL,
                omnigent_session_id TEXT NOT NULL,
                title TEXT NOT NULL,
                owner_user_id TEXT,
                host_id TEXT,
                workspace TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (team_id, channel_id, thread_ts)
            )
            """
        )
        await db.execute(
            "INSERT INTO thread_sessions "
            "VALUES ('T1','C1','100.1','conv_1','t','U1','h1','/ws',1,1)"
        )
        await db.commit()

    store = SQLiteStore(path)
    await store.initialize()
    # Idempotent: a second initialize on the upgraded file must not fail.
    await store.initialize()

    key = ThreadKey(team_id="T1", channel_id="C1", thread_ts="100.1")
    record = await store.get_session(key)
    assert record is not None
    assert record.session_id == "conv_1"
    assert record.host_type == "external"
    assert (record.context_read_ts, record.context_delivered_ts) == (None, None)

    # And the upgraded row takes marks normally from here on.
    await store.advance_thread_marks(key, read_ts="100.5", delivered_ts="100.5")
    record = await store.get_session(key)
    assert record is not None
    assert (record.context_read_ts, record.context_delivered_ts) == ("100.5", "100.5")
