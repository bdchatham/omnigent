"""Mutation-verify the catch-up tests: reintroduce each bug, confirm RED, restore."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SRC = Path("integrations/slack/src/omnigent_slack")
SERVICE = SRC / "service.py"
STORE = SRC / "store.py"
CTX = SRC / "thread_context.py"

T_SERVICE = "integrations/slack/tests/test_service.py"
T_STORE = "integrations/slack/tests/test_store.py"
T_CTX = "integrations/slack/tests/test_thread_context.py"

MUTATIONS: list[tuple[str, Path, str, str, list[str]]] = [
    (
        "M1 read mark claims the mention rather than what the crawl fetched",
        SERVICE,
        "read_ts = (mention_ts if complete else reached_ts) if pages else None",
        "read_ts = mention_ts if pages else None",
        [
            f"{T_SERVICE}::test_two_consecutive_catch_ups_recover_the_tail_the_first_abandoned",
            f"{T_SERVICE}::test_a_deadline_leaves_the_unread_tail_above_the_mark",
        ],
    ),
    (
        "M2 read mark advances even when zero pages landed",
        SERVICE,
        "read_ts = (mention_ts if complete else reached_ts) if pages else None",
        "read_ts = (mention_ts if complete else reached_ts) or mention_ts",
        [f"{T_SERVICE}::test_a_zero_page_read_leaves_the_read_mark_untouched"],
    ),
    (
        "M3 marks committed on a turn that never reached a model",
        SERVICE,
        "        if not errored:\n",
        "        if True:\n",
        [f"{T_SERVICE}::test_an_unaccepted_prompt_re_quotes_rather_than_skipping"],
    ),
    (
        "M4 store writes the mark unconditionally (rewinds)",
        STORE,
        "                    newer_ts(stored_read, read_ts),\n"
        "                    newer_ts(stored_delivered, delivered_ts),",
        "                    read_ts if read_ts is not None else stored_read,\n"
        "                    delivered_ts if delivered_ts is not None else stored_delivered,",
        [
            f"{T_STORE}::test_store_thread_marks_only_ever_move_forward",
            f"{T_SERVICE}::test_an_out_of_order_mention_never_rewinds_the_mark",
        ],
    ),
    (
        "M5 marks ordered as strings rather than as timestamps",
        CTX,
        "    candidate_key = _parse_ts(candidate)\n"
        "    if candidate_key is None:\n"
        "        return current\n"
        "    current_key = _parse_ts(current)\n"
        "    if current_key is None or candidate_key > current_key:\n"
        "        return candidate\n"
        "    return current",
        "    if candidate is None:\n"
        "        return current\n"
        "    if current is None or candidate > current:\n"
        "        return candidate\n"
        "    return current",
        [
            f"{T_CTX}::test_newer_ts_never_returns_the_earlier_of_two",
            f"{T_STORE}::test_store_thread_marks_only_ever_move_forward",
        ],
    ),
    (
        "M6 catch-up floor is inclusive, so the mark's own message repeats",
        CTX,
        "        if floor is not None and at <= floor:",
        "        if floor is not None and at < floor:",
        [
            f"{T_CTX}::test_since_ts_excludes_what_an_earlier_read_already_covered",
            f"{T_SERVICE}::test_two_consecutive_catch_ups_recover_the_tail_the_first_abandoned",
        ],
    ),
    (
        "M7 previously delivered mention is quoted back as background",
        CTX,
        "        if delivered is not None and at == delivered:\n            continue\n",
        "",
        [
            f"{T_CTX}::test_the_last_delivered_mention_is_not_quoted_back",
            f"{T_SERVICE}::test_catch_up_does_not_re_quote_the_last_delivered_mention",
        ],
    ),
    (
        "M8 the bot's own posts are caught up back into the session",
        CTX,
        '        if message.get("bot_id"):\n            continue\n',
        "",
        [
            f"{T_CTX}::test_the_bots_own_messages_are_never_caught_up",
            f"{T_SERVICE}::test_catch_up_never_quotes_the_bots_own_messages",
        ],
    ),
    (
        "M9 marks are not migrated onto a pre-existing database",
        STORE,
        '    ("thread_sessions", "context_read_ts", "TEXT"),\n'
        '    ("thread_sessions", "context_delivered_ts", "TEXT"),',
        "",
        [f"{T_STORE}::test_store_adds_thread_marks_to_a_pre_existing_database"],
    ),
    (
        "M10 bounded wrapper replaced by asyncio.wait_for",
        SERVICE,
        "        task = asyncio.ensure_future(coro)\n"
        "        try:\n"
        "            done, _pending = await asyncio.wait({task}, timeout=seconds)\n"
        "        except BaseException:\n"
        "            self._abandon(task, label)\n"
        "            raise\n"
        "        if not done:",
        "        task = asyncio.ensure_future(coro)\n"
        "        try:\n"
        "            await asyncio.wait_for(task, timeout=seconds)\n"
        "            done = True\n"
        "        except TimeoutError:\n"
        "            done = False\n"
        "        if not done:",
        [
            f"{T_SERVICE}::test_cancelling_the_wrapper_cancels_the_child_it_will_never_await",
            f"{T_SERVICE}::test_an_abandoned_child_that_fails_leaves_no_unretrieved_exception",
        ],
    ),
    (
        "M11 abandoned child's outcome is never retrieved",
        SERVICE,
        "        task.cancel()\n"
        "        task.add_done_callback(lambda finished: self._log_abandoned(label, finished))",
        "        task.cancel()",
        [f"{T_SERVICE}::test_an_abandoned_child_that_fails_leaves_no_unretrieved_exception"],
    ),
    (
        "M12 disclosure post is unbounded",
        SERVICE,
        "        with contextlib.suppress(Exception):\n"
        "            await self._within(\n"
        "                self._notifier.post_context_disclosure(\n"
        "                    turn.slack_client,\n"
        "                    turn.key,\n"
        "                    turn.context_messages,\n"
        "                    catch_up=turn.context_catch_up,\n"
        "                ),\n"
        "                _DISCLOSURE_TIMEOUT_SECONDS,\n"
        "                label=\"context disclosure\",\n"
        "            )",
        "        with contextlib.suppress(Exception):\n"
        "            await self._notifier.post_context_disclosure(\n"
        "                turn.slack_client,\n"
        "                turn.key,\n"
        "                turn.context_messages,\n"
        "                catch_up=turn.context_catch_up,\n"
        "            )",
        [f"{T_SERVICE}::test_a_stalled_disclosure_does_not_hold_the_turn_open"],
    ),
    (
        "M13 catch-up never runs on an existing session (the original bug)",
        SERVICE,
        "                context = _ThreadContext(prompt=text, catch_up=True)\n"
        "                if is_mention:",
        "                context = _ThreadContext(prompt=text, catch_up=True)\n"
        "                if False:",
        [
            f"{T_SERVICE}::test_existing_session_catches_up_from_its_read_mark",
            f"{T_SERVICE}::test_two_consecutive_catch_ups_recover_the_tail_the_first_abandoned",
        ],
    ),
]


def run(tests: list[str], timeout: str) -> tuple[bool, str]:
    proc = subprocess.run(
        [
            ".venv/bin/python", "-m", "pytest", *tests,
            "-q", "-p", "no:cacheprovider", "--timeout", timeout, "--no-header",
        ],
        capture_output=True,
        text=True,
    )
    tail = [line for line in proc.stdout.splitlines() if "passed" in line or "failed" in line]
    return proc.returncode == 0, (tail[-1] if tail else proc.stdout[-200:])


def main() -> int:
    backup = Path(tempfile.mkdtemp())
    for path in (SERVICE, STORE, CTX):
        shutil.copy(path, backup / path.name)

    rows = []
    for name, path, old, new, tests in MUTATIONS:
        text = path.read_text()
        if text.count(old) != 1:
            print(f"!! {name}: anchor matched {text.count(old)} times", file=sys.stderr)
            return 1
        path.write_text(text.replace(old, new))
        red_ok, red_msg = run(tests, "30")
        shutil.copy(backup / path.name, path)
        green_ok, green_msg = run(tests, "60")
        rows.append((name, red_ok, red_msg, green_ok, green_msg, tests))
        status = "OK" if (not red_ok and green_ok) else "PROBLEM"
        print(f"[{status}] {name}\n   mutated: {red_msg}\n   restored: {green_msg}")

    print("\n=== SUMMARY ===")
    bad = [r for r in rows if r[1] or not r[3]]
    for name, red_ok, red_msg, green_ok, green_msg, _t in rows:
        print(f"{'FAILED-TO-KILL' if red_ok else 'killed':>14}  {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
