# Recovery spec — Slack thread catch-up on re-mentions

Post-review end state, distilled from 4 cross-review rounds (`codex`) that the
runner loss destroyed. Rebuild targets THIS, not the naive v1.

Base: PR #6907 head `a0dec0b75` (thread context on new-session only).
Branch: `feat/slack-thread-catchup`.

## Problem

Thread context fired only on the new-session path. Tagged again later in the
same thread, the agent saw only the new mention's text — messages posted in
between were permanently invisible, and it did not know the gap existed.

## Design (post-review)

### Two persisted marks per thread, NOT one

| Column | Meaning |
|---|---|
| `context_read_ts` | how far the crawl actually **fetched**; the floor the next read starts from |
| `context_delivered_ts` | the newest mention whose prompt was **accepted** |

They coincide when a crawl reaches the mention, and diverge exactly when a
deadline or the page budget cuts it short. One mark conflates the two and
silently buries the unread tail below the next read's floor — this was the
single largest source of blockers (3 of 5 in round 1).

Storage: existing sqlite store behind `OMNIGENT_SLACK_DATABASE_PATH`. Migration
idempotent; NULL fallback for pre-existing sessions (bounded window, never an
unbounded backfill).

### Governing invariant

**No message may ever be permanently skipped. When in doubt, duplicate rather
than drop.** A gap is silent, permanent, and destroys the feature's purpose. A
duplicate is visible, harmless, self-correcting.

### Rules that fell out of review

- **Advance iff at least one page landed.** Zero pages fetched ⇒ mark untouched,
  so the gap stays catchable. (A timeout is no longer an exception under the new
  timeout semantics, so this is not implicit.)
- **Commit marks AFTER the prompt is accepted**, never before. Acceptance-then-crash
  must yield duplicates, not skips.
- **Never rewind.** Use `BEGIN IMMEDIATE` + a ts-aware comparison so a delayed
  older mention cannot move a mark backwards.
- **Partial reads keep the tail recoverable.** A partial marker explains the
  omission but must not make the omitted messages unreachable forever.
- **Bot self-exclusion** across `bot_id`, bot user id, and subtypes.
- **`_within` replaces `asyncio.wait_for`**, and must abandon the child on BOTH
  branches — timeout *and* wrapper cancellation. `wait_for` awaits cancellation
  completion, so a cancellation-suppressing child defeats the ceiling.
- **Do not** track the disclosure child in `_turn_tasks`: shutdown does
  `gather(...)`, so tracking would make shutdown await it and reintroduce the
  unbounded wait `_within` exists to prevent.
- **Disclosure gated on acceptance.** A session created but never submitted must
  not announce a forwarding that never happened. Single accepted-time hook for
  both first-read and catch-up disclosures.
- Disclosure is a **public thread reply**, one line per catch-up that quoted ≥1
  message. Public rather than ephemeral: the people whose words were forwarded
  are the ones who need to see it.

### Timeout semantics

`asyncio` deadline covers the whole crawl but degrades to **partial + marker**
rather than all-or-nothing. Default lowered 5.0s → 3.0s (independently endorsed
by review: one shared crawl budget, and the read is pre-ack dead air).

### Config

`OMNIGENT_SLACK_THREAD_CONTEXT=true`, `_MAX_MESSAGES=25` (int, ge=0),
`_MAX_CHARS=4000` (int, ge=0, budgets the WHOLE rendered block),
`_TIMEOUT=3.0` (float, gt=0, `allow_inf_nan=False`).
Pagination bounds hardcoded: `_REPLIES_PAGE_LIMIT=200`, `_REPLIES_MAX_PAGES=5`.
Config is fail-CLOSED (`ConfigError` → `SystemExit(2)`); runtime is fail-OPEN.

## Test traps this build already fell into — do not repeat

1. **Fake returns a plain `dict`.** Slack's async SDK returns
   `AsyncSlackResponse`, which supports `response["k"]` but is **not** a `dict`
   subclass (`issubclass(AsyncSlackResponse, dict) is False`, verified against
   the installed lib). An `isinstance(response, dict)` guard made the whole
   feature a silent production no-op while 440 tests passed. Parametrize over a
   **real `AsyncSlackResponse`** and the dict fake.
2. **Fake raises instead of stalling.** A test named for a disclosure *timeout*
   whose fake raised `SlackApiError` immediately tests failure logging, not
   deadline expiry.
3. **Cancellation fake suppresses only once** — the outer deadline's second
   attempt gets through and the ceiling appears to hold regardless.
4. **Child-cancellation test that only proves the child finished** (waiting on an
   event the child sets on its way out either way).
5. **`assert prompt.endswith(...)` passes even when junk was prepended.**
6. Malformed-page tests that only exercise the FIRST page, where the window is
   still empty and there is nothing to wrongly retain. Exercise a malformed
   SECOND page (`{"ok": true, "messages": "not-a-list"}`).

**Required regression test:** two consecutive catch-ups, asserting the tail
abandoned by the first is recovered by the second. Every blocker fix must fail
without the fix (mutation-verified).

## Also carried from PR #6907, do not regress

Delimiter escaping (`<`, `>`, `&` in body AND author — tags need those chars, so
they are structurally unforgeable); char cap budgets the whole block with a
`_MIN_QUOTED_CHARS=40` floor; logs carry `error=<class>` + allowlisted `code=`
only, never the exception (a stringified `SlackApiError` leaks message text);
`_slack_error_code` must not itself raise inside the exception handler.

## Docs honesty rules

- Injection tests prove **boundary containment**, NOT immunity to persuasion by
  malicious prose. Do not overclaim.
- The thread-owner gate is **not consent** from the people being quoted.
- A single delivered-ts cannot exclude every previously accepted mention, so an
  older request can be re-quoted. Do not promise otherwise.
- The old README line "a thread's ongoing human side-discussion is still never
  added to a running session" became FALSE with catch-up and was rewritten.
  Three false doc claims have already been caught this change — check for a
  fourth.
