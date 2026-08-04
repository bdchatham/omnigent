"""
Unit tests for ``scripts/gen_go_client.py`` (the Go SDK's binding generator).

These cover the parts of it that are *guarantees* rather than plumbing, and
they run without a Go toolchain:

- the keyword allowlist that makes "a construct the downgrade does not handle
  fails the build" true rather than aspirational,
- the narrowing, which must never become a way for a spec change to go
  unnoticed,
- the event-name disambiguation, the description sanitiser and the
  nil-instead-of-pointer marking, each of which is an API or a security promise
  the generator has to keep on every regeneration rather than once,
- and ``--check``'s fail-closed behaviour when ``oapi-codegen`` is absent.

The real ``openapi.json`` is used wherever the assertion is about the current
spec, so a spec change that outgrows the generator fails here too.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]

# ``scripts`` is a namespace package, and ``tests/scripts`` shadows it during a
# full-suite collection; load by file path, as the sibling tests do.
_SPEC = importlib.util.spec_from_file_location(
    "_gen_go_client_under_test", _REPO_ROOT / "scripts" / "gen_go_client.py"
)
assert _SPEC is not None and _SPEC.loader is not None
gen = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = gen
_SPEC.loader.exec_module(gen)


def _spec() -> dict[str, Any]:
    return json.loads((_REPO_ROOT / "openapi.json").read_text())


def _narrowed(spec: dict[str, Any]) -> dict[str, Any]:
    """Run the generator's own narrow-then-downgrade pipeline over spec."""
    variants = gen._event_variants(spec)
    roots = set(gen._HANDWRITTEN_ROOTS) | {go for _, go in variants}
    keep = gen._closure(spec["components"]["schemas"], roots)
    keep.discard(gen._UNION)
    return gen._downgrade(gen._prune(spec, keep))


# ── the keyword allowlist ────────────────────────────────────────────


def test_the_real_spec_uses_only_handled_constructs() -> None:
    """The spec as committed must pass the allowlist, or generation is unsound."""
    gen._assert_supported(_narrowed(_spec()))


@pytest.mark.parametrize(
    ("name", "injected"),
    [
        # None of these is a keyword the generator was taught. Before the
        # allowlist, only the first two were caught: the check was a list of
        # known-bad keywords, so anything not enumerated degraded silently.
        ("prefixItems", {"type": "array", "prefixItems": [{"type": "string"}]}),
        ("$defs", {"type": "object", "$defs": {"inner": {"type": "string"}}}),
        ("if", {"type": "object", "if": {"required": ["a"]}}),
        ("then", {"type": "object", "then": {"required": ["a"]}}),
        ("dependentSchemas", {"type": "object", "dependentSchemas": {"a": {}}}),
        ("dependentRequired", {"type": "object", "dependentRequired": {"a": ["b"]}}),
        ("patternProperties", {"type": "object", "patternProperties": {"^x": {}}}),
        ("propertyNames", {"type": "object", "propertyNames": {"pattern": "^x"}}),
        ("unevaluatedProperties", {"type": "object", "unevaluatedProperties": False}),
        ("contains", {"type": "array", "contains": {"type": "string"}}),
        ("contentSchema", {"type": "string", "contentSchema": {"type": "object"}}),
        ("$dynamicRef", {"$dynamicRef": "#node"}),
        ("array-valued type", {"type": ["string", "integer"]}),
        ("null type", {"type": "null"}),
        ("tuple items", {"type": "array", "items": [{"type": "string"}]}),
        ("boolean schema", True),
    ],
)
def test_an_unhandled_construct_fails_closed(name: str, injected: Any) -> None:
    spec = _spec()
    # Inject into a schema the SDK definitely keeps, so pruning cannot drop it.
    spec["components"]["schemas"]["SessionResponse"]["properties"]["probe"] = injected
    with pytest.raises(SystemExit) as raised:
        gen._assert_supported(_narrowed(spec))
    assert "does not\nhandle" in str(raised.value), name


def test_a_construct_in_a_dropped_schema_is_out_of_scope() -> None:
    """The allowlist covers what becomes a Go type, not the whole document.

    A schema this SDK does not ship cannot degrade a type it does not generate,
    so an unhandled construct there is not this generator's problem.
    """
    spec = _spec()
    dropped = "AutomaticSessionRenameResponse"
    assert dropped in spec["components"]["schemas"], "pick another dropped schema"
    spec["components"]["schemas"][dropped]["prefixItems"] = [{"type": "string"}]
    gen._assert_supported(_narrowed(spec))


# ── narrowing without losing the drift guarantee ─────────────────────


def test_a_missing_handwritten_root_fails_closed() -> None:
    schemas = _spec()["components"]["schemas"]
    del schemas["ValidationError"]
    with pytest.raises(SystemExit) as raised:
        gen._closure(schemas, set(gen._HANDWRITTEN_ROOTS))
    assert "ValidationError" in str(raised.value)


def test_every_union_variant_survives_narrowing() -> None:
    spec = _spec()
    variants = gen._event_variants(spec)
    assert len(variants) >= 52
    narrowed = _narrowed(copy.deepcopy(spec))
    for _, go_type in variants:
        assert go_type in narrowed["components"]["schemas"]


def test_a_new_union_variant_is_picked_up_automatically() -> None:
    """A variant added to the union enters the kept set with no code change.

    This is what keeps narrowing from hiding a spec change: the event roots are
    read from the union's own discriminator rather than from a list here.
    """
    spec = _spec()
    spec["components"]["schemas"]["ProbeEvent"] = {
        "type": "object",
        "properties": {"type": {"const": "session.probe"}},
        "required": ["type"],
    }
    union = spec["components"]["schemas"][gen._UNION]
    union["discriminator"]["mapping"]["session.probe"] = "#/components/schemas/ProbeEvent"
    narrowed = _narrowed(spec)
    assert "ProbeEvent" in narrowed["components"]["schemas"]


def test_a_new_reference_pulls_its_target_in() -> None:
    spec = _spec()
    dropped = "AutomaticSessionRenameResponse"
    assert dropped not in _narrowed(copy.deepcopy(spec))["components"]["schemas"]
    spec["components"]["schemas"]["SessionResponse"]["properties"]["probe"] = {
        "$ref": f"#/components/schemas/{dropped}"
    }
    assert dropped in _narrowed(spec)["components"]["schemas"]


def test_narrowing_drops_operations_and_the_union_itself() -> None:
    narrowed = _narrowed(_spec())
    assert narrowed["paths"] == {}
    # The union's generated form is a second public representation of what the
    # hand-written Event interface already models, so it is dropped while its
    # members are kept.
    assert gen._UNION not in narrowed["components"]["schemas"]


def test_a_lost_union_discriminator_fails_closed() -> None:
    spec = _spec()
    del spec["components"]["schemas"][gen._UNION]["discriminator"]
    with pytest.raises(SystemExit) as raised:
        gen._event_variants(spec)
    assert "discriminator" in str(raised.value)


# ── event names a reader cannot pick wrongly ─────────────────────────


def test_a_colliding_trailing_name_is_namespaced_on_both_sides() -> None:
    """Five trailing names are published under two ``type`` prefixes each.

    The spec names only one member of each pair with its prefix, so the bare Go
    name belongs to whichever the spec left unprefixed — and for the heartbeat
    that is ``response.heartbeat``, not the ``session.heartbeat`` a caller sees
    in the prologue and every 15 seconds after.
    """
    names = gen._event_go_names(gen._event_variants(_spec()))
    assert names["response.heartbeat"] == "ResponseHeartbeatEvent"
    assert names["session.heartbeat"] == "SessionHeartbeatEvent"
    assert names["response.created"] == "ResponseCreatedEvent"
    assert names["session.created"] == "SessionCreatedEvent"
    assert names["response.completed"] == "ResponseCompletedEvent"
    assert names["turn.completed"] == "TurnCompletedEvent"
    assert names["response.failed"] == "ResponseFailedEvent"
    assert names["turn.failed"] == "TurnFailedEvent"
    assert names["response.cancelled"] == "ResponseCancelledEvent"
    assert names["turn.cancelled"] == "TurnCancelledEvent"


def test_an_unambiguous_name_is_left_alone() -> None:
    """Only a collision earns a prefix; the spec's own name is otherwise kept."""
    names = gen._event_go_names(gen._event_variants(_spec()))
    assert names["response.output_text.delta"] == "OutputTextDeltaEvent"
    # A deliberately nicer name than its wire type, which must survive.
    assert names["response.function_call_output.delta"] == "ToolOutputDeltaEvent"
    assert names["session.status"] == "SessionStatusEvent"


def test_a_new_collision_is_namespaced_with_no_code_change() -> None:
    """The rule is collision-driven, not a list, so it keeps working."""
    variants = [
        ("response.output_text.delta", "OutputTextDeltaEvent"),
        ("turn.output_text.delta", "SomethingElseEvent"),
    ]
    names = gen._event_go_names(variants)
    assert names["response.output_text.delta"] == "ResponseOutputTextDeltaEvent"
    assert names["turn.output_text.delta"] == "TurnOutputTextDeltaEvent"


def test_renaming_rewrites_the_references_to_the_renamed_schema() -> None:
    spec = _spec()
    variants = gen._event_variants(spec)
    narrowed = _narrowed(spec)
    renamed = gen._rename_event_schemas(narrowed, variants)
    schemas = narrowed["components"]["schemas"]
    assert "ResponseHeartbeatEvent" in schemas
    assert "HeartbeatEvent" not in schemas
    assert ("response.heartbeat", "ResponseHeartbeatEvent") in renamed
    # No $ref may still point at a name the document no longer defines.
    referenced: set[str] = set()
    gen._referenced(narrowed, referenced)
    assert not referenced - set(schemas)


def test_a_rename_that_would_collide_fails_closed() -> None:
    spec = _spec()
    variants = gen._event_variants(spec)
    narrowed = _narrowed(spec)
    # Occupy the name the rule is about to choose.
    narrowed["components"]["schemas"]["ResponseHeartbeatEvent"] = {"type": "object"}
    with pytest.raises(SystemExit) as raised:
        gen._rename_event_schemas(narrowed, variants)
    assert "ResponseHeartbeatEvent" in str(raised.value)


def test_every_event_doc_states_its_wire_type_verbatim() -> None:
    spec = _spec()
    variants = gen._event_variants(spec)
    narrowed = _narrowed(spec)
    variants = gen._rename_event_schemas(narrowed, variants)
    gen._annotate_wire_types(narrowed, variants)
    for wire, go_type in variants:
        description = narrowed["components"]["schemas"][go_type]["description"]
        assert f'Wire type: "{wire}".' in description


# ── descriptions that do not publish the server's internals ──────────


@pytest.mark.parametrize(
    ("original", "expected"),
    [
        # A home directory in an example path becomes a neutral one.
        (
            'Absolute path, e.g. `"/Users/someone/src/project"`.',
            'Absolute path, e.g. `"/path/to/workspace"`.',
        ),
        ('e.g. `"/home/someone/src"`.', 'e.g. `"/path/to/workspace"`.'),
        # A parenthetical that is only a pointer at the source goes entirely.
        (
            "Always `x` (the value of `_A_CONSTANT` in `pkg/mod.py`).",
            "Always `x`.",
        ),
        ("A fetch (`_load_it` in `pkg/mod.py`) happens.", "A fetch happens."),
        # A located reference is redacted, and the prose around it survives.
        (
            "Emitted by `pkg/mod.py` when a thing happens.",
            "Emitted by the server when a thing happens.",
        ),
        (
            "Cadence is set by `_INTERVAL_S` in `pkg/mod.py` (15 seconds).",
            "Cadence is set by the server (15 seconds).",
        ),
        # A reference in a possessive slot reads as a thing, not a place.
        (
            "Sourced from the server's `_a_cache` at build time.",
            "Sourced from the server's internal state at build time.",
        ),
        # A sentence that only points at an emit site goes.
        (
            "A token.\n\nWire shape matches `pkg/mod.py:12-20`.",
            "A token.",
        ),
        # Two references in one sentence: redacting both would read as
        # "the server ... and the server ...", so the sentence goes.
        (
            "A retry.\n\nEmitted by `a.py` (LLM) and `b.py` (tools) before sleeping.",
            "A retry.",
        ),
        (
            "Mirrors the shape that `a.py` and `b.py` emit today.",
            "",
        ),
        # Wire-level names that merely contain an underscore are not internals.
        (
            "`last_event_seq` is a `sequence_number`; `omnigent.codex_native.mode` is a label.",
            "`last_event_seq` is a `sequence_number`; `omnigent.codex_native.mode` is a label.",
        ),
    ],
)
def test_a_description_is_sanitised_without_losing_its_prose(original: str, expected: str) -> None:
    assert gen._sanitize_description(original) == expected


def test_the_real_spec_sanitises_clean() -> None:
    """The spec as committed must leave no internal behind, or the build stops."""
    gen._sanitize_descriptions(_narrowed(_spec()))


@pytest.mark.parametrize(
    "leak",
    [
        # Shapes the sanitiser handles: each must be gone, not merely reported.
        "see `omnigent/server/thing.py`",
        "the `_private_attr` field",
        'e.g. `"/Users/someone/x"`',
    ],
)
def test_a_known_leak_shape_is_removed(leak: str) -> None:
    spec = _spec()
    spec["components"]["schemas"]["SessionResponse"]["description"] = f"A snapshot. {leak}"
    narrowed = _narrowed(spec)
    gen._sanitize_descriptions(narrowed)
    assert not gen._LEAK_RE.search(
        narrowed["components"]["schemas"]["SessionResponse"]["description"]
    )


def test_a_residual_leak_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A reference that survives the rewrite stops the build rather than shipping.

    The rewrite rules are total over the shapes the scan recognises — a
    recognised reference is either redacted or taken out with its sentence — so
    nothing in the spec as committed can reach the scan. That makes the scan a
    self-check on the rules, and this is what proves it is a live one: with the
    rewrite stubbed out, generation fails instead of publishing the internals.
    """
    monkeypatch.setattr(gen, "_sanitize_description", lambda text: text)
    with pytest.raises(SystemExit) as raised:
        gen._sanitize_descriptions(_narrowed(_spec()))
    message = str(raised.value)
    assert "references to the server's" in message
    assert "Teach scripts/gen_go_client.py" in message


def test_only_descriptions_are_rewritten() -> None:
    """A ``title`` is not a doc comment, so it is out of the sanitiser's scope.

    oapi-codegen renders ``description`` into the Go comment and ignores
    ``title`` for a property, so a reference in a title cannot reach pkg.go.dev.
    The scan covers exactly what the rewrite covers, which is what keeps it from
    failing the build over something it does not fix.
    """
    spec = _spec()
    spec["components"]["schemas"]["SessionResponse"]["title"] = "See `omnigent/server/x.py`"
    narrowed = _narrowed(spec)
    gen._sanitize_descriptions(narrowed)
    assert narrowed["components"]["schemas"]["SessionResponse"]["title"] == (
        "See `omnigent/server/x.py`"
    )


def test_the_leak_scan_recognises_every_shape_it_claims_to() -> None:
    for leak in (
        "`omnigent/runtime/workflow.py`",
        "`workflow.py:4636-4639`",
        "`_HEARTBEAT_INTERVAL_S`",
        "`_drain_async_completions(block_for_one=True)`",
        # Also without the backticks, so the scan matches the Go-side test's.
        "see omnigent/runtime/workflow.py for the emit",
        "/Users/someone/src",
        "/home/someone/src",
    ):
        assert gen._LEAK_RE.search(leak), leak
    for benign in (
        "`last_event_seq`",
        "`omnigent.codex_native.collaboration_mode`",
        "`designs/SERVER_HARNESS_CONTRACT.md`",
        "`compact_conversation_now()`",
        "`POST /v1/sessions/{session_id}/events`",
    ):
        assert not gen._LEAK_RE.search(benign), benign


# ── nil instead of a pointer for collections ─────────────────────────


def test_arrays_and_maps_opt_out_of_the_optional_pointer() -> None:
    """``*[]T`` and ``*map[K]V`` are not Go, and this is what stops them."""
    schemas = _narrowed(_spec())["components"]["schemas"]
    gen._skip_optional_collection_pointers(schemas)
    ext = gen._SKIP_OPTIONAL_POINTER

    session = schemas["SessionResponse"]["properties"]
    assert session["items"][ext] is True, "the SDK's most-read field"
    assert session["labels"][ext] is True
    assert session["usage_by_model"][ext] is True
    # A struct keeps its pointer: nil there distinguishes absent from zeroed.
    assert ext not in session["sandbox_status"]


def test_the_marking_reaches_a_nested_collection() -> None:
    node = {
        "type": "object",
        "properties": {
            "outer": {"type": "array", "items": {"type": "object"}},
            "scalar": {"type": "string"},
        },
    }
    gen._skip_optional_collection_pointers(node)
    ext = gen._SKIP_OPTIONAL_POINTER
    assert node["properties"]["outer"][ext] is True
    assert node["properties"]["outer"]["items"][ext] is True
    assert ext not in node["properties"]["scalar"]
    # The struct at the top keeps its pointer.
    assert ext not in node


def test_the_allowlist_runs_before_the_generator_adds_its_own_keywords() -> None:
    """Order matters: the allowlist must keep constraining only the spec.

    Marking schemas adds ``x-go-type-skip-optional-pointer``, which is not an
    allowlisted keyword — deliberately, since the allowlist is about what
    openapi.json says. If the two ever swapped order, generation would fail.
    """
    assert gen._SKIP_OPTIONAL_POINTER not in gen._SUPPORTED


# ── the generated header ─────────────────────────────────────────────


def test_the_generated_package_doc_is_detached() -> None:
    source = (
        "// Package omnigent provides primitives to interact with the openapi HTTP API.\n"
        "//\n"
        "// Code generated by github.com/oapi-codegen/oapi-codegen/v2"
        " version v2.6.0 DO NOT EDIT.\n"
        "package omnigent\n"
    )
    rewritten = gen._detach_package_comment(source)
    lines = rewritten.split("\n")
    assert lines[0].startswith("// Code generated")
    # A blank line between the comment and the clause is what stops godoc from
    # reading it as a second package doc, appended after doc.go's.
    assert lines[2] == ""
    assert lines[3] == "package omnigent"
    assert "provides primitives" not in rewritten


def test_an_unrecognised_generated_header_fails_closed() -> None:
    with pytest.raises(SystemExit):
        gen._detach_package_comment("package omnigent\n")


# ── --check's fail-closed contract ───────────────────────────────────


def test_check_fails_when_the_generator_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gen.shutil, "which", lambda _name: None)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv(gen._SKIP_ENV, raising=False)
    assert gen._check() == 1


def test_the_local_opt_out_is_honoured_off_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gen.shutil, "which", lambda _name: None)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv(gen._SKIP_ENV, "1")
    assert gen._check() == 0


@pytest.mark.parametrize("ci_var", ["CI", "GITHUB_ACTIONS"])
def test_ci_cannot_skip_the_check(monkeypatch: pytest.MonkeyPatch, ci_var: str) -> None:
    """The whole point: no CI configuration can turn the drift gate off."""
    monkeypatch.setattr(gen.shutil, "which", lambda _name: None)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv(ci_var, "true")
    monkeypatch.setenv(gen._SKIP_ENV, "1")
    assert gen._check() == 1
