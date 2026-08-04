# go-client

A Go client for the omnigent server's session API. It covers the core surface:
client construction and auth, the session lifecycle, posting input, and
consuming a session's server-sent event stream as typed events.

## Install

```bash
go get github.com/omnigent-ai/omnigent/sdks/go-client@main
```

`@main`, not `@latest`. This module lives in a subdirectory, so the module proxy
resolves released versions only from tags prefixed with that subdirectory
(`sdks/go-client/v0.1.0`). The repository's release tags are bare `vX.Y.Z`, which
the proxy will never match to a nested module, so there is nothing for `@latest`
to find until a maintainer pushes the first prefixed tag.

The module is also outside the four-package version lockstep the Python and
TypeScript packages share: a Go module has no version file to keep in step, so
`scripts/update_versions.py` and the `version-lockstep` check do not cover it.

## Minimal invocation

```go
package main

import (
	"context"
	"fmt"
	"log"

	omnigent "github.com/omnigent-ai/omnigent/sdks/go-client"
)

func main() {
	ctx := context.Background()

	client, err := omnigent.New(omnigent.DefaultBaseURL)
	if err != nil {
		log.Fatal(err)
	}

	session, err := client.CreateSession(ctx, omnigent.SessionCreateRequest{AgentID: "ag_abc123"})
	if err != nil {
		log.Fatal(err)
	}

	// Open the stream before posting: the server buffers nothing for absent
	// subscribers, so input sent first can have its early events dropped.
	// OnSubscribed runs once the subscription is live, and only once.
	opts := omnigent.StreamOptions{
		OnSubscribed: func(ctx context.Context, sub omnigent.Subscription) error {
			_, err := client.SendMessage(ctx, sub.SessionID, "hello")
			return err
		},
	}
	for event, err := range client.Stream(ctx, session.ID, opts) {
		if err != nil {
			log.Fatal(err)
		}
		switch ev := event.(type) {
		case omnigent.OutputTextDeltaEvent:
			fmt.Print(ev.Delta)
		case omnigent.ResponseCompletedEvent:
			return
		}
	}
}
```

Authentication is a deployment choice, so the client guesses nothing. Pass
`WithAuthHeader` for the trusted-proxy identity header (whose name is
configurable — `X-Forwarded-Email` is only the default), `WithBearerToken` for
the OIDC and accounts modes' CLI fallback, or `WithSessionCookie` for a cookie
minted by an interactive login. Applying `WithSessionCookie` twice appends to the
one `Cookie` header rather than emitting a second one.

`Option` is a sealed interface, not `func(*Client) error`. Sealed so the option
set stays something this package can reason about, and decoupled from `*Client` so
option state can move into an unexported config later without changing an exported
signature. Third parties compose the `With*` constructors rather than writing
their own.

## Handling a credential

Four rules, each fail-closed rather than best-effort. The package doc's
**Security** section is the long form; this is what changes a caller's code.

- **A credential does not go over plain http off this machine.** `New` refuses a
  plaintext base URL once an auth option is supplied, unless the host is loopback
  — so `DefaultBaseURL` keeps working, and `http://api.example.test` with a token
  does not. Where the plaintext hop genuinely is not a network (a sidecar, a
  port-forward, a mesh terminating TLS ahead of you), say so with
  `WithInsecureCredentialTransport`. There is no warn-and-continue: a library has
  no logger to warn into.
- **Redirects do not carry it anywhere.** Neither `http.Client` follows a hop off
  the base URL's host, a step down from https to http, or a method rewrite; all
  three are `ErrUnsafeRedirect`. Go's own rule strips only `Authorization`,
  `Cookie`, `Www-Authenticate` and `Cookie2` on a cross-host hop, which leaves
  `WithAuthHeader`'s header travelling; it compares hostnames and not schemes; a
  cross-host 307/308 replays the request body; and a 302 on a POST becomes a GET,
  so a dropped write would otherwise return 200. Supply an `http.Client` with your
  own `CheckRedirect` and you keep yours.
- **A base URL carries no userinfo.** `net/http` would turn it into
  `Authorization: Basic` on every request. `New` rejects it, and no error from
  `New` echoes the base URL's password.
- **`APIError` is not a way to log a credential.** `Error()` renders the status,
  the server's code and message, and the request id — never the body, which on a
  non-2xx may be a proxy's login page rather than this API's. `Header` has
  `Set-Cookie` and the `Authorization` pair removed.

TLS configuration is untouched anywhere in this package: no `InsecureSkipVerify`,
no `RootCAs`, no reachable `tls.Config`. A private CA belongs in the system trust
store, or in a transport you build and pass to `WithHTTPClient`.

### Do not send on a heartbeat

`session.heartbeat` is two things with one payload: the acknowledgement the
server yields the instant the subscriber slot is registered, *and* the keepalive
it emits every 15 seconds while a stream sits idle between turns. Nothing on the
wire distinguishes them. "Send when I see a heartbeat" therefore re-sends the
message for as long as the stream stays open — which is why the quickstart uses
`StreamOptions.OnSubscribed`, called exactly once per stream regardless of what
the frames look like. When the input is known in advance,
`SessionCreateRequest.InitialItems` is better still: the server queues it at
create time and there is no ordering to get right.

## Finding an agent, and finding your own session

`CreateSession` takes an agent **id**, and there is no lookup-by-name route, so a
program that knows a name pages `ListAgents` until it matches. An id is stable, so
cache it rather than resolving on every run.

```go
func agentID(ctx context.Context, c *omnigent.Client, name string) (string, error) {
	var opts omnigent.ListAgentsOptions
	for {
		page, err := c.ListAgents(ctx, opts)
		if err != nil {
			return "", err
		}
		for _, a := range page.Data {
			if a.Name == name {
				return a.ID, nil
			}
		}
		if !page.HasMore || len(page.Data) == 0 {
			return "", fmt.Errorf("no agent named %q", name)
		}
		opts.After = page.LastID
	}
}
```

The loop breaks on two conditions. `HasMore` is the server's answer; the empty
check is what makes termination the caller's own property, since an empty page
carries an empty `LastID` and continuing would re-request the first page.

The listing is not only the agents that ship with the server, despite the route
being named for them. It is every agent not scoped to a single session, so
operator-installed ones are included; `AgentObject.Builtin` is what tells the two
apart.

`ListSessions` answers the other question. A program that runs repeatedly — one
review per pull request, say — must not create a second session when it already
made one, and a create is the one call this package will not retry, because a
retry after a committed-but-lost response orphans a session. So set a label the
program controls at create time, and find it again by filtering on the agent and
matching the label:

```go
// Returns a matching live session's id, or "" if none is found — in which case
// the caller creates one. An empty result is not the same as "this is the first
// run": the default listing omits archived sessions, so an earlier run whose
// session has since been archived also finds nothing, which is usually what a
// caller wants.
func adopt(ctx context.Context, c *omnigent.Client, agentID, runKey string) (string, error) {
	opts := omnigent.ListSessionsOptions{AgentID: agentID}
	for {
		page, err := c.ListSessions(ctx, opts)
		if err != nil {
			return "", err
		}
		for _, s := range page.Data {
			if s.Labels["run-key"] == runKey {
				return s.ID, nil // adopt it instead of creating another
			}
		}
		if !page.HasMore || len(page.Data) == 0 {
			return "", nil
		}
		opts.After = page.LastID
	}
}
```

**This has to page, and the loop above is the whole point of the section.** There
is no server-side label filter, so the label is matched client-side, and a page
holds 20 of that agent's newest sessions by default. A program on its tenth run
will not find its own earlier session on the first page — it would conclude none
exists and create the duplicate the label was there to prevent. Stopping at
`page.Data` is the mistake this recipe exists to avoid.

Filter on `AgentID` rather than `AgentName`: an agent can be renamed, and a
program holding the old name silently starts matching a different agent or none.
Setting both is not a fallback — the server applies them as two conditions on the
same column, so naming two different agents matches nothing.

## Answering an approval prompt

An agent that needs a decision parks its turn and publishes
`ElicitationRequestEvent`. Nothing advances until a verdict arrives, so an
unattended program has to answer these or the session stalls until the server
times the prompt out and synthesises a `cancel`.

```go
for ev, err := range c.Stream(ctx, sessionID, omnigent.StreamOptions{}) {
	if err != nil {
		return err
	}
	req, ok := ev.(omnigent.ElicitationRequestEvent)
	if !ok {
		continue
	}
	// What the prompt is asking for is in req.Params. Deciding from it is the
	// program's job — approving unconditionally is not a default, it is a policy,
	// and the paragraph below is why. Declining is the safe direction.
	verdict := omnigent.ElicitationDecline
	if allowed(req.Params) {
		verdict = omnigent.ElicitationAccept
	}
	if _, err := c.ResolveElicitation(ctx, sessionID, req.ElicitationID,
		omnigent.ElicitationResult{Action: verdict}); err != nil {
		return err
	}
}
```

Accepting is privileged differently from refusing, which is why it is worth a
policy rather than a constant. It authorises the pending tool to run with the
session owner's execution identity, so the server requires approval access for
`accept` specifically and answers `ErrForbidden` to a caller that only holds edit
access — which can still `decline` or `cancel`. A program that can stop an action
therefore cannot necessarily permit one, and an unattended program that accepts
every prompt has granted the agent whatever it thought to ask for.

After a reconnect, prompts raised while nobody was subscribed are not replayed on
the stream; they are on the snapshot, as `SessionResponse.PendingElicitations`.

The server also has a dedicated resolve route, which this package does not call.
It is registered `include_in_schema=False` for an internal flow where the prompt
carries that route's own URL for the client to hit directly, and its own
documentation names the approval event as the equivalent path with identical
semantics — both reach the same server-side resolver. One write route is enough.

## Layout

```
sdks/go-client/
  doc.go               # package documentation: quickstart, security, timeouts, reconnection
  client.go            # Client, New, options, redirect policy, the shared request path
  errors.go            # *APIError and the errors.Is sentinels
  session.go           # create / get / delete / send / approve, and the 4 hand-written types
  list.go              # the two cursor-paginated listings and the shared Page[T]
  event.go             # the sealed Event interface and UnknownEvent
  stream.go            # the SSE reader
  models.gen.go        # GENERATED from openapi.json — do not edit
  events.gen.go        # GENERATED from openapi.json — do not edit
  oapi-codegen.yaml    # generator config
  LICENSE              # Apache-2.0, verbatim from the repository root
  NOTICE               # ditto
  bin/check.sh         # gofmt, build, vet, race tests, go mod tidy -diff
```

`LICENSE` and `NOTICE` are copies rather than an oversight. A nested Go module is
distributed as a zip of the files under its own directory — `golang.org/x/mod/zip`
is what `cmd/go` builds one with, and it takes nothing from a parent — so the
repository root's copies do not travel with the module. Without them the module is
not redistributable and pkg.go.dev renders no licence, which is how it decides
whether to publish documentation at all. Keep both byte-identical to the root's;
`TestModuleShipsItsOwnLicence` fails if they drift.

One flat package, and deliberately no `internal/`. The sealed `Event` interface
needs its marker method declared alongside the generated event structs, and Go
forbids declaring a method on a type imported from another package — so splitting
models out would make the sealed interface impossible and degrade the 52 event
types to `any`.

## Regenerating

`models.gen.go` and `events.gen.go` come from the repository's `openapi.json`:

```bash
just go-sdk-gen        # or: python scripts/gen_go_client.py
just go-sdk-test
```

In a temp directory that is never committed, the generator narrows the document
to the schemas this package's API is built from, downgrades what is left into the
OAS 3.0 dialect `oapi-codegen`'s loader accepts, and then checks every surviving
schema keyword against an allowlist of what the downgrade handles. An unlisted
keyword is a build failure, so a new JSON-Schema construct stops the build rather
than quietly degrading a Go type. The allowlist constrains keywords, not values:
a new `format`, or a genuinely heterogeneous `anyOf`, still generates whatever
`oapi-codegen` makes of it.

Three more transformations run after that check, so the allowlist keeps
constraining what `openapi.json` says and not what the generator adds:

- **Event names are disambiguated.** Five trailing names are published under two
  `type` prefixes each — `response.heartbeat` and `session.heartbeat`,
  `response.created` and `session.created`, and `response.*` against `turn.*` for
  the three terminal states — and the spec prefixes only one member of each pair.
  The bare name therefore belonged to whichever the spec left unprefixed, which
  for the heartbeat is the wrong one: the heartbeat a caller actually sees is
  `session.heartbeat`. Every member of a colliding group is now namespaced from
  its own wire type (`ResponseHeartbeatEvent`, `SessionHeartbeatEvent`), the rule
  is collision-driven rather than a list, and each event's doc states its wire
  type verbatim. Unambiguous names are left alone, including deliberately nicer
  ones like `ToolOutputDeltaEvent`.
- **Descriptions are sanitised.** `openapi.json`'s prose is written for the people
  who maintain the server, so it cites emit sites, private attribute names and —
  in four example paths — a real home directory, and `oapi-codegen` copies it into
  Go doc comments that pkg.go.dev publishes. Those references are redacted and the
  prose around them is kept; an unfamiliar variant of one of those three shapes
  fails the build rather than reaching the docs. Public wire-level names that
  merely contain an underscore (`last_event_seq`, the
  `omnigent.codex_native.*` label keys) are untouched.

  What the sanitiser does not cover is a **dotted lowercase module path**, and the
  reason is that it cannot be recognised by shape:
  `omnigent.runtime.pending_inputs` and the wire-visible label key
  `omnigent.codex_native.collaboration_mode` are the same shape, so redacting the
  first without knowing which names the server publishes would also redact the
  second. Five such paths survive, in ten doc comments —
  `omnigent.server.schemas.ResponseObject` (3),
  `omnigent.runtime.pending_elicitations` (3),
  `omnigent.runtime.pending_inputs` (2),
  `omnigent.server.schemas.SessionEventInput` and
  `.ElicitationResult`. Three name a server-side schema class that models a payload
  this package already exposes as a Go type, so they are noise; the two
  `omnigent.runtime.*` ones name in-process server state a client cannot reach at
  all. None affects the wire contract, and the fix is a substitution table mapping
  each path to what it denotes rather than a wider pattern — deleting these
  references leaves sentences whose subject was the path.
- **Optional collections are nil, not pointers.** Every array- and map-valued
  schema opts out of `oapi-codegen`'s optional-field pointer, so
  `SessionResponse.Items` is `[]ConversationItem` rather than
  `*[]ConversationItem`. 23 fields had the pointer. Struct-valued fields keep
  theirs, where nil genuinely distinguishes absent from zeroed.

### Why the generated surface is narrower than the spec

Generating all 262 schema types exported an API nobody chose: 124 enum constants
at package scope with names like `URL`, `File` and `Input`, 46 types named after
FastAPI's path-mangled operationIds
(`UpdateMcpServerV1SessionsSessionIDAgentMcpServersServerNamePutJSONRequestBody`),
and a `ServerStreamEvent` union that was a second public representation of what
`Event` already models. What is generated now is the `$ref` closure of the
schemas this package's own signatures name — `SessionResponse`,
`ConversationDeleted`, `SessionGitOptions`, `ValidationError` — plus every member
of the event union, with `always-prefix-enum-values` so no enum constant occupies
a bare word at package scope. That is 322 exported package-scope identifiers
down from 424, and models.gen.go from 6,894 lines to 4,118.

The `github.com/oapi-codegen/runtime` dependency survives the narrowing: two
schemas inside the kept closure are genuine JSON-Schema unions —
`ConversationItem.data` (one of eleven item payloads) and `ValidationError.loc`
(a list of string-or-int) — and the generated accessors for those call
`runtime.JSONMerge`. Dropping `ServerStreamEvent` removes 52 accessor methods
over a `json.RawMessage`, not the module's only external dependency.

Narrowing does not weaken the drift gate. The roots are looked up by name and a
missing one fails the build; the event roots come from the union's own
`discriminator.mapping`, so a new variant is picked up automatically; and the
closure follows `$ref`, so a schema gaining a field or a reference to a new
schema still moves the generated bytes. What a spec change can no longer do is
force a Go type on this module for a route it does not implement.

Generated code is committed because `go get` fetches a module as source with no
build step: an ungenerated module simply does not compile for consumers. The
`go-client-fresh` pre-commit hook pins both files byte-for-byte to
`openapi.json`, which `tests/server/test_openapi_drift.py` in turn pins to the
live server. A route change that is not propagated fails at one of those two
links. The hook fails when `oapi-codegen` is absent instead of skipping;
`OMNIGENT_SKIP_GO_CLIENT_CHECK=1` downgrades that to a warning on a machine with
no Go toolchain, and CI ignores the variable.

Four types are hand-written because the server documents neither their routes
nor their schemas: `SessionCreateRequest` (the create route takes a raw request
and dispatches on `Content-Type`, so no `requestBody` is emitted), and
`SessionEventInput`, `EventAccepted` and `ElicitationResult` (the send route is
registered with `include_in_schema=False`, so neither its body nor its responses
appear in the spec). None of the four is covered by the drift gate, so a
server-side change to any of them breaks this client silently.

## CI

`sdks/go-client/bin/check.sh` — gofmt, `go build`, `go vet`, `go test -race`,
`go mod tidy -diff` — is what `just go-sdk-test` runs and what the required
`Pre-commit checks` job runs, so the two cannot drift. It lives inside that job
rather than a workflow of its own because
`.github/scripts/merge-ready/required.sh` is a generated file: a new workflow's
check name cannot be added to the required set from a PR, and an ungated check
rots. `.github/workflows/go-sdk.yml` adds golangci-lint and a two-version test
matrix; it is **advisory** until a maintainer adds its check names to whatever
generates `required.sh`.

## Notes on the stream

- **Cancelling a stream does not stop the agent.** The stream is a subscriber;
  the turn runs server-side regardless of who is listening. Real cancellation is
  `Client.Interrupt`.
- **A stream that ends is not a turn that finished.** Turn completion is a
  `ResponseCompletedEvent` and its siblings. A clean stream end means the server
  closed the subscription, which in practice means it is shutting down.
- **In-stream errors are events, not errors.** `ErrorEvent` is non-terminal and
  `RetryEvent` is informational; neither ends the subscription.
- **There is no resume.** On `ErrStreamInterrupted` or `ErrStreamIdle`, fetch the
  snapshot with `GetSession`, open a fresh stream, and dedupe persisted items by
  id. Some deployments cap stream duration at a few minutes, so this is routine.
- **The idle timeout bounds transport silence, not your handler.** The watchdog
  is suspended while the loop body runs, so a slow event handler cannot be
  mistaken for a dead server.
- **`SequenceNumber` is not a cursor.** It is nil on every `session.*` event and
  restarts each turn on the others. Order by arrival.
- **A frame is bounded, not just a line.** `bufio.Scanner` caps one line; the
  accumulated `data:` payload is capped too, so a server that never sends the
  blank line ending a frame fails with `ErrStreamFrameTooLarge` instead of growing
  the heap.
- **The idle watchdog reads the monotonic clock only.** A clock step or an NTP
  correction cannot cancel a healthy stream or hide a dead one.

`Stream` returns an `iter.Seq2[Event, error]`, which keeps errors and
cancellation on the caller's goroutine and makes a leak structurally impossible —
nothing is spawned, so there is nothing to leak. A `<-chan Event` plus an `Err()`
accessor is the pre-Go-1.23 equivalent and remains the fallback if the module's
floor ever has to drop below 1.23; it is recorded here so the choice is not
relitigated.
