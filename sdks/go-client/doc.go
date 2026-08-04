// Package omnigent is a Go client for the omnigent server's session API.
//
// It covers the core surface: constructing an authenticated client, the session
// lifecycle, posting input to a session, and consuming the session's
// server-sent event stream as typed [Event] values.
//
// # Quickstart
//
//	client, err := omnigent.New(omnigent.DefaultBaseURL)
//	if err != nil {
//		return err
//	}
//
//	session, err := client.CreateSession(ctx, omnigent.SessionCreateRequest{AgentID: agentID})
//	if err != nil {
//		return err
//	}
//
//	// Open the stream before posting, so the turn's first deltas cannot be
//	// missed: the server buffers nothing for absent subscribers. OnSubscribed
//	// runs once the subscription is live, and only once.
//	opts := omnigent.StreamOptions{
//		OnSubscribed: func(ctx context.Context, sub omnigent.Subscription) error {
//			_, err := client.SendMessage(ctx, sub.SessionID, "hello")
//			return err
//		},
//	}
//	for event, err := range client.Stream(ctx, session.ID, opts) {
//		if err != nil {
//			return err
//		}
//		switch ev := event.(type) {
//		case omnigent.OutputTextDeltaEvent:
//			fmt.Print(ev.Delta)
//		case omnigent.ResponseCompletedEvent:
//			return nil
//		}
//	}
//
// # Send-after-subscribe, and the heartbeat that looks like a signal
//
// The stream buffers nothing for absent subscribers, so input must not be posted
// until the subscription exists. The obvious-looking way to detect that is to
// wait for the first [SessionHeartbeatEvent] and send from there — and it is
// wrong. The server uses one event, with a byte-identical payload, for two
// unrelated jobs: the subscription acknowledgement it yields the moment the
// subscriber slot is registered, and the keepalive it emits every 15 seconds
// while a stream sits idle between turns. Nothing on the wire tells them apart.
// A caller that sends on every heartbeat therefore re-sends its message for as
// long as the stream stays open.
//
// [StreamOptions.OnSubscribed] is this package's answer: the iterator calls it
// once, before the first event reaches the caller, and never again for that
// stream. Where the input can be known up front,
// [SessionCreateRequest.InitialItems] is better still — the server queues it at
// create time, so there is no ordering to get right.
//
// # Generated versus hand-written
//
// models.gen.go and events.gen.go are generated from the repository's
// openapi.json by scripts/gen_go_client.py, together with the type-string
// dispatch for the 52 variants of the SSE event union. Do not edit them;
// regenerate instead.
//
// The generated surface is deliberately narrower than the spec. It is the $ref
// closure of the schemas this package's own API names — [SessionResponse],
// [ConversationDeleted], [SessionGitOptions], [ValidationError], [AgentObject],
// [SessionListItem] — plus every member of the event union. Generating the whole
// document would export types named after the server's path-mangled operationIds
// and a second public representation of what [Event] already models, neither of
// which is API this module intends to offer.
//
// Four types are hand-written in session.go because the server documents neither
// their routes nor their schemas, so openapi.json carries nothing to generate
// them from and no drift gate covers them:
// [SessionCreateRequest] (the create route takes a raw request and dispatches on
// Content-Type, so FastAPI emits no requestBody for it), and
// [SessionEventInput], [EventAccepted] and [ElicitationResult] (the send route is
// registered with include_in_schema=False, so neither its body nor its responses
// appear). A server-side change to any of the four breaks this client silently.
//
// # Listings
//
// [Client.ListAgents] and [Client.ListSessions] page by opaque cursor into a
// shared [Page]. Between them they cover the two lookups a program needs before
// it can do anything else: turning an agent name into the id a create wants, and
// finding a session it created on an earlier run rather than creating a second
// one. See [Page] for the paging loop and [ListSessionsOptions] for the filters.
//
// # Timeouts
//
// Go's http.Client.Timeout is a deadline on the whole exchange including reading
// the response body, so any non-zero value severs a healthy long-lived stream.
// This package therefore keeps two clients over one transport: unary calls carry
// a whole-exchange timeout, and the streaming client's is zero. Liveness on the
// stream is enforced instead by an idle watchdog — the server emits a heartbeat
// frame every 15 seconds of queue silence, so a read that blocks for longer than
// [StreamOptions.IdleTimeout] means the transport is gone. The watchdog measures
// time blocked on a read, not wall-clock time: it is suspended while the caller's
// own loop body runs, so a slow event handler cannot be mistaken for a dead
// server. Connect and response-header latency stay bounded for both clients by
// the transport's ResponseHeaderTimeout.
//
// # Cancellation
//
// Every call takes a context.Context, and cancelling it is the only way to stop
// a stream. Note what that does and does not do: dropping the stream ends the
// *subscription*, not the agent's turn. The turn runs on the server side
// independently of any subscriber. To actually stop work, post an interrupt with
// [Client.Interrupt].
//
// # Errors
//
// Every error this package returns is matchable with errors.Is against one of
// the sentinels in errors.go, and a server response also unwraps to [APIError]
// with errors.As for the status, the server's error code, and the X-Request-Id
// to quote when reporting it. [ErrInvalidArgument] is the odd one out: it means
// this package rejected the call before sending anything.
//
// # Security
//
// A client that holds a credential has to be careful about four things, and this
// package's answer to each is fail-closed rather than best-effort.
//
// Transport. A credential must not cross a network in clear. [New] therefore
// refuses a plain-http base URL once an auth option is supplied, unless the host
// is loopback — which is why [DefaultBaseURL] works as it is: nothing leaves the
// machine. A deployment where the plaintext hop is genuinely not a network (a
// sidecar, a port-forward, a mesh that terminates TLS ahead of you) opts in with
// [WithInsecureCredentialTransport]. There is no warn-and-continue option: a
// library has no logger to warn into, and silence is how a token ends up on a
// shared segment.
//
// Redirects. Neither of this package's http.Clients follows a redirect off the
// base URL's host, down from https to http, or across a method rewrite. Go's own
// rule strips only Authorization, Cookie, Www-Authenticate and Cookie2 on a
// cross-host hop, which leaves a custom identity header — [WithAuthHeader]'s, the
// trusted-proxy one — travelling to whatever host the response named; it compares
// hostnames and not schemes, so an https-to-http hop keeps the credential and
// loses the encryption; a cross-host 307 or 308 replays the request body, which
// here is the caller's prompt; and a 302 on a POST becomes a GET, so a dropped
// write would return 200. All four are [ErrUnsafeRedirect]. A caller supplying an
// http.Client with its own CheckRedirect keeps it, and owns that.
//
// Base URLs. A base URL carrying userinfo is rejected rather than quietly
// becoming Basic auth on every request, and no error from [New] echoes the base
// URL's password — the parse-failure path reports the reason without the value,
// because url.Parse's own error quotes back what it was handed.
//
// Error values. [APIError.Error] renders the status, the server's error code and
// message, and the request id, and never the response body: a non-2xx body may
// come from a proxy rather than this API, and an error string is the one thing
// that reliably reaches a log aggregator. [APIError.Header] has the headers that
// carry a credential by specification removed. See [APIError] for the detail.
//
// What this package does not do: it never touches TLS configuration. There is no
// option to skip verification, pin a root, or reach a tls.Config, because a
// client that can be talked into trusting anything is not a security boundary.
// A deployment with a private CA configures it where such things belong — the
// system trust store, or a transport the caller builds and passes to
// [WithHTTPClient].
//
// # Reconnection
//
// The stream is live-tail only. There is no resume: the server emits no SSE
// id: field, honours no Last-Event-ID, and drops events published while nobody
// is subscribed. When a stream ends with [ErrStreamInterrupted] or
// [ErrStreamIdle], recover by fetching the snapshot with [Client.GetSession],
// opening a fresh stream, and deduping persisted items by id. Reconnection is
// routine rather than exceptional — some deployments cap HTTP stream duration at
// a few minutes.
package omnigent
