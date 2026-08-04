package omnigent

// Event is one decoded frame from a session's event stream.
//
// The interface is sealed: its only implementations are the generated event
// structs in models.gen.go, one per member of the server's discriminated union,
// plus [UnknownEvent]. Consume it with a type switch:
//
//	switch ev := event.(type) {
//	case OutputTextDeltaEvent:
//		fmt.Print(ev.Delta)
//	case ResponseCompletedEvent:
//		return nil
//	}
//
// A minimal correct consumer needs relatively few of the variants. The turn
// lifecycle is [ResponseCreatedEvent], [InProgressEvent] and then exactly one of
// [ResponseCompletedEvent], [ResponseFailedEvent], [IncompleteEvent] or [ResponseCancelledEvent];
// assistant text arrives as [OutputTextDeltaEvent]; finished items as
// [OutputItemDoneEvent]; session-level state as [SessionStatusEvent]; and the
// echo of accepted input as [SessionInputConsumedEvent]. The rest — elicitation
// and approval flows, compaction, files, and session-metadata nudges — can be
// ignored without loss for that scope.
//
// Three things about the stream shape are easy to get wrong:
//
// Every stream opens with a fixed prologue, on every connect. First a
// [SessionHeartbeatEvent], which is the subscription acknowledgement — but note
// that it is indistinguishable from the keepalive of the same name that the
// server emits every 15 seconds on an idle stream, so it is a position in the
// stream and not a payload that marks "ready". Do not act on it; act on
// [StreamOptions.OnSubscribed], which fires once. Then, if a turn is already in flight, a
// REPLAY of the assistant text so far as a [ResponseCreatedEvent] plus one or more
// [OutputTextDeltaEvent] — already-emitted content, which double-renders if a
// snapshot was also fetched. Then a resource snapshot of session.* events. Only
// then does the live tail begin.
//
// Nothing that arrives in-stream ends the stream. [ErrorEvent] is
// non-terminal — the turn may still complete — and [RetryEvent] is purely
// informational. A turn ending is not a transport failure, and a transport
// failure says nothing about the turn, which keeps running server-side.
//
// SequenceNumber is not a stream cursor. It is nil on every session.* event and
// at best restarts from zero each turn on the others. Order by arrival.
//
// # Naming
//
// Each variant's doc states its wire type verbatim, and where two namespaces
// publish the same trailing name both are prefixed with theirs, so no bare name
// can stand for one of a pair. [ResponseHeartbeatEvent] is "response.heartbeat"
// and [SessionHeartbeatEvent] is "session.heartbeat"; likewise
// [ResponseCreatedEvent] against [SessionCreatedEvent], and
// [ResponseCompletedEvent], [ResponseFailedEvent] and [ResponseCancelledEvent]
// against their turn.* counterparts. The unprefixed name is nobody's: reaching
// for the wrong one of a pair now takes a deliberate act rather than a guess.
type Event interface {
	isEvent()
}

// UnknownEvent carries a frame whose discriminator this build does not know.
//
// It is not an error. The server's event schemas ignore unknown fields by
// contract so a new field cannot break an older parser, and this is the same
// guarantee one level up: a client built against an older openapi.json surfaces
// a newly added event type here and keeps streaming.
type UnknownEvent struct {
	// Type is the frame's discriminator, e.g. "session.something.new".
	Type string

	// Raw is the frame's JSON payload, owned by the caller.
	Raw []byte
}

func (UnknownEvent) isEvent() {}
