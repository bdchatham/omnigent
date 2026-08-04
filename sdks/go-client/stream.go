package omnigent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// doneSentinel terminates a stream cleanly. The server sends it as a bare
	// data line with no preceding event name, so it must be recognised before
	// any event-name handling.
	doneSentinel = "[DONE]"

	// maxFrameBytes caps one whole frame: the sum of its data: lines, not just
	// the longest of them. Both halves matter. bufio.Scanner.Buffer bounds a
	// single line, so without the accumulated bound a server that emits data:
	// lines and never the blank line that ends the frame grows this process's
	// heap until it dies. Snapshot frames listing a session's resources are the
	// large ones, and they are well inside this; anything past it fails the read
	// with ErrStreamFrameTooLarge rather than being absorbed.
	maxFrameBytes = 8 << 20
)

// StreamOptions configures one call to [Client.Stream].
type StreamOptions struct {
	// Idle marks this subscriber as present but inattentive, which co-viewers
	// see on their own streams as a presence edge. Flipping it means
	// reconnecting with the new value; there is no update path.
	Idle bool

	// IdleTimeout overrides the client's default tolerance for silence. The
	// server heartbeats every 15 seconds, so this bounds transport death
	// detection, not agent latency. Zero uses the client's setting.
	IdleTimeout time.Duration

	// OnSubscribed runs once the subscription is live, before the first event
	// reaches the caller, and is the supported way to post the input that
	// starts a turn. It runs on the caller's goroutine, so it must return
	// promptly; the idle watchdog is suspended while it does.
	//
	// It exists because the acknowledgement cannot be recognised by inspecting
	// events. The server sends the identical {"type": "session.heartbeat"}
	// payload for two different things — the subscription acknowledgement, and
	// the keepalive it emits every 15 seconds while a stream sits idle — so
	// "send when I see a heartbeat" sends again on every keepalive, forever.
	// This hook is called exactly once per stream, whatever the frames look
	// like — or not at all, if the stream ends before delivering an event.
	// Returning an error ends the stream with that error wrapped.
	//
	// Seeding the first turn through [SessionCreateRequest.InitialItems] avoids
	// needing this at all; it is the second and later turns that do.
	//
	// The second parameter is a struct rather than a growing parameter list
	// because this is the package's headline hook: its signature is the one thing
	// here that cannot be extended later without breaking every caller. What a
	// subscription is worth telling a caller about will grow; see [Subscription].
	OnSubscribed func(ctx context.Context, sub Subscription) error
}

// Subscription describes the live subscription an [StreamOptions.OnSubscribed]
// hook was called for.
//
// Fields will be added to it. Construct one with field names — go vet's
// composites check enforces that for a struct from another package — and it
// stays source-compatible as it grows.
type Subscription struct {
	// SessionID is the session this stream is subscribed to, so a hook shared
	// between streams does not need to close over it.
	SessionID string

	// Idle mirrors [StreamOptions.Idle]: whether this subscriber declared itself
	// present but inattentive.
	Idle bool
}

// Stream subscribes to a session's event stream.
//
// Range over the result; each step is one decoded [Event] or a terminal error:
//
//	for event, err := range client.Stream(ctx, sessionID, omnigent.StreamOptions{}) {
//		if err != nil {
//			return err
//		}
//		// handle event
//	}
//
// Errors are terminal by construction — an error step is always the last — so
// the loop needs no break after one. In-stream failures are not errors here:
// [ErrorEvent], [RetryEvent] and a failed turn all arrive as ordinary events,
// because none of them ends the subscription.
//
// No I/O happens until the first iteration, and none continues past the last:
// this spawns no goroutine, so abandoning the loop early cannot leak one.
// Breaking out of it, or cancelling ctx, closes the response body.
//
// Validation is the one place this package reports an argument error late. Every
// other entry point returns an error and so rejects a bad argument before doing
// any work; Stream returns a sequence, which has nowhere to put an error except
// the sequence itself, so an empty sessionID surfaces as the first and only step
// — matchable with errors.Is against [ErrInvalidArgument].
//
// Ending without an error means the server closed the subscription cleanly. In
// practice that means the server is shutting down rather than that the turn
// finished — turn completion is a [CompletedEvent] and its siblings. Every other
// ending is an error: [ErrStreamInterrupted] for a body that stopped without the
// terminal sentinel, [ErrStreamIdle] for silence past the timeout, ctx's error
// for cancellation, or an [APIError] if the subscription was refused outright.
// Recovery from the first two is snapshot, resubscribe, dedupe — see the package
// doc.
func (c *Client) Stream(ctx context.Context, sessionID string, opts StreamOptions) iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		if sessionID == "" {
			yield(nil, fmt.Errorf("stream session: %w: sessionID is required", ErrInvalidArgument))
			return
		}
		idleTimeout := opts.IdleTimeout
		if idleTimeout <= 0 {
			idleTimeout = c.idleTimeout
		}

		// A derived context lets the idle watchdog end the request without
		// touching the caller's, so the two causes stay distinguishable below.
		streamCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		query := url.Values{}
		if opts.Idle {
			query.Set("idle", "true")
		}
		segments := []string{"v1", "sessions", sessionID, "stream"}
		req, err := c.newRequest(streamCtx, http.MethodGet, segments, query, nil)
		if err != nil {
			yield(nil, err)
			return
		}
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Cache-Control", "no-cache")

		// c.stream, not c.unary: a whole-exchange timeout would sever a healthy
		// stream at the deadline. Liveness is the watchdog's job instead.
		resp, err := c.stream.Do(req)
		if err != nil {
			yield(nil, fmt.Errorf("open stream for session %s: %w", sessionID, err))
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			yield(nil, fmt.Errorf("open stream for session %s: %w", sessionID, newAPIError(resp)))
			return
		}

		watchdog := newIdleWatchdog(idleTimeout, cancel)
		defer watchdog.stop()

		lines := bufio.NewScanner(resp.Body)
		lines.Buffer(make([]byte, 0, 64<<10), maxFrameBytes)

		var (
			name       string
			payload    strings.Builder
			sawDone    bool
			subscribed bool
		)
	read:
		for lines.Scan() {
			// The read that just returned proves the transport is alive,
			// heartbeats included.
			watchdog.alive()

			line := lines.Text()
			switch {
			case line == "":
				event, done, err := decodeFrame(name, payload.String())
				name = ""
				payload.Reset()
				switch {
				case err != nil:
					yield(nil, fmt.Errorf("stream for session %s: %w", sessionID, err))
					return
				case done:
					sawDone = true
					break read
				case event == nil:
					// An empty frame: nothing to hand a caller.
				default:
					if !subscribed {
						subscribed = true
						if opts.OnSubscribed != nil {
							// ctx, not streamCtx: the hook's own request should
							// fail for the caller's reason, never the
							// watchdog's.
							watchdog.suspend()
							err := opts.OnSubscribed(ctx, Subscription{
								SessionID: sessionID,
								Idle:      opts.Idle,
							})
							watchdog.resume()
							if err != nil {
								yield(nil, fmt.Errorf("stream for session %s: on subscribed: %w", sessionID, err))
								return
							}
						}
					}
					watchdog.suspend()
					keepGoing := yield(event, nil)
					watchdog.resume()
					if !keepGoing {
						return
					}
				}
			case strings.HasPrefix(line, ":"):
				// A comment, which this server never sends but the format allows.
			case strings.HasPrefix(line, "event:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				chunk := strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
				// Bound the frame, not just the line: without this a server that
				// never sends the blank line ending the frame would grow this
				// builder until the process died.
				if payload.Len()+len(chunk)+1 > maxFrameBytes {
					yield(nil, fmt.Errorf("stream for session %s: %w of %d bytes",
						sessionID, ErrStreamFrameTooLarge, maxFrameBytes))
					return
				}
				if payload.Len() > 0 {
					payload.WriteByte('\n')
				}
				payload.WriteString(chunk)
			default:
				// id: and retry: are unused by this server; ignore any other field
				// rather than failing, so a future one is not a breaking change.
			}
		}

		switch {
		case sawDone:
			return
		case watchdog.expired():
			yield(nil, fmt.Errorf("stream for session %s: %w after %s", sessionID, ErrStreamIdle, idleTimeout))
		case ctx.Err() != nil:
			yield(nil, fmt.Errorf("stream for session %s: %w", sessionID, ctx.Err()))
		case errors.Is(lines.Err(), bufio.ErrTooLong):
			// One line past the frame bound, rather than an accumulation of
			// them. Same diagnosis, same sentinel.
			yield(nil, fmt.Errorf("stream for session %s: %w of %d bytes",
				sessionID, ErrStreamFrameTooLarge, maxFrameBytes))
		case lines.Err() != nil:
			// Join both: callers match ErrStreamInterrupted to decide to
			// reconcile, and the transport error to decide whether to back off.
			yield(nil, fmt.Errorf("read stream for session %s: %w",
				sessionID, errors.Join(lines.Err(), ErrStreamInterrupted)))
		default:
			yield(nil, fmt.Errorf("stream for session %s: %w", sessionID, ErrStreamInterrupted))
		}
	}
}

// idleWatchdog cancels a stream whose transport has gone quiet for longer than
// its timeout.
//
// It deliberately does not re-arm a timer per frame. time.Timer.Reset does not
// un-run a callback that has already started, so a frame landing as the timer
// expires would cancel a healthy stream and report [ErrStreamIdle] while data
// was flowing. Here the read loop only records a timestamp, and the timer's
// callback is the only thing that arms the timer: it re-reads that timestamp and
// cancels only if the recorded activity really is older than the timeout.
//
// The timeout measures time blocked on a read, not wall-clock time on the
// stream: suspend and resume bracket every call out of the read loop, because a
// slow event handler is not a dead server.
//
// It measures that on the monotonic clock, and never on the wall clock. A stream
// has no other liveness control, so an operator correcting the system time — or
// an NTP step, or a VM resuming from a snapshot — must not be able to either
// cancel a healthy stream or hide a dead one. Storing a wall-clock timestamp and
// asking time.Since about it later cannot do that: time.Unix reconstructs a Time
// with no monotonic reading, so the comparison is wall-to-wall.
type idleWatchdog struct {
	timeout time.Duration
	cancel  context.CancelFunc

	// elapsed reports monotonic time since this watchdog was created. It is a
	// field so a test can drive the clock instead of racing it.
	elapsed func() time.Duration

	// last is the reading of elapsed at the most recent recorded activity.
	// While paused is set, check re-arms without judging that reading at all.
	// fired records that the watchdog is what ended the stream; it is stored
	// before cancel, so the read loop sees it once the read fails.
	last   atomic.Int64
	paused atomic.Bool
	fired  atomic.Bool

	// mu guards timer, which the callback re-arms and stop clears. Held across
	// the initial time.AfterFunc so a callback that beats the assignment blocks
	// until it lands.
	mu    sync.Mutex
	timer *time.Timer
}

func newIdleWatchdog(timeout time.Duration, cancel context.CancelFunc) *idleWatchdog {
	// time.Now carries a monotonic reading and time.Since uses it, so every
	// measurement below is a difference of two monotonic readings.
	start := time.Now()
	return newIdleWatchdogWithClock(timeout, cancel, func() time.Duration {
		return time.Since(start)
	})
}

// newIdleWatchdogWithClock is newIdleWatchdog over an explicit clock, so a test
// can state what "the stream has been quiet for longer than the timeout" means
// instead of sleeping and hoping.
func newIdleWatchdogWithClock(
	timeout time.Duration,
	cancel context.CancelFunc,
	elapsed func() time.Duration,
) *idleWatchdog {
	w := &idleWatchdog{timeout: timeout, cancel: cancel, elapsed: elapsed}
	w.alive()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.timer = time.AfterFunc(timeout, w.check)
	return w
}

// alive records that the transport delivered something.
func (w *idleWatchdog) alive() { w.last.Store(int64(w.elapsed())) }

// suspend stops the clock for as long as the read loop is not reading.
func (w *idleWatchdog) suspend() { w.paused.Store(true) }

// resume restarts the clock from now. Pairs with suspend around every call the
// read loop makes into the caller's code.
func (w *idleWatchdog) resume() {
	w.alive()
	w.paused.Store(false)
}

// expired reports whether the watchdog is what ended the stream.
func (w *idleWatchdog) expired() bool { return w.fired.Load() }

// check runs on the timer's expiry: cancel if the stream really has been quiet
// for the whole timeout, otherwise re-arm for the remainder.
func (w *idleWatchdog) check() {
	if w.paused.Load() {
		w.rearm(w.timeout)
		return
	}
	quiet := w.elapsed() - time.Duration(w.last.Load())
	if remaining := w.timeout - quiet; remaining > 0 {
		w.rearm(remaining)
		return
	}
	w.fired.Store(true)
	w.cancel()
}

func (w *idleWatchdog) rearm(after time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer != nil {
		w.timer.Reset(after)
	}
}

// stop releases the timer. Further expiries cannot re-arm it.
func (w *idleWatchdog) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
}

// decodeFrame turns one complete frame into an event.
//
// It reports done for the terminal sentinel, and a nil event with no error for a
// frame carrying no payload — neither is something to hand a caller.
func decodeFrame(name, payload string) (Event, bool, error) {
	payload = strings.TrimRight(payload, "\n")
	if strings.TrimSpace(payload) == "" {
		return nil, false, nil
	}
	if strings.TrimSpace(payload) == doneSentinel {
		return nil, true, nil
	}

	// Dispatch on the payload's own discriminator rather than the event: line.
	// The server derives the line from this field, and taking it from the JSON
	// keeps frame parsing off the correctness path — including for a sentinel or
	// a future frame that carries no event name at all.
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(payload), &probe); err != nil {
		return nil, false, fmt.Errorf("%w: %w: %s", ErrStreamProtocol, err, bodyPreview([]byte(payload)))
	}
	typ := probe.Type
	if typ == "" {
		typ = name
	}
	if typ == "" {
		return nil, false, fmt.Errorf("%w: no discriminator: %s", ErrStreamProtocol, bodyPreview([]byte(payload)))
	}

	event, err := decodeEvent(typ, []byte(payload))
	if err != nil {
		return nil, false, err
	}
	return event, false, nil
}
