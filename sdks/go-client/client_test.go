package omnigent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		baseURL string
		opts    []Option
		wantErr string
	}{
		{name: "defaults when base URL is empty"},
		{name: "http", baseURL: "http://example.test:6767"},
		{name: "https with a path prefix", baseURL: "https://example.test/omnigent"},
		{name: "rejects a non-http scheme", baseURL: "ftp://example.test", wantErr: "http or https"},
		{name: "rejects a host-less URL", baseURL: "http://", wantErr: "no host"},
		{name: "rejects an unparseable URL", baseURL: "http://[::1", wantErr: "parse base URL"},
		{
			name:    "rejects a nil http client",
			opts:    []Option{WithHTTPClient(nil)},
			wantErr: "nil client",
		},
		{
			name:    "rejects an unnamed auth header",
			opts:    []Option{WithAuthHeader("", "someone@example.test")},
			wantErr: "empty header name",
		},
		{
			name:    "rejects an empty bearer token",
			opts:    []Option{WithBearerToken("")},
			wantErr: "empty token",
		},
		{
			name:    "rejects an unnamed session cookie",
			opts:    []Option{WithSessionCookie("", "value")},
			wantErr: "empty cookie name",
		},
		{
			name:    "rejects a negative idle timeout",
			opts:    []Option{WithStreamIdleTimeout(-time.Second)},
			wantErr: "negative duration",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, err := New(tc.baseURL, tc.opts...)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("New(%q) = nil error, want one containing %q", tc.baseURL, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("New(%q) error = %q, want it to contain %q", tc.baseURL, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q) = %v, want no error", tc.baseURL, err)
			}
			if !strings.HasSuffix(client.baseURL.Path, "/") {
				t.Errorf("base path = %q, want a trailing slash so a mount prefix survives", client.baseURL.Path)
			}
			if client.unary.Timeout == 0 {
				t.Error("unary client has no timeout; a unary call could hang forever")
			}
			if client.stream.Timeout != 0 {
				t.Errorf("stream client timeout = %s, want 0: a whole-exchange deadline severs a healthy stream",
					client.stream.Timeout)
			}
			if client.unary.Transport != client.stream.Transport {
				t.Error("unary and stream clients have different transports; they should share a connection pool")
			}
		})
	}
}

func TestClientRequestShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		baseURL   string
		opts      []Option
		call      func(context.Context, *Client) error
		wantPath  string
		wantQuery string
		wantHead  map[string]string
	}{
		{
			name: "create posts JSON to the sessions collection",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.CreateSession(ctx, SessionCreateRequest{AgentID: "ag_1"})
				return err
			},
			wantPath: "/v1/sessions",
			wantHead: map[string]string{"Content-Type": "application/json", "Accept": "application/json"},
		},
		{
			name:    "get honours a mounted base path",
			baseURL: "%s/omnigent",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetSession(ctx, "conv_1", GetSessionOptions{})
				return err
			},
			wantPath: "/omnigent/v1/sessions/conv_1",
		},
		{
			name: "get serialises its options as query parameters",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetSession(ctx, "conv_1", GetSessionOptions{
					IncludeItems:    Ptr(false),
					IncludeLiveness: Ptr(true),
					RefreshState:    Ptr(false),
				})
				return err
			},
			wantPath:  "/v1/sessions/conv_1",
			wantQuery: "include_items=false&include_liveness=true&refresh_state=false",
		},
		{
			name: "delete opts into branch cleanup",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.DeleteSession(ctx, "conv_1", DeleteSessionOptions{DeleteBranch: true})
				return err
			},
			wantPath:  "/v1/sessions/conv_1",
			wantQuery: "delete_branch=true",
		},
		{
			name:     "send posts to the undocumented events route",
			call:     func(ctx context.Context, c *Client) error { _, err := c.SendMessage(ctx, "conv_1", "hi"); return err },
			wantPath: "/v1/sessions/conv_1/events",
		},
		{
			name: "a session id needing escaping cannot traverse the path",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetSession(ctx, "conv/../admin", GetSessionOptions{})
				return err
			},
			wantPath: "/v1/sessions/conv%2F..%2Fadmin",
		},
		{
			name: "proxy header auth rides every request",
			opts: []Option{WithAuthHeader("X-Forwarded-Email", "someone@example.test")},
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetSession(ctx, "conv_1", GetSessionOptions{})
				return err
			},
			wantPath: "/v1/sessions/conv_1",
			wantHead: map[string]string{"X-Forwarded-Email": "someone@example.test"},
		},
		{
			name: "bearer auth rides every request",
			opts: []Option{WithBearerToken("tok"), WithUserAgent("test-agent/1")},
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetSession(ctx, "conv_1", GetSessionOptions{})
				return err
			},
			wantPath: "/v1/sessions/conv_1",
			wantHead: map[string]string{"Authorization": "Bearer tok", "User-Agent": "test-agent/1"},
		},
		{
			name: "cookie auth rides every request",
			opts: []Option{WithSessionCookie("ap_session", "sess")},
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetSession(ctx, "conv_1", GetSessionOptions{})
				return err
			},
			wantPath: "/v1/sessions/conv_1",
			wantHead: map[string]string{"Cookie": "ap_session=sess"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A buffered channel rather than a shared variable, so the handler's
			// write and this goroutine's read are ordered.
			requests := make(chan *http.Request, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.Clone(r.Context())
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"conv_1","agent_id":"ag_1","status":"idle","created_at":1,"queued":true}`))
			}))
			defer server.Close()

			baseURL := server.URL
			if strings.Contains(tc.baseURL, "%s") {
				baseURL = strings.Replace(tc.baseURL, "%s", server.URL, 1)
			}
			client, err := New(baseURL, tc.opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := tc.call(context.Background(), client); err != nil {
				t.Fatalf("call: %v", err)
			}
			var got *http.Request
			select {
			case got = <-requests:
			default:
				t.Fatal("the server saw no request")
			}
			if got.URL.EscapedPath() != tc.wantPath {
				t.Errorf("path = %q, want %q", got.URL.EscapedPath(), tc.wantPath)
			}
			if got.URL.RawQuery != tc.wantQuery {
				t.Errorf("query = %q, want %q", got.URL.RawQuery, tc.wantQuery)
			}
			for name, want := range tc.wantHead {
				if have := got.Header.Get(name); have != want {
					t.Errorf("header %s = %q, want %q", name, have, want)
				}
			}
		})
	}
}

func TestClientRequiresIdentifiers(t *testing.T) {
	t.Parallel()

	client, err := New("http://example.invalid")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
		want string
	}{
		{"create without an agent", func() error { _, err := client.CreateSession(ctx, SessionCreateRequest{}); return err }, "AgentID is required"},
		{"get without a session", func() error { _, err := client.GetSession(ctx, "", GetSessionOptions{}); return err }, "sessionID is required"},
		{"delete without a session", func() error { _, err := client.DeleteSession(ctx, "", DeleteSessionOptions{}); return err }, "sessionID is required"},
		{"send without a session", func() error { _, err := client.SendMessage(ctx, "", "hi"); return err }, "sessionID is required"},
		{"send without a type", func() error { _, err := client.SendInput(ctx, "conv_1", SessionEventInput{}); return err }, "Type is required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.call()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestClientDecodesResponses(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sessions":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"conv_1","agent_id":"ag_1","status":"running","created_at":1700000000}`))
		case r.Method == http.MethodDelete:
			_, _ = w.Write([]byte(`{"id":"conv_1","deleted":true,"object":"conversation.deleted"}`))
		default:
			_, _ = w.Write([]byte(`{"queued":true,"item_id":"item_9"}`))
		}
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	session, err := client.CreateSession(ctx, SessionCreateRequest{AgentID: "ag_1"})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if session.ID != "conv_1" || session.Status != "running" || session.CreatedAt != 1700000000 {
		t.Errorf("session = %+v, want conv_1/running/1700000000", session)
	}

	accepted, err := client.SendMessage(ctx, "conv_1", "hello")
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if !accepted.Queued || accepted.ItemID != "item_9" {
		t.Errorf("accepted = %+v, want queued with item_9", accepted)
	}

	if err := client.Interrupt(ctx, "conv_1"); err != nil {
		t.Fatalf("Interrupt: %v", err)
	}

	deleted, err := client.DeleteSession(ctx, "conv_1", DeleteSessionOptions{})
	if err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if deleted.ID != "conv_1" {
		t.Errorf("deleted.ID = %q, want conv_1", deleted.ID)
	}
}

func TestClientContextCancellation(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	client, err := New(server.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.GetSession(ctx, "conv_1", GetSessionOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("GetSession error = %v, want it to wrap context.Canceled", err)
	}
}

func TestUserMessage(t *testing.T) {
	t.Parallel()

	input := UserMessage("hello")
	if input.Type != InputTypeMessage {
		t.Errorf("Type = %q, want %q", input.Type, InputTypeMessage)
	}
	if input.Data["role"] != "user" {
		t.Errorf("role = %v, want user", input.Data["role"])
	}
	content, ok := input.Data["content"].([]map[string]any)
	if !ok || len(content) != 1 {
		t.Fatalf("content = %#v, want one part", input.Data["content"])
	}
	if content[0]["type"] != "input_text" || content[0]["text"] != "hello" {
		t.Errorf("content part = %#v, want an input_text part carrying the text", content[0])
	}
}

func TestWithSessionCookieEmitsOneCookieHeader(t *testing.T) {
	t.Parallel()

	// header.Add would emit two Cookie lines. RFC 6265 allows exactly one on a
	// request, and the server's ASGI framework reads only the first.
	requests := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"conv_1","deleted":true,"object":"conversation.deleted"}`))
	}))
	defer server.Close()

	client, err := New(server.URL,
		WithSessionCookie("ap_session", "first"),
		WithSessionCookie("csrf", "second"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.DeleteSession(context.Background(), "conv_1", DeleteSessionOptions{}); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	got := <-requests
	if lines := got.Header.Values("Cookie"); len(lines) != 1 {
		t.Fatalf("Cookie header lines = %d %q, want exactly 1", len(lines), lines)
	}
	if want := "ap_session=first; csrf=second"; got.Header.Get("Cookie") != want {
		t.Errorf("Cookie = %q, want %q", got.Header.Get("Cookie"), want)
	}
}

func TestClientArgumentErrorsAreMatchable(t *testing.T) {
	t.Parallel()

	client, err := New("http://example.invalid")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	calls := map[string]func() error{
		"create without an agent": func() error {
			_, err := client.CreateSession(ctx, SessionCreateRequest{})
			return err
		},
		"get without a session": func() error {
			_, err := client.GetSession(ctx, "", GetSessionOptions{})
			return err
		},
		"delete without a session": func() error {
			_, err := client.DeleteSession(ctx, "", DeleteSessionOptions{})
			return err
		},
		"send without a session": func() error { _, err := client.SendMessage(ctx, "", "hi"); return err },
		"send without a type": func() error {
			_, err := client.SendInput(ctx, "conv_1", SessionEventInput{})
			return err
		},
		"a non-http base URL":     func() error { _, err := New("ftp://example.test"); return err },
		"an option given no name": func() error { _, err := New("", WithAuthHeader("", "x")); return err },
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := call()
			if !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("error = %v, want it to wrap ErrInvalidArgument", err)
			}
			// An argument error is not a server response, so it must not look
			// like one to a caller switching on the sentinels.
			if errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrValidation) {
				t.Errorf("error = %v, want it not to masquerade as a server rejection", err)
			}
		})
	}
}

// TestNewRejectsUserinfoInTheBaseURL is S8's first half. net/http turns a base
// URL's userinfo into an Authorization: Basic header on every request — see
// Client.send in net/http/client.go — so a URL copied out of a browser silently
// becomes a credential this package never agreed to send, on a scheme the server
// does not offer. Against feat/go-client-v2 New returns a working Client here.
func TestNewRejectsUserinfoInTheBaseURL(t *testing.T) {
	t.Parallel()

	for _, baseURL := range []string{
		"http://someone:s3cr3t@127.0.0.1:6767",
		"https://someone:s3cr3t@example.test",
		"https://someone@example.test",
	} {
		t.Run(baseURL, func(t *testing.T) {
			t.Parallel()

			client, err := New(baseURL)
			if err == nil {
				t.Fatalf("New(%q) = %v, nil error: userinfo would become Basic auth", baseURL, client)
			}
			if !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("error = %v, want it to wrap ErrInvalidArgument", err)
			}
			if !strings.Contains(err.Error(), "userinfo") {
				t.Errorf("error %q does not say what was wrong", err)
			}
		})
	}
}

// TestNewNeverEchoesAPasswordFromTheBaseURL is S8's second half. Every rejection
// path in New used to render the base URL with %q, and url.Parse's own error does
// the same, so a password reached the error string — the one place a credential
// most reliably ends up in a log. Against feat/go-client-v2 the unparseable case
// fails: the message contains the password verbatim.
func TestNewNeverEchoesAPasswordFromTheBaseURL(t *testing.T) {
	t.Parallel()

	const password = "pa55word-must-not-appear"

	tests := []struct {
		name    string
		baseURL string
	}{
		{"unparseable, so only url.Parse's message is available", "http://someone:" + password + "@[::1"},
		{"userinfo on an otherwise valid URL", "https://someone:" + password + "@example.test"},
		{"a scheme this package does not speak", "ftp://someone:" + password + "@example.test"},
		{"no host at all", "http://someone:" + password + "@"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(tc.baseURL)
			if err == nil {
				t.Fatalf("New(%q) = nil error, want one", tc.baseURL)
			}
			if strings.Contains(err.Error(), password) {
				t.Errorf("error %q leaks the base URL's password", err)
			}
		})
	}
}

// TestNewRefusesAPlaintextCredentialOffTheMachine is S6. Sending a bearer token
// over plain http to a host that is not this machine puts it on a network in
// clear, and feat/go-client-v2 accepts that silently. Refusing is the only
// fail-closed answer a library can give: it has no logger to warn into.
func TestNewRefusesAPlaintextCredentialOffTheMachine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		baseURL string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "bearer token over http to a remote host",
			baseURL: "http://api.example.test",
			opts:    []Option{WithBearerToken("tok")},
			wantErr: true,
		},
		{
			name:    "proxy identity header over http to a remote host",
			baseURL: "http://api.example.test",
			opts:    []Option{WithAuthHeader("X-Forwarded-Email", "someone@example.test")},
			wantErr: true,
		},
		{
			name:    "session cookie over http to a remote host",
			baseURL: "http://api.example.test",
			opts:    []Option{WithSessionCookie("ap_session", "sess")},
			wantErr: true,
		},
		{
			name:    "a remote IP is no different from a name",
			baseURL: "http://198.51.100.7:6767",
			opts:    []Option{WithBearerToken("tok")},
			wantErr: true,
		},
		{
			name:    "the option order does not change the answer",
			baseURL: "http://api.example.test",
			opts:    []Option{WithBearerToken("tok"), WithUserAgent("test/1")},
			wantErr: true,
		},
		// Loopback over http is legitimate and must keep working: nothing leaves
		// the machine, which is what makes DefaultBaseURL a reasonable default.
		{name: "the default base URL with a credential", opts: []Option{WithBearerToken("tok")}},
		{name: "loopback by IPv4", baseURL: "http://127.0.0.1:6767", opts: []Option{WithBearerToken("tok")}},
		{name: "loopback by IPv6", baseURL: "http://[::1]:6767", opts: []Option{WithBearerToken("tok")}},
		{name: "loopback by name", baseURL: "http://localhost:6767", opts: []Option{WithBearerToken("tok")}},
		{
			name:    "a name reserved under localhost",
			baseURL: "http://omnigent.localhost:6767",
			opts:    []Option{WithBearerToken("tok")},
		},
		// And so are https anywhere, plain http with no credential, and the
		// explicit opt-in.
		{name: "https to a remote host", baseURL: "https://api.example.test", opts: []Option{WithBearerToken("tok")}},
		{name: "http to a remote host with no credential", baseURL: "http://api.example.test"},
		{
			name:    "the explicit opt-in",
			baseURL: "http://api.example.test",
			opts:    []Option{WithBearerToken("tok"), WithInsecureCredentialTransport()},
		},
		{
			name:    "the opt-in before the credential",
			baseURL: "http://api.example.test",
			opts:    []Option{WithInsecureCredentialTransport(), WithBearerToken("tok")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, err := New(tc.baseURL, tc.opts...)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("New(%q) = %v, want no error", tc.baseURL, err)
				}
				if client == nil {
					t.Fatal("New returned a nil client and no error")
				}
				return
			}
			if err == nil {
				t.Fatalf("New(%q) = nil error: a credential would travel in cleartext", tc.baseURL)
			}
			if !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("error = %v, want it to wrap ErrInvalidArgument", err)
			}
			if !strings.Contains(err.Error(), "cleartext") {
				t.Errorf("error %q does not say what the risk is", err)
			}
			if !strings.Contains(err.Error(), "WithInsecureCredentialTransport") {
				t.Errorf("error %q does not name the opt-out", err)
			}
		})
	}
}

// TestPathSegmentsCannotTraverseThePath is S5. resolve's comment claimed escaping
// stopped an identifier traversing the path, which held for slashes, '?', '#' and
// spaces but not for dot segments: url.PathEscape leaves '.' alone, so ".." reached
// the URL intact and RFC 3986 reference resolution walked it back up. Against
// feat/go-client-v2 every subtest here fails — the call succeeds and the server
// sees a request on a path the caller never named.
func TestPathSegmentsCannotTraverseThePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		call func(ctx context.Context, c *Client) error
	}{
		{
			name: "get with a parent-directory session id",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetSession(ctx, "..", GetSessionOptions{})
				return err
			},
		},
		{
			name: "get with a current-directory session id",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetSession(ctx, ".", GetSessionOptions{})
				return err
			},
		},
		{
			name: "delete with a parent-directory session id",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.DeleteSession(ctx, "..", DeleteSessionOptions{})
				return err
			},
		},
		{
			name: "send with a parent-directory session id",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.SendMessage(ctx, "..", "hi")
				return err
			},
		},
		{
			name: "stream with a parent-directory session id",
			call: func(ctx context.Context, c *Client) error {
				_, err := collectSeq(c.Stream(ctx, "..", StreamOptions{}))
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			paths := make(chan string, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths <- r.URL.EscapedPath()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"conv_1","agent_id":"ag_1","status":"idle","created_at":1}`))
			}))
			defer server.Close()

			client, err := New(server.URL)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = tc.call(context.Background(), client)
			if err == nil {
				t.Fatal("call = nil error, want a dot segment to be rejected")
			}
			if !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("error = %v, want it to wrap ErrInvalidArgument", err)
			}
			if len(paths) != 0 {
				t.Errorf("the server was reached at %q; the request should never have been sent", <-paths)
			}
		})
	}
}

// TestOptionIsSealedAndDecoupledFromClient is D1. `type Option func(*Client) error`
// baked *Client into an exported signature — so nothing in Client could ever move
// — and left the type open, so a third party could construct options this package
// has never seen. Against feat/go-client-v2 this test fails at the first check:
// Option is a func type, not a sealed interface.
func TestOptionIsSealedAndDecoupledFromClient(t *testing.T) {
	t.Parallel()

	option := reflect.TypeFor[Option]()
	if option.Kind() != reflect.Interface {
		t.Fatalf("Option is a %s; an interface with an unexported method is what seals it", option.Kind())
	}
	if option.NumMethod() != 1 {
		t.Fatalf("Option has %d methods, want exactly 1", option.NumMethod())
	}
	method := option.Method(0)
	if method.PkgPath == "" {
		t.Errorf("Option's only method %s is exported, so any package can implement it", method.Name)
	}
	// The signature must not mention Client, or the coupling has only moved.
	if signature := method.Type.String(); strings.Contains(signature, "Client") {
		t.Errorf("Option's method is %s, which is still coupled to Client", signature)
	}
	// And the options this package ships must satisfy it.
	for _, opt := range []Option{
		WithHTTPClient(http.DefaultClient),
		WithAuthHeader("X-Forwarded-Email", "someone@example.test"),
		WithBearerToken("tok"),
		WithSessionCookie("ap_session", "sess"),
		WithInsecureCredentialTransport(),
		WithUserAgent("test/1"),
		WithStreamIdleTimeout(time.Second),
	} {
		if opt == nil {
			t.Error("an option constructor returned nil")
		}
	}
}

func TestLoopbackNameMatchingIsCaseInsensitive(t *testing.T) {
	// RFC 4343 makes a hostname comparison case-insensitive and RFC 6761 §6.3
	// reserves the localhost name, so an uppercase spelling is the same loopback
	// host. Refusing it would reject a legitimate local development setup.
	for _, host := range []string{"localhost", "LOCALHOST", "LocalHost", "app.LOCALHOST"} {
		t.Run(host, func(t *testing.T) {
			_, err := New("http://"+host+":6767", WithBearerToken("token"))
			if err != nil {
				t.Fatalf("New over http to loopback %q = %v, want nil", host, err)
			}
		})
	}
}
