package omnigent

import (
	"encoding/json"
	"testing"
)

func TestDecodeEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		typ     string
		payload string
		want    Event
		wantErr bool
	}{
		{
			name:    "text delta",
			typ:     "response.output_text.delta",
			payload: `{"type":"response.output_text.delta","delta":"hi","index":3,"message_id":"m1"}`,
			want: OutputTextDeltaEvent{
				Type:      "response.output_text.delta",
				Delta:     "hi",
				Index:     Ptr(3),
				MessageID: Ptr("m1"),
			},
		},
		{
			name:    "session status carries a typed enum",
			typ:     "session.status",
			payload: `{"type":"session.status","conversation_id":"conv_1","status":"waiting"}`,
			want: SessionStatusEvent{
				Type:           "session.status",
				ConversationID: "conv_1",
				Status:         "waiting",
			},
		},
		{
			name:    "an execution-sourced error is accepted, not just llm and tool",
			typ:     "response.error",
			payload: `{"type":"response.error","source":"execution","error":{"code":"c","message":"m"}}`,
			want: ErrorEvent{
				Type:   "response.error",
				Source: "execution",
				Error:  RetryErrorDetail{Code: "c", Message: "m"},
			},
		},
		{
			name:    "sequence_number stays absent rather than defaulting to zero",
			typ:     "session.heartbeat",
			payload: `{"type":"session.heartbeat"}`,
			want:    SessionHeartbeatEvent{Type: "session.heartbeat"},
		},
		{
			name:    "an unmapped type becomes an opaque event",
			typ:     "session.invented",
			payload: `{"type":"session.invented","x":1}`,
			want:    UnknownEvent{Type: "session.invented", Raw: []byte(`{"type":"session.invented","x":1}`)},
		},
		{
			name:    "a payload that contradicts its own schema fails",
			typ:     "response.output_text.delta",
			payload: `{"type":"response.output_text.delta","delta":{"not":"a string"}}`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeEvent(tc.typ, []byte(tc.payload))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("decodeEvent(%q) = %#v, want an error", tc.typ, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeEvent(%q): %v", tc.typ, err)
			}
			// Compare through JSON so pointer fields compare by value.
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal got: %v", err)
			}
			wantJSON, err := json.Marshal(tc.want)
			if err != nil {
				t.Fatalf("marshal want: %v", err)
			}
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("decodeEvent(%q) = %s, want %s", tc.typ, gotJSON, wantJSON)
			}
		})
	}
}

// TestEventCoversEveryUnionMember guards the generated dispatch: every member of
// the server's union must decode to a distinct typed event rather than silently
// falling through to UnknownEvent.
func TestEventCoversEveryUnionMember(t *testing.T) {
	t.Parallel()

	// One representative per family; a member missing from events.gen.go would
	// come back as UnknownEvent instead of its own type.
	types := []string{
		"response.created", "response.in_progress", "response.completed",
		"response.failed", "response.incomplete", "response.cancelled",
		"response.queued", "response.output_text.delta", "response.output_item.done",
		"response.error", "response.retry", "response.heartbeat",
		"response.reasoning.started", "response.reasoning_text.delta",
		"response.reasoning_summary_text.delta", "response.function_call_output.delta",
		"response.compaction.in_progress", "response.compaction.completed",
		"response.compaction.failed", "response.elicitation_request",
		"response.elicitation_resolved", "response.policy_denied",
		"response.client_task.cancel", "response.output_file.done",
		"browser.action_request",
		"session.status", "session.input.consumed", "session.heartbeat",
		"session.interrupted", "session.usage", "session.model",
		"session.reasoning_effort", "session.collaboration_mode",
		"session.agent_changed", "session.todos", "session.terminal_pending",
		"session.sandbox_status", "session.mcp_startup", "session.skills",
		"session.model_options", "session.created", "session.superseded",
		"session.presence", "session.resource.created", "session.resource.deleted",
		"session.child_session.updated", "session.changed_files.invalidated",
		"session.terminal.activity",
		"turn.started", "turn.completed", "turn.failed", "turn.cancelled",
	}
	if len(types) != 52 {
		t.Fatalf("the union has 52 members; this test lists %d", len(types))
	}

	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			t.Parallel()

			// A payload carrying only the discriminator. Required fields are
			// absent, which is fine: encoding/json leaves them zero rather than
			// failing, so this exercises dispatch alone.
			event, err := decodeEvent(typ, []byte(`{"type":`+quote(typ)+`}`))
			if err != nil {
				t.Fatalf("decodeEvent(%q): %v", typ, err)
			}
			if unknown, ok := event.(UnknownEvent); ok {
				t.Fatalf("%q decoded to UnknownEvent(%q); the generated dispatch is missing it",
					typ, unknown.Type)
			}
		})
	}
}

func quote(s string) string {
	encoded, _ := json.Marshal(s)
	return string(encoded)
}
