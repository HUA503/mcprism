package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// A Streamable HTTP server can interleave a notification after the response.
// The client must pick the message whose id matches its request, not the last
// message in the stream.
func TestParseSSEPicksMatchingID(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`,
		``,
		`data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`,
		``,
	}, "\n"))

	resp, err := parseSSEResponse(stream, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var id int64
	if err := json.Unmarshal(resp.ID, &id); err != nil || id != 1 {
		t.Fatalf("expected response id 1, got id %q (err %v)", string(resp.ID), err)
	}
	if len(resp.Result) == 0 {
		t.Fatal("expected non-empty result for id 1")
	}
}

// When several responses are present, each request id selects its own message.
func TestParseSSEMultipleIDs(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`data: {"jsonrpc":"2.0","id":1,"result":{"a":1}}`,
		``,
		`data: {"jsonrpc":"2.0","id":2,"result":{"b":2}}`,
		``,
	}, "\n"))

	for _, want := range []int64{1, 2} {
		resp, err := parseSSEResponse(stream, want)
		if err != nil {
			t.Fatalf("id %d: %v", want, err)
		}
		var got int64
		if json.Unmarshal(resp.ID, &got) != nil || got != want {
			t.Fatalf("expected id %d, got %q", want, string(resp.ID))
		}
		if _, err := stream.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
	}
}

// A stream that only carries notifications cannot satisfy a request.
func TestParseSSENoMatchingID(t *testing.T) {
	stream := strings.NewReader(strings.Join([]string{
		`data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`,
		``,
	}, "\n"))
	if _, err := parseSSEResponse(stream, 1); err == nil {
		t.Fatal("expected an error when no response matches the request id")
	}
}

// Notifications (id 0) do not expect a result.
func TestParseSSENotification(t *testing.T) {
	stream := strings.NewReader(`data: {"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n\n")
	resp, err := parseSSEResponse(stream, 0)
	if err != nil {
		t.Fatalf("notification should not error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected an empty response, got nil")
	}
}
