package registry

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestSearchPagePagination(t *testing.T) {
	oldClient := client
	t.Cleanup(func() { client = oldClient })
	body := `{"servers":[{"server":{"name":"example/server","version":"1"}}],"metadata":{"nextCursor":"opaque cursor"}}`
	client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("version") != "latest" || r.URL.Query().Get("search") != "filesystem" || r.URL.Query().Get("limit") != "2" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	entries, cursor, err := SearchPage(context.Background(), "filesystem", 2, "")
	if err != nil || len(entries) != 1 || cursor != "opaque cursor" {
		t.Fatalf("SearchPage = %v, %v, %v", entries, more, err)
	}
	body = `{"servers":[],"metadata":{"nextCursor":null}}`
	entries, cursor, err = SearchPage(context.Background(), "filesystem", 2, "opaque cursor")
	if err != nil || len(entries) != 0 || cursor != "" {
		t.Fatalf("last page = %v, %v, %v", entries, more, err)
	}
}
