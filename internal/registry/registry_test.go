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
		expectedCursor := ""
		if body == `{"servers":[],"metadata":{"nextCursor":null}}` {
			expectedCursor = "opaque cursor"
		}
		if r.URL.Query().Get("cursor") != expectedCursor || r.URL.Query().Get("version") != "latest" || r.URL.Query().Get("search") != "filesystem" || r.URL.Query().Get("limit") != "2" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	entries, cursor, err := SearchPage(context.Background(), "filesystem", 2, "")
	if err != nil || len(entries) != 1 || cursor != "opaque cursor" {
		t.Fatalf("SearchPage = %v, %q, %v", entries, cursor, err)
	}
	body = `{"servers":[],"metadata":{"nextCursor":null}}`
	entries, cursor, err = SearchPage(context.Background(), "filesystem", 2, "opaque cursor")
	if err != nil || len(entries) != 0 || cursor != "" {
		t.Fatalf("last page = %v, %q, %v", entries, cursor, err)
	}
}

func TestSearchAllFollowsOpaqueCursor(t *testing.T) {
	oldClient := client
	t.Cleanup(func() { client = oldClient })
	requests := 0
	client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		var body string
		switch requests {
		case 1:
			if got := r.URL.Query().Get("cursor"); got != "" {
				t.Errorf("first request cursor = %q, want empty", got)
			}
			body = `{"servers":[{"server":{"name":"example/one","version":"1"}}],"metadata":{"nextCursor":"opaque / cursor"}}`
		case 2:
			if got := r.URL.Query().Get("cursor"); got != "opaque / cursor" {
				t.Errorf("next request cursor = %q, want exact opaque cursor", got)
			}
			body = `{"servers":[{"server":{"name":"example/two","version":"2"}}],"metadata":{"nextCursor":null}}`
		default:
			t.Fatalf("unexpected request %d", requests)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}

	entries, err := SearchAll(context.Background(), "filesystem", 1)
	if err != nil || len(entries) != 2 || requests != 2 {
		t.Fatalf("SearchAll = %d entries after %d requests, err %v", len(entries), requests, err)
	}
}

func TestSearchAllRejectsRepeatedCursor(t *testing.T) {
	oldClient := client
	t.Cleanup(func() { client = oldClient })
	requests := 0
	client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		body := `{"servers":[],"metadata":{"nextCursor":"repeat"}}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	_, err := SearchAll(context.Background(), "filesystem", 1)
	if err == nil || requests != 2 {
		t.Fatalf("SearchAll err = %v after %d requests, want repeated-cursor error after 2 requests", err, requests)
	}
}
