package protocol

import (
	"net"
	"net/http"
	"net/url"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"169.254.169.254", // AWS/Azure/GCP metadata
		"169.254.0.1",     // link-local
		"100.100.100.200", // Alibaba metadata
		"fe80::1",         // IPv6 link-local
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be blocked", s)
		}
	}
	allowed := []string{
		"127.0.0.1", "::1", // loopback MCP servers are legitimate
		"10.0.0.5", "192.168.1.10", "172.16.0.2", // RFC1918 intranet MCP
		"8.8.8.8", "2606:4700:4700::1111", // public
	}
	for _, s := range allowed {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be allowed", s)
		}
	}
}

func TestEgressControl(t *testing.T) {
	bad := []string{"tcp/169.254.169.254:80", "tcp/100.100.100.200:80", "tcp/[fe80::1]:80"}
	for _, addr := range bad {
		network := addr[:3]
		hostport := addr[4:]
		if err := egressControl(network, hostport, nil); err == nil {
			t.Errorf("expected egressControl to reject %s", addr)
		}
	}
	good := []string{"tcp/127.0.0.1:3000", "tcp/10.0.0.5:8080"}
	for _, addr := range good {
		if err := egressControl(addr[:3], addr[4:], nil); err != nil {
			t.Errorf("expected egressControl to allow %s, got %v", addr, err)
		}
	}
}

func hop(rawurl string) *http.Request {
	u, _ := url.Parse(rawurl)
	return &http.Request{URL: u}
}

func TestSafeCheckRedirect(t *testing.T) {
	root := []*http.Request{hop("https://mcp.example.com/mcp")}

	cases := []struct {
		name string
		to   string
		want bool // true = allowed
	}{
		{"same host path", "https://mcp.example.com/other", true},
		{"cross host", "https://evil.example.com/x", false},
		{"to metadata ip", "http://169.254.169.254/latest/meta-data", false},
		{"to gcp metadata host", "http://metadata.google.internal/computeMetadata", false},
		{"https downgrade", "http://mcp.example.com/mcp", false},
	}
	for _, c := range cases {
		err := safeCheckRedirect(hop(c.to), root)
		if c.want && err != nil {
			t.Errorf("%s: expected allowed, got %v", c.name, err)
		}
		if !c.want && err == nil {
			t.Errorf("%s: expected rejected, got nil", c.name)
		}
	}

	// Chain cap.
	var chain []*http.Request
	for i := 0; i < 4; i++ {
		chain = append(chain, hop("https://mcp.example.com/mcp"))
		if err := safeCheckRedirect(hop("https://mcp.example.com/mcp"), chain); err == nil && i >= 3 {
			t.Fatal("expected redirect chain to be capped at 3")
		}
	}
}
