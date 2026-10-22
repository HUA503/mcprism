package protocol

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
)

// metadataHosts are cloud instance-metadata endpoints that a malicious or
// compromised MCP server could redirect a probe at (SSRF). They are never
// legitimate MCP servers.
var metadataHosts = map[string]bool{
	"metadata.google.internal": true,
	"metadata":                 true,
	"169.254.169.254":          true, // AWS/Azure/GCP link-local metadata
	"100.100.100.200":          true, // Alibaba Cloud metadata
}

// validateProbeURL also checks literal destinations before proxy routing. The
// socket-level guard only sees the proxy's address when a proxy is configured.
func validateProbeURL(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("MCP probe requires an absolute http(s) URL")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if metadataHosts[host] {
		return fmt.Errorf("mcprism egress guard: refusing cloud-metadata host %s", host)
	}
	// IPv6 link-local URLs may carry a zone identifier, such as fe80::1%%eth0.
	ipHost, _, _ := strings.Cut(host, "%")
	if ip := net.ParseIP(ipHost); ip != nil && isBlockedIP(ip) {
		return fmt.Errorf("mcprism egress guard: refusing link-local/metadata address %s", host)
	}
	return nil
}

func sameHTTPOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

// isBlockedIP reports an address the probe must never connect to: IPv4
// link-local (169.254.0.0/16, which carries all major cloud metadata
// endpoints), the Alibaba metadata IP and IPv6 link-local (fe80::/10).
// Loopback and RFC1918 private ranges are allowed because local and intranet
// MCP servers are normal; only metadata/link-local targets are blocked.
func isBlockedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4.Equal(net.IPv4(100, 100, 100, 200)) {
			return true
		}
		return false
	}
	if len(ip) == net.IPv6len && ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true // fe80::/10
	}
	return false
}

// egressControl runs after DNS resolution but before the socket connects, so
// it also catches a hostname that resolves to a metadata/link-local address
// (DNS rebinding). address is an ip:port pair at this point.
func egressControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if metadataHosts[strings.ToLower(host)] {
		return fmt.Errorf("mcprism egress guard: refusing cloud-metadata host %s", host)
	}
	if ip := net.ParseIP(host); ip != nil && isBlockedIP(ip) {
		return fmt.Errorf("mcprism egress guard: refusing link-local/metadata address %s", host)
	}
	return nil
}

// safeCheckRedirect only follows redirects to the same scheme+host as the
// original request, never downgrades HTTPS, never targets a metadata host, and
// caps the chain at three hops. An open redirect can otherwise bounce an
// authorized probe at internal or metadata endpoints.
func safeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return fmt.Errorf("mcprism egress guard: stopped after %d redirects", len(via))
	}
	root := via[0].URL
	if err := validateProbeURL(req.URL); err != nil {
		return err
	}
	if !strings.EqualFold(req.URL.Host, root.Host) {
		return fmt.Errorf("mcprism egress guard: refusing cross-host redirect from %q to %q", root.Host, req.URL.Host)
	}
	if root.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("mcprism egress guard: refusing HTTPS downgrade to %q", req.URL.Scheme)
	}
	return nil
}
