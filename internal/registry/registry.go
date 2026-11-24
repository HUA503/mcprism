// Package registry reads server metadata from the official MCP Registry and
// converts published launch metadata into static mcprism audit inputs.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/HUA503/mcprism/internal/config"
)

const (
	baseURL        = "https://registry.modelcontextprotocol.io"
	maxBodyBytes   = 2 << 20
	defaultLimit   = 20
	maximumLimit   = 100
	requestTimeout = 15 * time.Second
)

var serverNamePattern = regexp.MustCompile(`^[A-Za-z0-9.-]+/[A-Za-z0-9._-]+$`)
var variablePattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Entry is one versioned record returned by the official registry.
type Entry struct {
	Server ServerDetail `json:"server"`
	Meta   struct {
		Official struct {
			Status        string `json:"status"`
			StatusMessage string `json:"statusMessage"`
			IsLatest      bool   `json:"isLatest"`
		} `json:"io.modelcontextprotocol.registry/official"`
	} `json:"_meta"`
}

type ServerDetail struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Version     string      `json:"version"`
	Packages    []Package   `json:"packages"`
	Remotes     []Transport `json:"remotes"`
}

type Package struct {
	RegistryType         string     `json:"registryType"`
	Identifier           string     `json:"identifier"`
	Version              string     `json:"version"`
	RuntimeHint          string     `json:"runtimeHint"`
	RuntimeArguments     []Argument `json:"runtimeArguments"`
	PackageArguments     []Argument `json:"packageArguments"`
	EnvironmentVariables []KeyValue `json:"environmentVariables"`
	Transport            Transport  `json:"transport"`
}

type Transport struct {
	Type      string           `json:"type"`
	URL       string           `json:"url"`
	Headers   []KeyValue       `json:"headers"`
	Variables map[string]Input `json:"variables"`
}

type Argument struct {
	Type       string           `json:"type"`
	Name       string           `json:"name"`
	Value      string           `json:"value"`
	Default    string           `json:"default"`
	ValueHint  string           `json:"valueHint"`
	IsRequired bool             `json:"isRequired"`
	Variables  map[string]Input `json:"variables"`
}

type KeyValue struct {
	Name      string           `json:"name"`
	Value     string           `json:"value"`
	Default   string           `json:"default"`
	IsSecret  bool             `json:"isSecret"`
	Variables map[string]Input `json:"variables"`
}

type Input struct {
	Value      string `json:"value"`
	Default    string `json:"default"`
	IsSecret   bool   `json:"isSecret"`
	IsRequired bool   `json:"isRequired"`
}

type serverList struct {
	Servers  []Entry `json:"servers"`
	Metadata struct {
		NextCursor string `json:"nextCursor"`
	} `json:"metadata"`
}

// SearchResult contains only safe discovery fields. Registry package inputs
// and headers are intentionally omitted from search output.
type SearchResult struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

var client = &http.Client{
	Timeout: requestTimeout,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Search returns the latest registry versions matching query. The official
// registry requires at least three non-space Unicode characters.
func Search(ctx context.Context, query string, limit int) ([]Entry, error) {
	entries, _, err := SearchPage(ctx, query, limit)
	return entries, err
}

// SearchPage returns matching entries and whether the Registry has another page.
func SearchPage(ctx context.Context, query string, limit int) ([]Entry, bool, error) {
	query = strings.TrimSpace(query)
	nonSpaceCharacters := 0
	for _, r := range query {
		if !unicode.IsSpace(r) {
			nonSpaceCharacters++
		}
	}
	if nonSpaceCharacters < 3 {
		return nil, false, errors.New("registry search needs at least 3 non-space characters")
	}
	if limit == 0 {
		limit = defaultLimit
	}
	if limit < 1 || limit > maximumLimit {
		return nil, false, fmt.Errorf("limit must be between 1 and %d", maximumLimit)
	}

	u, _ := url.Parse(baseURL + "/v0.1/servers")
	q := u.Query()
	q.Set("search", query)
	q.Set("version", "latest")
	q.Set("limit", fmt.Sprint(limit))
	u.RawQuery = q.Encode()
	var result serverList
	if err := getJSON(ctx, u.String(), &result); err != nil {
		return nil, false, err
	}
	return result.Servers, result.Metadata.NextCursor != "", nil
}

// Lookup fetches the latest version of one exact official registry name.
func Lookup(ctx context.Context, name string) (Entry, error) {
	name = strings.TrimSpace(name)
	if !serverNamePattern.MatchString(name) {
		return Entry{}, fmt.Errorf("invalid registry name %q (expected namespace/server-name)", name)
	}
	target := baseURL + "/v0.1/servers/" + url.PathEscape(name) + "/versions/latest"
	var entry Entry
	if err := getJSON(ctx, target, &entry); err != nil {
		return Entry{}, err
	}
	if entry.Server.Name == "" || entry.Server.Version == "" {
		return Entry{}, errors.New("registry returned an incomplete server record")
	}
	if entry.Server.Name != name {
		return Entry{}, errors.New("registry returned a different server name")
	}
	if entry.Meta.Official.Status == "deleted" {
		return Entry{}, fmt.Errorf("registry entry %s is deleted", entry.Server.Name)
	}
	return entry, nil
}

// Summarize returns the non-launch metadata appropriate for search output.
func Summarize(entry Entry) SearchResult {
	status := entry.Meta.Official.Status
	if status == "" {
		status = "unknown"
	}
	return SearchResult{
		Name:        SanitizeText(entry.Server.Name),
		Version:     SanitizeText(entry.Server.Version),
		Status:      SanitizeText(status),
		Description: SanitizeText(entry.Server.Description),
	}
}

// SanitizeText removes terminal control characters from untrusted registry
// metadata before it is printed or copied into report-visible fields.
func SanitizeText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
}

func getJSON(parent context.Context, target string, out any) error {
	ctx, cancel := context.WithTimeout(parent, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcprism")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request MCP Registry: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("MCP Registry returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return fmt.Errorf("read MCP Registry response: %w", err)
	}
	if len(body) > maxBodyBytes {
		return fmt.Errorf("MCP Registry response exceeds %d bytes", maxBodyBytes)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode MCP Registry response: %w", err)
	}
	return nil
}

// AuditServers converts supported package and remote transports into
// configuration-shaped inputs understood by mcprism's existing static rules.
// Unsupported package formats are returned as warnings so partial coverage is
// visible to the caller.
func AuditServers(entry Entry) ([]*config.Server, []string, error) {
	if strings.TrimSpace(entry.Server.Name) == "" || strings.TrimSpace(entry.Server.Version) == "" {
		return nil, nil, errors.New("registry entry is missing its name or version")
	}
	baseSource := fmt.Sprintf("MCP Registry %s@%s", entry.Server.Name, entry.Server.Version)
	if entry.Meta.Official.Status == "deprecated" {
		baseSource += " (deprecated)"
	}
	var servers []*config.Server
	var warnings []string

	for i, remote := range entry.Server.Remotes {
		srv, err := remoteServer(entry.Server.Name, baseSource, remote, len(servers)+1)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("remote transport %d: %v", i+1, err))
			continue
		}
		servers = append(servers, srv)
	}
	for i, pkg := range entry.Server.Packages {
		srv, err := packageServer(entry.Server.Name, baseSource, pkg, len(servers)+1)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("package %d (%s): %v", i+1, pkg.RegistryType, err))
			continue
		}
		servers = append(servers, srv)
	}
	if len(servers) == 0 {
		if len(warnings) == 0 {
			return nil, nil, errors.New("registry entry has no package or remote transports")
		}
		return nil, warnings, errors.New("registry entry has no transport mcprism can scan")
	}
	return servers, warnings, nil
}

func remoteServer(name, source string, transport Transport, index int) (*config.Server, error) {
	serverTransport, err := transportType(transport.Type)
	if err != nil {
		return nil, err
	}
	remoteURL := SanitizeText(renderValue(transport.URL, transport.Variables))
	if remoteURL == "" {
		return nil, errors.New("missing URL")
	}
	if !strings.HasPrefix(remoteURL, "http://") && !strings.HasPrefix(remoteURL, "https://") && !strings.HasPrefix(remoteURL, "{") {
		return nil, errors.New("URL must use http://, https://, or a transport variable")
	}
	if !strings.Contains(remoteURL, "{") {
		parsed, err := url.ParseRequestURI(remoteURL)
		if err != nil || parsed.Host == "" {
			return nil, errors.New("invalid remote URL")
		}
	}
	return &config.Server{
		Name:      fmt.Sprintf("%s (remote %d)", name, index),
		Transport: serverTransport,
		URL:       remoteURL,
		Headers:   keyValueMap(transport.Headers),
		Source:    SanitizeText(source),
		Client:    "registry",
		Scope:     "official",
	}, nil
}

func packageServer(name, source string, pkg Package, index int) (*config.Server, error) {
	if pkg.Identifier == "" || pkg.Version == "" {
		return nil, errors.New("missing package identifier or version")
	}
	switch strings.ToLower(pkg.Transport.Type) {
	case "streamable-http", "sse":
		return remoteServer(name, source, pkg.Transport, index)
	case "stdio":
	case "":
		return nil, errors.New("missing package transport type")
	default:
		return nil, fmt.Errorf("unsupported package transport %q", pkg.Transport.Type)
	}
	command := strings.TrimSpace(SanitizeText(pkg.RuntimeHint))
	if command == "" {
		switch strings.ToLower(pkg.RegistryType) {
		case "npm":
			command = "npx"
		case "pypi":
			command = "uvx"
		case "nuget":
			command = "dnx"
		case "oci":
			command = "docker"
		default:
			return nil, fmt.Errorf("unsupported package type %q without runtimeHint", pkg.RegistryType)
		}
	}
	packageRef, err := packageReference(pkg)
	if err != nil {
		return nil, err
	}
	packageRef = SanitizeText(packageRef)
	args := make([]string, 0, len(pkg.RuntimeArguments)+len(pkg.PackageArguments)+1)
	args = append(args, argumentValues(pkg.RuntimeArguments)...)
	args = append(args, packageRef)
	args = append(args, argumentValues(pkg.PackageArguments)...)
	server := &config.Server{
		Name:      fmt.Sprintf("%s (%s %d)", name, SanitizeText(pkg.RegistryType), index),
		Transport: config.TransportStdio,
		Command:   command,
		Args:      args,
		Env:       keyValueMap(pkg.EnvironmentVariables),
		Source:    SanitizeText(source),
		Client:    "registry",
		Scope:     "official",
	}
	server.Raw, _ = json.Marshal(map[string]any{"command": command, "args": args, "env": server.Env})
	return server, nil
}

func packageReference(pkg Package) (string, error) {
	switch strings.ToLower(pkg.RegistryType) {
	case "npm":
		return pkg.Identifier + "@" + pkg.Version, nil
	case "pypi":
		return pkg.Identifier + "==" + pkg.Version, nil
	case "nuget":
		return pkg.Identifier + "@" + pkg.Version, nil
	case "oci":
		return pkg.Identifier + ":" + pkg.Version, nil
	default:
		if pkg.RuntimeHint != "" {
			return pkg.Identifier + "@" + pkg.Version, nil
		}
		return "", fmt.Errorf("unsupported package type %q", pkg.RegistryType)
	}
}

func transportType(kind string) (config.Transport, error) {
	switch strings.ToLower(kind) {
	case "streamable-http":
		return config.TransportHTTP, nil
	case "sse":
		return config.TransportSSE, nil
	default:
		return "", fmt.Errorf("unsupported transport %q", kind)
	}
}

func argumentValues(args []Argument) []string {
	var values []string
	for _, arg := range args {
		value := firstValue(arg.Value, arg.Default)
		value = SanitizeText(renderValue(value, arg.Variables))
		if value == "" && arg.IsRequired {
			value = "${MCPRISM_INPUT}"
		}
		switch strings.ToLower(arg.Type) {
		case "named":
			if value == "" {
				values = append(values, arg.Name)
			} else if arg.Name != "" {
				values = append(values, arg.Name+"="+value)
			}
		default:
			if value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

func keyValueMap(items []KeyValue) map[string]string {
	if len(items) == 0 {
		return nil
	}
	values := make(map[string]string, len(items))
	for _, item := range items {
		if item.Name == "" {
			continue
		}
		value := renderValue(firstValue(item.Value, item.Default), item.Variables)
		if value == "" && item.IsSecret {
			value = "${MCPRISM_SECRET}"
		}
		values[item.Name] = value
	}
	return values
}

func firstValue(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func renderValue(value string, variables map[string]Input) string {
	if value == "" || len(variables) == 0 {
		return value
	}
	return variablePattern.ReplaceAllStringFunc(value, func(token string) string {
		name := strings.TrimSuffix(strings.TrimPrefix(token, "{"), "}")
		input, ok := variables[name]
		if !ok {
			return token
		}
		if resolved := firstValue(input.Value, input.Default); resolved != "" {
			return resolved
		}
		return "${" + name + "}"
	})
}
