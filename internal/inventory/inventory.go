// Package inventory stores privacy-preserving fingerprints of MCP tool
// definitions so users can detect changes between trusted reviews.
package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/HUA503/mcprism/internal/protocol"
)

const FormatVersion = 1

// Lock contains only a server label, tool names, and fingerprints. Descriptions,
// schemas, and credentials are never copied into the lock file.
type Lock struct {
	Version int          `json:"version"`
	Server  string       `json:"server"`
	Tools   []ToolRecord `json:"tools"`
}

// ToolRecord identifies one tool definition without storing its contents.
type ToolRecord struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Change describes one added, removed, or modified tool definition.
type Change struct {
	Kind     string
	Name     string
	Previous string
	Current  string
}

// fingerprintInput is the complete MCP tool definition, including its schema,
// output schema, title, description, and annotations.
type fingerprintInput struct {
	Name         string `json:"name"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	InputSchema  string `json:"inputSchema"`
	OutputSchema string `json:"outputSchema"`
	Annotations  string `json:"annotations"`
}

// New fingerprints and sorts the tools for a server.
func New(server string, tools []protocol.Tool) (Lock, error) {
	if server == "" {
		return Lock{}, fmt.Errorf("server name is empty")
	}
	out := Lock{Version: FormatVersion, Server: server, Tools: make([]ToolRecord, 0, len(tools))}
	for _, tool := range tools {
		if tool.Name == "" {
			return Lock{}, fmt.Errorf("tool has an empty name; refusing to create an incomplete lock")
		}
		input, err := canonicalJSON(tool.InputSchema)
		if err != nil {
			return Lock{}, fmt.Errorf("tool %q input schema: %w", tool.Name, err)
		}
		output, err := canonicalJSON(tool.OutputSchema)
		if err != nil {
			return Lock{}, fmt.Errorf("tool %q output schema: %w", tool.Name, err)
		}
		annotations, err := canonicalJSON(tool.Annotations)
		if err != nil {
			return Lock{}, fmt.Errorf("tool %q annotations: %w", tool.Name, err)
		}
		material, err := json.Marshal(fingerprintInput{
			Name: tool.Name, Title: tool.Title, Description: tool.Description,
			InputSchema: input, OutputSchema: output, Annotations: annotations,
		})
		if err != nil {
			return Lock{}, fmt.Errorf("fingerprint tool %q: %w", tool.Name, err)
		}
		sum := sha256.Sum256(material)
		out.Tools = append(out.Tools, ToolRecord{Name: tool.Name, SHA256: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out.Tools, func(i, j int) bool {
		if out.Tools[i].Name != out.Tools[j].Name {
			return out.Tools[i].Name < out.Tools[j].Name
		}
		return out.Tools[i].SHA256 < out.Tools[j].SHA256
	})
	return out, nil
}

// Compare returns deterministic changes between two locks.
func Compare(previous, current Lock) ([]Change, error) {
	if err := Validate(previous); err != nil {
		return nil, fmt.Errorf("invalid baseline: %w", err)
	}
	if err := Validate(current); err != nil {
		return nil, fmt.Errorf("invalid current inventory: %w", err)
	}
	if previous.Server != current.Server {
		return nil, fmt.Errorf("lock is for server %q, but current target is %q", previous.Server, current.Server)
	}

	oldByName := group(previous.Tools)
	newByName := group(current.Tools)
	names := make(map[string]bool, len(oldByName)+len(newByName))
	for name := range oldByName {
		names[name] = true
	}
	for name := range newByName {
		names[name] = true
	}

	var changes []Change
	for name := range names {
		oldCounts := counts(oldByName[name])
		newCounts := counts(newByName[name])
		var oldRemaining, newRemaining []string
		for hash, count := range oldCounts {
			match := min(count, newCounts[hash])
			oldCounts[hash] -= match
			newCounts[hash] -= match
		}
		for hash, count := range oldCounts {
			for range count {
				oldRemaining = append(oldRemaining, hash)
			}
		}
		for hash, count := range newCounts {
			for range count {
				newRemaining = append(newRemaining, hash)
			}
		}
		sort.Strings(oldRemaining)
		sort.Strings(newRemaining)
		pairs := min(len(oldRemaining), len(newRemaining))
		for i := 0; i < pairs; i++ {
			changes = append(changes, Change{Kind: "changed", Name: name, Previous: oldRemaining[i], Current: newRemaining[i]})
		}
		for _, hash := range oldRemaining[pairs:] {
			changes = append(changes, Change{Kind: "removed", Name: name, Previous: hash})
		}
		for _, hash := range newRemaining[pairs:] {
			changes = append(changes, Change{Kind: "added", Name: name, Current: hash})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Name != changes[j].Name {
			return changes[i].Name < changes[j].Name
		}
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		if changes[i].Previous != changes[j].Previous {
			return changes[i].Previous < changes[j].Previous
		}
		return changes[i].Current < changes[j].Current
	})
	return changes, nil
}

// Validate checks the supported lock format and every fingerprint.
func Validate(lock Lock) error {
	if lock.Version != FormatVersion {
		return fmt.Errorf("unsupported lock version %d (supported: %d)", lock.Version, FormatVersion)
	}
	if lock.Server == "" {
		return fmt.Errorf("server name is empty")
	}
	for i, tool := range lock.Tools {
		if tool.Name == "" {
			return fmt.Errorf("tool %d has an empty name", i+1)
		}
		sum, err := hex.DecodeString(tool.SHA256)
		if err != nil || len(sum) != sha256.Size {
			return fmt.Errorf("tool %q has an invalid SHA-256 fingerprint", tool.Name)
		}
	}
	return nil
}

// Load reads and validates a lock file.
func Load(path string) (Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, fmt.Errorf("read lock file: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var lock Lock
	if err := dec.Decode(&lock); err != nil {
		return Lock{}, fmt.Errorf("parse lock file %q: %w", path, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		if err == nil {
			return Lock{}, fmt.Errorf("parse lock file %q: trailing JSON value", path)
		}
		return Lock{}, fmt.Errorf("parse lock file %q: %w", path, err)
	}
	if err := Validate(lock); err != nil {
		return Lock{}, fmt.Errorf("invalid lock file %q: %w", path, err)
	}
	return lock, nil
}

// Save writes a new lock with owner-only permissions. Existing files are
// preserved unless overwrite is explicitly requested.
func Save(path string, lock Lock, overwrite bool) error {
	if path == "" {
		return fmt.Errorf("output path is empty")
	}
	if err := Validate(lock); err != nil {
		return fmt.Errorf("refusing to write invalid lock: %w", err)
	}
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return fmt.Errorf("encode lock file: %w", err)
	}
	data = append(data, '\n')
	if overwrite {
		return replaceAtomically(path, data)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create lock file %q: %w", path, err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("set lock file permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write lock file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync lock file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close lock file: %w", err)
	}
	ok = true
	return nil
}

// replaceAtomically writes beside the destination, then renames the completed
// file over it. This keeps the previous lock intact on write errors and replaces
// a symlink itself instead of following it to a different file.
func replaceAtomically(path string, data []byte) error {
	dir := filepath.Dir(path)
	pattern := "." + filepath.Base(path) + ".tmp-*"
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return fmt.Errorf("create temporary lock file for %q: %w", path, err)
	}
	tmpPath := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary lock file permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temporary lock file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temporary lock file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temporary lock file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace lock file %q: %w", path, err)
	}
	ok = true
	return nil
}

func canonicalJSON(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return "", err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		if err == nil {
			return "", fmt.Errorf("multiple JSON values")
		}
		return "", err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func group(tools []ToolRecord) map[string][]string {
	out := make(map[string][]string)
	for _, tool := range tools {
		out[tool.Name] = append(out[tool.Name], tool.SHA256)
	}
	return out
}

func counts(values []string) map[string]int {
	out := make(map[string]int, len(values))
	for _, value := range values {
		out[value]++
	}
	return out
}
