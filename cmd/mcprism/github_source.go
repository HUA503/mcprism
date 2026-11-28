package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxGitHubArchiveBytes  = 100 << 20
	maxExpandedSourceBytes = 128 << 20
	maxArchiveEntries      = 20000
)

// fetchGitHubSource downloads and safely extracts a public GitHub repository
// archive into a temporary directory. The returned directory is owned by the
// caller and must be removed after the scan. Repository code is never executed.
func fetchGitHubSource(rawURL, ref string) (string, error) {
	repo, err := url.Parse(rawURL)
	if err != nil || repo.Scheme != "https" || !strings.EqualFold(repo.Host, "github.com") || repo.User != nil || repo.RawQuery != "" || repo.Fragment != "" {
		return "", fmt.Errorf("--repo must be an HTTPS URL to a public github.com/owner/repo repository")
	}
	parts := strings.Split(strings.Trim(repo.Path, "/"), "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("--repo must point to github.com/owner/repo (without a subpath)")
	}
	owner, name := parts[0], strings.TrimSuffix(parts[1], ".git")
	if !validGitHubName(owner) || !validGitHubName(name) {
		return "", fmt.Errorf("invalid GitHub owner or repository name")
	}
	if strings.ContainsAny(ref, "\r\n\x00") || len(ref) > 256 {
		return "", fmt.Errorf("invalid --ref")
	}
	endpoint := "https://api.github.com/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/tarball"
	if ref != "" {
		endpoint += "/" + url.PathEscape(ref)
	}
	ctxURL, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid GitHub archive URL: %w", err)
	}
	request, err := http.NewRequest(http.MethodGet, ctxURL.String(), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "mcprism")
	client := &http.Client{
		Timeout: 90 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			host := strings.ToLower(request.URL.Hostname())
			githubHost := host == "github.com" || strings.HasSuffix(host, ".github.com") || host == "githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com")
			if request.URL.Scheme != "https" || !githubHost || len(via) >= 5 {
				return fmt.Errorf("GitHub archive redirected to an unexpected host")
			}
			return nil
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download GitHub source archive: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("GitHub archive request returned %s", response.Status)
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, maxGitHubArchiveBytes+1))
	if err != nil {
		return "", fmt.Errorf("read GitHub source archive: %w", err)
	}
	if len(archive) > maxGitHubArchiveBytes {
		return "", fmt.Errorf("GitHub source archive exceeds the %d MiB download limit", maxGitHubArchiveBytes>>20)
	}
	tmp, err := os.MkdirTemp("", "mcprism-github-*")
	if err != nil {
		return "", fmt.Errorf("create temporary scan directory: %w", err)
	}
	if err := extractGitHubTarGz(tmp, archive); err != nil {
		_ = os.RemoveAll(tmp)
		return "", err
	}
	return tmp, nil
}

func validGitHubName(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func extractGitHubTarGz(destination string, archive []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("invalid GitHub source archive: %w", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	root := ""
	seen := make(map[string]bool)
	var expanded int64
	for entries := 0; ; entries++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read GitHub source archive: %w", err)
		}
		if entries >= maxArchiveEntries {
			return fmt.Errorf("GitHub source archive exceeds the %d-entry limit", maxArchiveEntries)
		}
		archivePath := strings.TrimSuffix(strings.ReplaceAll(header.Name, "\\", "/"), "/")
		if !filepath.IsLocal(filepath.FromSlash(archivePath)) {
			return fmt.Errorf("GitHub archive contains an unsafe path")
		}
		clean := path.Clean(archivePath)
		if clean == "." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return fmt.Errorf("GitHub archive contains an unsafe path")
		}
		parts := strings.Split(clean, "/")
		if root == "" {
			root = parts[0]
		}
		if parts[0] != root {
			return fmt.Errorf("GitHub archive has multiple root directories")
		}
		if len(parts) == 1 {
			continue
		}
		rel := filepath.Join(parts[1:]...)
		target := filepath.Join(destination, rel)
		if !filepath.IsLocal(rel) {
			return fmt.Errorf("GitHub archive contains an unsafe path")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("extract GitHub source directory: %w", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if seen[rel] {
				return fmt.Errorf("GitHub archive contains duplicate file paths")
			}
			seen[rel] = true
			if header.Size < 0 || expanded+header.Size > maxExpandedSourceBytes {
				return fmt.Errorf("expanded GitHub source exceeds the %d MiB limit", maxExpandedSourceBytes>>20)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("extract GitHub source directory: %w", err)
			}
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, safeArchiveMode(header.Mode))
			if err != nil {
				return fmt.Errorf("extract GitHub source file: %w", err)
			}
			written, copyErr := io.CopyN(file, reader, header.Size)
			closeErr := file.Close()
			if copyErr != nil {
				return fmt.Errorf("extract GitHub source file: %w", copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close extracted source file: %w", closeErr)
			}
			expanded += written
		default:
			// Links and special files are not needed for static scanning.
		}
	}
	if root == "" {
		return fmt.Errorf("GitHub source archive is empty")
	}
	return nil
}

func safeArchiveMode(mode int64) os.FileMode {
	if mode&0111 != 0 {
		return 0755
	}
	return 0644
}
