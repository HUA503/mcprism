package protocol

import (
	"strings"
	"testing"

	"github.com/HUA503/mcprism/internal/config"
)

func envHas(env []string, key string) bool {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return true
		}
	}
	return false
}

// By default a probed server must not inherit arbitrary host credentials, but
// it must keep PATH and the server's own declared variables.
func TestChildEnvAllowlist(t *testing.T) {
	t.Setenv("MCPRISM_FAKE_SECRET_TOKEN", "leaked")
	t.Setenv("MCPRISM_FAKE_PATH_KEEP", "/usr/bin")
	srv := &config.Server{Name: "s", Env: map[string]string{"MY_TOOL_VAR": "x"}}

	prev := InheritChildEnv
	defer func() { InheritChildEnv = prev }()

	InheritChildEnv = false
	env := childEnv(srv)
	if envHas(env, "MCPRISM_FAKE_SECRET_TOKEN") {
		t.Fatal("secret host variable leaked to the probed server")
	}
	if !envHas(env, "MY_TOOL_VAR") {
		t.Fatal("server's own env variable must be passed through")
	}
	if !envHas(env, "PATH") {
		t.Fatal("PATH must be in the allowlist so toolchains can resolve")
	}

	InheritChildEnv = true
	env = childEnv(srv)
	if !envHas(env, "MCPRISM_FAKE_SECRET_TOKEN") {
		t.Fatal("with --inherit-env the full parent environment should be passed")
	}
}
