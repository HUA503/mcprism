package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/spf13/cobra"
)

func vetCmd() *cobra.Command {
	var o auditOpts
	var probe bool
	cmd := &cobra.Command{
		Use:   "vet [target] | vet -- <command> [args...]",
		Short: "Vet a server straight from a launch command, URL or package name",
		Long: `Vet a server without adding it to any client config. This is the fastest way
to check something you are about to install.

Targets:
  Launch command   vet -- npx -y some-mcp-server
                   vet -- uvx some-mcp-server
                   vet -- docker run -i mcp-image
                   vet "npx -y some-mcp-server"   (quoted string)
  Remote URL       vet https://mcp.example.com
  Package shorthand vet npm:@scope/name
                   vet pypi:some-package

By default vet is static: it does not run the target and has no side effects.
--probe actually launches the process or connects to the URL to enumerate
tools, resources and prompts; run it against untrusted code in a sandbox.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			servers, err := resolveVetTargets(args)
			if err != nil {
				return err
			}
			return audit(servers, nil, probe, o)
		},
	}
	addAuditFlags(cmd, &o)
	cmd.Flags().BoolVar(&probe, "probe", false, "actually launch/connect to enumerate tools (runs the target; prefer a sandbox)")
	return cmd
}

// resolveVetTargets 把命令行给出的即时目标解析为一组 config.Server。
func resolveVetTargets(args []string) ([]*config.Server, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("give a server to vet: a launch command after -- (e.g. vet -- npx -y pkg), a URL, or npm:/pypi: package")
	}
	var out []*config.Server
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://"):
			out = append(out, urlServer(a))
			i++
		case strings.HasPrefix(a, "npm:"):
			out =append(out, commandServer([]string{"npx", "-y", strings.TrimPrefix(a, "npm:")}))
			i++
		case strings.HasPrefix(a, "pypi:"):
			out = append(out, commandServer([]string{"uvx", strings.TrimPrefix(a, "pypi:")}))
			i++
		case strings.Contains(a, " "):
			parts, err := shellSplit(a)
			if err != nil {
				return nil, err
			}
			out = append(out, commandServer(parts))
			i++
		default:
			// 裸 token：从 i 到下一个独立目标之前，整体视为一个命令。
			j := i + 1
			for j < len(args) && !isNewTarget(args[j]) {
				j++
			}
			out = append(out, commandServer(args[i:j]))
			i = j
		}
	}
	return out, nil
}

func isNewTarget(tok string) bool {
	return strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") ||
		strings.HasPrefix(tok, "npm:") || strings.HasPrefix(tok, "pypi:") ||
		strings.Contains(tok, " ")
}

func commandServer(parts []string) *config.Server {
	cmd := parts[0]
	args := append([]string(nil), parts[1:]...)
	raw, _ := json.Marshal(map[string]any{"command": cmd, "args": args})
	return &config.Server{
		Name:      vetName(parts),
		Transport: config.TransportStdio,
		Command:   cmd,
		Args:      args,
		Source:    "vet (command line)",
		Client:    "vet",
		Scope:     "ad-hoc",
		Raw:       raw,
	}
}

func urlServer(u string) *config.Server {
	return &config.Server{
		Name:      hostFromURL(u),
		URL:       u,
		Transport: transportFor(u, ""),
		Source:    "vet (url)",
		Client:    "vet",
		Scope:     "ad-hoc",
	}
}

// vetName 从启动命令中提取一个可读的 server 名。
func vetName(parts []string) string {
	if len(parts) == 0 {
		return "server"
	}
	cmd := filepath.Base(parts[0])
	args := parts[1:]

	switch cmd {
	case "npx", "npm", "bunx", "pnpm", "yarn", "bun", "deno":
		for _, a := range args {
			if strings.HasPrefix(a, "-") || a == "" {
				continue
			}
			return pkgShort(a)
		}
	case "uvx", "pipx":
		for _, a := range args {
			if strings.HasPrefix(a, "-") || a == "" {
				continue
			}
			return pkgShort(strings.SplitN(a, "==", 2)[0])
		}
	case "docker", "podman":
		started := false
		for _, a := range args {
			if a == "run" {
				started = true
				continue
			}
			if !started || strings.HasPrefix(a, "-") {
				continue
			}
			return a
		}
	}

	// node / python / 本地可执行：取第一个脚本路径的 basename，否则用命令名。
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if strings.ContainsAny(a, "/.") {
			return strings.TrimSuffix(filepath.Base(a), filepath.Ext(a))
		}
	}
	return cmd
}

// pkgShort 去掉版本 pin，保留 npm scope。
func pkgShort(pkg string) string {
	pkg = strings.SplitN(pkg, "==", 2)[0]
	if strings.HasPrefix(pkg, "@") {
		if i := strings.Index(pkg, "/"); i >= 0 {
			path := pkg[i+1:]
			if j := strings.Index(path, "@"); j >= 0 {
				path = path[:j]
			}
			return "@" + pkg[1:i] + "/" + path
		}
		return pkg
	}
	if i := strings.Index(pkg, "@"); i >= 0 {
		return pkg[:i]
	}
	return pkg
}

// shellSplit 按 shell 规则做简单分词，尊重单双引号。
func shellSplit(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	var quote rune
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case ' ', '\t':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in %q", s)
	}
	flush()
	return out, nil
}
