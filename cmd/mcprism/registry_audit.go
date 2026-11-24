package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/registry"
	"github.com/spf13/cobra"
)

func registryAuditCmd() *cobra.Command {
	var o auditOpts
	var limit int
	cmd := &cobra.Command{
		Use:   "audit <query>",
		Short: "Search and statically audit matching official MCP Registry entries",
		Long: `Search the official MCP Registry, then apply mcprism's static rules and
policy to supported package and remote transport metadata from the matching
entries. The command never launches packages or connects to MCP servers.
Unsupported formats and deprecated entries are reported as warnings.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := registry.Search(context.Background(), args[0], limit)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				return fmt.Errorf("no official MCP Registry entries matched %q", args[0])
			}

			var servers []*config.Server
			auditedEntries := 0
			for _, entry := range entries {
				name := registry.SanitizeText(entry.Server.Name)
				status := strings.ToLower(strings.TrimSpace(entry.Meta.Official.Status))
				if status == "deleted" {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: registry entry %s is deleted; skipped\n", name)
					continue
				}

				entryServers, warnings, auditErr := registry.AuditServers(entry)
				for _, warning := range warnings {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s: %s\n", name, registry.SanitizeText(warning))
				}
				if auditErr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s: %s\n", name, registry.SanitizeText(auditErr.Error()))
					continue
				}

				if status == "deprecated" {
					message := registry.SanitizeText(strings.TrimSpace(entry.Meta.Official.StatusMessage))
					if message == "" {
						message = "entry is deprecated"
					}
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s: %s\n", name, message)
				}

				servers = append(servers, entryServers...)
				auditedEntries++
			}
			if len(servers) == 0 {
				return fmt.Errorf("no supported server configurations found among %d matching Registry entries", len(entries))
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Registry audit: %d of %d entries, %d server configurations\n", auditedEntries, len(entries), len(servers))
			return audit(servers, nil, false, o)
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum matching entries to audit (1-100)")
	addAuditFlags(cmd, &o)
	return cmd
}
