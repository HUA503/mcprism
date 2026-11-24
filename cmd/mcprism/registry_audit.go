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
	return registryAuditCmdWithSearch(func(ctx context.Context, query string, limit int) ([]registry.Entry, bool, error) {
		entries, cursor, err := registry.SearchPage(ctx, query, limit, "")
		return entries, cursor != "", err
	})
}

func registryAuditCmdWithSearch(search func(context.Context, string, int) ([]registry.Entry, bool, error)) *cobra.Command {
	var o auditOpts
	var limit int
	var requireComplete bool
	var auditAll bool
	cmd := &cobra.Command{
		Use:   "audit <query>",
		Short: "Search and statically audit matching official MCP Registry entries",
		Long: `Search the official MCP Registry, then apply mcprism's static rules and
policy to supported package and remote transport metadata from the matching
entries. The command never launches packages or connects to MCP servers.
Only the first page of up to --limit results is audited; further matches may
exist. Unsupported formats and skipped entries are reported on stderr and may
not appear in the report. Review warnings before interpreting the results.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var entries []registry.Entry
			var hasMore bool
			var err error
			if auditAll {
				entries, err = registry.SearchAll(cmd.Context(), args[0], limit)
			} else {
				entries, hasMore, err = search(cmd.Context(), args[0], limit)
			}
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				return fmt.Errorf("no official MCP Registry entries matched %q", args[0])
			}

			incomplete := hasMore
			if hasMore {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: more Registry matches exist beyond this page")
			}
			var servers []*config.Server
			auditedEntries := 0
			for _, entry := range entries {
				name := registry.SanitizeText(entry.Server.Name)
				status := strings.ToLower(strings.TrimSpace(entry.Meta.Official.Status))
				if status == "deleted" {
					incomplete = true
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: registry entry %s is deleted; skipped\n", name)
					continue
				}

				entryServers, warnings, auditErr := registry.AuditServers(entry)
				if len(warnings) > 0 || auditErr != nil {
					incomplete = true
				}
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
			err = audit(servers, nil, false, o)
			if err != nil {
				return err
			}
			if requireComplete && incomplete {
				return fmt.Errorf("Registry audit incomplete; see warnings on stderr")
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum matching entries to audit (1-100)")
	cmd.Flags().BoolVar(&auditAll, "all", false, "follow Registry cursors and audit every matching result")
	cmd.Flags().BoolVar(&requireComplete, "require-complete", false, "exit non-zero if matches remain or configurations cannot be audited")
	addAuditFlags(cmd, &o)
	return cmd
}
