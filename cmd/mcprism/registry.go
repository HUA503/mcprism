package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/HUA503/mcprism/internal/registry"
	"github.com/spf13/cobra"
)

func registryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Search and scan servers in the official MCP Registry",
	}
	cmd.AddCommand(registrySearchCmd(), registryScanCmd(), registryAuditCmd())
	return cmd
}

func registrySearchCmd() *cobra.Command {
	var format string
	var limit int
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search the official MCP Registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "table" && format != "json" {
				return fmt.Errorf("unknown format %q (expected table or json)", format)
			}
			entries, err := registry.Search(context.Background(), args[0], limit)
			if err != nil {
				return err
			}
			summaries := make([]registry.SearchResult, 0, len(entries))
			for _, entry := range entries {
				summaries = append(summaries, registry.Summarize(entry))
			}
			if format == "json" {
				b, err := json.MarshalIndent(summaries, "", "  ")
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			return printRegistrySearch(cmd.OutOrStdout(), summaries)
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table|json")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum results to return (1-100)")
	return cmd
}

func printRegistrySearch(out io.Writer, entries []registry.SearchResult) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "NAME\tVERSION\tSTATUS\tDESCRIPTION"); err != nil {
		return err
	}
	for _, entry := range entries {
		description := strings.Join(strings.Fields(entry.Description), " ")
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", entry.Name, entry.Version, entry.Status, description); err != nil {
			return err
		}
	}
	return w.Flush()
}

func registryScanCmd() *cobra.Command {
	var o auditOpts
	cmd := &cobra.Command{
		Use:   "scan <server-name>",
		Short: "Statically scan an official MCP Registry entry",
		Long: `Fetch the latest version of an exact server name from the official MCP Registry,
then apply mcprism's static rules to its published package and remote transport
configuration. Unsupported package formats are reported as warnings. This command
never launches a package or connects to a remote MCP server. Use a local config
with 'scan --dynamic' or 'vet --probe' for opt-in probing.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entry, err := registry.Lookup(context.Background(), args[0])
			if err != nil {
				return err
			}
			servers, warnings, err := registry.AuditServers(entry)
			for _, warning := range warnings {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s\n", registry.SanitizeText(warning))
			}
			if err != nil {
				return err
			}
			if entry.Meta.Official.Status == "deprecated" && entry.Meta.Official.StatusMessage != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: registry entry is deprecated: %s\n", registry.SanitizeText(entry.Meta.Official.StatusMessage))
			}
			return audit(servers, nil, false, o)
		},
	}
	addAuditFlags(cmd, &o)
	return cmd
}
