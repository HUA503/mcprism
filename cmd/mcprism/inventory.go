package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/HUA503/mcprism/internal/inventory"
	"github.com/HUA503/mcprism/internal/protocol"
	"github.com/spf13/cobra"
)

var errInventoryDrift = errors.New("tool inventory differs from the saved lock")

func inventoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Save or verify a trusted snapshot of MCP tool definitions",
		Long: "Inventory commands connect to the target and enumerate tool metadata.\n" +
			"They do not invoke tools. For stdio targets they launch the configured process;\n" +
			"review the target first and use a sandbox for untrusted servers.",
	}
	cmd.AddCommand(inventorySaveCmd(), inventoryVerifyCmd())
	return cmd
}

func inventorySaveCmd() *cobra.Command {
	var output, transport string
	var timeout time.Duration
	var force bool
	cmd := &cobra.Command{
		Use:   "save <target>",
		Short: "Save a privacy-preserving lock of a server's tool definitions",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if output == "" {
				return fmt.Errorf("--output is required")
			}
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be positive")
			}
			if err := validateInventoryTransport(transport); err != nil {
				return err
			}
			server, tools, err := enumerateForInventory(args[0], transport, timeout)
			if err != nil {
				return err
			}
			lock, err := inventory.New(server.Name, tools)
			if err != nil {
				return err
			}
			if err := inventory.Save(output, lock, force); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Saved tool inventory for %q (%d tools) to %s\n", lock.Server, len(lock.Tools), output)
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "path for the new lock file")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing lock file after reviewing the changes")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "connection and enumeration timeout")
	cmd.Flags().StringVar(&transport, "transport", "", "force transport for URL targets: http|sse")
	return cmd
}

func inventoryVerifyCmd() *cobra.Command {
	var baseline, transport string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "verify <target>",
		Short: "Fail if a server's tool definitions differ from a saved lock",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if baseline == "" {
				return fmt.Errorf("--baseline is required")
			}
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be positive")
			}
			if err := validateInventoryTransport(transport); err != nil {
				return err
			}
			previous, err := inventory.Load(baseline)
			if err != nil {
				return err
			}
			server, tools, err := enumerateForInventory(args[0], transport, timeout)
			if err != nil {
				return err
			}
			current, err := inventory.New(server.Name, tools)
			if err != nil {
				return err
			}
			changes, err := inventory.Compare(previous, current)
			if err != nil {
				return err
			}
			if len(changes) == 0 {
				fmt.Fprintf(os.Stdout, "Tool inventory matches the saved lock for %q (%d tools)\n", current.Server, len(current.Tools))
				return nil
			}
			for _, change := range changes {
				switch change.Kind {
				case "changed":
					fmt.Fprintf(os.Stdout, "CHANGED %q  %s -> %s\n", change.Name, shortFingerprint(change.Previous), shortFingerprint(change.Current))
				case "added":
					fmt.Fprintf(os.Stdout, "ADDED   %q  %s\n", change.Name, shortFingerprint(change.Current))
				case "removed":
					fmt.Fprintf(os.Stdout, "REMOVED %q  %s\n", change.Name, shortFingerprint(change.Previous))
				}
			}
			fmt.Fprintf(os.Stdout, "%d tool definition change(s) detected\n", len(changes))
			return errInventoryDrift
		},
	}
	cmd.Flags().StringVar(&baseline, "baseline", "", "saved tool inventory lock file")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "connection and enumeration timeout")
	cmd.Flags().StringVar(&transport, "transport", "", "force transport for URL targets: http|sse")
	return cmd
}

func enumerateForInventory(target, transport string, timeout time.Duration) (*config.Server, []protocol.Tool, error) {
	servers, _, err := collectMany([]string{target}, transport)
	if err != nil {
		return nil, nil, err
	}
	if len(servers) != 1 {
		return nil, nil, fmt.Errorf("inventory requires exactly one MCP server (found %d)", len(servers))
	}
	server := servers[0]
	in := probeServer(context.Background(), server, timeout)
	if in.ConnectErr != nil {
		return nil, nil, in.ConnectErr
	}
	for _, enumErr := range in.EnumErr {
		if strings.HasPrefix(enumErr, "tools/list:") {
			return nil, nil, fmt.Errorf("could not enumerate a complete tool inventory: %s", enumErr)
		}
	}
	return server, in.Tools, nil
}

func validateInventoryTransport(transport string) error {
	if transport != "" && !strings.EqualFold(transport, "http") && !strings.EqualFold(transport, "sse") {
		return fmt.Errorf("invalid --transport %q (expected http or sse)", transport)
	}
	return nil
}

func shortFingerprint(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}
