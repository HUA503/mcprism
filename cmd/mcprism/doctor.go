package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/HUA503/mcprism/internal/config"
	"github.com/spf13/cobra"
)

func doctorCmd() *cobra.Command {
	var project string
	var projectOnly bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Explain which MCP configs mcprism discovers",
		Long: `Run the same static config discovery as 'mcprism scan' and list the
config files and server counts it finds. This command never launches a server
or connects to a URL. It honors environment variables used to locate client
configs, but does not resolve server credential variables.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			projectDir := project
			if projectDir == "" {
				var err error
				projectDir, err = os.Getwd()
				if err != nil {
					return err
				}
			}
			projectDir, err := filepath.Abs(projectDir)
			if err != nil {
				return err
			}
			info, err := os.Stat(projectDir)
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return fmt.Errorf("project path %q is not a directory", projectDir)
			}

			files, err := config.Discover(projectDir, !projectOnly)
			if err != nil {
				return err
			}
			serverCount := 0
			for _, file := range files {
				serverCount += len(file.Servers)
			}

			fmt.Printf("mcprism %s · config discovery\n", version)
			fmt.Printf("Project: %s\n", projectDir)
			if projectOnly {
				fmt.Println("Global client configs: skipped")
			} else {
				fmt.Println("Global client configs: included")
			}
			fmt.Printf("Found %d config file(s) with %d MCP server(s).\n", len(files), serverCount)
			for _, file := range files {
				fmt.Printf("  %s · %s · %d server(s)\n    %s\n",
					file.Client, file.Scope, len(file.Servers), file.Path)
			}
			if len(files) == 0 {
				fmt.Println("No supported MCP configs with servers were found.")
				if projectOnly {
					fmt.Println("Try without --project-only to include user and system configs.")
				}
				fmt.Println("Try 'mcprism scan path/to/config.json', or run 'mcprism demo' to explore the built-in examples.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project directory for project-level config discovery")
	cmd.Flags().BoolVar(&projectOnly, "project-only", false, "discover project configs only (skip global client configs)")
	return cmd
}
