// Doge — AI Security Research Workspace
//
// This is the entry point for the workspace CLI. Every command is thin:
// it parses flags, validates input, and delegates to an Application Service.
// No business logic lives here.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Build-time variables, set via ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd creates the root command with all subcommands registered.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "doge",
		Short: "AI Security Research Workspace",
		Long: `Doge is a terminal-native workspace that helps security researchers
organize, remember, and reason about the artifacts a real engagement produces.

It watches your project directory for tool output, parses it into structured
observations, builds a knowledge graph, and surfaces insights — all without
requiring AI. AI reasoning is available but optional.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newStartCmd(),
		newVersionCmd(),
		newInitCmd(),
		newStatusCmd(),
		newImportCmd(),
		newTimelineCmd(),
		newSearchCmd(),
		newGraphCmd(),
		newInsightsCmd(),
		newTasksCmd(),
		newSnapshotCmd(),
		newSnapshotsCmd(),
		newDiffCmd(),
		newAskCmd(),
		newInvestigateCmd(),
		newWatchCmd(),
		newTUICmd(),
		// Phase 4: Multi-terminal control plane.
		newRuntimeStatusCmd(),
		newConsoleCmd(),
		newLogsCmd(),
		newApprovalsCmd(),
		// v1.2: Research Copilot — primary commands.
		newWorkCmd(),
		newMonitorCmd(),
		newNotebookCmd(),
		// v1.2: Secondary/fallback commands.
		newIngestCmd(),
		newJournalCmd(),
		newNoteCmd(),
		newCoverageCmd(),
		newGapsCmd(),
	)

	return root
}

// newVersionCmd creates the 'version' command.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("doge %s (commit: %s, built: %s)\n", version, commit, date)
		},
	}
}
