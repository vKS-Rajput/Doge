// Doge — AI Security Research Workspace
//
// This is the entry point for the workspace CLI. It initializes the
// command router and dispatches to the appropriate module handler.
//
// Usage:
//
//	workspace init [name]        Initialize a new workspace
//	workspace open [path]        Open an existing workspace
//	workspace version            Print version information
package main

import (
	"fmt"
	"os"
)

// Version information, set at build time via ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// TODO(Phase 2): Replace with cobra command router.
	// For now, this is a minimal entry point that verifies the build works.
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("doge %s (commit: %s, built: %s)\n", version, commit, date)
		return
	}

	fmt.Println("doge — AI Security Research Workspace")
	fmt.Println("Run 'doge version' for version information.")
	fmt.Println()
	fmt.Println("Commands will be available after Phase 2 (Command Router).")
}
