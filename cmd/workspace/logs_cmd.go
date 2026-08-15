package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/session"
)

func newLogsCmd() *cobra.Command {
	var follow bool
	var lines int
	var filter string

	cmd := &cobra.Command{
		Use:   "logs [workspace]",
		Short: "Show live investigation event stream",
		Long: `Show the DOGE investigation event log.

By default shows the last 50 lines. Use -f to follow (tail) the log.

The log contains:
  • Scheduler events (jobs queued, started, completed)
  • Executor events (tool execution, artifacts)
  • Ingestion events (parsing, observations)
  • Brain events (priorities, recommendations)
  • Human gate events (approvals, findings)

Use --filter to show only specific event types:
  doge logs --filter scheduler
  doge logs --filter executor
  doge logs --filter brain
  doge logs --filter ingest`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wsPath := "."
			if len(args) > 0 {
				wsPath = args[0]
			}
			absPath, _ := filepath.Abs(wsPath)

			state, err := session.LoadState(absPath)
			if err != nil {
				// Try default log path.
				logPath := filepath.Join(absPath, ".doge", "doge.log")
				if _, statErr := os.Stat(logPath); statErr != nil {
					fmt.Println("🐕 DOGE — No active session or log file found")
					fmt.Println("  Start with: doge start --target <IP> --env htb")
					return nil
				}
				return showLogs(logPath, follow, lines, filter)
			}

			logPath := state.LogFile
			if logPath == "" {
				logPath = filepath.Join(absPath, ".doge", "doge.log")
			}

			return showLogs(logPath, follow, lines, filter)
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output (like tail -f)")
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "Number of lines to show")
	cmd.Flags().StringVar(&filter, "filter", "", "Filter by component (scheduler, executor, brain, ingest)")

	return cmd
}

func showLogs(logPath string, follow bool, numLines int, filter string) error {
	file, err := os.Open(logPath)
	if err != nil {
		fmt.Printf("Cannot open log file: %s\n", err)
		return nil
	}
	defer file.Close()

	fmt.Println()
	fmt.Println("🐕 DOGE Event Log")
	fmt.Printf("File: %s\n", logPath)
	if filter != "" {
		fmt.Printf("Filter: %s\n", filter)
	}
	fmt.Println("────────────────────────────────────")
	fmt.Println()

	// Read all lines for tail.
	var allLines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if filter != "" && !matchesFilter(line, filter) {
			continue
		}
		allLines = append(allLines, line)
	}

	// Show last N lines.
	start := len(allLines) - numLines
	if start < 0 {
		start = 0
	}
	for _, line := range allLines[start:] {
		fmt.Println(formatLogLine(line))
	}

	if !follow {
		return nil
	}

	// Follow mode: tail the file.
	fmt.Println()
	fmt.Println("── Following (Ctrl+C to stop) ──")
	fmt.Println()

	// Seek to end.
	file.Seek(0, io.SeekEnd)

	// Handle Ctrl+C.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	reader := bufio.NewReader(file)
	for {
		select {
		case <-sigCh:
			fmt.Println("\n👋 Log stream detached.")
			return nil
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				// No new data — wait briefly.
				time.Sleep(200 * time.Millisecond)
				continue
			}
			line = strings.TrimRight(line, "\r\n")
			if filter != "" && !matchesFilter(line, filter) {
				continue
			}
			fmt.Println(formatLogLine(line))
		}
	}
}

func matchesFilter(line, filter string) bool {
	lower := strings.ToLower(line)
	filterLower := strings.ToLower(filter)
	return strings.Contains(lower, filterLower)
}

func formatLogLine(line string) string {
	// Colorize by component.
	if strings.Contains(line, "SCHEDULER") || strings.Contains(line, "scheduler") {
		return "\033[36m" + line + "\033[0m" // Cyan
	}
	if strings.Contains(line, "EXECUTOR") || strings.Contains(line, "executor") || strings.Contains(line, "executing tool") {
		return "\033[32m" + line + "\033[0m" // Green
	}
	if strings.Contains(line, "BRAIN") || strings.Contains(line, "brain") || strings.Contains(line, "priority") {
		return "\033[35m" + line + "\033[0m" // Magenta
	}
	if strings.Contains(line, "INGEST") || strings.Contains(line, "ingest") || strings.Contains(line, "observation") {
		return "\033[33m" + line + "\033[0m" // Yellow
	}
	if strings.Contains(line, "ERROR") || strings.Contains(line, "error") {
		return "\033[31m" + line + "\033[0m" // Red
	}
	if strings.Contains(line, "WARN") || strings.Contains(line, "warn") {
		return "\033[33m" + line + "\033[0m" // Yellow
	}
	return line
}
