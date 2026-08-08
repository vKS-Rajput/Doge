package watch

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Display handles terminal output for the watch mode.
// All live-mode output goes through Display so it can be
// quieted, formatted consistently, and tested.
type Display struct {
	quiet bool
}

// NewDisplay creates a new watch display.
func NewDisplay(quiet bool) *Display {
	return &Display{quiet: quiet}
}

// Banner prints the watch mode header.
func (d *Display) Banner(watchDir string) {
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("🐕 Doge Watch — Monitoring workspace")
	fmt.Printf("   %s\n", watchDir)
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("Waiting for file changes...")
	fmt.Println()
}

// FileDetected logs that a new/changed file was detected.
func (d *Display) FileDetected(fileName string) {
	d.timestamp()
	fmt.Printf("📥 New file: %s\n", fileName)
}

// FileDeleted logs that a file was removed (evidence preserved).
func (d *Display) FileDeleted(path string) {
	d.timestamp()
	fmt.Printf("🗑  File deleted: %s (evidence preserved)\n", filepath.Base(path))
}

// ImportFailed logs a failed import without crashing.
func (d *Display) ImportFailed(fileName string, err error) {
	d.timestamp()
	fmt.Printf("❌ Import failed: %s\n", fileName)
	fmt.Printf("   Reason: %s\n", err)
	fmt.Printf("   Watch continues...\n\n")
}

// ChangeSummary displays an aggregated change summary.
func (d *Display) ChangeSummary(summary ChangeSummary) {
	if summary.Files == 0 && summary.Duplicates > 0 {
		if !d.quiet {
			d.timestamp()
			fmt.Printf("   (duplicate content, skipped)\n\n")
		}
		return
	}

	if summary.Files == 0 {
		return
	}

	d.timestamp()
	fmt.Printf("✅ Import complete")
	if summary.Files > 1 {
		fmt.Printf(" (%d files)", summary.Files)
	}
	fmt.Println()

	// Counts line.
	parts := []string{}
	if summary.Observations > 0 {
		parts = append(parts, fmt.Sprintf("+%d observations", summary.Observations))
	}
	if summary.Duplicates > 0 {
		parts = append(parts, fmt.Sprintf("%d duplicates", summary.Duplicates))
	}
	if len(parts) > 0 {
		fmt.Printf("   %s\n", strings.Join(parts, " | "))
	}

	// Notable items.
	if len(summary.Items) > 0 {
		fmt.Println()
		d.timestamp()
		fmt.Println("🔍 Notable changes:")
		for _, item := range summary.Items {
			icon := "  "
			switch item.Priority {
			case "high", "critical":
				icon = "⚡"
			case "medium":
				icon = "📋"
			default:
				icon = "  "
			}
			fmt.Printf("   %s [%s] %s\n", icon, strings.ToUpper(item.Priority), item.Value)
		}
	}

	fmt.Println()
}

// AITriggered displays an AI reasoning suggestion.
func (d *Display) AITriggered(reason string) {
	d.timestamp()
	fmt.Println("🧠 AI reasoning recommended")
	fmt.Printf("   Reason: %s\n", reason)
	fmt.Println("   Run: doge ask \"What changed?\"")
	fmt.Println()
}

// Info prints an informational message.
func (d *Display) Info(msg string) {
	d.timestamp()
	fmt.Println(msg)
}

// Warn prints a warning message.
func (d *Display) Warn(msg string) {
	if !d.quiet {
		d.timestamp()
		fmt.Printf("⚠ %s\n", msg)
	}
}

func (d *Display) timestamp() {
	fmt.Printf("[%s] ", time.Now().Format("15:04:05"))
}
