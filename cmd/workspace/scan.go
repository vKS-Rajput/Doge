package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/internal/scanner"
)

func newScanCmd() *cobra.Command {
	var (
		budget    int
		rps       int
		timeout   int
		outScope  string
		report    string
		skipTLS   bool
		headers   []string
	)

	cmd := &cobra.Command{
		Use:   "scan [target-url]",
		Short: "Autonomously scan a target for security vulnerabilities",
		Long: `DOGE Autonomous Security Scanner — point it at any URL and it will:

  1. Discover live endpoints (crawl, robots.txt, common paths, API schemas)
  2. Test for real vulnerabilities (BOLA, SQLi, XSS, SSRF, Path Traversal,
     CORS, Command Injection, Timing Oracles, Info Disclosure, and more)
  3. Generate cryptographic proof bundles with SHA-256 Merkle chains
  4. Produce a security assessment report

Examples:
  doge scan http://target.com
  doge scan http://target.com --budget 500 --rps 20
  doge scan http://target.com --out-of-scope "/logout,/admin/delete*"
  doge scan http://localhost:8080 --skip-tls --report findings.md`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]

			// Parse custom headers
			customHeaders := make(map[string]string)
			for _, h := range headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}

			// Parse out-of-scope paths
			var outOfScope []string
			if outScope != "" {
				for _, p := range strings.Split(outScope, ",") {
					outOfScope = append(outOfScope, strings.TrimSpace(p))
				}
			}

			cfg := scanner.ScanConfig{
				TargetURL:      targetURL,
				Budget:         budget,
				RatePerSecond:  rps,
				TimeoutMinutes: timeout,
				OutOfScope:     outOfScope,
				CustomHeaders:  customHeaders,
				SkipTLSVerify:  skipTLS,
			}

			s := scanner.NewScanner(cfg)
			result, err := s.Run(cmd.Context())
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Print summary
			fmt.Println()
			fmt.Println("🐕 SCAN RESULTS SUMMARY")
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Printf("Target:          %s\n", result.TargetURL)
			fmt.Printf("Duration:        %v\n", result.Duration.Round(time.Millisecond))
			fmt.Printf("Endpoints Found: %d\n", result.EndpointsFound)
			fmt.Printf("Requests Made:   %d / %d\n", result.RequestsMade, budget)
			fmt.Printf("Vulnerabilities: %d\n", len(result.Findings))
			fmt.Printf("Proof Bundles:   %d\n", len(result.ProofBundles))

			if len(result.Findings) > 0 {
				fmt.Println()
				fmt.Println("FINDINGS:")
				for i, f := range result.Findings {
					fmt.Printf("  [%d] [%s] %s\n", i+1, f.Severity, f.Title)
					fmt.Printf("      Type: %s | Endpoint: %s\n", f.Type, f.Endpoint)
				}
			}

			if len(result.ProofBundles) > 0 {
				fmt.Println()
				fmt.Println("PROOF BUNDLES:")
				for _, b := range result.ProofBundles {
					fmt.Printf("  📦 %s — Merkle: %s\n", b.VulnerabilityClass, b.MerkleRoot[:24]+"...")
				}
			}

			// Write report if requested
			if report != "" {
				err := os.WriteFile(report, []byte(result.Report), 0644)
				if err != nil {
					return fmt.Errorf("failed to write report: %w", err)
				}
				fmt.Printf("\n📄 Report saved to: %s\n", report)
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&budget, "budget", 200, "Maximum number of HTTP requests to make")
	cmd.Flags().IntVar(&rps, "rps", 10, "Max requests per second (rate limiting)")
	cmd.Flags().IntVar(&timeout, "timeout", 5, "Scan timeout in minutes")
	cmd.Flags().StringVar(&outScope, "out-of-scope", "", "Comma-separated list of paths to exclude (supports * wildcards)")
	cmd.Flags().StringVar(&report, "report", "", "Output file for the assessment report (.md)")
	cmd.Flags().BoolVar(&skipTLS, "skip-tls", false, "Skip TLS certificate verification")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "Custom headers (e.g. -H 'Authorization: Bearer token')")

	return cmd
}
