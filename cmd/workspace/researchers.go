package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

type researcherInfo struct {
	Type        domain.ResearcherType
	Name        string
	Domain      string
	Description string
}

func newResearchersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "researchers",
		Aliases: []string{"fleet", "agents"},
		Short:   "List available specialized security researcher capabilities and their domains",
		Long: `DOGE Researcher Fleet — Displays all specialized research capabilities available
for autonomous dispatch by the Research Director.`,
		Run: func(cmd *cobra.Command, args []string) {
			fleet := []researcherInfo{
				{
					Type:        domain.ResearcherRecon,
					Name:        "Reconnaissance Researcher",
					Domain:      "Surface Mapping",
					Description: "Discovers external topology, subdomains, live ports, endpoints, and technologies.",
				},
				{
					Type:        domain.ResearcherAPI,
					Name:        "API & Schema Researcher",
					Domain:      "REST & GraphQL",
					Description: "Discovers OpenAPI/Swagger definitions, GraphQL schemas, parameter structures, and HTTP verb tampering.",
				},
				{
					Type:        domain.ResearcherAuthentication,
					Name:        "Authentication & Identity Researcher",
					Domain:      "Tokens & Sessions",
					Description: "Tests JWT alg:none, signature stripping, session fixation, and unauthenticated route leaks.",
				},
				{
					Type:        domain.ResearcherAuthorization,
					Name:        "Authorization Researcher",
					Domain:      "BOLA & IDOR",
					Description: "Performs cross-tenant object access testing, tenant isolation evaluation, and privilege boundary checks.",
				},
				{
					Type:        domain.ResearcherDifferential,
					Name:        "Differential Matrix Researcher",
					Domain:      "Multi-Principal",
					Description: "Executes synchronized multi-principal matrix probes (Anon vs User A vs User B vs Admin).",
				},
				{
					Type:        domain.ResearcherMetamorphic,
					Name:        "Metamorphic Relation Researcher",
					Domain:      "Invariants & Pipelines",
					Description: "Tests order invariance, batch context bleed, and execution frame isolation across sub-operations.",
				},
				{
					Type:        domain.ResearcherRace,
					Name:        "Concurrency & Race Researcher",
					Domain:      "TOCTOU & State Windows",
					Description: "Dispatches synchronized concurrent bursts to expose latent transaction race windows and limit overdraw.",
				},
				{
					Type:        domain.ResearcherCache,
					Name:        "Cache & Proxy Bleed Researcher",
					Domain:      "Normalization & Poisoning",
					Description: "Tests unkeyed header injection and path canonicalization discrepancy collisions.",
				},
				{
					Type:        domain.ResearcherInjection,
					Name:        "Input Injection Researcher",
					Domain:      "SQLi, SSTI, Traversal",
					Description: "Tests syntax errors, boolean discrepancies, template evaluations, and path traversal.",
				},
				{
					Type:        domain.ResearcherChain,
					Name:        "Attack Chain Researcher",
					Domain:      "Attack Graph Composition",
					Description: "Composes isolated primitives and access states into multi-step escalation paths.",
				},
				{
					Type:        domain.ResearcherExploit,
					Name:        "Controlled Exploit Researcher",
					Domain:      "Bounded Proofs",
					Description: "Formulates safe, bounded, reversible exploit proofs under policy controls and approval gates.",
				},
				{
					Type:        domain.ResearcherSource,
					Name:        "Source Code Researcher",
					Domain:      "Whitebox AST & Taint",
					Description: "Correlates static code AST routes and taint paths with runtime observations.",
				},
				{
					Type:        domain.ResearcherValidation,
					Name:        "Independent Validator",
					Domain:      "Reproducibility",
					Description: "Independently reproduces candidate findings using fresh context to eliminate false positives.",
				},
				{
					Type:        domain.ResearcherImpact,
					Name:        "Impact Demonstration Researcher",
					Domain:      "Impact Quantification",
					Description: "Demonstrates tangible real-world business and financial impact to seal proven findings.",
				},
			}

			fmt.Println()
			fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
			fmt.Println("║               🐕 DOGE SPECIALIZED RESEARCHER FLEET               ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
			fmt.Printf(" Registered Specialized Capabilities: %d\n\n", len(fleet))

			for i, r := range fleet {
				fmt.Printf("[%02d] [%-14s] %s\n", i+1, r.Type, r.Name)
				fmt.Printf("     Domain:      %s\n", r.Domain)
				fmt.Printf("     Capability:  %s\n", r.Description)
				fmt.Println("──────────────────────────────────────────────────────────────────")
			}
		},
	}

	return cmd
}
