// Package context provides the Context Builder, which transforms
// evidence bundles into structured AI prompts.
//
// The Context Builder takes a question and an evidence bundle
// and produces a prompt that:
//   - Is grounded in evidence
//   - Has citations
//   - Is compressed (no redundancy)
//   - Has a clear structure
//
// No AI is used in context building. The output is a structured
// prompt ready for any LLM.
//
// Flow:
//
//	Evidence Bundle
//	    ↓
//	Compress (remove redundancy)
//	    ↓
//	Order (by relevance and type)
//	    ↓
//	Format (structured prompt with citations)
//	    ↓
//	Prompt
package context

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vKS-Rajput/doge/internal/retriever"
)

// Prompt is a structured, evidence-grounded prompt ready for an LLM.
type Prompt struct {
	SystemMessage string `json:"system_message"`
	UserMessage   string `json:"user_message"`
	EvidenceCount int    `json:"evidence_count"`
	TokenEstimate int    `json:"token_estimate"` // Rough token count estimate.
}

// Builder transforms evidence bundles into LLM prompts.
type Builder struct {
	maxTokens int // Maximum estimated tokens for evidence section.
}

// NewBuilder creates a new Context Builder.
func NewBuilder(maxTokens int) *Builder {
	if maxTokens <= 0 {
		maxTokens = 4000 // Conservative default.
	}
	return &Builder{maxTokens: maxTokens}
}

// Build transforms a question and evidence bundle into a structured prompt.
func (b *Builder) Build(question string, bundle *retriever.Bundle) *Prompt {
	// Group evidence by type.
	groups := groupEvidence(bundle.Evidence)

	// Build the evidence section.
	var sections []string
	sectionOrder := []retriever.EvidenceType{
		retriever.EvidenceInsight,
		retriever.EvidenceTask,
		retriever.EvidenceEntity,
		retriever.EvidenceRelationship,
		retriever.EvidenceObservation,
		retriever.EvidenceTimeline,
	}

	totalChars := 0
	evidenceCount := 0

	for _, etype := range sectionOrder {
		items, ok := groups[etype]
		if !ok || len(items) == 0 {
			continue
		}

		sectionTitle := evidenceSectionTitle(etype)
		var lines []string
		lines = append(lines, fmt.Sprintf("## %s", sectionTitle))

		for _, e := range items {
			// Check token budget (rough: 1 token ≈ 4 chars).
			lineLen := len(e.Summary) + len(e.Detail)
			if totalChars+lineLen > b.maxTokens*4 {
				lines = append(lines, fmt.Sprintf("... (%d more items truncated)", len(items)-evidenceCount))
				break
			}

			lines = append(lines, fmt.Sprintf("- [%s] %s", e.ID[:8], e.Summary))

			// Add detail for high-relevance evidence.
			if e.Relevance >= 0.7 && e.Detail != "" {
				detailLines := strings.Split(e.Detail, "\n")
				for _, dl := range detailLines {
					lines = append(lines, "  "+dl)
				}
			}

			totalChars += lineLen
			evidenceCount++
		}

		sections = append(sections, strings.Join(lines, "\n"))
	}

	evidenceSection := ""
	if len(sections) > 0 {
		evidenceSection = "\n\n# Evidence\n\n" + strings.Join(sections, "\n\n")
	}

	systemMessage := `You are Doge, an AI security research assistant.

You MUST follow these rules:
1. Only answer based on the evidence provided below.
2. Cite evidence using [ID] references.
3. If the evidence is insufficient to answer, say "I don't have enough evidence to answer this."
4. Never speculate beyond what the evidence shows.
5. Be concise but thorough.
6. Prioritize security-relevant findings.`

	userMessage := fmt.Sprintf("# Question\n\n%s%s", question, evidenceSection)

	if bundle.Truncated {
		userMessage += "\n\n> Note: Evidence was truncated. " +
			fmt.Sprintf("Showing %d of %d items found.", len(bundle.Evidence), bundle.TotalFound)
	}

	return &Prompt{
		SystemMessage: systemMessage,
		UserMessage:   userMessage,
		EvidenceCount: evidenceCount,
		TokenEstimate: (len(systemMessage) + len(userMessage)) / 4,
	}
}

func groupEvidence(evidence []retriever.Evidence) map[retriever.EvidenceType][]retriever.Evidence {
	groups := make(map[retriever.EvidenceType][]retriever.Evidence)
	for _, e := range evidence {
		groups[e.Type] = append(groups[e.Type], e)
	}

	// Sort each group by relevance.
	for _, items := range groups {
		sort.Slice(items, func(i, j int) bool {
			return items[i].Relevance > items[j].Relevance
		})
	}

	return groups
}

func evidenceSectionTitle(t retriever.EvidenceType) string {
	switch t {
	case retriever.EvidenceEntity:
		return "Entities"
	case retriever.EvidenceRelationship:
		return "Relationships"
	case retriever.EvidenceObservation:
		return "Observations"
	case retriever.EvidenceInsight:
		return "Insights (Detected Patterns)"
	case retriever.EvidenceTask:
		return "Tasks (Actionable Items)"
	case retriever.EvidenceTimeline:
		return "Timeline Events"
	default:
		return "Other"
	}
}
