package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

const (
	SarifSchemaVersion = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	SarifFormatVersion = "2.1.0"
	DogeToolName       = "DOGE Autonomous Security Science"
	DogeToolVersion    = "7.0.0"
	DogeToolURI        = "https://github.com/vKS-Rajput/Doge"
)

// SarifLog is the root container of an OASIS SARIF v2.1.0 document.
type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

// SarifRun represents a single execution of the analysis tool.
type SarifRun struct {
	Tool      SarifTool     `json:"tool"`
	Results   []SarifResult `json:"results"`
	Artifacts []SarifArtifact `json:"artifacts,omitempty"`
}

// SarifTool contains information about the scanning tool and its driver.
type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

// SarifDriver describes the tool's identification, version, and defined rules.
type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

// SarifRule defines a category or class of security vulnerability tested.
type SarifRule struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name"`
	ShortDescription     SarifMultiformatMessage `json:"shortDescription"`
	FullDescription      SarifMultiformatMessage `json:"fullDescription"`
	DefaultConfiguration SarifConfiguration      `json:"defaultConfiguration"`
	Help                 SarifMultiformatMessage `json:"help"`
	Properties           map[string]any          `json:"properties,omitempty"`
}

// SarifConfiguration specifies the default alert level of a rule.
type SarifConfiguration struct {
	Level string `json:"level"` // "error", "warning", "note", "none"
}

// SarifResult represents a single finding emitted by the analysis.
type SarifResult struct {
	RuleID       string                  `json:"ruleId"`
	RuleIndex    int                     `json:"ruleIndex"`
	Level        string                  `json:"level"` // "error", "warning", "note"
	Message      SarifMultiformatMessage `json:"message"`
	Locations    []SarifLocation         `json:"locations,omitempty"`
	Properties   map[string]any          `json:"properties,omitempty"`
}

// SarifLocation pinpoints the target resource where the flaw was detected.
type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

// SarifPhysicalLocation details the URI and offset of the affected resource.
type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}

// SarifArtifactLocation identifies the artifact by URI.
type SarifArtifactLocation struct {
	URI   string `json:"uri"`
	Index int    `json:"index,omitempty"`
}

// SarifRegion specifies line or character numbers.
type SarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// SarifArtifact lists tracked assets in the run.
type SarifArtifact struct {
	Location SarifArtifactLocation `json:"location"`
}

// SarifMultiformatMessage contains plain-text or markdown messages.
type SarifMultiformatMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// ExportSARIF converts a DOGE security report and associated cryptographic proof bundles into OASIS SARIF v2.1.0 JSON.
func ExportSARIF(rep *Report, bundles []*ProofBundle) ([]byte, error) {
	if rep == nil {
		return nil, fmt.Errorf("report is nil")
	}

	bundleByFinding := make(map[string]*ProofBundle)
	for _, b := range bundles {
		bundleByFinding[b.FindingID.String()] = b
	}

	ruleMap := make(map[string]int)
	var rules []SarifRule
	var results []SarifResult

	for _, f := range rep.Findings {
		vulnType := mapCategoryToVulnType(f.Category, f.Title)
		score := GetVulnerabilityScore(vulnType)

		ruleID := fmt.Sprintf("DOGE-%s", strings.ToUpper(vulnType))
		ruleIdx, exists := ruleMap[ruleID]
		if !exists {
			ruleIdx = len(rules)
			ruleMap[ruleID] = ruleIdx

			ruleLevel := mapSeverityToSarifLevel(f.Severity)
			rules = append(rules, SarifRule{
				ID:   ruleID,
				Name: f.Title,
				ShortDescription: SarifMultiformatMessage{
					Text: f.Title,
				},
				FullDescription: SarifMultiformatMessage{
					Text: f.Description,
				},
				DefaultConfiguration: SarifConfiguration{
					Level: ruleLevel,
				},
				Help: SarifMultiformatMessage{
					Text:     f.Remediation,
					Markdown: fmt.Sprintf("### Remediation Advisory\n\n%s\n\n**CWE**: %s (%s)\n**CVSS 3.1 Base Score**: %.1f (%s)", f.Remediation, score.CWEID, score.CWEName, score.BaseScore, score.Severity),
				},
				Properties: map[string]any{
					"tags": []string{
						"security",
						strings.ToLower(score.CWEID),
						fmt.Sprintf("cvss:%.1f", score.BaseScore),
					},
					"precision": "very-high",
					"cvss":      score.BaseScore,
					"cwe":       score.CWEID,
				},
			})
		}

		level := mapSeverityToSarifLevel(f.Severity)
		targetURI := extractTargetURI(f, rep.Executive.Target)

		resProps := map[string]any{
			"severity":   string(f.Severity),
			"category":   string(f.Category),
			"cvss_score": score.BaseScore,
			"cvss_vect":  score.VectorString,
			"cwe_id":     score.CWEID,
			"cwe_name":   score.CWEName,
		}

		// Attach cryptographic proof metadata if bundle is available
		for _, b := range bundles {
			if b.VulnerabilityClass == vulnType || strings.Contains(strings.ToLower(f.Title), strings.ToLower(b.VulnerabilityClass)) {
				resProps["proof_bundle_id"] = b.ID.String()
				resProps["proof_chain_digest"] = b.ChainDigest
				resProps["proof_merkle_root"] = b.MerkleRoot
				resProps["proof_steps_count"] = len(b.Steps)
				resProps["proof_attested_engine"] = b.Attestation.EngineVersion
				break
			}
		}

		result := SarifResult{
			RuleID:    ruleID,
			RuleIndex: ruleIdx,
			Level:     level,
			Message: SarifMultiformatMessage{
				Text: fmt.Sprintf("[%s] %s: %s", score.Severity, f.Title, f.Description),
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							URI: targetURI,
						},
						Region: &SarifRegion{
							StartLine: 1,
						},
					},
				},
			},
			Properties: resProps,
		}

		results = append(results, result)
	}

	sarifLog := SarifLog{
		Schema:  SarifSchemaVersion,
		Version: SarifFormatVersion,
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           DogeToolName,
						Version:        DogeToolVersion,
						InformationURI: DogeToolURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(sarifLog, "", "  ")
}

func mapSeverityToSarifLevel(sev domain.Severity) string {
	switch sev {
	case domain.SeverityCritical, domain.SeverityHigh:
		return "error"
	case domain.SeverityMedium:
		return "warning"
	case domain.SeverityLow, domain.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

func mapCategoryToVulnType(cat domain.FindingCategory, title string) string {
	tLower := strings.ToLower(title)
	switch {
	case strings.Contains(tLower, "bola") || strings.Contains(tLower, "idor") || strings.Contains(tLower, "object level"):
		return "BOLA"
	case strings.Contains(tLower, "race") || strings.Contains(tLower, "concurrency") || strings.Contains(tLower, "overdraw"):
		return "RaceCondition"
	case strings.Contains(tLower, "smuggl") || strings.Contains(tLower, "te.cl") || strings.Contains(tLower, "desync"):
		return "RequestSmuggling"
	case strings.Contains(tLower, "jwt") || strings.Contains(tLower, "token") || strings.Contains(tLower, "algorithm confusion"):
		return "JWTConfusion"
	case strings.Contains(tLower, "timing") || strings.Contains(tLower, "blind"):
		return "BlindTimingOracle"
	case strings.Contains(tLower, "context bleed") || strings.Contains(tLower, "pipeline bleed"):
		return "ContextBleed"
	case strings.Contains(tLower, "workflow") || strings.Contains(tLower, "paywall") || strings.Contains(tLower, "state"):
		return "WorkflowBypass"
	default:
		if cat == domain.FindingCatAuthorization {
			return "BOLA"
		}
		return "GenericVulnerability"
	}
}

func extractTargetURI(f FindingSection, defaultTarget string) string {
	for _, step := range f.ReproductionSteps {
		if strings.HasPrefix(step.Description, "http://") || strings.HasPrefix(step.Description, "https://") {
			return step.Description
		}
		if strings.HasPrefix(step.ExpectedResult, "http://") || strings.HasPrefix(step.ExpectedResult, "https://") {
			return step.ExpectedResult
		}
	}
	if defaultTarget != "" {
		return defaultTarget
	}
	return "https://target.local/api"
}
