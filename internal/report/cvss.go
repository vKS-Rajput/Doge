package report

import (
	"fmt"
	"math"
	"strings"
)

// CVSSVector represents the parsed metrics of a CVSS v3.1 vector.
type CVSSVector struct {
	AttackVector       string // N, A, L, P
	AttackComplexity   string // L, H
	PrivilegesRequired string // N, L, H
	UserInteraction    string // N, R
	Scope              string // U, C
	Confidentiality    string // N, L, H
	Integrity          string // N, L, H
	Availability       string // N, L, H
	RawVector          string
}

// CVSSScore encapsulates the calculated numeric score and qualitative severity rating.
type CVSSScore struct {
	BaseScore        float64 `json:"base_score"`
	Exploitability   float64 `json:"exploitability_score"`
	Impact           float64 `json:"impact_score"`
	Severity         string  `json:"severity"` // "None", "Low", "Medium", "High", "Critical"
	VectorString     string  `json:"vector_string"`
	CWEID            string  `json:"cwe_id"`
	CWEName          string  `json:"cwe_name"`
}

// RoundUp implements the FIRST CVSS v3.1 round-up specification.
func RoundUp(input float64) float64 {
	val := int(math.Round(input * 100000))
	if val%10000 == 0 {
		return float64(val/10000) / 10.0
	}
	return float64(int(val/10000)+1) / 10.0
}

// ParseCVSSVector parses a standard CVSS:3.1 vector string.
func ParseCVSSVector(vector string) (*CVSSVector, error) {
	v := &CVSSVector{
		RawVector: vector,
	}

	parts := strings.Split(vector, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid CVSS vector format: %s", vector)
	}

	for _, part := range parts {
		kv := strings.Split(part, ":")
		if len(kv) != 2 {
			continue
		}
		key := strings.ToUpper(kv[0])
		val := strings.ToUpper(kv[1])

		switch key {
		case "AV":
			v.AttackVector = val
		case "AC":
			v.AttackComplexity = val
		case "PR":
			v.PrivilegesRequired = val
		case "UI":
			v.UserInteraction = val
		case "S":
			v.Scope = val
		case "C":
			v.Confidentiality = val
		case "I":
			v.Integrity = val
		case "A":
			v.Availability = val
		}
	}

	if v.AttackVector == "" || v.AttackComplexity == "" || v.PrivilegesRequired == "" ||
		v.UserInteraction == "" || v.Scope == "" || v.Confidentiality == "" ||
		v.Integrity == "" || v.Availability == "" {
		return nil, fmt.Errorf("incomplete CVSS vector: %s", vector)
	}

	return v, nil
}

// CalculateCVSS computes the CVSS v3.1 base score according to the official specification.
func CalculateCVSS(v *CVSSVector) *CVSSScore {
	// Attack Vector
	var av float64
	switch v.AttackVector {
	case "N":
		av = 0.85
	case "A":
		av = 0.62
	case "L":
		av = 0.55
	case "P":
		av = 0.20
	default:
		av = 0.85
	}

	// Attack Complexity
	var ac float64
	switch v.AttackComplexity {
	case "L":
		ac = 0.77
	case "H":
		ac = 0.44
	default:
		ac = 0.77
	}

	// Privileges Required
	var pr float64
	if v.Scope == "C" { // Changed scope
		switch v.PrivilegesRequired {
		case "N":
			pr = 0.85
		case "L":
			pr = 0.68
		case "H":
			pr = 0.50
		default:
			pr = 0.85
		}
	} else { // Unchanged scope
		switch v.PrivilegesRequired {
		case "N":
			pr = 0.85
		case "L":
			pr = 0.62
		case "H":
			pr = 0.27
		default:
			pr = 0.85
		}
	}

	// User Interaction
	var ui float64
	switch v.UserInteraction {
	case "N":
		ui = 0.85
	case "R":
		ui = 0.62
	default:
		ui = 0.85
	}

	// Confidentiality, Integrity, Availability
	var c, i, a float64
	switch v.Confidentiality {
	case "H":
		c = 0.56
	case "L":
		c = 0.22
	}
	switch v.Integrity {
	case "H":
		i = 0.56
	case "L":
		i = 0.22
	}
	switch v.Availability {
	case "H":
		a = 0.56
	case "L":
		a = 0.22
	}

	// ISS = 1 - [ (1 - ImpactConf) × (1 - ImpactInteg) × (1 - ImpactAvail) ]
	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

	var impact float64
	if v.Scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	exploitability := 8.22 * av * ac * pr * ui

	var baseScore float64
	if impact <= 0 {
		baseScore = 0.0
	} else if v.Scope == "U" {
		baseScore = RoundUp(math.Min(impact+exploitability, 10.0))
	} else {
		baseScore = RoundUp(math.Min(1.08*(impact+exploitability), 10.0))
	}

	var severity string
	switch {
	case baseScore == 0.0:
		severity = "None"
	case baseScore < 4.0:
		severity = "Low"
	case baseScore < 7.0:
		severity = "Medium"
	case baseScore < 9.0:
		severity = "High"
	default:
		severity = "Critical"
	}

	return &CVSSScore{
		BaseScore:      baseScore,
		Exploitability: RoundUp(exploitability),
		Impact:         RoundUp(impact),
		Severity:       severity,
		VectorString:   v.RawVector,
	}
}

// VulnerabilityMetadata associates vulnerability classes with canonical CVSS vectors and CWE definitions.
type VulnerabilityMetadata struct {
	VulnerabilityType string
	DefaultVector     string
	CWEID             string
	CWEName           string
	DefaultRemedy     string
}

// CanonicalVulnerabilityRegistry maps discovered vulnerability classes to standard CVSS and CWE metadata.
var CanonicalVulnerabilityRegistry = map[string]VulnerabilityMetadata{
	"BOLA": {
		VulnerabilityType: "BOLA",
		DefaultVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		CWEID:             "CWE-639",
		CWEName:           "Authorization Bypass Through User-Controlled Key",
		DefaultRemedy:     "Enforce principal ownership checks on all object identifiers at the database repository layer.",
	},
	"RaceCondition": {
		VulnerabilityType: "RaceCondition",
		DefaultVector:     "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
		CWEID:             "CWE-362",
		CWEName:           "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
		DefaultRemedy:     "Wrap balance updates and resource allocations in serialized database transactions (SELECT FOR UPDATE) or distributed mutexes.",
	},
	"RequestSmuggling": {
		VulnerabilityType: "RequestSmuggling",
		DefaultVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		CWEID:             "CWE-444",
		CWEName:           "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')",
		DefaultRemedy:     "Normalize HTTP framing at frontend reverse proxies, reject ambiguous Content-Length/Transfer-Encoding headers, and enforce end-to-end HTTP/2.",
	},
	"JWTConfusion": {
		VulnerabilityType: "JWTConfusion",
		DefaultVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		CWEID:             "CWE-287",
		CWEName:           "Improper Authentication (Cryptographic Algorithm Confusion)",
		DefaultRemedy:     "Explicitly pin and whitelist the allowed JWT signing algorithm (RS256) and reject HMAC verification using public keys.",
	},
	"BlindTimingOracle": {
		VulnerabilityType: "BlindTimingOracle",
		DefaultVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CWEID:             "CWE-200",
		CWEName:           "Exposure of Sensitive Information to an Unauthorized Actor via Timing Oracle",
		DefaultRemedy:     "Use constant-time equality comparisons (subtle.ConstantTimeCompare) and avoid conditional backend query latency.",
	},
	"ContextBleed": {
		VulnerabilityType: "ContextBleed",
		DefaultVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
		CWEID:             "CWE-200",
		CWEName:           "Exposure of Sensitive Information via Batch Pipeline Context Bleed",
		DefaultRemedy:     "Reset and isolate execution contexts, thread-locals, and memory buffers between individual batch pipeline requests.",
	},
	"WorkflowBypass": {
		VulnerabilityType: "WorkflowBypass",
		DefaultVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
		CWEID:             "CWE-863",
		CWEName:           "Incorrect Authorization (State-Machine Workflow Bypass)",
		DefaultRemedy:     "Validate state transitions server-side against a strict finite-state machine before fulfilling final actions.",
	},
}

// GetVulnerabilityScore returns the full CVSS score and CWE metadata for a given vulnerability type.
func GetVulnerabilityScore(vulnType string) *CVSSScore {
	meta, ok := CanonicalVulnerabilityRegistry[vulnType]
	if !ok {
		// Default generic finding CVSS
		meta = VulnerabilityMetadata{
			VulnerabilityType: vulnType,
			DefaultVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
			CWEID:             "CWE-699",
			CWEName:           "Software Development Security Flaw",
			DefaultRemedy:     "Review and remediate application security boundaries.",
		}
	}

	vec, err := ParseCVSSVector(meta.DefaultVector)
	if err != nil {
		return &CVSSScore{
			BaseScore:    5.0,
			Severity:     "Medium",
			VectorString: meta.DefaultVector,
			CWEID:        meta.CWEID,
			CWEName:      meta.CWEName,
		}
	}

	score := CalculateCVSS(vec)
	score.CWEID = meta.CWEID
	score.CWEName = meta.CWEName
	return score
}
