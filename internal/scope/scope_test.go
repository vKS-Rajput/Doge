package scope

import (
	"testing"
)

func TestScopeEngine_Classification(t *testing.T) {
	cfg := Config{
		Target:      "example.com",
		Environment: "authorized",
		InScope: []string{
			"example.com",
			"*.example.com",
			"192.168.1.0/24",
			"10.0.0.5",
		},
		OutOfScope: []string{
			"payments.example.com",
			"billing.example.com",
			"192.168.1.100",
		},
		AllowLocalhost:  false,
		AllowPrivateIPs: false,
		Rules: ProgramRules{
			ProgramName:       "Example Bug Bounty",
			ProhibitedTesting: []string{"dos", "brute_force", "social_engineering"},
			RateLimitPerSec:   5,
			MaxConcurrency:    2,
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create scope engine: %v", err)
	}

	tests := []struct {
		input          string
		expectedClass  AssetClassification
		expectedInScope bool
	}{
		{"example.com", AssetInScope, true},
		{"https://example.com/api/v1", AssetInScope, true},
		{"sub.example.com", AssetInScope, true},
		{"deep.nested.sub.example.com", AssetInScope, true},
		{"payments.example.com", AssetOutOfScope, false}, // Explicitly denied
		{"billing.example.com", AssetOutOfScope, false},  // Explicitly denied
		{"192.168.1.50", AssetInScope, true},
		{"192.168.1.100", AssetOutOfScope, false}, // Explicitly denied
		{"10.0.0.5", AssetInScope, true},
		{"10.0.0.6", AssetCandidate, false},
		{"otherdomain.com", AssetCandidate, false},
		{"assets.s3.amazonaws.com", AssetThirdPartyDependency, false},
		{"cdn.cloudflare.net", AssetThirdPartyDependency, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			class, _ := engine.ClassifyAsset(tt.input)
			if class != tt.expectedClass {
				t.Errorf("ClassifyAsset(%q) = %v; want %v", tt.input, class, tt.expectedClass)
			}
			inScope := engine.IsInScope(tt.input)
			if inScope != tt.expectedInScope {
				t.Errorf("IsInScope(%q) = %v; want %v", tt.input, inScope, tt.expectedInScope)
			}
		})
	}
}

func TestScopeEngine_ValidateAction(t *testing.T) {
	cfg := Config{
		Target:      "example.com",
		Environment: "authorized",
		InScope:     []string{"*.example.com"},
		OutOfScope:  []string{"payments.example.com"},
		Rules: ProgramRules{
			ProhibitedTesting: []string{"dos", "sqlmap_dangerous"},
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create scope engine: %v", err)
	}

	// 1. In-scope passive tool
	allowed, _, needsApproval := engine.ValidateAction("api.example.com", "httpx", "http_probe")
	if !allowed {
		t.Errorf("expected httpx against in-scope target to be allowed")
	}
	if needsApproval {
		t.Errorf("expected httpx probe not to require special approval")
	}

	// 2. In-scope active tool in authorized env -> needs approval
	allowed, _, needsApproval = engine.ValidateAction("api.example.com", "nuclei", "vuln_scan")
	if !allowed {
		t.Errorf("expected nuclei against in-scope target to be valid")
	}
	if !needsApproval {
		t.Errorf("expected nuclei to require approval in authorized environment")
	}

	// 3. Out-of-scope target -> blocked
	allowed, reason, _ := engine.ValidateAction("payments.example.com", "httpx", "http_probe")
	if allowed {
		t.Errorf("expected payments.example.com to be blocked")
	}
	if reason == "" {
		t.Errorf("expected reason for blocking")
	}

	// 4. Prohibited action -> blocked
	allowed, _, _ = engine.ValidateAction("api.example.com", "dos_tool", "dos")
	if allowed {
		t.Errorf("expected dos tool to be blocked by program rules")
	}
}
