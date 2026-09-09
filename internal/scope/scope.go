// Package scope implements a machine-enforced, fail-closed target scope engine.
//
// Scope is a hard security boundary that cannot be weakened by learning,
// reasoning, or automated heuristics.
//
// It distinguishes:
//   - In-Scope assets (authorized for testing)
//   - Out-of-Scope assets (explicitly forbidden)
//   - Candidate targets (discovered, pending scope evaluation)
//   - Third-Party dependencies (CDNs, SaaS, cloud infrastructure)
//   - Unknown assets
package scope

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AssetClassification classifies an asset relative to authorization boundaries.
type AssetClassification string

const (
	AssetInScope              AssetClassification = "in_scope"
	AssetOutOfScope           AssetClassification = "out_of_scope"
	AssetCandidate            AssetClassification = "candidate"
	AssetThirdPartyDependency AssetClassification = "third_party_dependency"
	AssetUnknown              AssetClassification = "unknown"
)

// ScopeRuleType identifies the format of a scope rule.
type ScopeRuleType string

const (
	RuleDomain   ScopeRuleType = "domain"
	RuleWildcard ScopeRuleType = "wildcard" // *.example.com
	RuleIP       ScopeRuleType = "ip"
	RuleCIDR     ScopeRuleType = "cidr"
)

// Rule defines a single scope boundary rule.
type Rule struct {
	Raw     string        `json:"raw"`
	Type    ScopeRuleType `json:"type"`
	Value   string        `json:"value"`
	IP      net.IP        `json:"-"`
	Network *net.IPNet    `json:"-"`
	Comment string        `json:"comment,omitempty"`
}

// ProgramRules contains the bug bounty or engagement rules.
type ProgramRules struct {
	ProgramName         string        `json:"program_name"`
	AllowedTesting      []string      `json:"allowed_testing"`
	ProhibitedTesting   []string      `json:"prohibited_testing"`
	RateLimitPerSec     int           `json:"rate_limit_per_sec"`
	MaxConcurrency      int           `json:"max_concurrency"`
	AllowedPorts        []int         `json:"allowed_ports,omitempty"`
	RestrictedPaths     []string      `json:"restricted_paths,omitempty"`
	RequireCustomHeader string        `json:"require_custom_header,omitempty"` // e.g. "X-Bug-Bounty: researcher"
	SpecialConditions   string        `json:"special_conditions,omitempty"`
}

// DefaultProgramRules returns safe baseline rules for bug bounty engagements.
func DefaultProgramRules() ProgramRules {
	return ProgramRules{
		ProgramName:       "Default Safe Bounty Rules",
		AllowedTesting:    []string{"subdomain_enum", "port_scan", "web_probing", "content_discovery", "hypothesis_testing"},
		ProhibitedTesting: []string{"dos", "ddos", "bruteforce", "mass_exploitation", "destructive_testing"},
		RateLimitPerSec:   10,
		MaxConcurrency:    5,
	}
}

// Config defines the complete scope configuration for an engagement.
type Config struct {
	Target             string        `json:"target"`
	Environment        string        `json:"environment"` // "authorized", "lab", "htb", "owned"
	InScope            []string      `json:"in_scope"`
	OutOfScope         []string      `json:"out_of_scope"`
	AllowLocalhost     bool          `json:"allow_localhost"`
	AllowPrivateIPs    bool          `json:"allow_private_ips"`
	Rules              ProgramRules  `json:"rules"`
	CreatedAt          time.Time     `json:"created_at"`
}

// ScopeFile is the default filename for persisted scope configs.
const ScopeFile = "scope.json"

// SaveConfig writes the scope config to .doge/scope.json.
func SaveConfig(workspacePath string, cfg Config) error {
	dogeDir := filepath.Join(workspacePath, ".doge")
	if err := os.MkdirAll(dogeDir, 0755); err != nil {
		return fmt.Errorf("creating .doge dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling scope config: %w", err)
	}
	return os.WriteFile(filepath.Join(dogeDir, ScopeFile), data, 0644)
}

// LoadConfig reads the scope config from .doge/scope.json.
func LoadConfig(workspacePath string) (*Config, error) {
	path := filepath.Join(workspacePath, ".doge", ScopeFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing scope config: %w", err)
	}
	return &cfg, nil
}

// ScopeEngine provides deterministic, thread-safe scope evaluation.
type ScopeEngine struct {
	mu           sync.RWMutex
	config       Config
	inScopeRules []Rule
	outScopeRules []Rule
	thirdParty   []string
}

// KnownThirdPartySuffixes contains common cloud/SaaS domains that are typically out of scope.
var KnownThirdPartySuffixes = []string{
	"amazonaws.com",
	"cloudfront.net",
	"azureedge.net",
	"azure.com",
	"cloudflare.com",
	"cloudflare.net",
	"fastly.net",
	"akamai.net",
	"akamaiedge.net",
	"google.com",
	"googleapis.com",
	"gstatic.com",
	"github.com",
	"github.io",
	"herokuapp.com",
	"vercel.app",
	"netlify.app",
	"zendesk.com",
	"salesforce.com",
	"okta.com",
	"auth0.com",
}

// NewEngine creates a new ScopeEngine from the given Config.
func NewEngine(cfg Config) (*ScopeEngine, error) {
	e := &ScopeEngine{
		config:     cfg,
		thirdParty: append([]string{}, KnownThirdPartySuffixes...),
	}

	if err := e.compileRules(); err != nil {
		return nil, err
	}

	return e, nil
}

func (e *ScopeEngine) compileRules() error {
	e.inScopeRules = make([]Rule, 0, len(e.config.InScope))
	for _, raw := range e.config.InScope {
		r, err := ParseRule(raw)
		if err != nil {
			return fmt.Errorf("invalid in-scope rule %q: %w", raw, err)
		}
		e.inScopeRules = append(e.inScopeRules, r)
	}

	e.outScopeRules = make([]Rule, 0, len(e.config.OutOfScope))
	for _, raw := range e.config.OutOfScope {
		r, err := ParseRule(raw)
		if err != nil {
			return fmt.Errorf("invalid out-of-scope rule %q: %w", raw, err)
		}
		e.outScopeRules = append(e.outScopeRules, r)
	}

	return nil
}

// ParseRule parses a raw string into a structured scope Rule.
func ParseRule(raw string) (Rule, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Rule{}, fmt.Errorf("empty rule")
	}

	lower := strings.ToLower(trimmed)

	// CIDR notation
	if strings.Contains(lower, "/") {
		_, netw, err := net.ParseCIDR(lower)
		if err == nil {
			return Rule{
				Raw:     trimmed,
				Type:    RuleCIDR,
				Value:   lower,
				Network: netw,
			}, nil
		}
	}

	// Single IP address
	if ip := net.ParseIP(lower); ip != nil {
		return Rule{
			Raw:   trimmed,
			Type:  RuleIP,
			Value: lower,
			IP:    ip,
		}, nil
	}

	// Wildcard domain (*.example.com or .example.com)
	if strings.HasPrefix(lower, "*.") {
		domain := strings.TrimPrefix(lower, "*.")
		return Rule{
			Raw:   trimmed,
			Type:  RuleWildcard,
			Value: domain,
		}, nil
	}
	if strings.HasPrefix(lower, ".") {
		domain := strings.TrimPrefix(lower, ".")
		return Rule{
			Raw:   trimmed,
			Type:  RuleWildcard,
			Value: domain,
		}, nil
	}

	// Exact domain / host
	domain := strings.TrimPrefix(lower, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.Split(domain, "/")[0]
	domain = strings.Split(domain, ":")[0]

	return Rule{
		Raw:   trimmed,
		Type:  RuleDomain,
		Value: domain,
	}, nil
}

// ClassifyAsset evaluates any hostname, IP, or URL string and classifies it.
func (e *ScopeEngine) ClassifyAsset(input string) (AssetClassification, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	host := ExtractHost(input)
	if host == "" {
		return AssetUnknown, "unable to parse host from input"
	}

	lowerHost := strings.ToLower(host)

	// Check explicit Out-of-Scope rules first (highest priority deny)
	for _, rule := range e.outScopeRules {
		if matchRule(rule, lowerHost) {
			return AssetOutOfScope, fmt.Sprintf("matches out-of-scope rule %s", rule.Raw)
		}
	}

	// Check In-Scope rules
	for _, rule := range e.inScopeRules {
		if matchRule(rule, lowerHost) {
			return AssetInScope, fmt.Sprintf("matches in-scope rule %s", rule.Raw)
		}
	}

	// Check if this matches a third-party dependency
	for _, tp := range e.thirdParty {
		if lowerHost == tp || strings.HasSuffix(lowerHost, "."+tp) {
			return AssetThirdPartyDependency, fmt.Sprintf("matches known third-party SaaS/CDN %s", tp)
		}
	}

	// If environment is lab/htb, localhost and private IPs are in scope if configured
	if ip := net.ParseIP(lowerHost); ip != nil {
		if ip.IsLoopback() && e.config.AllowLocalhost {
			return AssetInScope, "localhost permitted in lab environment"
		}
		if (ip.IsPrivate() || ip.IsLoopback()) && e.config.AllowPrivateIPs {
			return AssetInScope, "private IP permitted in lab/htb environment"
		}
	}

	return AssetCandidate, "discovered asset not matching explicit scope rules"
}

// IsInScope returns true only if the asset is strictly classified as AssetInScope.
func (e *ScopeEngine) IsInScope(input string) bool {
	class, _ := e.ClassifyAsset(input)
	return class == AssetInScope
}

// ValidateAction performs a pre-execution safety check for a proposed action against a target.
func (e *ScopeEngine) ValidateAction(target, tool, actionType string) (bool, string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	classification, reason := e.ClassifyAsset(target)
	if classification != AssetInScope {
		return false, fmt.Sprintf("action blocked: target %q is %s (%s)", target, classification, reason), false
	}

	// Check prohibited testing techniques from program rules
	lowerTool := strings.ToLower(tool)
	lowerAction := strings.ToLower(actionType)

	for _, prohibited := range e.config.Rules.ProhibitedTesting {
		pLower := strings.ToLower(prohibited)
		if strings.Contains(lowerTool, pLower) || strings.Contains(lowerAction, pLower) {
			return false, fmt.Sprintf("action blocked: prohibited testing rule %q violated", prohibited), false
		}
	}

	// Determine if approval is required based on environment and tool risk
	needsApproval := false
	if e.config.Environment == "authorized" || e.config.Environment == "other" {
		// Active scanners and intrusive tools require explicit approval in authorized scope
		switch lowerTool {
		case "sqlmap", "nuclei", "ffuf", "feroxbuster", "gobuster", "dirsearch", "dalfox":
			needsApproval = true
		}
	}

	return true, "target is in scope and action complies with program rules", needsApproval
}

// Config returns the current scope config.
func (e *ScopeEngine) Config() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// AddInScope adds a new in-scope rule dynamically (must be researcher-driven).
func (e *ScopeEngine) AddInScope(ruleStr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	r, err := ParseRule(ruleStr)
	if err != nil {
		return err
	}
	e.inScopeRules = append(e.inScopeRules, r)
	e.config.InScope = append(e.config.InScope, ruleStr)
	return nil
}

// AddOutOfScope adds a new exclusion rule dynamically.
func (e *ScopeEngine) AddOutOfScope(ruleStr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	r, err := ParseRule(ruleStr)
	if err != nil {
		return err
	}
	e.outScopeRules = append(e.outScopeRules, r)
	e.config.OutOfScope = append(e.config.OutOfScope, ruleStr)
	return nil
}

func matchRule(rule Rule, host string) bool {
	switch rule.Type {
	case RuleDomain:
		return host == rule.Value
	case RuleWildcard:
		// *.example.com matches sub.example.com, a.b.example.com, AND example.com
		if host == rule.Value {
			return true
		}
		if strings.HasSuffix(host, "."+rule.Value) {
			return true
		}
		return false
	case RuleIP:
		ip := net.ParseIP(host)
		return ip != nil && ip.Equal(rule.IP)
	case RuleCIDR:
		ip := net.ParseIP(host)
		return ip != nil && rule.Network != nil && rule.Network.Contains(ip)
	}
	return false
}

// ExtractHost strips scheme, port, path, and credentials from a URL or host string.
func ExtractHost(input string) string {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return ""
	}

	if !strings.Contains(raw, "://") && !strings.HasPrefix(raw, "//") {
		raw = "http://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		// Fallback simple parsing
		parts := strings.Split(input, "/")
		hostPort := parts[0]
		host, _, err := net.SplitHostPort(hostPort)
		if err == nil {
			return host
		}
		return hostPort
	}

	h := u.Hostname()
	if h == "" {
		return u.Host
	}
	return h
}
