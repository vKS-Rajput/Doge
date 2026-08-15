package domain

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Target is the root of an investigation. Everything DOGE does
// is scoped to the target.
//
// A target is NOT a list of URLs. It is a definition of:
//   - What the researcher is authorized to investigate
//   - What DOGE is allowed to touch
//   - What boundaries are enforced
type Target struct {
	// ID uniquely identifies this target.
	ID uuid.UUID `json:"id"`

	// Primary is the main target identifier.
	// Examples: "10.10.11.123", "example.com", "http://target:8080"
	Primary string `json:"primary"`

	// TargetType classifies the primary identifier.
	TargetType TargetType `json:"target_type"`

	// Environment declares the authorization context.
	// This determines the default research policy.
	Environment TargetEnvironment `json:"environment"`

	// Scope defines what DOGE is allowed to interact with.
	// Everything not in scope is DENIED by default (fail-closed).
	Scope []ScopeEntry `json:"scope"`

	// Exclusions are explicit deny entries that override scope.
	Exclusions []string `json:"exclusions"`

	// InvestigationID links to the owning investigation.
	InvestigationID uuid.UUID `json:"investigation_id"`

	// ProjectID links to the owning project.
	ProjectID uuid.UUID `json:"project_id"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TargetType classifies the primary target identifier.
type TargetType string

const (
	TargetIP     TargetType = "ip"
	TargetDomain TargetType = "domain"
	TargetURL    TargetType = "url"
	TargetCIDR   TargetType = "cidr"
)

// TargetEnvironment declares the authorization context.
// This is NOT a security boundary — the scope gate is.
// The environment controls the DEFAULT research policy.
type TargetEnvironment string

const (
	// EnvHTB is a HackTheBox machine. Auto-recon enabled.
	EnvHTB TargetEnvironment = "htb"

	// EnvLab is a dedicated lab environment. Auto-recon enabled.
	EnvLab TargetEnvironment = "lab"

	// EnvOwned is infrastructure the researcher owns. Configurable.
	EnvOwned TargetEnvironment = "owned"

	// EnvAuthorized is third-party infrastructure with authorization.
	// Requires approval for initial recon by default.
	EnvAuthorized TargetEnvironment = "authorized"

	// EnvOther is any other environment. Explicit approval required.
	EnvOther TargetEnvironment = "other"
)

// ScopeEntry defines one boundary of what DOGE may interact with.
type ScopeEntry struct {
	// Value is the scope item: IP, CIDR, domain, wildcard.
	Value string `json:"value"`

	// Type classifies the scope entry.
	Type ScopeEntryType `json:"type"`

	// Added is when this scope entry was created.
	Added time.Time `json:"added"`

	// AddedBy identifies who added this entry.
	// "user" = researcher defined it.
	// "discovery" = DOGE discovered it (must pass scope validation).
	AddedBy string `json:"added_by"`
}

// ScopeEntryType classifies scope entries.
type ScopeEntryType string

const (
	ScopeIP       ScopeEntryType = "ip"
	ScopeCIDR     ScopeEntryType = "cidr"
	ScopeDomain   ScopeEntryType = "domain"
	ScopeWildcard ScopeEntryType = "wildcard"
)

// InScope checks whether a given host is within the target's scope.
// This is fail-closed: if the check fails or is ambiguous, it returns false.
func (t *Target) InScope(host string) bool {
	// Check exclusions first.
	for _, excl := range t.Exclusions {
		if strings.EqualFold(host, excl) {
			return false
		}
	}

	for _, entry := range t.Scope {
		switch entry.Type {
		case ScopeIP:
			if host == entry.Value {
				return true
			}
		case ScopeCIDR:
			_, cidr, err := net.ParseCIDR(entry.Value)
			if err != nil {
				continue // fail-closed
			}
			ip := net.ParseIP(host)
			if ip != nil && cidr.Contains(ip) {
				return true
			}
		case ScopeDomain:
			if strings.EqualFold(host, entry.Value) {
				return true
			}
		case ScopeWildcard:
			// *.example.com matches sub.example.com
			pattern := entry.Value
			if strings.HasPrefix(pattern, "*.") {
				suffix := pattern[1:] // ".example.com"
				if strings.HasSuffix(strings.ToLower(host), strings.ToLower(suffix)) {
					return true
				}
				// Also match the bare domain.
				if strings.EqualFold(host, pattern[2:]) {
					return true
				}
			}
		}
	}

	return false // fail-closed
}

// ValidateTarget checks that a target is well-formed.
func ValidateTarget(t Target) error {
	if t.Primary == "" {
		return fmt.Errorf("target primary identifier is required")
	}
	if t.TargetType == "" {
		return fmt.Errorf("target type is required")
	}
	if t.Environment == "" {
		return fmt.Errorf("target environment is required")
	}
	if len(t.Scope) == 0 {
		return fmt.Errorf("target must have at least one scope entry")
	}

	// Validate scope entries.
	for _, entry := range t.Scope {
		if entry.Value == "" {
			return fmt.Errorf("scope entry value is empty")
		}
		if entry.Type == "" {
			return fmt.Errorf("scope entry type is empty")
		}
	}

	// Validate target type matches primary.
	switch t.TargetType {
	case TargetIP:
		if net.ParseIP(t.Primary) == nil {
			return fmt.Errorf("target type is IP but %q is not a valid IP", t.Primary)
		}
	case TargetCIDR:
		if _, _, err := net.ParseCIDR(t.Primary); err != nil {
			return fmt.Errorf("target type is CIDR but %q is not valid: %w", t.Primary, err)
		}
	case TargetDomain, TargetURL:
		// Accept any non-empty string for these.
	default:
		return fmt.Errorf("unknown target type: %s", t.TargetType)
	}

	return nil
}

// DetectTargetType guesses the target type from the primary string.
func DetectTargetType(primary string) TargetType {
	if net.ParseIP(primary) != nil {
		return TargetIP
	}
	if _, _, err := net.ParseCIDR(primary); err == nil {
		return TargetCIDR
	}
	if strings.HasPrefix(primary, "http://") || strings.HasPrefix(primary, "https://") {
		return TargetURL
	}
	return TargetDomain
}

// DefaultScope creates a default scope from the primary target.
func DefaultScope(primary string, targetType TargetType) []ScopeEntry {
	return []ScopeEntry{
		{
			Value:   primary,
			Type:    scopeTypeFromTarget(targetType),
			Added:   time.Now().UTC(),
			AddedBy: "user",
		},
	}
}

func scopeTypeFromTarget(tt TargetType) ScopeEntryType {
	switch tt {
	case TargetIP:
		return ScopeIP
	case TargetCIDR:
		return ScopeCIDR
	case TargetDomain:
		return ScopeDomain
	default:
		return ScopeDomain
	}
}
