package validation

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ScopeType classifies a scope entry.
type ScopeType string

const (
	ScopeTypeDomain   ScopeType = "domain"
	ScopeTypeWildcard ScopeType = "wildcard" // *.example.com
	ScopeTypeIP       ScopeType = "ip"
	ScopeTypeCIDR     ScopeType = "cidr"
)

// ScopeEntry is a parsed scope target.
type ScopeEntry struct {
	Raw     string    `json:"raw"`
	Type    ScopeType `json:"type"`
	Domain  string    `json:"domain,omitempty"`  // For domain/wildcard
	IP      net.IP    `json:"ip,omitempty"`      // For IP
	Network *net.IPNet `json:"-"`                // For CIDR
}

// ScopeGate enforces target authorization with SSRF protection.
//
// Every request — including redirects — passes through this gate.
// The gate is deterministic, fail-closed, and not AI-controlled.
//
// Validation pipeline (every request + every redirect):
//
//  1. Parse and canonicalize URL
//  2. Check hostname against scope
//  3. Resolve DNS
//  4. Validate resolved IPs against IP policy
//  5. Check deny list
//  6. Return approved destination or error
type ScopeGate struct {
	// AllowedTargets from Project.TargetScope.
	AllowedTargets []ScopeEntry

	// DenyList overrides AllowedTargets.
	DenyList []string

	// AllowPrivateIPs is false by default.
	// Set true ONLY for lab/HTB/CTF projects via project policy.
	AllowPrivateIPs bool

	// AllowLocalhost is false by default.
	// Set true ONLY for local lab projects via project policy.
	AllowLocalhost bool

	// resolver is used for DNS lookups. Overridable for testing.
	resolver DNSResolver
}

// DNSResolver abstracts DNS resolution for testability.
type DNSResolver interface {
	LookupHost(host string) ([]string, error)
}

// defaultResolver uses net.LookupHost.
type defaultResolver struct{}

func (d *defaultResolver) LookupHost(host string) ([]string, error) {
	return net.LookupHost(host)
}

// ApprovedTarget is a target that has passed scope validation.
type ApprovedTarget struct {
	URL        string `json:"url"`
	Host       string `json:"host"`
	ResolvedIP string `json:"resolved_ip"`
}

// NewScopeGate creates a scope gate from project target scope strings.
func NewScopeGate(targets []string, denyList []string, allowPrivate, allowLocalhost bool) *ScopeGate {
	entries := make([]ScopeEntry, 0, len(targets))
	for _, t := range targets {
		entries = append(entries, parseScopeEntry(t))
	}
	return &ScopeGate{
		AllowedTargets:  entries,
		DenyList:        denyList,
		AllowPrivateIPs: allowPrivate,
		AllowLocalhost:  allowLocalhost,
		resolver:        &defaultResolver{},
	}
}

// parseScopeEntry parses a scope string into a typed entry.
func parseScopeEntry(raw string) ScopeEntry {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)

	// CIDR notation.
	if strings.Contains(raw, "/") {
		_, network, err := net.ParseCIDR(raw)
		if err == nil {
			return ScopeEntry{Raw: raw, Type: ScopeTypeCIDR, Network: network}
		}
	}

	// IP address.
	if ip := net.ParseIP(raw); ip != nil {
		return ScopeEntry{Raw: raw, Type: ScopeTypeIP, IP: ip}
	}

	// Wildcard domain.
	if strings.HasPrefix(lower, "*.") {
		return ScopeEntry{Raw: raw, Type: ScopeTypeWildcard, Domain: lower[2:]}
	}

	// Regular domain.
	return ScopeEntry{Raw: raw, Type: ScopeTypeDomain, Domain: lower}
}

// ValidateTarget performs the full scope validation pipeline.
func (g *ScopeGate) ValidateTarget(target string) (*ApprovedTarget, error) {
	// Fail-closed: empty scope means nothing is allowed.
	if len(g.AllowedTargets) == 0 {
		return nil, fmt.Errorf("scope gate: no targets in scope (fail-closed)")
	}

	// Step 1: Parse and canonicalize URL.
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("scope gate: invalid URL %q: %w", target, err)
	}

	host := canonicalizeHost(u.Hostname())
	if host == "" {
		return nil, fmt.Errorf("scope gate: empty hostname in %q", target)
	}

	// Step 2: Check deny list first (overrides allow).
	for _, denied := range g.DenyList {
		if strings.EqualFold(host, strings.TrimSpace(denied)) {
			return nil, fmt.Errorf("scope gate: %q is in deny list", host)
		}
	}

	// Step 3: Check hostname against scope.
	if !g.hostnameInScope(host) {
		return nil, fmt.Errorf("scope gate: %q is not in authorized scope", host)
	}

	// Step 4: Resolve DNS and validate IPs.
	resolvedIP, err := g.resolveAndValidate(host)
	if err != nil {
		return nil, err
	}

	return &ApprovedTarget{
		URL:        target,
		Host:       host,
		ResolvedIP: resolvedIP,
	}, nil
}

// hostnameInScope checks if a hostname matches any scope entry.
func (g *ScopeGate) hostnameInScope(host string) bool {
	// If host is an IP, check IP/CIDR scope entries.
	if ip := net.ParseIP(host); ip != nil {
		return g.ipInScope(ip)
	}

	// Check domain scope entries.
	lower := strings.ToLower(host)
	for _, entry := range g.AllowedTargets {
		switch entry.Type {
		case ScopeTypeDomain:
			if lower == entry.Domain {
				return true
			}
		case ScopeTypeWildcard:
			// *.example.com matches sub.example.com but NOT example.com.
			if strings.HasSuffix(lower, "."+entry.Domain) {
				return true
			}
		}
	}
	return false
}

// ipInScope checks if an IP matches any IP/CIDR scope entry.
func (g *ScopeGate) ipInScope(ip net.IP) bool {
	for _, entry := range g.AllowedTargets {
		switch entry.Type {
		case ScopeTypeIP:
			if entry.IP.Equal(ip) {
				return true
			}
		case ScopeTypeCIDR:
			if entry.Network != nil && entry.Network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// resolveAndValidate resolves DNS and validates the resulting IPs.
func (g *ScopeGate) resolveAndValidate(host string) (string, error) {
	// If host is already an IP, validate it directly.
	if ip := net.ParseIP(host); ip != nil {
		if err := g.validateIP(ip); err != nil {
			return "", err
		}
		return ip.String(), nil
	}

	// Resolve DNS.
	addrs, err := g.resolver.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("scope gate: DNS resolution failed for %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("scope gate: DNS returned no addresses for %q", host)
	}

	// Validate ALL resolved IPs (not just the first).
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if err := g.validateIP(ip); err != nil {
			return "", fmt.Errorf("scope gate: %q resolves to %s: %w", host, addr, err)
		}
	}

	return addrs[0], nil
}

// validateIP checks an IP against the IP policy.
func (g *ScopeGate) validateIP(ip net.IP) error {
	// Unspecified (0.0.0.0, ::) — always blocked.
	if ip.IsUnspecified() {
		return fmt.Errorf("scope gate: unspecified IP %s is always blocked", ip)
	}

	// Link-local — always blocked.
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("scope gate: link-local IP %s is always blocked", ip)
	}

	// Loopback — blocked unless AllowLocalhost.
	if ip.IsLoopback() {
		if !g.AllowLocalhost {
			return fmt.Errorf("scope gate: loopback %s is blocked (enable AllowLocalhost for lab projects)", ip)
		}
		return nil
	}

	// Private — blocked unless AllowPrivateIPs.
	if ip.IsPrivate() {
		if !g.AllowPrivateIPs {
			return fmt.Errorf("scope gate: private IP %s is blocked (enable AllowPrivateIPs for lab/HTB projects)", ip)
		}
		return nil
	}

	return nil
}

// canonicalizeHost normalizes a hostname.
func canonicalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".") // Remove trailing dot.
	return host
}

// --- Redirect Policy ---

// RedirectPolicy controls how redirects are handled.
type RedirectPolicy struct {
	// MaxRedirects is the maximum redirect chain length. Default: 3.
	MaxRedirects int

	// ScopeGate for re-validating redirect targets.
	ScopeGate *ScopeGate
}

// CheckRedirect validates a redirect target.
//
// Every redirect is a new security decision:
//  1. Count check
//  2. Re-validate scope (full DNS pipeline)
//  3. Determine if cross-origin (for credential stripping)
func (p *RedirectPolicy) CheckRedirect(redirectURL string, redirectCount int) (*ApprovedTarget, bool, error) {
	maxR := p.MaxRedirects
	if maxR <= 0 {
		maxR = 3
	}

	// Count check.
	if redirectCount >= maxR {
		return nil, false, fmt.Errorf("redirect policy: max redirects exceeded (%d/%d)", redirectCount, maxR)
	}

	// Re-validate scope (full pipeline including DNS).
	approved, err := p.ScopeGate.ValidateTarget(redirectURL)
	if err != nil {
		return nil, false, fmt.Errorf("redirect policy: redirect target out of scope: %w", err)
	}

	return approved, true, nil
}

// IsCrossOrigin checks if two URLs have different origins.
// Used to determine whether credentials should be stripped.
func IsCrossOrigin(originalURL, redirectURL string) bool {
	orig, err1 := url.Parse(originalURL)
	redir, err2 := url.Parse(redirectURL)
	if err1 != nil || err2 != nil {
		return true // Fail-safe: treat parse errors as cross-origin.
	}

	return !strings.EqualFold(orig.Hostname(), redir.Hostname()) ||
		orig.Scheme != redir.Scheme ||
		orig.Port() != redir.Port()
}
