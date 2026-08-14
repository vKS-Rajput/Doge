package validation

import (
	"fmt"
	"net"
	"testing"
)

// mockResolver simulates DNS for deterministic tests.
type mockResolver struct {
	hosts map[string][]string
	err   error
}

func (m *mockResolver) LookupHost(host string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	addrs, ok := m.hosts[host]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	return addrs, nil
}

func newMockResolver(hosts map[string][]string) *mockResolver {
	return &mockResolver{hosts: hosts}
}

// --- Scope Entry Parsing ---

func TestParseScopeEntryDomain(t *testing.T) {
	e := parseScopeEntry("example.com")
	if e.Type != ScopeTypeDomain {
		t.Errorf("expected domain, got %s", e.Type)
	}
	if e.Domain != "example.com" {
		t.Errorf("expected example.com, got %s", e.Domain)
	}
}

func TestParseScopeEntryWildcard(t *testing.T) {
	e := parseScopeEntry("*.example.com")
	if e.Type != ScopeTypeWildcard {
		t.Errorf("expected wildcard, got %s", e.Type)
	}
	if e.Domain != "example.com" {
		t.Errorf("expected example.com, got %s", e.Domain)
	}
}

func TestParseScopeEntryIP(t *testing.T) {
	e := parseScopeEntry("192.0.2.1")
	if e.Type != ScopeTypeIP {
		t.Errorf("expected ip, got %s", e.Type)
	}
	if !e.IP.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("expected 192.0.2.1, got %s", e.IP)
	}
}

func TestParseScopeEntryCIDR(t *testing.T) {
	e := parseScopeEntry("10.0.0.0/24")
	if e.Type != ScopeTypeCIDR {
		t.Errorf("expected cidr, got %s", e.Type)
	}
	if e.Network == nil {
		t.Fatal("expected non-nil network")
	}
}

// --- Fail-Closed ---

func TestScopeGateEmptyScopeBlocksEverything(t *testing.T) {
	gate := NewScopeGate(nil, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"example.com": {"93.184.216.34"},
	})

	_, err := gate.ValidateTarget("https://example.com")
	if err == nil {
		t.Error("empty scope should block everything (fail-closed)")
	}
}

// --- Domain Matching ---

func TestScopeGateAllowsInScopeDomain(t *testing.T) {
	gate := NewScopeGate([]string{"example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"example.com": {"93.184.216.34"},
	})

	approved, err := gate.ValidateTarget("https://example.com/path")
	if err != nil {
		t.Fatalf("in-scope domain should be allowed: %v", err)
	}
	if approved.Host != "example.com" {
		t.Errorf("expected example.com, got %s", approved.Host)
	}
}

func TestScopeGateBlocksOutOfScopeDomain(t *testing.T) {
	gate := NewScopeGate([]string{"example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"evil.com": {"203.0.113.1"},
	})

	_, err := gate.ValidateTarget("https://evil.com")
	if err == nil {
		t.Error("out-of-scope domain should be blocked")
	}
}

// --- Wildcard Matching ---

func TestScopeGateWildcardMatchesSubdomain(t *testing.T) {
	gate := NewScopeGate([]string{"*.example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"admin.example.com": {"93.184.216.34"},
	})

	_, err := gate.ValidateTarget("https://admin.example.com")
	if err != nil {
		t.Fatalf("wildcard should match subdomain: %v", err)
	}
}

func TestScopeGateWildcardDoesNotMatchBase(t *testing.T) {
	gate := NewScopeGate([]string{"*.example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"example.com": {"93.184.216.34"},
	})

	_, err := gate.ValidateTarget("https://example.com")
	if err == nil {
		t.Error("wildcard *.example.com should NOT match example.com itself")
	}
}

// --- SSRF: DNS rebinding to private IPs ---

func TestScopeGateBlocksDNSRebindToLoopback(t *testing.T) {
	gate := NewScopeGate([]string{"target.example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"target.example.com": {"127.0.0.1"},
	})

	_, err := gate.ValidateTarget("https://target.example.com")
	if err == nil {
		t.Error("domain resolving to 127.0.0.1 should be BLOCKED")
	}
}

func TestScopeGateBlocksDNSRebindToPrivate10(t *testing.T) {
	gate := NewScopeGate([]string{"target.example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"target.example.com": {"10.0.0.5"},
	})

	_, err := gate.ValidateTarget("https://target.example.com")
	if err == nil {
		t.Error("domain resolving to 10.0.0.5 should be BLOCKED")
	}
}

func TestScopeGateBlocksDNSRebindToPrivate172(t *testing.T) {
	gate := NewScopeGate([]string{"target.example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"target.example.com": {"172.16.0.1"},
	})

	_, err := gate.ValidateTarget("https://target.example.com")
	if err == nil {
		t.Error("domain resolving to 172.16.0.1 should be BLOCKED")
	}
}

func TestScopeGateBlocksDNSRebindToPrivate192(t *testing.T) {
	gate := NewScopeGate([]string{"target.example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"target.example.com": {"192.168.1.1"},
	})

	_, err := gate.ValidateTarget("https://target.example.com")
	if err == nil {
		t.Error("domain resolving to 192.168.1.1 should be BLOCKED")
	}
}

// --- Lab/HTB Policy Exceptions ---

func TestScopeGateAllowsLocalhostWhenExplicit(t *testing.T) {
	gate := NewScopeGate([]string{"localhost"}, nil, false, true)
	gate.resolver = newMockResolver(map[string][]string{
		"localhost": {"127.0.0.1"},
	})

	_, err := gate.ValidateTarget("https://localhost/api")
	if err != nil {
		t.Fatalf("localhost should be allowed when AllowLocalhost=true: %v", err)
	}
}

func TestScopeGateAllowsPrivateIPWhenExplicit(t *testing.T) {
	gate := NewScopeGate([]string{"10.10.10.1"}, nil, true, false)
	gate.resolver = newMockResolver(map[string][]string{})

	_, err := gate.ValidateTarget("https://10.10.10.1/")
	if err != nil {
		t.Fatalf("private IP should be allowed when AllowPrivateIPs=true: %v", err)
	}
}

// --- CIDR Matching ---

func TestScopeGateCIDRMatch(t *testing.T) {
	gate := NewScopeGate([]string{"10.10.10.0/24"}, nil, true, false)
	gate.resolver = newMockResolver(map[string][]string{})

	_, err := gate.ValidateTarget("https://10.10.10.42/")
	if err != nil {
		t.Fatalf("IP in CIDR range should be allowed: %v", err)
	}
}

func TestScopeGateCIDRNoMatch(t *testing.T) {
	gate := NewScopeGate([]string{"10.10.10.0/24"}, nil, true, false)
	gate.resolver = newMockResolver(map[string][]string{})

	_, err := gate.ValidateTarget("https://10.10.11.1/")
	if err == nil {
		t.Error("IP outside CIDR range should be blocked")
	}
}

// --- Deny List ---

func TestScopeGateDenyListOverridesAllow(t *testing.T) {
	gate := NewScopeGate(
		[]string{"*.example.com"},
		[]string{"admin.example.com"},
		false, false,
	)
	gate.resolver = newMockResolver(map[string][]string{
		"admin.example.com": {"93.184.216.34"},
	})

	_, err := gate.ValidateTarget("https://admin.example.com")
	if err == nil {
		t.Error("denied target should be blocked even if in scope")
	}
}

// --- Special IPs ---

func TestScopeGateBlocksUnspecified(t *testing.T) {
	gate := NewScopeGate([]string{"0.0.0.0"}, nil, true, true)
	gate.resolver = newMockResolver(map[string][]string{})

	_, err := gate.ValidateTarget("https://0.0.0.0/")
	if err == nil {
		t.Error("0.0.0.0 should always be blocked")
	}
}

func TestScopeGateBlocksLinkLocal(t *testing.T) {
	gate := NewScopeGate([]string{"169.254.1.1"}, nil, true, true)
	gate.resolver = newMockResolver(map[string][]string{})

	_, err := gate.ValidateTarget("https://169.254.1.1/")
	if err == nil {
		t.Error("link-local should always be blocked")
	}
}

// --- Canonicalization ---

func TestCanonicalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"  EXAMPLE.COM  ", "example.com"},
		{"127.0.0.1", "127.0.0.1"},
	}

	for _, tt := range tests {
		result := canonicalizeHost(tt.input)
		if result != tt.expected {
			t.Errorf("canonicalize(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// --- Cross-Origin Detection ---

func TestIsCrossOrigin(t *testing.T) {
	tests := []struct {
		name     string
		orig     string
		redir    string
		expected bool
	}{
		{"same", "https://example.com/a", "https://example.com/b", false},
		{"different host", "https://example.com", "https://evil.com", true},
		{"different scheme", "https://example.com", "http://example.com", true},
		{"different port", "https://example.com:443", "https://example.com:8443", true},
		{"subdomain", "https://a.example.com", "https://b.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCrossOrigin(tt.orig, tt.redir)
			if result != tt.expected {
				t.Errorf("IsCrossOrigin(%q, %q) = %v, want %v",
					tt.orig, tt.redir, result, tt.expected)
			}
		})
	}
}

// --- Redirect Policy ---

func TestRedirectPolicyBlocksOutOfScope(t *testing.T) {
	gate := NewScopeGate([]string{"example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"example.com": {"93.184.216.34"},
		"evil.com":    {"203.0.113.1"},
	})

	policy := &RedirectPolicy{MaxRedirects: 3, ScopeGate: gate}

	_, _, err := policy.CheckRedirect("https://evil.com/malicious", 0)
	if err == nil {
		t.Error("redirect to out-of-scope target should be blocked")
	}
}

func TestRedirectPolicyMaxRedirects(t *testing.T) {
	gate := NewScopeGate([]string{"example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"example.com": {"93.184.216.34"},
	})

	policy := &RedirectPolicy{MaxRedirects: 3, ScopeGate: gate}

	_, _, err := policy.CheckRedirect("https://example.com/page", 3)
	if err == nil {
		t.Error("exceeding max redirects should be blocked")
	}
}

func TestRedirectPolicyAllowsInScopeRedirect(t *testing.T) {
	gate := NewScopeGate([]string{"example.com"}, nil, false, false)
	gate.resolver = newMockResolver(map[string][]string{
		"example.com": {"93.184.216.34"},
	})

	policy := &RedirectPolicy{MaxRedirects: 3, ScopeGate: gate}

	approved, ok, err := policy.CheckRedirect("https://example.com/new-page", 1)
	if err != nil {
		t.Fatalf("in-scope redirect should be allowed: %v", err)
	}
	if !ok {
		t.Error("expected ok=true")
	}
	if approved.Host != "example.com" {
		t.Errorf("expected example.com, got %s", approved.Host)
	}
}

// --- DNS Resolution Failure ---

func TestScopeGateBlocksDNSFailure(t *testing.T) {
	gate := NewScopeGate([]string{"target.example.com"}, nil, false, false)
	gate.resolver = &mockResolver{err: fmt.Errorf("DNS timeout")}

	_, err := gate.ValidateTarget("https://target.example.com")
	if err == nil {
		t.Error("DNS failure should block the request")
	}
}
