package entity

import (
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestResolve_URL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Case normalization.
		{"lowercase host", "https://Example.COM/path", "https://example.com/path"},
		{"lowercase scheme", "HTTPS://example.com/path", "https://example.com/path"},
		{"mixed case host", "https://Admin.EXAMPLE.com", "https://admin.example.com"},

		// Default port removal.
		{"strip https 443", "https://example.com:443/path", "https://example.com/path"},
		{"strip http 80", "http://example.com:80/path", "http://example.com/path"},
		{"keep non-default port", "https://example.com:8443/path", "https://example.com:8443/path"},
		{"keep http 443", "http://example.com:443/path", "http://example.com:443/path"},

		// Trailing slash normalization.
		{"strip root trailing slash", "https://example.com/", "https://example.com"},
		{"strip path trailing slash", "https://example.com/api/v1/", "https://example.com/api/v1"},
		{"preserve root only", "https://example.com", "https://example.com"},

		// Path casing preserved.
		{"preserve path case", "https://example.com/API/Users", "https://example.com/API/Users"},

		// Query and fragment preserved.
		{"preserve query", "https://example.com/search?q=test", "https://example.com/search?q=test"},

		// No scheme.
		{"add scheme if missing", "example.com/path", "https://example.com/path"},

		// Combined.
		{"full normalization", "HTTPS://WWW.Example.COM:443/path/", "https://www.example.com/path"},

		// Empty.
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(domain.EntityURL, tt.input)
			if got != tt.want {
				t.Errorf("Resolve(URL, %q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolve_URL_SameEntity(t *testing.T) {
	// These should all resolve to the same canonical form.
	variants := []string{
		"https://example.com",
		"https://Example.COM",
		"https://EXAMPLE.com:443",
		"https://example.com/",
		"https://example.com:443/",
	}

	canonical := Resolve(domain.EntityURL, variants[0])
	for _, v := range variants[1:] {
		got := Resolve(domain.EntityURL, v)
		if got != canonical {
			t.Errorf("Resolve(URL, %q) = %q, want %q (same entity)", v, got, canonical)
		}
	}
}

func TestResolve_Host(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"lowercase", "Example.COM", "example.com"},
		{"strip www", "www.example.com", "example.com"},
		{"preserve www if single label", "www.com", "www.com"},
		{"strip trailing dot", "example.com.", "example.com"},
		{"trim whitespace", "  example.com  ", "example.com"},
		{"complex subdomain", "admin.api.Example.COM", "admin.api.example.com"},
		{"www with subdomain", "www.admin.example.com", "admin.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(domain.EntitySubdomain, tt.input)
			if got != tt.want {
				t.Errorf("Resolve(Subdomain, %q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolve_Host_SameEntity(t *testing.T) {
	variants := []string{
		"example.com",
		"Example.COM",
		"www.example.com",
		"example.com.",
		"  example.com  ",
	}

	canonical := Resolve(domain.EntityDomain, variants[0])
	for _, v := range variants[1:] {
		got := Resolve(domain.EntityDomain, v)
		if got != canonical {
			t.Errorf("Resolve(Domain, %q) = %q, want %q (same entity)", v, got, canonical)
		}
	}
}

func TestResolve_IP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal ipv4", "192.168.1.1", "192.168.1.1"},
		{"leading zeros", "192.168.001.001", "192.168.1.1"},
		{"all zeros", "000.000.000.000", "0.0.0.0"},
		{"trim whitespace", " 10.0.0.1 ", "10.0.0.1"},
		{"ipv6 lowercase", "2001:DB8::1", "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(domain.EntityIPAddress, tt.input)
			if got != tt.want {
				t.Errorf("Resolve(IP, %q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolve_Technology(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"lowercase", "Nginx", "nginx"},
		{"all caps", "PHP", "php"},
		{"with version", "Apache/2.4.52", "apache/2.4.52"},
		{"mixed case", "jQuery", "jquery"},
		{"trim whitespace", " Cloudflare ", "cloudflare"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(domain.EntityTechnology, tt.input)
			if got != tt.want {
				t.Errorf("Resolve(Technology, %q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolve_Endpoint(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"uppercase method", "get /api/users", "GET /api/users"},
		{"strip trailing slash", "POST /api/users/", "POST /api/users"},
		{"preserve root", "GET /", "GET /"},
		{"path only", "/api/v1/", "/api/v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(domain.EntityEndpoint, tt.input)
			if got != tt.want {
				t.Errorf("Resolve(Endpoint, %q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolve_Header(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Content-Type", "content-type"},
		{"X-Custom-Header", "x-custom-header"},
		{" Server ", "server"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := Resolve(domain.EntityHeader, tt.input)
			if got != tt.want {
				t.Errorf("Resolve(Header, %q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCanonicalHash_Deterministic(t *testing.T) {
	h1 := CanonicalHash(domain.EntityURL, "https://example.com")
	h2 := CanonicalHash(domain.EntityURL, "https://example.com")

	if h1 != h2 {
		t.Error("same input should produce same hash")
	}
}

func TestCanonicalHash_DifferentValues(t *testing.T) {
	h1 := CanonicalHash(domain.EntityURL, "https://a.com")
	h2 := CanonicalHash(domain.EntityURL, "https://b.com")

	if h1 == h2 {
		t.Error("different values should produce different hashes")
	}
}

func TestCanonicalHash_DifferentTypes(t *testing.T) {
	// Same value, different type → different hash.
	h1 := CanonicalHash(domain.EntityURL, "example.com")
	h2 := CanonicalHash(domain.EntityDomain, "example.com")

	if h1 == h2 {
		t.Error("different types with same value should produce different hashes")
	}
}

func TestCanonicalHash_ResolvedVariantsMatch(t *testing.T) {
	// These URL variants should resolve to the same canonical form,
	// and therefore produce the same canonical hash.
	v1 := Resolve(domain.EntityURL, "https://example.com")
	v2 := Resolve(domain.EntityURL, "https://Example.COM:443/")

	h1 := CanonicalHash(domain.EntityURL, v1)
	h2 := CanonicalHash(domain.EntityURL, v2)

	if h1 != h2 {
		t.Errorf("resolved variants should produce same hash: %q vs %q", v1, v2)
	}
}
