// Package entity provides entity resolution, persistence, and
// relationship building for the Knowledge Graph.
//
// The Knowledge Graph is a materialized projection of immutable
// observations — not a primary source of truth. When new observations
// arrive, entities and relationships are materialized from them.
//
// The Entity Resolver is the core of this package. It answers:
// "Given a type and a raw value, what is the canonical identity?"
//
// Examples of identity resolution:
//
//	https://Example.COM:443/path  →  https://example.com/path
//	https://example.com/path/     →  https://example.com/path
//	www.example.com               →  example.com
//	NGINX                         →  nginx
//
// The canonical identity is deterministic: same input always produces
// the same canonical form. This enables deduplication and merging
// across observations from different tools and time periods.
package entity

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Resolve normalizes a raw value based on its entity type and returns
// the canonical form. This is a pure function: no side effects,
// deterministic, same input → same output.
//
// The canonical form is used as the entity's Value in the database
// and is the basis for the CanonicalHash that enables deduplication.
func Resolve(entityType domain.EntityType, rawValue string) string {
	switch entityType {
	case domain.EntityURL:
		return normalizeURL(rawValue)
	case domain.EntityDomain, domain.EntitySubdomain:
		return normalizeHost(rawValue)
	case domain.EntityIPAddress:
		return normalizeIP(rawValue)
	case domain.EntityTechnology:
		return normalizeTechnology(rawValue)
	case domain.EntityEndpoint:
		return normalizeEndpoint(rawValue)
	case domain.EntityPort:
		return strings.TrimSpace(rawValue)
	case domain.EntityHeader:
		return normalizeHeader(rawValue)
	case domain.EntityCookie:
		return strings.TrimSpace(rawValue)
	default:
		// For types without specific normalization, trim whitespace.
		return strings.TrimSpace(rawValue)
	}
}

// CanonicalHash returns a deterministic hash of (entityType, canonicalValue).
// Two observations that resolve to the same canonical hash refer to
// the same real-world entity.
//
// This hash is stored as Entity.CanonicalID (as a string, not UUID)
// but note the domain type uses uuid.UUID for CanonicalID which
// points to another entity's ID. The hash here is for lookup/dedup.
func CanonicalHash(entityType domain.EntityType, canonicalValue string) string {
	input := string(entityType) + ":" + canonicalValue
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:16]) // 128-bit is sufficient for dedup.
}

// normalizeURL normalizes a URL to canonical form:
//   - Lowercase scheme and host
//   - Remove default ports (:443 for https, :80 for http)
//   - Remove trailing slash if path is "/" only
//   - Preserve path casing (paths are case-sensitive on most servers)
//   - Preserve query string and fragment
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// Ensure scheme exists for parsing.
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return strings.TrimSpace(raw) // Can't parse — return as-is.
	}

	// Lowercase scheme and host.
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// Remove default ports.
	host := u.Hostname()
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		u.Host = host
	}

	// Remove trailing slash if path is just "/".
	if u.Path == "/" {
		u.Path = ""
	}

	// Remove trailing slash from paths (normalize /path/ → /path).
	if len(u.Path) > 1 && strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimRight(u.Path, "/")
	}

	return u.String()
}

// normalizeHost normalizes a hostname:
//   - Lowercase
//   - Remove trailing dot (DNS notation)
//   - Strip "www." prefix (common alias)
func normalizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ToLower(raw)
	raw = strings.TrimSuffix(raw, ".")

	// Strip www. prefix — www.example.com and example.com are usually
	// the same entity. This is a deliberate normalization choice.
	if strings.HasPrefix(raw, "www.") && strings.Count(raw, ".") >= 2 {
		raw = strings.TrimPrefix(raw, "www.")
	}

	return raw
}

// normalizeIP normalizes an IP address:
//   - Trim whitespace
//   - For IPv4: remove leading zeros (e.g., 192.168.001.001 → 192.168.1.1)
//   - For IPv6: lowercase
func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ToLower(raw)

	// Simple IPv4 leading-zero removal.
	if !strings.Contains(raw, ":") {
		parts := strings.Split(raw, ".")
		if len(parts) == 4 {
			for i, p := range parts {
				// Remove leading zeros but keep at least one digit.
				parts[i] = strings.TrimLeft(p, "0")
				if parts[i] == "" {
					parts[i] = "0"
				}
			}
			return strings.Join(parts, ".")
		}
	}

	return raw
}

// normalizeTechnology normalizes a technology name:
//   - Lowercase
//   - Trim whitespace
//   - Normalize common variations: version separators, etc.
func normalizeTechnology(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ToLower(raw)

	// Normalize common version separators.
	// "nginx/1.24.0" → "nginx/1.24.0" (keep slash for version)
	// "PHP 8.1" → "php 8.1"
	// Already handled by ToLower.

	return raw
}

// normalizeEndpoint normalizes an endpoint (method + path):
//   - Uppercase method
//   - Trim whitespace
//   - Remove trailing slash from path
func normalizeEndpoint(raw string) string {
	raw = strings.TrimSpace(raw)

	// If it looks like "METHOD /path", normalize both parts.
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) == 2 {
		method := strings.ToUpper(strings.TrimSpace(parts[0]))
		path := strings.TrimSpace(parts[1])
		if len(path) > 1 {
			path = strings.TrimRight(path, "/")
		}
		return method + " " + path
	}

	// Just a path.
	if len(raw) > 1 {
		raw = strings.TrimRight(raw, "/")
	}
	return raw
}

// normalizeHeader normalizes an HTTP header name:
//   - Lowercase (headers are case-insensitive per HTTP spec)
//   - Trim whitespace
func normalizeHeader(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}
