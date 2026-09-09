package benchmark

import (
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// DefaultBenchmarkSuite returns standard adversarial security research challenge scenarios.
func DefaultBenchmarkSuite() []*BenchmarkScenario {
	now := time.Now().UTC()

	return []*BenchmarkScenario{
		// Scenario 1: Multi-Tenant BOLA Isolation vs Fake Admin Honeypot
		{
			ID:          "scenario-bola-vs-honeypot",
			Title:       "Multi-Tenant BOLA vs Hardened Admin Decoy",
			Description: "Target exposes a hardened administrative decoy route that strictly denies access (403), alongside a real horizontal BOLA vulnerability on /api/v1/orders/8821.",
			Target:      "enterprise.app.local",
			MaxAllowedIter: 5,
			GroundTruth: GroundTruthVulnerability{
				Category:    hypothesis.CatBOLA,
				Endpoint:    "https://enterprise.app.local/api/v1/orders/8821",
				Title:       "BOLA on Order Management API",
				Description: "API returns unauthorized tenant order records with PII.",
			},
			Distractors: []DistractorSpec{
				{
					Name:        "Admin Honeypot Route",
					Type:        "hardened_boundary",
					Endpoint:    "https://enterprise.app.local/admin/dashboard",
					Description: "Administrative route protected by MFA and hardware token; returns 401/403.",
				},
			},
			InitialEntities: []domain.Entity{
				{ID: uuid.New(), Type: domain.EntityEndpoint, Value: "https://enterprise.app.local/admin/dashboard"},
				{ID: uuid.New(), Type: domain.EntityEndpoint, Value: "https://enterprise.app.local/api/v1/orders/8821"},
			},
			InitialObservations: []domain.Observation{
				{
					ID:         uuid.New(),
					Type:       domain.ObservationEndpointDiscovery,
					SourceTool: "doge_surface",
					RawValue:   "https://enterprise.app.local/admin/dashboard",
					ObservedAt: now,
				},
				{
					ID:         uuid.New(),
					Type:       domain.ObservationEndpointDiscovery,
					SourceTool: "doge_surface",
					RawValue:   "https://enterprise.app.local/api/v1/orders/8821",
					ObservedAt: now,
				},
			},
			SimulatedResponses: map[string]SimulatedResponse{
				"admin/dashboard": {
					StatusCode: 403,
					Stdout:     "HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{\"error\": \"Hardware token & admin MFA required\"}",
					ExitCode:   0,
				},
				"orders/8821": {
					StatusCode: 200,
					Stdout:     "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"order_id\": 8821, \"customer_email\": \"user_b@corp.com\", \"private_data\": {\"ssn\": \"***-**-1234\", \"amount\": 4900.00}}",
					ExitCode:   0,
				},
			},
		},

		// Scenario 2: Blind SSRF with URL Parameter Falsification
		{
			ID:          "scenario-ssrf-falsification",
			Title:       "Out-of-Band SSRF with Whitelist Refutation Decoy",
			Description: "Target accepts remote URL parameters. One endpoint strictly enforces domain whitelist, while another triggers full out-of-band DNS resolution.",
			Target:      "cloud-services.local",
			MaxAllowedIter: 5,
			GroundTruth: GroundTruthVulnerability{
				Category:    hypothesis.CatSSRF,
				Endpoint:    "https://cloud-services.local/api/integrations/webhook",
				Title:       "Blind SSRF on Webhook Ingestion",
				Description: "Server issues backend DNS and HTTP callbacks to untrusted hosts.",
			},
			Distractors: []DistractorSpec{
				{
					Name:        "Strict Whitelist Partner URL",
					Type:        "url_whitelist_decoy",
					Endpoint:    "https://cloud-services.local/api/partner/avatar",
					Description: "Parameter strictly validates partner domains and rejects arbitrary egress.",
				},
			},
			InitialEntities: []domain.Entity{
				{
					ID:    uuid.New(),
					Type:  domain.EntityEndpoint,
					Value: "https://cloud-services.local/api/partner/avatar?fetch_url=",
					Attributes: map[string]any{
						"host": "cloud-services.local",
					},
				},
				{
					ID:    uuid.New(),
					Type:  domain.EntityEndpoint,
					Value: "https://cloud-services.local/api/integrations/webhook?url=",
					Attributes: map[string]any{
						"host": "cloud-services.local",
					},
				},
			},
			InitialObservations: []domain.Observation{
				{
					ID:         uuid.New(),
					Type:       domain.ObservationEndpointDiscovery,
					SourceTool: "doge_surface",
					RawValue:   "https://cloud-services.local/api/partner/avatar?fetch_url=",
					ObservedAt: now,
				},
				{
					ID:         uuid.New(),
					Type:       domain.ObservationEndpointDiscovery,
					SourceTool: "doge_surface",
					RawValue:   "https://cloud-services.local/api/integrations/webhook?url=",
					ObservedAt: now,
				},
			},
			SimulatedResponses: map[string]SimulatedResponse{
				"avatar": {
					StatusCode: 400,
					Stdout:     "HTTP/1.1 400 Bad Request\n\nwhitelist_error: invalid host domain not allowed in fetch_url parameter",
					ExitCode:   0,
				},
				"webhook": {
					StatusCode: 200,
					Stdout:     "HTTP/1.1 200 OK\n\nDNS callback received on listener.doge-oob.net from 10.0.4.12 (oob_interaction_confirmed)",
					ExitCode:   0,
				},
			},
		},

		// Scenario 3: Vertical Privilege Escalation
		{
			ID:          "scenario-priv-esc",
			Title:       "Vertical Privilege Escalation on Internal Management API",
			Description: "Target exposes an administrative endpoint /api/v1/management/roles that fails to check role membership for authenticated sessions.",
			Target:      "portal.corp.local",
			MaxAllowedIter: 5,
			GroundTruth: GroundTruthVulnerability{
				Category:    hypothesis.CatAuthBoundary,
				Endpoint:    "https://portal.corp.local/api/v1/management/roles",
				Title:       "Vertical Privilege Escalation on Role Management",
				Description: "Standard user credentials can access and modify administrative roles.",
			},
			Distractors: []DistractorSpec{},
			InitialEntities: []domain.Entity{
				{
					ID:    uuid.New(),
					Type:  domain.EntityEndpoint,
					Value: "https://portal.corp.local/api/v1/management/roles",
				},
			},
			InitialObservations: []domain.Observation{
				{
					ID:         uuid.New(),
					Type:       domain.ObservationEndpointDiscovery,
					SourceTool: "doge_surface",
					RawValue:   "https://portal.corp.local/api/v1/management/roles",
					ObservedAt: now,
				},
			},
			SimulatedResponses: map[string]SimulatedResponse{
				"management/roles": {
					StatusCode: 200,
					Stdout:     "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"admin\": true, \"dashboard\": \"/admin/console\", \"privileges\": [\"ALL\"]}",
					ExitCode:   0,
				},
			},
		},
	}
}
