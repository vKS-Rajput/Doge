package domain

import (
	"time"

	"github.com/google/uuid"
)

// ObservationType classifies the kind of data an observation represents.
// Each type corresponds to a category of security tool output.
type ObservationType string

const (
	ObservationSubdomainDiscovery ObservationType = "subdomain_discovery"
	ObservationHTTPProbe          ObservationType = "http_probe"
	ObservationEndpointDiscovery  ObservationType = "endpoint_discovery"
	ObservationVulnerabilityScan  ObservationType = "vulnerability_scan"
	ObservationJavaScriptAnalysis ObservationType = "javascript_analysis"
	ObservationScreenshotCapture  ObservationType = "screenshot_capture"
	ObservationDNSLookup          ObservationType = "dns_lookup"
	ObservationPortScan           ObservationType = "port_scan"
	ObservationTechnologyDetect   ObservationType = "technology_detection"
	ObservationCertificateInfo    ObservationType = "certificate_info"
	ObservationHARCapture         ObservationType = "har_capture"
	ObservationResearcherNote     ObservationType = "researcher_note"
	ObservationCrawlResult        ObservationType = "crawl_result"
	ObservationAPIDiscovery       ObservationType = "api_discovery"
	ObservationAuthProbe          ObservationType = "authentication_probe"
)

// RawObservation is the pre-normalization output from a parser.
// Parsers produce RawObservations; the Observation Engine normalizes
// them into canonical Observations.
//
// RawObservation exists to decouple parser output format from the
// canonical observation schema. Parsers should not need to know
// the exact canonical field names — they extract what they can,
// and the Observation Engine handles normalization.
type RawObservation struct {
	// Type classifies what kind of data this observation represents.
	Type ObservationType `json:"type"`

	// SourceTool is the name of the tool that produced the original data
	// (e.g., "httpx", "nuclei", "subfinder").
	SourceTool string `json:"source_tool"`

	// Data holds the type-specific extracted fields. The keys and
	// structure depend on the ObservationType and parser.
	Data map[string]any `json:"data"`

	// RawValue is the original text or line from the source file,
	// preserved for provenance and debugging.
	RawValue string `json:"raw_value"`

	// ObservedAt is when the tool produced this data. May differ
	// from ingestion time (e.g., importing historical results).
	ObservedAt time.Time `json:"observed_at"`
}

// Observation is the canonical, immutable unit of parsed data.
// It is Immutable Pillar #1 of the system.
//
// Invariants:
//   - Once created, an Observation is never modified or deleted.
//   - If new data arrives about the same subject, a new Observation
//     is created. The Entity Resolver and Knowledge Graph handle merging.
//   - Every Observation links to its source Artifact via ArtifactID.
//   - Deduplication is based on the Checksum field (hash of Data).
type Observation struct {
	// ID is the unique identifier for this observation.
	ID uuid.UUID `json:"id"`

	// Type classifies what kind of data this observation represents.
	Type ObservationType `json:"type"`

	// ArtifactID links to the source artifact that this observation
	// was extracted from. This is the provenance chain.
	ArtifactID uuid.UUID `json:"artifact_id"`

	// SourceTool is the name of the tool that produced the original data.
	SourceTool string `json:"source_tool"`

	// ProjectID is the owning project's identifier.
	ProjectID uuid.UUID `json:"project_id"`

	// Data holds the type-specific extracted fields, normalized by the
	// Observation Engine into a canonical schema per ObservationType.
	Data map[string]any `json:"data"`

	// RawValue is the original text or line from the source file.
	RawValue string `json:"raw_value"`

	// Checksum is a hash of the Data field, used for deduplication
	// within a project. Two observations with the same checksum
	// and project are considered duplicates.
	Checksum string `json:"checksum"`

	// ObservedAt is when the tool produced this data.
	ObservedAt time.Time `json:"observed_at"`

	// IngestedAt is when the system processed this observation.
	IngestedAt time.Time `json:"ingested_at"`

	// ParserVersion is the version of the parser that extracted this
	// observation. Enables re-parsing if parser logic improves.
	ParserVersion string `json:"parser_version"`
}
