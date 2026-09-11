package novelty

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/property"
)

// MDLObservation represents a structured observation for Minimum Description Length analysis.
type MDLObservation struct {
	ID             uuid.UUID         `json:"id"`
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body"`
	BodyLength     int               `json:"body_length"`
	BodyEntropy    float64           `json:"body_entropy"`
	ResponseTimeMs float64           `json:"response_time_ms"`
	PrincipalID    string            `json:"principal_id"`
	Timestamp      time.Time         `json:"timestamp"`
}

// MDLAnomalyResult represents the outcome of MDL compression analysis for an observation.
type MDLAnomalyResult struct {
	ObservationID          uuid.UUID `json:"observation_id"`
	RawDescriptionLength   float64   `json:"raw_description_length"`   // L(o | empty) in bits
	ModelDescriptionLength float64   `json:"model_description_length"` // L(o | K_t) in bits
	CompressionDeficiency  float64   `json:"compression_deficiency"`  // (L_raw - L_model) / L_raw
	AnomalyScore           float64   `json:"anomaly_score"`            // Normalized [0.0, 1.0]
	IsStructuralAnomaly    bool      `json:"is_structural_anomaly"`    // Exceeds threshold
	DiscrepancyDimension   string    `json:"discrepancy_dimension"`
	Explanation            string    `json:"explanation"`
}

// ProvisionalConcept represents a newly minted candidate concept from representation expansion rho.
type ProvisionalConcept struct {
	ID                 string    `json:"id"`
	DiscrepancyDim     string    `json:"discrepancy_dim"`
	ObservedTarget     string    `json:"observed_target"`
	StructuralRelation string    `json:"structural_relation"`
	AnomalyScore       float64   `json:"anomaly_score"`
	TriggeringObsID    uuid.UUID `json:"triggering_obs_id"`
	CreatedAt          time.Time `json:"created_at"`
}

// MDLAnomalyDetector scores observations against the current security ontology K_t.
type MDLAnomalyDetector struct {
	threshold      float64
	knownPatterns  map[string]bool
	statusPriors   map[int]float64
	knownHeaders   map[string]bool
}

// NewMDLAnomalyDetector instantiates an MDL anomaly detector with sensible priors.
func NewMDLAnomalyDetector(threshold float64) *MDLAnomalyDetector {
	if threshold <= 0 {
		threshold = 0.65
	}
	detector := &MDLAnomalyDetector{
		threshold: threshold,
		knownPatterns: map[string]bool{
			"unauthorized":        true,
			"forbidden":           true,
			"not found":           true,
			"bad request":         true,
			"ok":                  true,
			"internal error":      true,
			"success":             true,
			"invalid token":       true,
			"rate limit exceeded": true,
		},
		statusPriors: map[int]float64{
			200: 0.50, // very common
			401: 0.20,
			403: 0.15,
			404: 0.10,
			500: 0.05,
		},
		knownHeaders: map[string]bool{
			"content-type":   true,
			"content-length": true,
			"date":           true,
			"server":         true,
			"connection":     true,
			"cache-control":  true,
		},
	}
	return detector
}

// ComputeShannonEntropy calculates the Shannon entropy in bits per byte of a string.
func ComputeShannonEntropy(data string) float64 {
	if len(data) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, r := range data {
		freq[r]++
	}
	total := float64(len(data))
	var entropy float64
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// EvaluateObservation calculates L(o | empty) and L(o | K_t) to compute the anomaly score.
func (d *MDLAnomalyDetector) EvaluateObservation(obs *MDLObservation, catalog *property.Catalog) *MDLAnomalyResult {
	if obs == nil {
		return nil
	}

	// 1. Raw Description Length L(o | empty)
	// Base encoding of status code, method, headers, and body with uniform prior
	bodyBytes := float64(len(obs.Body))
	entropy := obs.BodyEntropy
	if entropy == 0 && bodyBytes > 0 {
		entropy = ComputeShannonEntropy(obs.Body)
	}
	// L(o | empty) = 16 bits (status) + 32 bits (method/url) + bodyBytes * 8 bits
	rawLength := 48.0 + (bodyBytes * 8.0)
	if rawLength < 64.0 {
		rawLength = 64.0
	}

	// 2. Model Description Length L(o | K_t)
	// How many bits are required to encode this observation given known ontology K_t?
	modelBits := 0.0

	// Status code under prior
	if prior, ok := d.statusPriors[obs.StatusCode]; ok {
		modelBits += -math.Log2(prior)
	} else {
		modelBits += -math.Log2(0.001) // unexpected status requires ~10 bits
	}

	// Headers: standard headers cost 2 bits each; unexpected/sensitive headers cost 32 bits
	unexpectedHeaderCount := 0
	for h := range obs.Headers {
		lh := strings.ToLower(h)
		if d.knownHeaders[lh] {
			modelBits += 2.0
		} else {
			unexpectedHeaderCount++
			modelBits += 32.0
		}
	}

	// Body compressibility under ontology:
	// If body matches known security error schemas or property violations, it is compressed well.
	bodyExplained := false
	bodyLower := strings.ToLower(obs.Body)
	for pat := range d.knownPatterns {
		if strings.Contains(bodyLower, pat) {
			bodyExplained = true
			break
		}
	}

	var dim string
	var explanation string

	if bodyExplained {
		// Model can explain the body with concise reference to known schema (~32 bits + entropy residual)
		modelBits += 32.0 + (entropy * math.Min(bodyBytes, 100.0))
	} else if bodyBytes > 0 {
		// Unexplained body: model must encode raw residual
		modelBits += (entropy * bodyBytes)
		if obs.StatusCode >= 200 && obs.StatusCode < 300 && strings.Contains(bodyLower, "debug") {
			dim = "DebugLeakedInSuccess"
			explanation = "200 OK response contains unexplained debug/privileged metadata resisting standard API ontology"
		} else if obs.StatusCode == 200 && strings.Contains(bodyLower, "role") && strings.Contains(bodyLower, "admin") {
			dim = "PrivilegeStateDesync"
			explanation = "Successful response reflects unauthorized administrative credentials or elevated state"
		} else {
			dim = "UncompressedResponseAnomaly"
			explanation = "Response structure diverges from expected canonical model schemas"
		}
	}

	// Cross-check with property catalog if available
	if catalog != nil && obs.URL != "" {
		props := catalog.GenerateForEndpoint(obs.URL)
		if len(props) > 0 {
			// Existing properties reduce model bits if matched
			modelBits *= 0.95
		}
	}

	// Calculate Compression Deficiency:
	// A high deficiency means the model fails to compress the observation (observation is an anomaly).
	// AnomalyScore = max(0, min(1, (modelBits - expectedBits) / rawLength))
	anomalyScore := 0.0
	if rawLength > 0 {
		// Normalized anomaly ratio
		ratio := modelBits / rawLength
		if ratio > 1.0 {
			ratio = 1.0
		}
		// When modelBits is large relative to expected compression, anomaly is high
		if unexpectedHeaderCount > 0 || (bodyBytes > 0 && !bodyExplained) {
			anomalyScore = math.Min(1.0, 0.50+(float64(unexpectedHeaderCount)*0.15)+(0.35*(1.0-1.0/(1.0+modelBits/100.0))))
		} else {
			anomalyScore = 0.20 * ratio
		}
	}

	isAnomaly := anomalyScore >= d.threshold
	if isAnomaly && explanation == "" {
		explanation = "Observation description length under K_t exceeds compressibility threshold"
		dim = "StructuralInvariantDivergence"
	}

	return &MDLAnomalyResult{
		ObservationID:          obs.ID,
		RawDescriptionLength:   rawLength,
		ModelDescriptionLength: modelBits,
		CompressionDeficiency:  anomalyScore,
		AnomalyScore:           anomalyScore,
		IsStructuralAnomaly:    isAnomaly,
		DiscrepancyDimension:   dim,
		Explanation:            explanation,
	}
}

// RepresentationExpansionOperator represents rho: (O_{1:t}, K_t) -> K_{t+1}.
// Promotes an uncompressed, validated anomaly into a provisional concept in the research ontology.
func RepresentationExpansionOperator(res *MDLAnomalyResult, obs *MDLObservation) *ProvisionalConcept {
	if res == nil || !res.IsStructuralAnomaly || obs == nil {
		return nil
	}

	hasher := sha256.New()
	hasher.Write([]byte(obs.URL + ":" + obs.Method + ":" + res.DiscrepancyDimension))
	conceptHash := hex.EncodeToString(hasher.Sum(nil))[:12]

	conceptID := "CONCEPT_EMERGENT_" + strings.ToUpper(res.DiscrepancyDimension) + "_" + conceptHash
	relation := fmt.Sprintf("Relation(%s %s [dim=%s] score=%.3f)", obs.Method, obs.URL, res.DiscrepancyDimension, res.AnomalyScore)

	return &ProvisionalConcept{
		ID:                 conceptID,
		DiscrepancyDim:     res.DiscrepancyDimension,
		ObservedTarget:     obs.URL,
		StructuralRelation: relation,
		AnomalyScore:       res.AnomalyScore,
		TriggeringObsID:    obs.ID,
		CreatedAt:          time.Now().UTC(),
	}
}
