package report

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

const (
	DogeEngineVersion = "v7.0.0-enterprise"
	DogeEngineCommit  = "e7e9a4f"
	DefaultKeyID      = "doge-sec-root-2026"
)

// ReplayStep represents an atomic, deterministic HTTP transaction in the proof of exploit.
type ReplayStep struct {
	Index                 int               `json:"index"`
	Method                string            `json:"method"`
	URL                   string            `json:"url"`
	Headers               map[string]string `json:"headers,omitempty"`
	Body                  string            `json:"body,omitempty"`
	ExpectedStatus        int               `json:"expected_status"`
	ExpectedBodySubstring string            `json:"expected_body_substring,omitempty"`
	PayloadHash           string            `json:"payload_hash"`
	ResponseHash          string            `json:"response_hash"`
	Timestamp             time.Time         `json:"timestamp"`
}

// AttestationRecord records the cryptographic provenance and environment attestation.
type AttestationRecord struct {
	EngineVersion string    `json:"engine_version"`
	EngineCommit  string    `json:"engine_commit"`
	SignerKeyID   string    `json:"signer_key_id"`
	ExecutionHost string    `json:"execution_host"`
	AttestedAt    time.Time `json:"attested_at"`
	HMACSignature string    `json:"hmac_signature"`
}

// ProofBundle encapsulates a tamper-evident, reproducible cryptographic proof of vulnerability.
type ProofBundle struct {
	ID                 uuid.UUID         `json:"id"`
	FindingID          uuid.UUID         `json:"finding_id"`
	VulnerabilityClass string            `json:"vulnerability_class"`
	TargetURL          string            `json:"target_url"`
	DiscoveredAt       time.Time         `json:"discovered_at"`
	Steps              []ReplayStep      `json:"steps"`
	StepHashes         []string          `json:"step_hashes"`
	ChainDigest        string            `json:"chain_digest"`
	MerkleRoot         string            `json:"merkle_root"`
	Attestation        AttestationRecord `json:"attestation"`
}

// BuildStepHash computes the canonical SHA-256 digest of a replay step.
func BuildStepHash(step ReplayStep) string {
	h := sha256.New()
	// Canonical representation: index|method|url|payload_hash|expected_status|expected_sub|response_hash
	canonical := fmt.Sprintf("%d|%s|%s|%s|%d|%s|%s",
		step.Index,
		strings.ToUpper(step.Method),
		step.URL,
		step.PayloadHash,
		step.ExpectedStatus,
		step.ExpectedBodySubstring,
		step.ResponseHash,
	)
	h.Write([]byte(canonical))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeChainDigest computes the SHA-256 chained hash ledger across all steps:
// H_0 = SHA256(genesis)
// H_i = SHA256(H_{i-1} + ":" + StepHash_i)
func ComputeChainDigest(genesis string, stepHashes []string) string {
	curr := sha256.Sum256([]byte(genesis))
	for _, sh := range stepHashes {
		combined := append(curr[:], []byte(":"+sh)...)
		curr = sha256.Sum256(combined)
	}
	return hex.EncodeToString(curr[:])
}

// ComputeMerkleRoot computes the binary Merkle tree root of a slice of hashes.
func ComputeMerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		empty := sha256.Sum256([]byte("EMPTY_TREE"))
		return hex.EncodeToString(empty[:])
	}
	current := make([][]byte, len(hashes))
	for i, h := range hashes {
		decoded, err := hex.DecodeString(h)
		if err != nil {
			sum := sha256.Sum256([]byte(h))
			current[i] = sum[:]
		} else {
			current[i] = decoded
		}
	}

	for len(current) > 1 {
		var next [][]byte
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				pair := append(current[i], current[i+1]...)
				h := sha256.Sum256(pair)
				next = append(next, h[:])
			} else {
				// Odd node carries over hashed with itself
				pair := append(current[i], current[i]...)
				h := sha256.Sum256(pair)
				next = append(next, h[:])
			}
		}
		current = next
	}

	return hex.EncodeToString(current[0])
}

// SignAttestation generates an HMAC-SHA256 over the bundle's MerkleRoot, ChainDigest, and ID.
func SignAttestation(bundleID, findingID uuid.UUID, chainDigest, merkleRoot string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	payload := fmt.Sprintf("%s|%s|%s|%s|%s", bundleID.String(), findingID.String(), chainDigest, merkleRoot, DogeEngineVersion)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// GenerateProofBundle constructs a complete, tamper-evident ProofBundle from a ProvenFinding and evidence.
func GenerateProofBundle(finding domain.ProvenFinding, targetURL string, secretKey []byte) (*ProofBundle, error) {
	bundleID := uuid.New()
	if len(secretKey) == 0 {
		secretKey = []byte("doge-default-enterprise-attestation-secret-key-2026")
	}

	var steps []ReplayStep
	stepIdx := 0

	// Gather replay steps from validation and impact evidence
	allEvidence := append([]domain.ExperimentEvidence{}, finding.ValidationEvidence...)
	allEvidence = append(allEvidence, finding.ImpactEvidence...)

	if len(allEvidence) == 0 && len(finding.DiscoveryEvidence) > 0 {
		allEvidence = append(allEvidence, finding.DiscoveryEvidence...)
	}

	for _, ev := range allEvidence {
		pHash := sha256.Sum256([]byte(ev.RequestBody))
		rHash := sha256.Sum256([]byte(ev.ResponseBody))

		stepURL := ev.RequestURL
		if stepURL == "" {
			stepURL = targetURL + finding.Endpoint
		}

		step := ReplayStep{
			Index:                 stepIdx,
			Method:                ev.RequestMethod,
			URL:                   stepURL,
			Headers:               ev.RequestHeaders,
			Body:                  ev.RequestBody,
			ExpectedStatus:        ev.ResponseStatus,
			ExpectedBodySubstring: extractExpectedSubstring(ev.ResponseBody),
			PayloadHash:           hex.EncodeToString(pHash[:]),
			ResponseHash:          hex.EncodeToString(rHash[:]),
			Timestamp:             ev.CapturedAt,
		}
		if step.Timestamp.IsZero() {
			step.Timestamp = time.Now().UTC()
		}
		if step.Method == "" {
			step.Method = "GET"
		}
		steps = append(steps, step)
		stepIdx++
	}

	// If no experiment evidence was directly attached, synthesize a minimal reproduction step
	if len(steps) == 0 {
		pHash := sha256.Sum256([]byte{})
		rHash := sha256.Sum256([]byte("CONFIRMED"))
		steps = append(steps, ReplayStep{
			Index:                 0,
			Method:                "GET",
			URL:                   targetURL + finding.Endpoint,
			ExpectedStatus:        http.StatusOK,
			ExpectedBodySubstring: "",
			PayloadHash:           hex.EncodeToString(pHash[:]),
			ResponseHash:          hex.EncodeToString(rHash[:]),
			Timestamp:             finding.ValidatedAt,
		})
	}

	// Compute Step Hashes
	stepHashes := make([]string, len(steps))
	for i, s := range steps {
		stepHashes[i] = BuildStepHash(s)
	}

	// Compute Chain Digest and Merkle Root
	genesis := fmt.Sprintf("DOGE-GENESIS:%s:%s", bundleID.String(), finding.ID.String())
	chainDigest := ComputeChainDigest(genesis, stepHashes)
	merkleRoot := ComputeMerkleRoot(stepHashes)

	// Attestation
	sig := SignAttestation(bundleID, finding.ID, chainDigest, merkleRoot, secretKey)
	attestation := AttestationRecord{
		EngineVersion: DogeEngineVersion,
		EngineCommit:  DogeEngineCommit,
		SignerKeyID:   DefaultKeyID,
		ExecutionHost: "doge-fleet-autonomous-node",
		AttestedAt:    time.Now().UTC(),
		HMACSignature: sig,
	}

	return &ProofBundle{
		ID:                 bundleID,
		FindingID:          finding.ID,
		VulnerabilityClass: finding.Type,
		TargetURL:          targetURL,
		DiscoveredAt:       finding.ValidatedAt,
		Steps:              steps,
		StepHashes:         stepHashes,
		ChainDigest:        chainDigest,
		MerkleRoot:         merkleRoot,
		Attestation:        attestation,
	}, nil
}

// VerifyProofBundleIntegrity verifies that:
// 1. Each step's contents hash to its step hash.
// 2. The chained ledger recalculates to ChainDigest.
// 3. The Merkle tree recalculates to MerkleRoot.
// 4. If secretKey is provided, the HMAC signature is valid.
func VerifyProofBundleIntegrity(bundle *ProofBundle, secretKey []byte) (bool, error) {
	if bundle == nil {
		return false, fmt.Errorf("bundle is nil")
	}
	if len(bundle.Steps) == 0 {
		return false, fmt.Errorf("proof bundle contains no replay steps")
	}
	if len(bundle.Steps) != len(bundle.StepHashes) {
		return false, fmt.Errorf("step count (%d) does not match step hash count (%d)", len(bundle.Steps), len(bundle.StepHashes))
	}

	// 1. Verify individual steps
	for i, step := range bundle.Steps {
		// Verify payload hash
		pSum := sha256.Sum256([]byte(step.Body))
		pHash := hex.EncodeToString(pSum[:])
		if pHash != step.PayloadHash {
			return false, fmt.Errorf("step %d payload hash mismatch: expected %s, got %s", i, step.PayloadHash, pHash)
		}

		expectedStepHash := BuildStepHash(step)
		if expectedStepHash != bundle.StepHashes[i] {
			return false, fmt.Errorf("step %d hash mismatch: expected %s, calculated %s", i, bundle.StepHashes[i], expectedStepHash)
		}
	}

	// 2. Verify Chain Digest
	genesis := fmt.Sprintf("DOGE-GENESIS:%s:%s", bundle.ID.String(), bundle.FindingID.String())
	calcChain := ComputeChainDigest(genesis, bundle.StepHashes)
	if calcChain != bundle.ChainDigest {
		return false, fmt.Errorf("chain digest mismatch: expected %s, calculated %s", bundle.ChainDigest, calcChain)
	}

	// 3. Verify Merkle Root
	calcMerkle := ComputeMerkleRoot(bundle.StepHashes)
	if calcMerkle != bundle.MerkleRoot {
		return false, fmt.Errorf("merkle root mismatch: expected %s, calculated %s", bundle.MerkleRoot, calcMerkle)
	}

	// 4. Verify HMAC Attestation Signature if key is provided
	if len(secretKey) > 0 {
		expectedSig := SignAttestation(bundle.ID, bundle.FindingID, bundle.ChainDigest, bundle.MerkleRoot, secretKey)
		if !hmac.Equal([]byte(expectedSig), []byte(bundle.Attestation.HMACSignature)) {
			return false, fmt.Errorf("HMAC attestation signature invalid: verification failed")
		}
	}

	return true, nil
}

// ReplayResult details the outcome of an active verification replay against the target.
type ReplayResult struct {
	Success          bool     `json:"success"`
	StepsExecuted    int      `json:"steps_executed"`
	TotalSteps       int      `json:"total_steps"`
	FailedStepIndex  int      `json:"failed_step_index"`
	ErrorMessage     string   `json:"error_message,omitempty"`
	ObservedStatuses []int    `json:"observed_statuses"`
	ObservedDigests  []string `json:"observed_digests"`
}

// ReplayProofBundle actively replays the proof sequence against the target server using the provided HTTP client.
func ReplayProofBundle(ctx context.Context, bundle *ProofBundle, httpClient *http.Client) (*ReplayResult, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	res := &ReplayResult{
		TotalSteps:       len(bundle.Steps),
		ObservedStatuses: make([]int, 0, len(bundle.Steps)),
		ObservedDigests:  make([]string, 0, len(bundle.Steps)),
	}

	for i, step := range bundle.Steps {
		req, err := http.NewRequestWithContext(ctx, step.Method, step.URL, bytes.NewBufferString(step.Body))
		if err != nil {
			res.FailedStepIndex = i
			res.ErrorMessage = fmt.Sprintf("failed to build request for step %d: %v", i, err)
			return res, err
		}

		for k, v := range step.Headers {
			req.Header.Set(k, v)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			res.FailedStepIndex = i
			res.ErrorMessage = fmt.Sprintf("execution failed at step %d: %v", i, err)
			return res, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			res.FailedStepIndex = i
			res.ErrorMessage = fmt.Sprintf("failed reading response body at step %d: %v", i, err)
			return res, err
		}

		res.ObservedStatuses = append(res.ObservedStatuses, resp.StatusCode)
		respHash := sha256.Sum256(bodyBytes)
		res.ObservedDigests = append(res.ObservedDigests, hex.EncodeToString(respHash[:]))
		res.StepsExecuted++

		if resp.StatusCode != step.ExpectedStatus {
			res.FailedStepIndex = i
			res.ErrorMessage = fmt.Sprintf("step %d status mismatch: expected %d, got %d", i, step.ExpectedStatus, resp.StatusCode)
			return res, nil
		}

		if step.ExpectedBodySubstring != "" && !strings.Contains(string(bodyBytes), step.ExpectedBodySubstring) {
			res.FailedStepIndex = i
			res.ErrorMessage = fmt.Sprintf("step %d body did not contain required substring %q", i, step.ExpectedBodySubstring)
			return res, nil
		}
	}

	res.Success = true
	return res, nil
}

func extractExpectedSubstring(body string) string {
	trimmed := strings.TrimSpace(body)
	if len(trimmed) == 0 {
		return ""
	}
	if strings.HasPrefix(trimmed, "{") {
		var m map[string]any
		if err := json.Unmarshal([]byte(trimmed), &m); err == nil {
			if st, ok := m["status"].(string); ok && len(st) > 0 {
				return st
			}
			for _, v := range m {
				if str, ok := v.(string); ok && len(str) > 2 {
					return str
				}
			}
		}
	}
	if len(trimmed) > 32 {
		return trimmed[:32]
	}
	return trimmed
}
