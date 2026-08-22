// Package scheduler provides engagement authorization for
// non-auto-recon environments (authorized, other).
//
// When auto_recon is false, the scheduler will not run any tools
// until a human explicitly authorizes the engagement.
//
// The authorization is persisted to .doge/authorization.json
// so that it can be granted from doge approvals in any terminal
// and picked up by the scheduler in the machine terminal.
package scheduler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ReconAuthorizationFile is where authorization state lives.
const ReconAuthorizationFile = "authorization.json"

// AuthStatus tracks the authorization lifecycle.
type AuthStatus string

const (
	AuthPending  AuthStatus = "pending"
	AuthApproved AuthStatus = "approved"
	AuthDenied   AuthStatus = "denied"
)

// ReconAuthorization represents the human's explicit approval
// of what DOGE is allowed to do for a given engagement.
//
// For HTB/Lab targets this is pre-approved (auto_recon=true).
// For Authorized/Other targets, a human must approve this
// before any tools execute.
type ReconAuthorization struct {
	// Identity.
	Target      string `json:"target"`
	Environment string `json:"environment"`

	// Status.
	Status AuthStatus `json:"status"`

	// What is being requested.
	RequestedCapabilities []ReconCapability `json:"requested_capabilities"`

	// Approval metadata.
	ApprovedBy string    `json:"approved_by,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitempty"`
	DeniedAt   time.Time `json:"denied_at,omitempty"`

	// Rate limiting (optional).
	MaxConcurrent int `json:"max_concurrent,omitempty"`
	MaxJobRuntime int `json:"max_job_runtime_seconds,omitempty"`
}

// ReconCapability represents a single type of reconnaissance
// that can be authorized.
type ReconCapability struct {
	// Name of the capability (e.g., "DNS discovery", "Port scanning").
	Name string `json:"name"`

	// Category maps to the policy field.
	Category string `json:"category"`

	// Tools that implement this capability.
	Tools []string `json:"tools"`

	// Whether this capability is approved.
	Approved bool `json:"approved"`
}

// DefaultCapabilities returns the initial set of recon capabilities
// that DOGE requests authorization for.
func DefaultCapabilities() []ReconCapability {
	return []ReconCapability{
		{
			Name:     "DNS discovery",
			Category: "subdomain_enum",
			Tools:    []string{"subfinder", "dnsx"},
			Approved: false,
		},
		{
			Name:     "Service discovery",
			Category: "recon",
			Tools:    []string{"nmap"},
			Approved: false,
		},
		{
			Name:     "HTTP probing",
			Category: "web_enum",
			Tools:    []string{"httpx"},
			Approved: false,
		},
		{
			Name:     "Web crawling",
			Category: "web_enum",
			Tools:    []string{"katana"},
			Approved: false,
		},
		{
			Name:     "Directory fuzzing",
			Category: "fuzzing",
			Tools:    []string{"ffuf"},
			Approved: false,
		},
		{
			Name:     "Vulnerability scanning",
			Category: "scanning",
			Tools:    []string{"nuclei"},
			Approved: false,
		},
	}
}

// NewPendingAuthorization creates an authorization request
// for a non-auto-recon engagement.
func NewPendingAuthorization(target, environment string) *ReconAuthorization {
	return &ReconAuthorization{
		Target:                target,
		Environment:           environment,
		Status:                AuthPending,
		RequestedCapabilities: DefaultCapabilities(),
	}
}

// Approve marks the authorization as approved.
// Only capabilities marked approved=true will be allowed.
func (a *ReconAuthorization) Approve(approvedBy string) {
	a.Status = AuthApproved
	a.ApprovedBy = approvedBy
	a.ApprovedAt = time.Now().UTC()
}

// ApproveAll marks all capabilities as approved and approves.
func (a *ReconAuthorization) ApproveAll(approvedBy string) {
	for i := range a.RequestedCapabilities {
		a.RequestedCapabilities[i].Approved = true
	}
	a.Approve(approvedBy)
}

// ApproveByIndex approves a specific capability by index.
func (a *ReconAuthorization) ApproveByIndex(idx int) error {
	if idx < 0 || idx >= len(a.RequestedCapabilities) {
		return fmt.Errorf("capability index %d out of range", idx)
	}
	a.RequestedCapabilities[idx].Approved = true
	return nil
}

// Deny rejects the authorization.
func (a *ReconAuthorization) Deny() {
	a.Status = AuthDenied
	a.DeniedAt = time.Now().UTC()
}

// IsToolAuthorized checks if a specific tool is approved.
func (a *ReconAuthorization) IsToolAuthorized(toolName string) bool {
	if a.Status != AuthApproved {
		return false
	}
	for _, cap := range a.RequestedCapabilities {
		if !cap.Approved {
			continue
		}
		for _, t := range cap.Tools {
			if t == toolName {
				return true
			}
		}
	}
	return false
}

// ApprovedTools returns the list of all approved tools.
func (a *ReconAuthorization) ApprovedTools() []string {
	var tools []string
	for _, cap := range a.RequestedCapabilities {
		if cap.Approved {
			tools = append(tools, cap.Tools...)
		}
	}
	return tools
}

// --- Persistence ---

// SaveAuthorization writes the authorization state to disk.
func SaveAuthorization(workspacePath string, auth *ReconAuthorization) error {
	dogeDir := filepath.Join(workspacePath, ".doge")
	if err := os.MkdirAll(dogeDir, 0755); err != nil {
		return fmt.Errorf("creating .doge dir: %w", err)
	}

	data, err := json.MarshalIndent(auth, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling authorization: %w", err)
	}

	path := filepath.Join(dogeDir, ReconAuthorizationFile)
	return os.WriteFile(path, data, 0644)
}

// LoadAuthorization reads the authorization state from disk.
func LoadAuthorization(workspacePath string) (*ReconAuthorization, error) {
	path := filepath.Join(workspacePath, ".doge", ReconAuthorizationFile)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No authorization file = not applicable.
		}
		return nil, fmt.Errorf("reading authorization: %w", err)
	}

	var auth ReconAuthorization
	if err := json.Unmarshal(data, &auth); err != nil {
		return nil, fmt.Errorf("parsing authorization: %w", err)
	}

	return &auth, nil
}
