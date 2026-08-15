// Package scheduler provides the event-driven reconnaissance
// scheduler that automatically executes tools within policy bounds.
//
// The scheduler is the MACHINERY layer. It creates jobs from
// deterministic event-driven rules. It does NOT:
//   - Execute exploitation tools
//   - Generate shell commands
//   - Bypass scope
//   - Accept commands from AI reasoning
//
// The scheduler's authority is separate from the AI's authority:
//
//	Scheduler → deterministic recon rules → jobs
//	AI        → hypotheses → validation plans → HUMAN APPROVAL
//
// Neither can impersonate the other.
package scheduler

import (
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ResearchPolicy controls what the scheduler is allowed to do
// automatically vs what requires human approval.
//
// The policy is set by the target's environment and can be
// overridden by configuration.
type ResearchPolicy struct {
	// Environment this policy is for.
	Environment domain.TargetEnvironment `json:"environment"`

	// AutoRecon controls whether initial port scanning starts automatically.
	AutoRecon bool `json:"auto_recon"`

	// AutoWebEnum controls whether HTTP probing and crawling run automatically.
	AutoWebEnum bool `json:"auto_web_enum"`

	// AutoFuzzing controls whether directory fuzzing runs automatically.
	AutoFuzzing bool `json:"auto_fuzzing"`

	// AutoScanning controls whether vulnerability scanning runs automatically.
	AutoScanning bool `json:"auto_scanning"`

	// AutoSubdomainEnum controls whether subdomain enumeration runs automatically.
	AutoSubdomainEnum bool `json:"auto_subdomain_enum"`

	// RequireApprovalFor lists tools that always need human approval.
	RequireApprovalFor []string `json:"require_approval_for"`

	// MaxConcurrentTools limits parallel tool execution.
	MaxConcurrentTools int `json:"max_concurrent_tools"`

	// MaxQueueSize limits the job queue.
	MaxQueueSize int `json:"max_queue_size"`

	// MaxJobRuntime limits any single job.
	MaxJobRuntime time.Duration `json:"max_job_runtime"`

	// MaxDiscoveryDepth limits recursive discovery.
	MaxDiscoveryDepth int `json:"max_discovery_depth"`

	// PerToolLimits sets per-tool concurrency limits.
	PerToolLimits map[string]int `json:"per_tool_limits"`
}

// DefaultPolicy returns the research policy for an environment.
//
// | Environment | Initial recon | Web enum | Fuzzing | Scanning |
// |-------------|---------------|----------|---------|----------|
// | HTB         | 🟢 Auto      | 🟢 Auto | 🟢 Auto| 🟢 Auto |
// | Lab         | 🟢 Auto      | 🟢 Auto | 🟢 Auto| 🟢 Auto |
// | Owned       | 🟢 Auto      | 🟢 Auto | 🟡 Cfg | 🟡 Cfg  |
// | Authorized  | 🟡 Approval  | 🟡 Cfg  | 🔴 No  | 🔴 No   |
// | Other       | 🔴 Approval  | 🔴 No   | 🔴 No  | 🔴 No   |
func DefaultPolicy(env domain.TargetEnvironment) ResearchPolicy {
	base := ResearchPolicy{
		Environment:        env,
		MaxConcurrentTools: 3,
		MaxQueueSize:       50,
		MaxJobRuntime:      10 * time.Minute,
		MaxDiscoveryDepth:  3,
		PerToolLimits: map[string]int{
			"nmap":      1,
			"subfinder": 1,
			"httpx":     3,
			"dnsx":      2,
			"katana":    2,
			"ffuf":      1,
			"nuclei":    2,
		},
	}

	switch env {
	case domain.EnvHTB, domain.EnvLab:
		base.AutoRecon = true
		base.AutoWebEnum = true
		base.AutoFuzzing = true
		base.AutoScanning = true
		base.AutoSubdomainEnum = true

	case domain.EnvOwned:
		base.AutoRecon = true
		base.AutoWebEnum = true
		base.AutoFuzzing = false
		base.AutoScanning = false
		base.AutoSubdomainEnum = true

	case domain.EnvAuthorized:
		base.AutoRecon = false
		base.AutoWebEnum = false
		base.AutoFuzzing = false
		base.AutoScanning = false
		base.AutoSubdomainEnum = false
		base.RequireApprovalFor = []string{"nmap", "ffuf", "nuclei"}

	case domain.EnvOther:
		base.AutoRecon = false
		base.AutoWebEnum = false
		base.AutoFuzzing = false
		base.AutoScanning = false
		base.AutoSubdomainEnum = false
		base.RequireApprovalFor = []string{"nmap", "httpx", "subfinder", "dnsx", "katana", "ffuf", "nuclei"}
	}

	return base
}

// CanAutoRun checks if a tool is allowed to run automatically
// under this policy.
func (p *ResearchPolicy) CanAutoRun(toolName string) bool {
	// Check explicit approval requirements.
	for _, t := range p.RequireApprovalFor {
		if t == toolName {
			return false
		}
	}

	// Check category permissions.
	switch toolName {
	case "nmap":
		return p.AutoRecon
	case "httpx", "katana":
		return p.AutoWebEnum
	case "subfinder", "dnsx":
		return p.AutoSubdomainEnum
	case "ffuf":
		return p.AutoFuzzing
	case "nuclei":
		return p.AutoScanning
	default:
		return false // unknown tools require approval
	}
}

// ToolConcurrency returns the max concurrent instances for a tool.
func (p *ResearchPolicy) ToolConcurrency(toolName string) int {
	if limit, ok := p.PerToolLimits[toolName]; ok {
		return limit
	}
	return 1
}
