package domain

// ModuleHealth classifies the operational state of a module.
type ModuleHealth string

const (
	// ModuleHealthy indicates the module is functioning normally.
	ModuleHealthy ModuleHealth = "healthy"

	// ModuleWarning indicates the module is functioning but with
	// degraded performance or non-critical issues.
	ModuleWarning ModuleHealth = "warning"

	// ModuleFailed indicates the module is not functioning and
	// cannot serve requests.
	ModuleFailed ModuleHealth = "failed"
)

// ModuleHealthStatus reports the current health of a single module.
// Every module in the system implements the HealthReporter interface
// and produces this status.
type ModuleHealthStatus struct {
	// Module is the name of the module reporting.
	Module string `json:"module"`

	// Health is the current operational state.
	Health ModuleHealth `json:"health"`

	// Message provides additional context about the health state.
	// For healthy modules, this may be empty.
	// For warning/failed modules, this should explain the issue.
	Message string `json:"message,omitempty"`
}
