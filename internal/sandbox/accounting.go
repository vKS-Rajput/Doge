package sandbox

import (
	"fmt"
	"sync"
)

// ResourceAccountant tracks execution cost, token consumption, and network volume.
type ResourceAccountant struct {
	mu                 sync.Mutex
	TotalRequests      int     `json:"total_requests"`
	TotalBytesSent     int64   `json:"total_bytes_sent"`
	TotalBytesReceived int64   `json:"total_bytes_received"`
	TotalLatencyMs     int64   `json:"total_latency_ms"`
	EstimatedCostUSD   float64 `json:"estimated_cost_usd"`
}

// NewResourceAccountant creates a new resource tracking instance.
func NewResourceAccountant() *ResourceAccountant {
	return &ResourceAccountant{}
}

// RecordTransaction adds metrics from an executed HTTP request/response.
func (a *ResourceAccountant) RecordTransaction(sentBytes, recvBytes int, latencyMs int64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.TotalRequests++
	a.TotalBytesSent += int64(sentBytes)
	a.TotalBytesReceived += int64(recvBytes)
	a.TotalLatencyMs += latencyMs

	// Industrial cost model: ~$0.00005 per raw network transaction + bandwidth overhead
	a.EstimatedCostUSD += 0.00005 + (float64(sentBytes+recvBytes) * 0.00000001)
}

// Snapshot returns a copy of the current accounting metrics.
func (a *ResourceAccountant) Snapshot() ResourceAccountant {
	a.mu.Lock()
	defer a.mu.Unlock()
	return *a
}

// FormatSummary generates a readable accounting report.
func (a *ResourceAccountant) FormatSummary() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	return fmt.Sprintf("Requests: %d | Data: %d KB sent, %d KB received | Avg Latency: %.1fms | Est Cost: $%.5f",
		a.TotalRequests,
		a.TotalBytesSent/1024,
		a.TotalBytesReceived/1024,
		float64(a.TotalLatencyMs)/float64(a.TotalRequests+1),
		a.EstimatedCostUSD,
	)
}
