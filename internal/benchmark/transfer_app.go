package benchmark

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// MedicalTelemetryApp represents BENCH-007: an IoT medical device gateway with an un-templated concurrency race.
type MedicalTelemetryApp struct {
	mu                 sync.Mutex
	server             *httptest.Server
	calibrationCredits map[string]int // deviceID -> available calibration budget
	appliedUnits       map[string]int // deviceID -> total applied units
}

// NewMedicalTelemetryApp starts a simulated medical telemetry target.
func NewMedicalTelemetryApp() *MedicalTelemetryApp {
	app := &MedicalTelemetryApp{
		calibrationCredits: map[string]int{
			"dev_icu_9921": 10, // maximum allowable calibration units
		},
		appliedUnits: map[string]int{
			"dev_icu_9921": 0,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/api/v1/telemetry/device/", app.handleDeviceRouting)

	app.server = httptest.NewServer(mux)
	return app
}

// URL returns the test server URL.
func (m *MedicalTelemetryApp) URL() string {
	return m.server.URL
}

// Close terminates the mock server.
func (m *MedicalTelemetryApp) Close() {
	m.server.Close()
}

// GetAppliedUnits returns total applied units for a device.
func (m *MedicalTelemetryApp) GetAppliedUnits(deviceID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.appliedUnits[deviceID]
}

// GetCredits returns remaining allowable credits.
func (m *MedicalTelemetryApp) GetCredits(deviceID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calibrationCredits[deviceID]
}

func (m *MedicalTelemetryApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "healthy",
		"service": "medical-telemetry-gateway",
	})
}

func (m *MedicalTelemetryApp) handleDeviceRouting(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 6 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	deviceID := parts[4]
	action := parts[5]

	w.Header().Set("Content-Type", "application/json")

	switch action {
	case "status":
		m.mu.Lock()
		credits := m.calibrationCredits[deviceID]
		applied := m.appliedUnits[deviceID]
		m.mu.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_id":         deviceID,
			"remaining_credits": credits,
			"applied_units":     applied,
			"status":            "online",
		})

	case "calibrate":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Units int `json:"units"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Units <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// ASYNCHRONOUS CHECK-THEN-ACT RACE CONDITION:
		// Check available credits first
		m.mu.Lock()
		credits := m.calibrationCredits[deviceID]
		m.mu.Unlock()

		if credits < req.Units {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "calibration credit limit exceeded",
			})
			return
		}

		// Vulnerability window: 30ms async latency before state mutation
		time.Sleep(30 * time.Millisecond)

		m.mu.Lock()
		// Mutate state without re-verifying balance under lock
		m.calibrationCredits[deviceID] -= req.Units
		m.appliedUnits[deviceID] += req.Units
		newRemaining := m.calibrationCredits[deviceID]
		newApplied := m.appliedUnits[deviceID]
		m.mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":            "calibrated",
			"device_id":         deviceID,
			"applied_units":     req.Units,
			"remaining_credits": newRemaining,
			"total_applied":     newApplied,
		})

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
