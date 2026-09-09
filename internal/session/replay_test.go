package session

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/hypothesis"
)

func TestSessionTraceRecorderAndReplay(t *testing.T) {
	invID := uuid.New()
	target := "api.target.com"
	recorder := NewTraceRecorder(invID, target, ProfileStandard)

	hypID := uuid.New()

	// 1. Record Iteration 1: BOLA Differential (Rejected on 403 Forbidden)
	recorder.RecordIteration(&IterationTraceEntry{
		IterationNumber:      1,
		ActionTitle:          "BOLA Differential on /api/users/123",
		Tool:                 "doge_differential",
		TargetEndpoint:       "https://api.target.com/api/users/123",
		InformationGainScore: 4.85,
		PriorityReason:       "High potential impact and high uncertainty reduction on direct object ID",
		ExecutionStdout:      "HTTP/1.1 403 Forbidden\nAccess Denied",
		ExitCode:             0,
		HypothesisDeltas: []HypothesisDelta{
			{
				HypothesisID:    hypID,
				HypothesisTitle: "BOLA on /api/users/123",
				OldStatus:       hypothesis.StatusUnvalidated,
				NewStatus:       hypothesis.StatusRejected,
				OldConfidence:   0.60,
				NewConfidence:   0.0,
				Reason:          "Refuted by 403 Forbidden",
			},
		},
		LearningBoostDelta: -0.60,
		RecordedAt:         time.Now().UTC(),
	})

	// 2. Record Iteration 2: SSRF OOB Probe (Confirmed on DNS interaction)
	recorder.RecordIteration(&IterationTraceEntry{
		IterationNumber:      2,
		ActionTitle:          "SSRF Probe on webhook_url",
		Tool:                 "doge_ssrf_probe",
		TargetEndpoint:       "https://api.target.com/api/webhook?url=",
		InformationGainScore: 5.20,
		PriorityReason:       "URL ingestion parameter with unprobed remote callback surface",
		ExecutionStdout:      "DNS callback received from 192.0.2.45",
		ExitCode:             0,
		HypothesisDeltas: []HypothesisDelta{
			{
				HypothesisID:    uuid.New(),
				HypothesisTitle: "SSRF on webhook_url",
				OldStatus:       hypothesis.StatusUnvalidated,
				NewStatus:       hypothesis.StatusConfirmed,
				OldConfidence:   0.55,
				NewConfidence:   0.95,
				Reason:          "Out-of-band DNS resolution confirmed",
			},
		},
		LearningBoostDelta: 0.50,
		RecordedAt:         time.Now().UTC(),
	})

	finalTrace := recorder.Finalize(1, "Discovered confirmed SSRF vulnerability; BOLA refuted by multi-tenant isolation.")

	if len(finalTrace.Iterations) != 2 {
		t.Fatalf("expected 2 recorded iterations, got %d", len(finalTrace.Iterations))
	}

	// 3. Export to JSON
	jsonBytes, err := recorder.ExportJSON()
	if err != nil {
		t.Fatalf("failed to export trace to JSON: %v", err)
	}

	// 4. Load trace with ReplayEngine
	replayEngine := NewReplayEngine()
	loadedTrace, err := replayEngine.LoadTrace(jsonBytes)
	if err != nil {
		t.Fatalf("failed to load trace: %v", err)
	}

	if loadedTrace.Target != target || len(loadedTrace.Iterations) != 2 {
		t.Fatalf("loaded trace mismatch: target=%s, iterations=%d", loadedTrace.Target, len(loadedTrace.Iterations))
	}

	// 5. Deterministic Step-by-Step Replay
	replayedCount := 0
	err = replayEngine.ReplayStepByStep(loadedTrace, func(step *IterationTraceEntry) error {
		replayedCount++
		t.Logf("Replayed Step %d: %s -> Output: %s (Gain: %.2f)", step.IterationNumber, step.ActionTitle, step.ExecutionStdout, step.InformationGainScore)
		return nil
	})

	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	if replayedCount != 2 {
		t.Fatalf("expected 2 replayed steps, got %d", replayedCount)
	}

	t.Logf("✓ Verified Session Recording, JSON Export, and Deterministic Replay Engine")
}

func TestBudgetTrackerLimitsAndExhaustion(t *testing.T) {
	budget := ResourceBudget{
		MaxIterations:   3,
		MaxRequests:     10,
		MaxCostUSD:      2.0,
		RateLimitPerSec: 5,
	}

	tracker := NewBudgetTracker(ProfileStealth, &budget)

	// Consume iterations 1 and 2
	if err := tracker.ConsumeIteration(); err != nil {
		t.Fatalf("unexpected error on iter 1: %v", err)
	}
	if err := tracker.ConsumeIteration(); err != nil {
		t.Fatalf("unexpected error on iter 2: %v", err)
	}

	// Iteration 3 reaches limit
	if err := tracker.ConsumeIteration(); err == nil {
		t.Fatalf("expected budget exhaustion error on iter 3")
	}

	if !tracker.IsExhausted {
		t.Errorf("expected tracker.IsExhausted to be true")
	}

	utilization := tracker.UtilizationPercent()
	if utilization < 100.0 {
		t.Errorf("expected utilization to be 100%%, got %.2f%%", utilization)
	}

	t.Logf("✓ Verified Budget Tracker bounds enforcement (Utilization: %.1f%%, Reason: %s)", utilization, tracker.ExhaustionReason)
}
