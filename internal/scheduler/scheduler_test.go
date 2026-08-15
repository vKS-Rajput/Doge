package scheduler

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/bus"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// --- Policy Tests ---

func TestDefaultPolicyHTB(t *testing.T) {
	p := DefaultPolicy(domain.EnvHTB)
	if !p.AutoRecon {
		t.Error("HTB should auto-recon")
	}
	if !p.AutoWebEnum {
		t.Error("HTB should auto web enum")
	}
	if !p.AutoFuzzing {
		t.Error("HTB should auto fuzz")
	}
	if !p.AutoScanning {
		t.Error("HTB should auto scan")
	}
}

func TestDefaultPolicyAuthorized(t *testing.T) {
	p := DefaultPolicy(domain.EnvAuthorized)
	if p.AutoRecon {
		t.Error("authorized should NOT auto-recon")
	}
	if p.AutoFuzzing {
		t.Error("authorized should NOT auto-fuzz")
	}
	if len(p.RequireApprovalFor) == 0 {
		t.Error("authorized should require approval for some tools")
	}
}

func TestDefaultPolicyOther(t *testing.T) {
	p := DefaultPolicy(domain.EnvOther)
	if p.AutoRecon {
		t.Error("other should NOT auto-recon")
	}
	if len(p.RequireApprovalFor) != 7 {
		t.Errorf("other should require approval for all 7 tools, got %d", len(p.RequireApprovalFor))
	}
}

func TestCanAutoRun(t *testing.T) {
	htb := DefaultPolicy(domain.EnvHTB)
	auth := DefaultPolicy(domain.EnvAuthorized)

	if !htb.CanAutoRun("nmap") {
		t.Error("HTB should allow auto nmap")
	}
	if !htb.CanAutoRun("httpx") {
		t.Error("HTB should allow auto httpx")
	}
	if !htb.CanAutoRun("nuclei") {
		t.Error("HTB should allow auto nuclei")
	}
	if auth.CanAutoRun("nmap") {
		t.Error("authorized should NOT allow auto nmap")
	}
	if htb.CanAutoRun("unknown-tool") {
		t.Error("unknown tools should never auto-run")
	}
}

// --- Registry Tests ---

func TestRegistryBuiltins(t *testing.T) {
	r := NewToolRegistry()

	expected := []string{"nmap", "subfinder", "httpx", "dnsx", "katana", "ffuf", "nuclei"}
	for _, name := range expected {
		def, ok := r.Get(name)
		if !ok {
			t.Errorf("registry missing built-in: %s", name)
			continue
		}
		if def.Binary == "" {
			t.Errorf("%s has no binary", name)
		}
		if def.Parser == "" {
			t.Errorf("%s has no parser", name)
		}
		if def.Category == "" {
			t.Errorf("%s has no category", name)
		}
	}
}

func TestRegistryCustomTool(t *testing.T) {
	r := NewToolRegistry()
	r.Register(ToolDefinition{
		Name:     "custom",
		Binary:   "custom-tool",
		Parser:   "custom",
		Category: CategoryRecon,
	})

	def, ok := r.Get("custom")
	if !ok {
		t.Fatal("custom tool not found")
	}
	if def.Binary != "custom-tool" {
		t.Error("custom tool binary mismatch")
	}
}

func TestRegistryCaptureMode(t *testing.T) {
	r := NewToolRegistry()

	nmap, _ := r.Get("nmap")
	if nmap.CaptureMode != CaptureFlag {
		t.Error("nmap should use flag capture")
	}

	httpx, _ := r.Get("httpx")
	if httpx.CaptureMode != CaptureStdout {
		t.Error("httpx should use stdout capture")
	}
}

// --- Queue Tests ---

func TestQueueEnqueueDequeue(t *testing.T) {
	q := NewJobQueue(10)
	job := NewJob(uuid.New(), "nmap", "10.10.11.123", "test", JobPriorityNormal)

	if err := q.Enqueue(job); err != nil {
		t.Fatalf("enqueue should succeed: %v", err)
	}
	if q.Len() != 1 {
		t.Errorf("queue length should be 1, got %d", q.Len())
	}

	dequeued := q.Dequeue()
	if dequeued == nil {
		t.Fatal("dequeue should return a job")
	}
	if dequeued.Tool != "nmap" {
		t.Error("dequeued job should be nmap")
	}
	if dequeued.Status != JobRunning {
		t.Error("dequeued job should be running")
	}
}

func TestQueuePriorityOrder(t *testing.T) {
	q := NewJobQueue(10)
	q.Enqueue(NewJob(uuid.New(), "low", "t", "r", JobPriorityLow))
	q.Enqueue(NewJob(uuid.New(), "critical", "t", "r", JobPriorityCritical))
	q.Enqueue(NewJob(uuid.New(), "normal", "t", "r", JobPriorityNormal))

	first := q.Dequeue()
	if first.Tool != "critical" {
		t.Errorf("first dequeue should be critical, got %s", first.Tool)
	}
}

func TestQueueBoundedBackpressure(t *testing.T) {
	q := NewJobQueue(2)
	q.Enqueue(NewJob(uuid.New(), "a", "t", "r", JobPriorityNormal))
	q.Enqueue(NewJob(uuid.New(), "b", "t2", "r", JobPriorityNormal))

	err := q.Enqueue(NewJob(uuid.New(), "c", "t3", "r", JobPriorityNormal))
	if err == nil {
		t.Error("should reject when queue is full")
	}
}

func TestQueueDeduplication(t *testing.T) {
	q := NewJobQueue(10)
	q.Enqueue(NewJob(uuid.New(), "nmap", "10.10.11.123", "r", JobPriorityNormal))

	err := q.Enqueue(NewJob(uuid.New(), "nmap", "10.10.11.123", "r2", JobPriorityNormal))
	if err == nil {
		t.Error("should reject duplicate tool+target")
	}
}

func TestQueueRunningForTool(t *testing.T) {
	q := NewJobQueue(10)
	job := NewJob(uuid.New(), "nmap", "10.10.11.123", "r", JobPriorityNormal)
	q.Enqueue(job)
	q.Dequeue()

	if q.RunningForTool("nmap") != 1 {
		t.Error("should have 1 running nmap")
	}
	if q.RunningForTool("httpx") != 0 {
		t.Error("should have 0 running httpx")
	}
}

func TestJobStatusTerminal(t *testing.T) {
	if !JobCompleted.IsTerminal() {
		t.Error("completed should be terminal")
	}
	if !JobFailed.IsTerminal() {
		t.Error("failed should be terminal")
	}
	if !JobCancelled.IsTerminal() {
		t.Error("cancelled should be terminal")
	}
	if JobQueued.IsTerminal() {
		t.Error("queued should not be terminal")
	}
	if JobRunning.IsTerminal() {
		t.Error("running should not be terminal")
	}
}

// --- Target Scope Tests ---

func TestTargetInScope(t *testing.T) {
	target := domain.Target{
		Primary: "10.10.11.123",
		Scope: []domain.ScopeEntry{
			{Value: "10.10.11.123", Type: domain.ScopeIP},
		},
	}

	if !target.InScope("10.10.11.123") {
		t.Error("target IP should be in scope")
	}
	if target.InScope("10.10.11.124") {
		t.Error("other IP should not be in scope")
	}
}

func TestTargetScopeCIDR(t *testing.T) {
	target := domain.Target{
		Primary: "10.10.11.0/24",
		Scope: []domain.ScopeEntry{
			{Value: "10.10.11.0/24", Type: domain.ScopeCIDR},
		},
	}

	if !target.InScope("10.10.11.123") {
		t.Error("IP in CIDR should be in scope")
	}
	if target.InScope("10.10.12.1") {
		t.Error("IP outside CIDR should not be in scope")
	}
}

func TestTargetScopeWildcard(t *testing.T) {
	target := domain.Target{
		Primary: "example.com",
		Scope: []domain.ScopeEntry{
			{Value: "*.example.com", Type: domain.ScopeWildcard},
		},
	}

	if !target.InScope("sub.example.com") {
		t.Error("subdomain should be in scope")
	}
	if !target.InScope("example.com") {
		t.Error("bare domain should be in scope")
	}
	if target.InScope("other.com") {
		t.Error("other domain should not be in scope")
	}
}

func TestTargetScopeExclusion(t *testing.T) {
	target := domain.Target{
		Primary: "10.10.11.123",
		Scope: []domain.ScopeEntry{
			{Value: "10.10.11.0/24", Type: domain.ScopeCIDR},
		},
		Exclusions: []string{"10.10.11.1"},
	}

	if !target.InScope("10.10.11.123") {
		t.Error("non-excluded IP should be in scope")
	}
	if target.InScope("10.10.11.1") {
		t.Error("excluded IP should NOT be in scope")
	}
}

func TestTargetScopeFailClosed(t *testing.T) {
	target := domain.Target{
		Primary: "10.10.11.123",
		Scope:   []domain.ScopeEntry{},
	}

	if target.InScope("10.10.11.123") {
		t.Error("empty scope should fail-closed")
	}
}

func TestTargetValidation(t *testing.T) {
	valid := domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvHTB,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}
	if err := domain.ValidateTarget(valid); err != nil {
		t.Errorf("valid target should pass: %v", err)
	}

	noPrimary := valid
	noPrimary.Primary = ""
	if err := domain.ValidateTarget(noPrimary); err == nil {
		t.Error("should reject empty primary")
	}

	noScope := valid
	noScope.Scope = nil
	if err := domain.ValidateTarget(noScope); err == nil {
		t.Error("should reject empty scope")
	}

	badIP := valid
	badIP.Primary = "not-an-ip"
	if err := domain.ValidateTarget(badIP); err == nil {
		t.Error("should reject invalid IP")
	}
}

func TestDetectTargetType(t *testing.T) {
	tests := []struct {
		input    string
		expected domain.TargetType
	}{
		{"10.10.11.123", domain.TargetIP},
		{"192.168.1.0/24", domain.TargetCIDR},
		{"http://example.com", domain.TargetURL},
		{"https://example.com", domain.TargetURL},
		{"example.com", domain.TargetDomain},
	}

	for _, tt := range tests {
		result := domain.DetectTargetType(tt.input)
		if result != tt.expected {
			t.Errorf("DetectTargetType(%q) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

// --- Scheduler Integration ---

func TestSchedulerInitialReconHTB(t *testing.T) {
	ctx := context.Background()
	target := &domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvHTB,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	b := newTestBus(t)
	defer b.Drain()

	sched := newTestScheduler(t, b, target)
	sched.Start(ctx)
	defer sched.Stop()

	if err := sched.ScheduleInitialRecon(); err != nil {
		t.Fatalf("initial recon should succeed: %v", err)
	}

	stats := sched.Stats()
	if stats.Queued != 1 {
		t.Errorf("should have 1 queued job, got %d", stats.Queued)
	}
}

func TestSchedulerNoAutoReconAuthorized(t *testing.T) {
	ctx := context.Background()
	target := &domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvAuthorized,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	b := newTestBus(t)
	defer b.Drain()

	sched := newTestScheduler(t, b, target)
	sched.Start(ctx)
	defer sched.Stop()

	sched.ScheduleInitialRecon()

	stats := sched.Stats()
	if stats.Queued != 0 {
		t.Errorf("authorized target should NOT auto-queue, got %d queued", stats.Queued)
	}
}

func TestSchedulerScopeEnforcement(t *testing.T) {
	ctx := context.Background()
	target := &domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvHTB,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	b := newTestBus(t)
	defer b.Drain()

	sched := newTestScheduler(t, b, target)
	sched.Start(ctx)
	defer sched.Stop()

	sched.scheduleIfAllowed("nmap", "10.10.11.999", "test", JobPriorityNormal)

	if sched.Queue().Queued() != 0 {
		t.Error("out-of-scope target should be rejected")
	}
}

func TestSchedulerCooldown(t *testing.T) {
	ctx := context.Background()
	target := &domain.Target{
		Primary:     "10.10.11.123",
		TargetType:  domain.TargetIP,
		Environment: domain.EnvHTB,
		Scope:       []domain.ScopeEntry{{Value: "10.10.11.123", Type: domain.ScopeIP}},
	}

	b := newTestBus(t)
	defer b.Drain()

	sched := newTestScheduler(t, b, target)
	sched.Start(ctx)
	defer sched.Stop()

	sched.scheduleIfAllowed("httpx", "10.10.11.123", "first", JobPriorityNormal)
	if sched.Queue().Queued() != 1 {
		t.Fatal("first schedule should succeed")
	}

	sched.Queue().Dequeue()

	sched.scheduleIfAllowed("httpx", "10.10.11.123", "second", JobPriorityNormal)
	if sched.Queue().Queued() != 0 {
		t.Error("cooldown should prevent re-scheduling")
	}
}

// --- Test Helpers ---

func newTestBus(t *testing.T) *bus.Bus {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	b := bus.New(bus.Options{QueueSize: 64, Logger: logger})
	b.Start()
	return b
}

func newTestScheduler(t *testing.T, b *bus.Bus, target *domain.Target) *Scheduler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	registry := NewToolRegistry()
	policy := DefaultPolicy(target.Environment)

	return New(b, registry, Options{
		Policy:          policy,
		Target:          target,
		InvestigationID: uuid.New(),
	}, logger)
}
