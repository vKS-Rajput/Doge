package httpx

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/parser/parsertest"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// projectRoot returns the absolute path to the project root directory.
func projectRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	// Go up from internal/parser/httpx/ to project root.
	return filepath.Join(filepath.Dir(filename), "..", "..", "..")
}

func testArtifact(fileName string) domain.Artifact {
	return domain.Artifact{
		ID:        uuid.New(),
		FileName:  fileName,
		MIMEType:  "application/json",
		ProjectID: uuid.New(),
	}
}

func TestCanParse_Filename(t *testing.T) {
	p := New()

	tests := []struct {
		name     string
		fileName string
		want     bool
	}{
		{"httpx json", "httpx_output.json", true},
		{"httpx jsonl", "httpx_results.jsonl", true},
		{"httpx txt", "httpx.txt", true},
		{"unrelated json", "config.json", false},
		{"nuclei", "nuclei_output.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifact := testArtifact(tt.fileName)
			got := p.CanParse(artifact, nil)
			if got != tt.want {
				t.Errorf("CanParse(%q) = %v, want %v", tt.fileName, got, tt.want)
			}
		})
	}
}

func TestCanParse_ContentDetection(t *testing.T) {
	p := New()
	artifact := testArtifact("unknown_output.json")

	// httpx-like content should be detected.
	header := []byte(`{"url":"https://example.com","status_code":200,"host":"example.com"}`)
	if !p.CanParse(artifact, header) {
		t.Error("expected CanParse to detect httpx content from header")
	}

	// Non-httpx content.
	header = []byte(`{"name":"John","age":30}`)
	if p.CanParse(artifact, header) {
		t.Error("expected CanParse to reject non-httpx content")
	}
}

func TestParse_GoldenTest(t *testing.T) {
	p := New()
	artifact := testArtifact("httpx_output.jsonl")

	// Read golden test input.
	goldenPath := filepath.Join(projectRoot(t), "testdata", "httpx", "input.jsonl")
	f, err := os.Open(goldenPath)
	if err != nil {
		t.Fatalf("opening golden test input: %v", err)
	}
	defer f.Close()

	observations, err := p.Parse(context.Background(), artifact, f)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// --- Contract tests (every parser must pass) ---
	parsertest.AssertValidObservations(t, observations)
	parsertest.AssertAllSameTool(t, observations, "httpx")
	parsertest.AssertAllSameType(t, observations, domain.ObservationHTTPProbe)
	parsertest.AssertDataField(t, observations, "url")
	parsertest.AssertDataField(t, observations, "status_code")
	parsertest.AssertDataField(t, observations, "host")

	// --- Golden assertions (specific to this input file) ---

	// Should produce 4 observations (5th line is failed=true, skipped).
	parsertest.AssertObservationCount(t, observations, 4)

	// First observation should be admin.example.com.
	if url, ok := observations[0].Data["url"].(string); !ok || url != "https://admin.example.com" {
		t.Errorf("obs[0] url = %v, want 'https://admin.example.com'", observations[0].Data["url"])
	}

	// First observation should have technologies.
	if tech, ok := observations[0].Data["technologies"]; !ok {
		t.Error("obs[0] should have technologies")
	} else if techSlice, ok := tech.([]string); ok {
		if len(techSlice) != 3 {
			t.Errorf("obs[0] technologies count = %d, want 3", len(techSlice))
		}
	}

	// Third observation should have final_url (redirect).
	if finalURL, ok := observations[2].Data["final_url"].(string); !ok || finalURL != "https://staging.example.com/login" {
		t.Errorf("obs[2] final_url = %v, want redirect URL", observations[2].Data["final_url"])
	}

	// Timestamps should be parsed from the input.
	expectedTime, _ := time.Parse(time.RFC3339, "2024-01-15T10:30:00Z")
	if !observations[0].ObservedAt.Equal(expectedTime) {
		t.Errorf("obs[0] ObservedAt = %v, want %v", observations[0].ObservedAt, expectedTime)
	}
}

func TestParse_MalformedLines(t *testing.T) {
	p := New()
	artifact := testArtifact("httpx_broken.jsonl")

	input := `{"url":"https://good.example.com","status_code":200,"host":"good.example.com"}
this is not json
{"url":"","status_code":0}
{"url":"https://also-good.example.com","status_code":301,"host":"also-good.example.com"}
`

	observations, err := p.Parse(context.Background(), artifact, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Should skip malformed and empty-URL lines, keep the 2 good ones.
	parsertest.AssertObservationCount(t, observations, 2)
}

func TestParse_EmptyInput(t *testing.T) {
	p := New()
	artifact := testArtifact("empty.jsonl")

	observations, err := p.Parse(context.Background(), artifact, strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(observations) != 0 {
		t.Errorf("expected 0 observations for empty input, got %d", len(observations))
	}
}

func TestName(t *testing.T) {
	p := New()
	if p.Name() != "httpx" {
		t.Errorf("Name() = %q, want 'httpx'", p.Name())
	}
}

func TestVersion(t *testing.T) {
	p := New()
	if p.Version() == "" {
		t.Error("Version() should not be empty")
	}
}
