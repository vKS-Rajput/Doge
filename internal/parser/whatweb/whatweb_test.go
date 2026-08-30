package whatweb

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

const realWhatWebOutput = `https://revastra.online [200 OK] Country[UNITED STATES][US], HTML5, HTTPServer[Vercel], Script[module], Title[Re-Vastra], Strict-Transport-Security[max-age=31536000]`

const multiLineOutput = `https://revastra.online [200 OK] Country[UNITED STATES][US], HTML5, HTTPServer[Vercel], Title[Re-Vastra]
https://api.revastra.online [200 OK] HTTPServer[nginx/1.18.0], X-Powered-By[Express]`

func TestCanParse(t *testing.T) {
	p := New()

	tests := []struct {
		name     string
		artifact domain.Artifact
		header   []byte
		want     bool
	}{
		{"whatweb filename", domain.Artifact{FileName: "whatweb_3_234603.txt"}, nil, true},
		{"whatweb content", domain.Artifact{FileName: "output.txt"}, []byte("https://example.com [200 OK] "), true},
		{"not json", domain.Artifact{FileName: "data.json"}, nil, false},
		{"random file", domain.Artifact{FileName: "notes.txt"}, []byte("hello world"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.CanParse(tt.artifact, tt.header)
			if got != tt.want {
				t.Errorf("CanParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParse_RealOutput(t *testing.T) {
	p := New()
	artifact := domain.Artifact{FileName: "whatweb_3_234603.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(realWhatWebOutput))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(obs) == 0 {
		t.Fatal("expected observations, got 0")
	}

	// Should have http_probe + multiple technology_detection.
	var httpProbes, techDetects int
	for _, o := range obs {
		switch o.Type {
		case domain.ObservationHTTPProbe:
			httpProbes++
			if o.Data["url"] != "https://revastra.online" {
				t.Errorf("url = %v", o.Data["url"])
			}
			if o.Data["status_code"] != 200 {
				t.Errorf("status_code = %v, want 200", o.Data["status_code"])
			}
			if o.Data["webserver"] != "Vercel" {
				t.Errorf("webserver = %v, want Vercel", o.Data["webserver"])
			}
			if o.Data["title"] != "Re-Vastra" {
				t.Errorf("title = %v, want Re-Vastra", o.Data["title"])
			}
		case domain.ObservationTechnologyDetect:
			techDetects++
		}
	}

	if httpProbes != 1 {
		t.Errorf("expected 1 http_probe, got %d", httpProbes)
	}
	if techDetects < 3 {
		t.Errorf("expected ≥3 tech detections, got %d", techDetects)
	}
}

func TestParse_MultiLine(t *testing.T) {
	p := New()
	artifact := domain.Artifact{FileName: "whatweb_scan.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(multiLineOutput))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Should have observations from both lines.
	httpProbes := 0
	for _, o := range obs {
		if o.Type == domain.ObservationHTTPProbe {
			httpProbes++
		}
	}

	if httpProbes != 2 {
		t.Errorf("expected 2 http_probes (one per URL), got %d", httpProbes)
	}
}

func TestParse_Empty(t *testing.T) {
	p := New()
	artifact := domain.Artifact{FileName: "whatweb_empty.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("expected 0, got %d", len(obs))
	}
}

func TestParsePlugins(t *testing.T) {
	plugins := parsePlugins("HTML5, HTTPServer[Vercel], Title[Re-Vastra], Script[module]")

	if plugins["HTTPServer"] != "Vercel" {
		t.Errorf("HTTPServer = %q, want Vercel", plugins["HTTPServer"])
	}
	if plugins["Title"] != "Re-Vastra" {
		t.Errorf("Title = %q, want Re-Vastra", plugins["Title"])
	}
	if _, ok := plugins["HTML5"]; !ok {
		t.Error("HTML5 not found in plugins")
	}
}
