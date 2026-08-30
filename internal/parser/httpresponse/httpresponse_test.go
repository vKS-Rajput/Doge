package httpresponse

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

const curlHeadersOutput = `HTTP/2 200
server: Vercel
content-type: text/html; charset=utf-8
strict-transport-security: max-age=31536000
x-frame-options: DENY
x-content-type-options: nosniff
`

const curlFullOutput = `HTTP/2 200
server: nginx
content-type: text/html; charset=utf-8
set-cookie: session=abc123; Path=/; HttpOnly

<!doctype html>
<html>
<head><title>Re-Vastra</title></head>
<body>
<script src="/assets/index-P2L-8joX.js"></script>
</body>
</html>
`

const curlVerboseOutput = `* Trying 1.2.3.4:443...
* Connected to revastra.online (1.2.3.4) port 443
> GET / HTTP/2
> Host: revastra.online
> Accept: */*
>
< HTTP/2 200
< server: Vercel
< content-type: text/html
<
`

func TestCanParse(t *testing.T) {
	p := New()

	tests := []struct {
		name     string
		artifact domain.Artifact
		header   []byte
		want     bool
	}{
		{"curl txt", domain.Artifact{FileName: "curl_1_234403.txt"}, nil, true},
		{"wget log", domain.Artifact{FileName: "wget_output.log"}, nil, true},
		{"http status line", domain.Artifact{FileName: "output.txt"}, []byte("HTTP/2 200\r\n"), true},
		{"curl verbose", domain.Artifact{FileName: "output.txt"}, []byte("< HTTP/2 200"), true},
		{"not json", domain.Artifact{FileName: "data.json"}, []byte("HTTP/2 200"), false},
		{"not xml", domain.Artifact{FileName: "nmap.xml"}, nil, false},
		{"random txt", domain.Artifact{FileName: "notes.txt"}, []byte("hello world"), false},
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

func TestParse_CurlHeaders(t *testing.T) {
	p := New()
	artifact := domain.Artifact{FileName: "curl_1_234403.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(curlHeadersOutput))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(obs) == 0 {
		t.Fatal("expected observations, got 0")
	}

	// Should have at least 1 http_probe + technology_detection for Vercel.
	var httpProbes, techDetects int
	for _, o := range obs {
		switch o.Type {
		case domain.ObservationHTTPProbe:
			httpProbes++
			if o.Data["status_code"] != 200 {
				t.Errorf("status_code = %v, want 200", o.Data["status_code"])
			}
			if o.Data["webserver"] != "Vercel" {
				t.Errorf("webserver = %v, want Vercel", o.Data["webserver"])
			}
			if o.Data["content_type"] != "text/html; charset=utf-8" {
				t.Errorf("content_type = %v", o.Data["content_type"])
			}
			// Check security headers.
			if sh, ok := o.Data["security_headers"].(map[string]string); ok {
				if _, ok := sh["strict-transport-security"]; !ok {
					t.Error("missing HSTS header")
				}
				if _, ok := sh["x-frame-options"]; !ok {
					t.Error("missing X-Frame-Options header")
				}
			} else {
				t.Error("security_headers not extracted")
			}
		case domain.ObservationTechnologyDetect:
			techDetects++
		}
	}

	if httpProbes == 0 {
		t.Error("expected at least 1 http_probe observation")
	}
	if techDetects == 0 {
		t.Error("expected at least 1 technology_detection observation")
	}
}

func TestParse_CurlFull(t *testing.T) {
	p := New()
	artifact := domain.Artifact{FileName: "curl_2_234500.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(curlFullOutput))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Should extract title, cookie, script src.
	var foundTitle, foundCookie, foundJS bool
	for _, o := range obs {
		if o.Type == domain.ObservationHTTPProbe {
			if title, ok := o.Data["title"].(string); ok && title == "Re-Vastra" {
				foundTitle = true
			}
			if cookie, ok := o.Data["cookies"].(string); ok && strings.Contains(cookie, "session") {
				foundCookie = true
			}
		}
		if o.Type == domain.ObservationJavaScriptAnalysis {
			if url, ok := o.Data["url"].(string); ok && strings.Contains(url, "index-P2L") {
				foundJS = true
			}
		}
	}

	if !foundTitle {
		t.Error("title not extracted from HTML body")
	}
	if !foundCookie {
		t.Error("cookie not extracted from Set-Cookie header")
	}
	if !foundJS {
		t.Error("JavaScript source not extracted from HTML")
	}
}

func TestParse_CurlVerbose(t *testing.T) {
	p := New()
	artifact := domain.Artifact{FileName: "curl_verbose.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(curlVerboseOutput))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(obs) == 0 {
		t.Fatal("expected observations from curl -v output")
	}

	// Should parse the response (< HTTP/2 200).
	for _, o := range obs {
		if o.Type == domain.ObservationHTTPProbe {
			if o.Data["status_code"] != 200 {
				t.Errorf("status_code = %v, want 200", o.Data["status_code"])
			}
			return
		}
	}
	t.Error("no http_probe observation from curl verbose output")
}

func TestParse_Empty(t *testing.T) {
	p := New()
	artifact := domain.Artifact{FileName: "curl_empty.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("expected 0 observations, got %d", len(obs))
	}
}
