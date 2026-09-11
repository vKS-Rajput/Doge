package whitebox

import (
	"testing"
)

func TestASTParserAndTaintTracer(t *testing.T) {
	parser := NewASTParser()
	tracer := NewTaintTracer()

	goSource := `package main
import (
	"fmt"
	"net/http"
	"os/exec"
)

func handleUsers(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", search)
	_ = query
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("ping", "-c", "1", host)
	_ = cmd
}

func main() {
	http.HandleFunc("/api/v1/users", handleUsers)
	http.HandleFunc("/api/v1/ping", handlePing)
}
`

	routes, sources, err := parser.ParseContent(goSource, "main.go", LangGo)
	if err != nil {
		t.Fatalf("failed to parse content: %v", err)
	}

	if len(routes) < 2 {
		t.Errorf("expected at least 2 routes, got %d", len(routes))
	}

	if len(sources) < 2 {
		t.Errorf("expected at least 2 input sources, got %d", len(sources))
	}

	t.Logf("Discovered %d Routes and %d Sources in Go source:", len(routes), len(sources))
	for _, r := range routes {
		t.Logf("  Route: [%s] %s (line %d)", r.Method, r.Path, r.LineNumber)
	}
	for _, s := range sources {
		t.Logf("  Source: %s (%s, line %d)", s.Parameter, s.SourceType, s.LineNumber)
	}

	// Trace taint
	taintPaths := tracer.TraceTaint(goSource, "main.go", sources)
	if len(taintPaths) < 2 {
		t.Fatalf("expected at least 2 taint paths, got %d", len(taintPaths))
	}

	foundSQL := false
	foundCmd := false
	for _, tp := range taintPaths {
		t.Logf("✓ Taint Path: param=%s -> sink=%s (line %d: %q)",
			tp.SourceParam, tp.Sink.Type, tp.Sink.LineNumber, tp.Sink.Expression)
		if tp.Sink.Type == SinkSQL {
			foundSQL = true
		}
		if tp.Sink.Type == SinkCommand {
			foundCmd = true
		}
	}

	if !foundSQL {
		t.Errorf("expected SQL injection taint path detected")
	}
	if !foundCmd {
		t.Errorf("expected Command injection taint path detected")
	}
}

func TestPythonAndJSTaintDetection(t *testing.T) {
	parser := NewASTParser()
	tracer := NewTaintTracer()

	pySource := `from flask import Flask, request
import requests
app = Flask(__name__)

@app.route("/api/v1/fetch")
def fetch_proxy():
    url = request.args.get("url")
    resp = requests.get(url)
    return resp.text
`

	_, sources, err := parser.ParseContent(pySource, "app.py", LangPython)
	if err != nil {
		t.Fatalf("failed to parse python content: %v", err)
	}

	paths := tracer.TraceTaint(pySource, "app.py", sources)
	if len(paths) == 0 {
		t.Fatalf("expected SSRF taint path in Python code")
	}

	if paths[0].Sink.Type != SinkSSRF {
		t.Errorf("expected SinkSSRF, got %s", paths[0].Sink.Type)
	}
	t.Logf("✓ Detected Python SSRF Taint Path: %s (payload: %s)", paths[0].Description, paths[0].TriggerPayload)
}
