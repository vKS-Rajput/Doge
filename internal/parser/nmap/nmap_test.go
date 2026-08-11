package nmap

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestName(t *testing.T) {
	p := New()
	if p.Name() != "nmap" {
		t.Errorf("expected 'nmap', got '%s'", p.Name())
	}
}

// Contract Test 1: Golden output.
func TestParseXML(t *testing.T) {
	p := New()

	f, err := os.Open("../../../testdata/nmap/scan.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	artifact := domain.Artifact{FileName: "nmap_scan.xml"}
	obs, err := p.Parse(context.Background(), artifact, f)
	if err != nil {
		t.Fatal(err)
	}

	// 2 hosts: host1 has 4 ports (3 open + 1 filtered), host2 has 2 open.
	if len(obs) != 6 {
		t.Fatalf("expected 6 observations, got %d", len(obs))
	}

	// Verify first observation: SSH on host1.
	first := obs[0]
	if first.Type != domain.ObservationPortScan {
		t.Errorf("expected port_scan, got %s", first.Type)
	}
	if first.SourceTool != "nmap" {
		t.Errorf("expected nmap, got %s", first.SourceTool)
	}
	if first.Data["host"] != "203.0.113.10" {
		t.Errorf("expected 203.0.113.10, got %v", first.Data["host"])
	}
	if first.Data["port"] != 22 {
		t.Errorf("expected port 22, got %v", first.Data["port"])
	}
	if first.Data["service"] != "ssh" {
		t.Errorf("expected ssh, got %v", first.Data["service"])
	}
	if first.Data["product"] != "OpenSSH" {
		t.Errorf("expected OpenSSH, got %v", first.Data["product"])
	}
	if first.Data["hostname"] != "admin.example.com" {
		t.Errorf("expected admin.example.com, got %v", first.Data["hostname"])
	}

	// Verify filtered port included.
	var foundFiltered bool
	for _, o := range obs {
		if o.Data["state"] == "filtered" {
			foundFiltered = true
			if o.Data["port"] != 3306 {
				t.Errorf("expected filtered port 3306, got %v", o.Data["port"])
			}
		}
	}
	if !foundFiltered {
		t.Error("expected filtered port observation")
	}
}

// Contract Test 2: CanParse detection.
func TestCanParse(t *testing.T) {
	p := New()

	tests := []struct {
		filename string
		header   string
		expected bool
	}{
		{"nmap_scan.xml", "", true},
		{"nmap_output.xml", "", true},
		{"unknown.xml", "<?xml version=\"1.0\"?><nmaprun>", true},
		{"unknown.xml", "<!DOCTYPE nmaprun>", true},
		{"httpx_output.jsonl", "", false},
		{"scan.json", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			artifact := domain.Artifact{FileName: tt.filename}
			got := p.CanParse(artifact, []byte(tt.header))
			if got != tt.expected {
				t.Errorf("CanParse(%s) = %v, want %v", tt.filename, got, tt.expected)
			}
		})
	}
}

// Contract Test 3: Malformed input.
func TestParseMalformedXML(t *testing.T) {
	p := New()
	artifact := domain.Artifact{FileName: "nmap_bad.xml"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader("<broken>xml"))
	if err != nil {
		t.Fatal("should not error on malformed XML")
	}
	if len(obs) != 0 {
		t.Errorf("expected 0 observations from malformed XML, got %d", len(obs))
	}
}

// Contract Test 4: Empty input.
func TestParseEmptyInput(t *testing.T) {
	p := New()
	artifact := domain.Artifact{FileName: "nmap_empty.xml"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(""))
	if err != nil {
		t.Fatal("should not error on empty input")
	}
	if len(obs) != 0 {
		t.Errorf("expected 0 observations from empty, got %d", len(obs))
	}
}

// Contract Test 5: Closed ports excluded.
func TestClosedPortsExcluded(t *testing.T) {
	p := New()

	xml := `<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1705312200">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="81">
        <state state="closed"/>
        <service name="unknown"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	artifact := domain.Artifact{FileName: "nmap.xml"}
	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Errorf("expected 1 observation (open only), got %d", len(obs))
	}
}
