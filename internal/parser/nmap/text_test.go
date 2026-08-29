package nmap

import (
	"context"
	"strings"
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Real nmap text output from the user's localhost test.
const realNmapOutput = `Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-29 23:13 +0530
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0000030s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx
|_http-title: Apache2 Debian Default Page: It works

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.36 seconds
`

const multiPortOutput = `Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-29 23:00 +0530
Nmap scan report for target.example.com (10.10.11.123)
Host is up (0.032s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp   open  http       Apache httpd 2.4.52
443/tcp  open  ssl/http   nginx 1.18.0

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 12.05 seconds
`

const multiHostOutput = `Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-29 23:00 +0530
Nmap scan report for 10.10.11.1
Host is up.
PORT   STATE SERVICE
22/tcp open  ssh
Nmap scan report for 10.10.11.2
Host is up.
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
Nmap done: 2 IP addresses (2 hosts up) scanned in 3.21 seconds
`

const noPortsOutput = `Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-29 23:00 +0530
Nmap scan report for 10.10.11.123
Host is up (0.032s latency).
All 1000 scanned ports on 10.10.11.123 are closed

Nmap done: 1 IP address (1 host up) scanned in 2.13 seconds
`

func TestTextParser_CanParse(t *testing.T) {
	p := NewTextParser()

	tests := []struct {
		name     string
		artifact domain.Artifact
		header   []byte
		want     bool
	}{
		{
			name:     "nmap txt filename",
			artifact: domain.Artifact{FileName: "nmap_3_231347.txt"},
			want:     true,
		},
		{
			name:     "nmap xml should not match",
			artifact: domain.Artifact{FileName: "scan.xml"},
			want:     false,
		},
		{
			name:     "content detection Starting Nmap",
			artifact: domain.Artifact{FileName: "output.log"},
			header:   []byte("Starting Nmap 7.98"),
			want:     true,
		},
		{
			name:     "content detection scan report",
			artifact: domain.Artifact{FileName: "capture.log"},
			header:   []byte("Nmap scan report for localhost"),
			want:     true,
		},
		{
			name:     "unrelated file",
			artifact: domain.Artifact{FileName: "httpx_results.json"},
			header:   []byte(`{"url":"http://example.com"}`),
			want:     false,
		},
		{
			name:     "xml nmap should not match text parser",
			artifact: domain.Artifact{FileName: "nmap.xml"},
			header:   []byte(`<?xml version="1.0"?><nmaprun`),
			want:     false, // .xml extension, text parser should not claim it
		},
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

func TestTextParser_Parse_RealOutput(t *testing.T) {
	p := NewTextParser()
	artifact := domain.Artifact{FileName: "nmap_3_231347.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(realNmapOutput))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}

	o := obs[0]

	// Verify observation type.
	if o.Type != domain.ObservationPortScan {
		t.Errorf("type = %v, want port_scan", o.Type)
	}

	// Verify semantic data.
	if o.Data["host"] != "127.0.0.1" {
		t.Errorf("host = %v, want 127.0.0.1", o.Data["host"])
	}
	if o.Data["hostname"] != "localhost" {
		t.Errorf("hostname = %v, want localhost", o.Data["hostname"])
	}
	if o.Data["port"] != 80 {
		t.Errorf("port = %v, want 80", o.Data["port"])
	}
	if o.Data["protocol"] != "tcp" {
		t.Errorf("protocol = %v, want tcp", o.Data["protocol"])
	}
	if o.Data["state"] != "open" {
		t.Errorf("state = %v, want open", o.Data["state"])
	}
	if o.Data["service"] != "http" {
		t.Errorf("service = %v, want http", o.Data["service"])
	}
	if o.Data["product"] != "nginx" {
		t.Errorf("product = %v, want nginx", o.Data["product"])
	}
	if o.SourceTool != "nmap" {
		t.Errorf("source_tool = %v, want nmap", o.SourceTool)
	}
}

func TestTextParser_Parse_MultiPort(t *testing.T) {
	p := NewTextParser()
	artifact := domain.Artifact{FileName: "nmap_1_230000.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(multiPortOutput))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(obs) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(obs))
	}

	// Verify each port.
	expected := []struct {
		port    int
		service string
		product string
		version string
	}{
		{22, "ssh", "OpenSSH", "8.9p1"},
		{80, "http", "Apache", "httpd"},
		{443, "ssl/http", "nginx", "1.18.0"},
	}

	for i, e := range expected {
		o := obs[i]
		if o.Data["host"] != "10.10.11.123" {
			t.Errorf("obs[%d] host = %v, want 10.10.11.123", i, o.Data["host"])
		}
		if o.Data["hostname"] != "target.example.com" {
			t.Errorf("obs[%d] hostname = %v, want target.example.com", i, o.Data["hostname"])
		}
		if o.Data["port"] != e.port {
			t.Errorf("obs[%d] port = %v, want %d", i, o.Data["port"], e.port)
		}
		if o.Data["service"] != e.service {
			t.Errorf("obs[%d] service = %v, want %s", i, o.Data["service"], e.service)
		}
		if o.Data["product"] != e.product {
			t.Errorf("obs[%d] product = %v, want %s", i, o.Data["product"], e.product)
		}
		if v, ok := o.Data["version"]; ok && v != e.version {
			t.Errorf("obs[%d] version = %v, want %s", i, v, e.version)
		}
	}
}

func TestTextParser_Parse_MultiHost(t *testing.T) {
	p := NewTextParser()
	artifact := domain.Artifact{FileName: "nmap_scan.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(multiHostOutput))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(obs) != 3 {
		t.Fatalf("expected 3 observations (1 + 2), got %d", len(obs))
	}

	// First host: 10.10.11.1, port 22.
	if obs[0].Data["host"] != "10.10.11.1" {
		t.Errorf("obs[0] host = %v, want 10.10.11.1", obs[0].Data["host"])
	}
	if obs[0].Data["port"] != 22 {
		t.Errorf("obs[0] port = %v, want 22", obs[0].Data["port"])
	}

	// Second host: 10.10.11.2, ports 80 and 443.
	if obs[1].Data["host"] != "10.10.11.2" {
		t.Errorf("obs[1] host = %v, want 10.10.11.2", obs[1].Data["host"])
	}
	if obs[2].Data["host"] != "10.10.11.2" {
		t.Errorf("obs[2] host = %v, want 10.10.11.2", obs[2].Data["host"])
	}
}

func TestTextParser_Parse_NoPorts(t *testing.T) {
	p := NewTextParser()
	artifact := domain.Artifact{FileName: "nmap_empty.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(noPortsOutput))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(obs) != 0 {
		t.Errorf("expected 0 observations for no-ports scan, got %d", len(obs))
	}
}

func TestTextParser_Parse_EmptyInput(t *testing.T) {
	p := NewTextParser()
	artifact := domain.Artifact{FileName: "nmap_empty.txt"}

	obs, err := p.Parse(context.Background(), artifact, strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(obs) != 0 {
		t.Errorf("expected 0 observations, got %d", len(obs))
	}
}

func TestParseVersionString(t *testing.T) {
	tests := []struct {
		input       string
		wantProduct string
		wantVersion string
	}{
		{"nginx 1.18.0", "nginx", "1.18.0"},
		{"OpenSSH 8.9p1 Ubuntu 3ubuntu0.1", "OpenSSH", "8.9p1"},
		{"Apache httpd 2.4.52", "Apache", "httpd"},
		{"nginx", "nginx", ""},
		{"", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			product, version := parseVersionString(tt.input)
			if product != tt.wantProduct {
				t.Errorf("product = %q, want %q", product, tt.wantProduct)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}
