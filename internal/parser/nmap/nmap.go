// Package nmap implements a parser for nmap XML output.
//
// nmap is the standard network scanner. Its XML output (-oX) contains
// rich host/port/service data including version detection.
//
// This parser produces port_scan observations — one per open/filtered port.
//
// Input format: XML with <nmaprun> root element.
package nmap

import (
	"context"
	"encoding/xml"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Parser converts nmap XML output into port scan observations.
type Parser struct{}

// New creates a new nmap parser.
func New() *Parser { return &Parser{} }

// Name returns the parser identifier.
func (p *Parser) Name() string { return "nmap" }

// Version returns the parser version.
func (p *Parser) Version() string { return "1.0.0" }

// CanParse returns true if the artifact looks like nmap XML output.
func (p *Parser) CanParse(artifact domain.Artifact, header []byte) bool {
	name := strings.ToLower(artifact.FileName)
	ext := strings.ToLower(filepath.Ext(name))

	// Filename-based detection.
	if strings.Contains(name, "nmap") && ext == ".xml" {
		return true
	}

	// Content-based detection: look for nmaprun XML element.
	if len(header) > 0 {
		s := string(header)
		if strings.Contains(s, "<nmaprun") || strings.Contains(s, "<!DOCTYPE nmaprun") {
			return true
		}
	}

	return false
}

// --- XML structures ---

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Args    string     `xml:"args,attr"`
	Start   string     `xml:"start,attr"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus     `xml:"status"`
	Address   nmapAddress    `xml:"address"`
	Hostnames nmapHostnames  `xml:"hostnames"`
	Ports     nmapPorts      `xml:"ports"`
}

type nmapStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel    string `xml:"tunnel,attr"`
	Conf      string `xml:"conf,attr"`
}

// Parse reads nmap XML and produces port scan observations.
func (p *Parser) Parse(ctx context.Context, artifact domain.Artifact, content io.Reader) ([]domain.RawObservation, error) {
	data, err := io.ReadAll(content)
	if err != nil {
		return nil, err
	}

	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, nil // Malformed XML — return empty, not error.
	}

	var observations []domain.RawObservation

	scanTime := time.Now().UTC()
	if run.Start != "" {
		if ts, err := strconv.ParseInt(run.Start, 10, 64); err == nil {
			scanTime = time.Unix(ts, 0).UTC()
		}
	}

	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}

		hostAddr := host.Address.Addr
		var hostname string
		if len(host.Hostnames.Hostnames) > 0 {
			hostname = host.Hostnames.Hostnames[0].Name
		}

		for _, port := range host.Ports.Ports {
			// Only report open and filtered ports.
			if port.State.State != "open" && port.State.State != "filtered" {
				continue
			}

			obs := p.portToObservation(hostAddr, hostname, port, scanTime)
			observations = append(observations, obs)
		}
	}

	return observations, nil
}

func (p *Parser) portToObservation(host, hostname string, port nmapPort, scanTime time.Time) domain.RawObservation {
	portNum, _ := strconv.Atoi(port.PortID)

	data := map[string]any{
		"host":     host,
		"port":     portNum,
		"protocol": port.Protocol,
		"state":    port.State.State,
	}

	if hostname != "" {
		data["hostname"] = hostname
	}
	if port.Service.Name != "" {
		data["service"] = port.Service.Name
	}
	if port.Service.Product != "" {
		data["product"] = port.Service.Product
	}
	if port.Service.Version != "" {
		data["version"] = port.Service.Version
	}
	if port.Service.ExtraInfo != "" {
		data["extra_info"] = port.Service.ExtraInfo
	}
	if port.Service.Tunnel != "" {
		data["tunnel"] = port.Service.Tunnel
	}

	return domain.RawObservation{
		Type:       domain.ObservationPortScan,
		SourceTool: "nmap",
		Data:       data,
		RawValue:   strings.Join([]string{host, port.PortID, port.Protocol, port.State.State, port.Service.Name}, "|"),
		ObservedAt: scanTime,
	}
}
