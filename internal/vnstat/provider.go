// Package vnstat exposes optional bandwidth statistics from vnStat's JSON API.
package vnstat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Counter represents received and transmitted bytes.
type Counter struct {
	RX uint64 `json:"rx"`
	TX uint64 `json:"tx"`
}

// Interface is the bandwidth summary for one network interface.
type Interface struct {
	Name       string  `json:"name"`
	Alias      string  `json:"alias,omitempty"`
	Total      Counter `json:"total"`
	FiveMinute Counter `json:"fiveMinute"`
}

// Report is the dashboard's stable representation of vnStat output.
type Report struct {
	Interfaces []Interface `json:"interfaces"`
}

// Provider reads bandwidth statistics through the vnStat executable.
type Provider struct {
	binary        string
	interfaceName string
}

// New returns nil when the integration is disabled or vnStat is unavailable.
func New(enabled bool, binary, interfaceName string) (*Provider, error) {
	if !enabled {
		return nil, nil
	}
	binary = strings.TrimSpace(binary)
	if binary == "" {
		binary = "vnstat"
	}
	if _, err := exec.LookPath(binary); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("find vnStat executable: %w", err)
	}
	return &Provider{binary: binary, interfaceName: strings.TrimSpace(interfaceName)}, nil
}

// Report returns total and most recent five-minute counters for each interface.
func (p *Provider) Report(ctx context.Context) (Report, error) {
	args := []string{"--json"}
	if p.interfaceName != "" {
		args = append(args, "--iface", p.interfaceName)
	}
	out, err := exec.CommandContext(ctx, p.binary, args...).Output()
	if err != nil {
		return Report{}, fmt.Errorf("vnStat query: %w", err)
	}
	var raw vnstatJSON
	if err := json.Unmarshal(out, &raw); err != nil {
		return Report{}, fmt.Errorf("decode vnStat JSON: %w", err)
	}
	report := Report{Interfaces: make([]Interface, 0, len(raw.Interfaces))}
	for _, iface := range raw.Interfaces {
		entry := Interface{Name: iface.Name, Alias: iface.Alias, Total: iface.Traffic.Total}
		if len(iface.Traffic.FiveMinute) > 0 {
			latest := iface.Traffic.FiveMinute[len(iface.Traffic.FiveMinute)-1]
			entry.FiveMinute = Counter{RX: latest.RX, TX: latest.TX}
		}
		report.Interfaces = append(report.Interfaces, entry)
	}
	sort.Slice(report.Interfaces, func(i, j int) bool { return report.Interfaces[i].Name < report.Interfaces[j].Name })
	return report, nil
}

type vnstatJSON struct {
	Interfaces []vnstatInterface `json:"interfaces"`
}

type vnstatInterface struct {
	Name    string `json:"name"`
	Alias   string `json:"alias"`
	Traffic struct {
		Total      Counter   `json:"total"`
		FiveMinute []Counter `json:"fiveminute"`
	} `json:"traffic"`
}
