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
	"time"
)

const historyLimit = 48

// Counter represents received and transmitted bytes.
type Counter struct {
	RX uint64 `json:"rx"`
	TX uint64 `json:"tx"`
}

// Sample is one vnStat five-minute counter sample.
type Sample struct {
	At string `json:"at"`
	Counter
}

// Interface is the bandwidth summary for one network interface.
type Interface struct {
	Name       string   `json:"name"`
	Alias      string   `json:"alias,omitempty"`
	Total      Counter  `json:"total"`
	FiveMinute Counter  `json:"fiveMinute"`
	History    []Sample `json:"history"`
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

// Report returns total, current, and recent five-minute counters for each interface.
func (p *Provider) Report(ctx context.Context) (Report, error) {
	args := []string{"--json"}
	if p.interfaceName != "" {
		args = append(args, "--iface", p.interfaceName)
	}
	out, err := exec.CommandContext(ctx, p.binary, args...).Output()
	if err != nil {
		return Report{}, fmt.Errorf("vnStat query: %w", err)
	}
	return parseReport(out)
}

func parseReport(data []byte) (Report, error) {
	var raw vnstatJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return Report{}, fmt.Errorf("decode vnStat JSON: %w", err)
	}
	report := Report{Interfaces: make([]Interface, 0, len(raw.Interfaces))}
	for _, iface := range raw.Interfaces {
		entry := Interface{
			Name:    iface.Name,
			Alias:   iface.Alias,
			Total:   iface.Traffic.Total,
			History: fiveMinuteHistory(iface.Traffic.FiveMinute),
		}
		if len(entry.History) > 0 {
			latest := entry.History[len(entry.History)-1]
			entry.FiveMinute = latest.Counter
		}
		report.Interfaces = append(report.Interfaces, entry)
	}
	sort.Slice(report.Interfaces, func(i, j int) bool { return report.Interfaces[i].Name < report.Interfaces[j].Name })
	return report, nil
}

func fiveMinuteHistory(samples []vnstatSample) []Sample {
	history := make([]Sample, 0, len(samples))
	for _, sample := range samples {
		at, ok := sample.timestamp()
		if !ok {
			continue
		}
		history = append(history, Sample{
			At:      at.Format(time.RFC3339),
			Counter: Counter{RX: sample.RX, TX: sample.TX},
		})
	}
	sort.Slice(history, func(i, j int) bool { return history[i].At < history[j].At })
	if len(history) > historyLimit {
		history = history[len(history)-historyLimit:]
	}
	return history
}

type vnstatJSON struct {
	Interfaces []vnstatInterface `json:"interfaces"`
}

type vnstatInterface struct {
	Name    string `json:"name"`
	Alias   string `json:"alias"`
	Traffic struct {
		Total      Counter        `json:"total"`
		FiveMinute []vnstatSample `json:"fiveminute"`
	} `json:"traffic"`
}

type vnstatSample struct {
	Date struct {
		Year  int `json:"year"`
		Month int `json:"month"`
		Day   int `json:"day"`
	} `json:"date"`
	Time struct {
		Hour   int `json:"hour"`
		Minute int `json:"minute"`
	} `json:"time"`
	RX uint64 `json:"rx"`
	TX uint64 `json:"tx"`
}

func (s vnstatSample) timestamp() (time.Time, bool) {
	if s.Date.Year <= 0 || s.Date.Month < 1 || s.Date.Month > 12 || s.Date.Day < 1 || s.Date.Day > 31 || s.Time.Hour < 0 || s.Time.Hour > 23 || s.Time.Minute < 0 || s.Time.Minute > 59 {
		return time.Time{}, false
	}
	at := time.Date(s.Date.Year, time.Month(s.Date.Month), s.Date.Day, s.Time.Hour, s.Time.Minute, 0, 0, time.Local)
	if at.Year() != s.Date.Year || int(at.Month()) != s.Date.Month || at.Day() != s.Date.Day {
		return time.Time{}, false
	}
	return at, true
}
