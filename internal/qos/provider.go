// Package qos exposes read-only PF/ALTQ queue statistics.
package qos

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Queue is one ALTQ queue and its current counters.
type Queue struct {
	Name           string `json:"name"`
	Interface      string `json:"interface,omitempty"`
	Parent         string `json:"parent,omitempty"`
	Bandwidth      string `json:"bandwidth,omitempty"`
	Scheduler      string `json:"scheduler,omitempty"`
	Packets        uint64 `json:"packets"`
	Bytes          uint64 `json:"bytes"`
	DroppedPackets uint64 `json:"droppedPackets"`
	DroppedBytes   uint64 `json:"droppedBytes"`
	QueueLength    uint64 `json:"queueLength"`
	QueueLimit     uint64 `json:"queueLimit"`
}

// Report contains the active PF/ALTQ queues.
type Report struct {
	Backend string  `json:"backend"`
	Queues  []Queue `json:"queues"`
}

// Provider reads queue statistics through pfctl.
type Provider struct {
	binary string
	debug  bool
}

// New returns nil when PF/ALTQ monitoring is disabled or unavailable.
func New(enabled bool, backend, binary string, debug bool) (*Provider, error) {
	if !enabled || strings.ToLower(strings.TrimSpace(backend)) != "pf" {
		return nil, nil
	}
	if runtime.GOOS != "freebsd" && runtime.GOOS != "openbsd" {
		return nil, nil
	}
	binary = strings.TrimSpace(binary)
	if binary == "" {
		binary = "pfctl"
	}
	if _, err := exec.LookPath(binary); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("find pfctl executable for QoS: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, binary, "-s", "queue", "-v").Run(); err != nil {
		if debug {
			log.Printf("qos backend unavailable: pfctl queue probe failed: %v", err)
		}
		return nil, nil
	}
	return &Provider{binary: binary, debug: debug}, nil
}

// Report returns current ALTQ queue counters.
func (p *Provider) Report(ctx context.Context) (Report, error) {
	args := []string{"-s", "queue", "-v"}
	if p.debug {
		log.Printf("qos backend command: %s %s", p.binary, strings.Join(args, " "))
	}
	out, err := exec.CommandContext(ctx, p.binary, args...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(out))
		if message != "" {
			return Report{}, fmt.Errorf("PF QoS query: %w: %s", err, message)
		}
		return Report{}, fmt.Errorf("PF QoS query: %w", err)
	}
	return Report{Backend: "pf-altq", Queues: parsePFQueues(string(out))}, nil
}

var (
	queueHeaderPattern = regexp.MustCompile(`^queue\s+(\S+)(?:\s+on\s+(\S+))?(.*)$`)
	parentPattern      = regexp.MustCompile(`\bparent\s+(\S+)`)
	bandwidthPattern   = regexp.MustCompile(`\bbandwidth\s+(\S+)`)
	statsPattern       = regexp.MustCompile(`pkts:\s*(\d+)\s+bytes:\s*(\d+)\s+dropped pkts:\s*(\d+)\s+bytes:\s*(\d+)`)
	lengthPattern      = regexp.MustCompile(`qlength:\s*(\d+)(?:\s*/\s*(\d+))?`)
)

func parsePFQueues(output string) []Queue {
	var queues []Queue
	var current *Queue
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if matches := queueHeaderPattern.FindStringSubmatch(line); matches != nil {
			queue := Queue{Name: matches[1], Interface: matches[2]}
			tail := matches[3]
			if parent := parentPattern.FindStringSubmatch(tail); parent != nil {
				queue.Parent = parent[1]
			}
			if bandwidth := bandwidthPattern.FindStringSubmatch(tail); bandwidth != nil {
				queue.Bandwidth = bandwidth[1]
			}
			queue.Scheduler = parseScheduler(tail)
			queues = append(queues, queue)
			current = &queues[len(queues)-1]
			continue
		}
		if current == nil {
			continue
		}
		if matches := statsPattern.FindStringSubmatch(line); matches != nil {
			current.Packets = parseUint(matches[1])
			current.Bytes = parseUint(matches[2])
			current.DroppedPackets = parseUint(matches[3])
			current.DroppedBytes = parseUint(matches[4])
		}
		if matches := lengthPattern.FindStringSubmatch(line); matches != nil {
			current.QueueLength = parseUint(matches[1])
			current.QueueLimit = parseUint(matches[2])
		}
	}
	if queues == nil {
		return []Queue{}
	}
	return queues
}

func parseScheduler(tail string) string {
	fields := strings.Fields(tail)
	for _, field := range fields {
		name := strings.TrimSuffix(field, "(")
		switch strings.ToLower(name) {
		case "cbq", "priq", "hfsc", "fairq", "codel", "fqcodel":
			return strings.ToLower(name)
		}
	}
	return ""
}

func parseUint(value string) uint64 {
	number, _ := strconv.ParseUint(value, 10, 64)
	return number
}
