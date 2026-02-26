//go:build linux

package nftables

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"pfctl-golang/internal/firewall"
)

const (
	nftBinary        = "nft"
	conntrackBinary  = "conntrack"
	maxCounterRules  = 200
	maxConntrackRows = 200
)

type provider struct {
	debug bool
}

// New returns an nftables-backed provider.
func New(debug bool) (firewall.Provider, error) {
	if err := requireBinary(nftBinary); err != nil {
		return nil, err
	}
	if err := requireBinary(conntrackBinary); err != nil {
		return nil, err
	}
	return &provider{debug: debug}, nil
}

func (p *provider) BlockedTraffic(ctx context.Context) ([]firewall.PacketLogEntry, error) {
	// nftables rule counters and chain policies do not provide blocked packet
	// endpoint details (source/destination IP:port). To avoid misleading UI
	// output, report no blocked packet rows until packet-level logging is wired.
	return []firewall.PacketLogEntry{}, nil
}

func (p *provider) PassedTraffic(ctx context.Context) ([]firewall.PacketLogEntry, error) {
	out, err := p.run(ctx, conntrackBinary, "-L", "-o", "json")
	if err != nil {
		if strings.Contains(err.Error(), "Bad parameter `json'") {
			if p.debug {
				log.Printf("nft backend: json output unsupported, falling back to text conntrack")
			}
			return p.passedTrafficText(ctx)
		}
		return nil, fmt.Errorf("conntrack list: %w", err)
	}
	return parseConntrack(out), nil
}

func (p *provider) passedTrafficText(ctx context.Context) ([]firewall.PacketLogEntry, error) {
	out, err := p.run(ctx, conntrackBinary, "-L")
	if err != nil {
		return nil, fmt.Errorf("conntrack list text: %w", err)
	}
	return parseConntrackText(out), nil
}

func (p *provider) RuleCounters(ctx context.Context) ([]firewall.RuleCounter, error) {
	rules, err := p.fetchRuleset(ctx)
	if err != nil {
		return nil, err
	}
	counters := make([]firewall.RuleCounter, 0, len(rules))
	for _, rule := range rules {
		packets := uint64(0)
		bytes := uint64(0)
		if rule.Counter != nil {
			packets = rule.Counter.Packets
			bytes = rule.Counter.Bytes
		}
		counters = append(counters, firewall.RuleCounter{
			RuleID:      int(rule.Handle),
			RuleLabel:   rule.RenderLabel(),
			Evaluations: packets,
			Packets:     packets,
			Bytes:       bytes,
		})
		if len(counters) >= maxCounterRules {
			break
		}
	}
	return counters, nil
}

type nftRule struct {
	Family       string
	Table        string
	Chain        string
	Handle       uint64
	Expr         []map[string]json.RawMessage
	Counter      *nftCounter
	Action       string
	ProtocolHint string
	UserHandle   string
	Comment      string
}

type nftCounter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type rulesetResponse struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

func (p *provider) fetchRuleset(ctx context.Context) ([]nftRule, error) {
	out, err := p.run(ctx, nftBinary, "--json", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	resp := rulesetResponse{}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("parse ruleset: %w", err)
	}
	var rules []nftRule
	for _, block := range resp.Nftables {
		ruleRaw, ok := block["rule"]
		if !ok {
			continue
		}
		var parsed struct {
			Family     string                       `json:"family"`
			Table      string                       `json:"table"`
			Chain      string                       `json:"chain"`
			Handle     uint64                       `json:"handle"`
			UserHandle string                       `json:"user_handle"`
			Expr       []map[string]json.RawMessage `json:"expr"`
			Comment    string                       `json:"comment"`
		}
		if err := json.Unmarshal(ruleRaw, &parsed); err != nil {
			continue
		}
		rule := nftRule{
			Family:     parsed.Family,
			Table:      parsed.Table,
			Chain:      parsed.Chain,
			Handle:     parsed.Handle,
			Expr:       parsed.Expr,
			UserHandle: parsed.UserHandle,
			Comment:    parsed.Comment,
		}
		for _, expr := range parsed.Expr {
			if counterRaw, ok := expr["counter"]; ok {
				var counter nftCounter
				if err := json.Unmarshal(counterRaw, &counter); err == nil {
					rule.Counter = &counter
				}
			}
			if acceptRaw, ok := expr["accept"]; ok && acceptRaw != nil {
				rule.Action = "accept"
			}
			if dropRaw, ok := expr["drop"]; ok && dropRaw != nil {
				rule.Action = "drop"
			}
			if rejectRaw, ok := expr["reject"]; ok && rejectRaw != nil {
				rule.Action = "reject"
			}
			if verdictRaw, ok := expr["verdict"]; ok {
				var verdict struct {
					Kind string `json:"kind"`
				}
				if err := json.Unmarshal(verdictRaw, &verdict); err == nil && verdict.Kind != "" {
					rule.Action = strings.ToLower(verdict.Kind)
				}
			}
			if matchRaw, ok := expr["match"]; ok {
				var match struct {
					Left struct {
						Payload struct {
							Field    string `json:"field"`
							Protocol string `json:"protocol"`
						} `json:"payload"`
					} `json:"left"`
				}
				if err := json.Unmarshal(matchRaw, &match); err == nil {
					if match.Left.Payload.Field == "l4proto" {
						rule.ProtocolHint = strings.ToLower(match.Left.Payload.Protocol)
					}
				}
			}
			if payloadRaw, ok := expr["payload"]; ok && rule.ProtocolHint == "" {
				var payload struct {
					Protocol string `json:"protocol"`
				}
				if err := json.Unmarshal(payloadRaw, &payload); err == nil {
					rule.ProtocolHint = strings.ToLower(payload.Protocol)
				}
			}
		}
		if rule.Action == "" {
			rule.Action = "unknown"
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (r nftRule) RenderLabel() string {
	var b strings.Builder
	if r.UserHandle != "" {
		fmt.Fprintf(&b, "%s ", r.UserHandle)
	}
	if r.Action != "" {
		fmt.Fprintf(&b, "%s ", r.Action)
	}
	fmt.Fprintf(&b, "%s/%s handle %d", r.Table, r.Chain, r.Handle)
	if r.Comment != "" {
		fmt.Fprintf(&b, " (%s)", r.Comment)
	}
	return strings.TrimSpace(b.String())
}

func parseConntrack(data []byte) []firewall.PacketLogEntry {
	var flows []map[string]any
	if err := json.Unmarshal(data, &flows); err != nil {
		return nil
	}
	entries := make([]firewall.PacketLogEntry, 0, len(flows))
	now := time.Now()
	for _, flow := range flows {
		protocol := getString(flow, "p")
		if protocol == "" {
			protocol = getString(flow, "proto")
		}
		protocol = strings.ToLower(protocol)
		orig := getMap(flow, "orig")
		if len(orig) == 0 {
			continue
		}
		src := endpointFrom(orig, "src", "sport")
		dst := endpointFrom(orig, "dst", "dport")
		status := sliceToString(flow["state"])
		if status == "" {
			status = sliceToString(flow["status"])
		}
		entry := firewall.PacketLogEntry{
			Timestamp: now,
			Interface: fmt.Sprintf("zone:%s", getString(flow, "zone")),
			Source:    src,
			Dest:      dst,
			Protocol:  protocol,
			Action:    "pass",
			Reason:    status,
		}
		entries = append(entries, entry)
		if len(entries) >= maxConntrackRows {
			break
		}
	}
	return entries
}

func parseConntrackText(data []byte) []firewall.PacketLogEntry {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	entries := make([]firewall.PacketLogEntry, 0)
	now := time.Now()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		entry := parseConntrackTextLine(line, now)
		if entry != nil {
			entries = append(entries, *entry)
			if len(entries) >= maxConntrackRows {
				break
			}
		}
	}
	return entries
}

func parseConntrackTextLine(line string, ts time.Time) *firewall.PacketLogEntry {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}
	action := "pass"
	proto := fields[0]
	state := fields[3]
	data := fields[4:]
	info := make(map[string]string)
	for _, field := range data {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			continue
		}
		info[parts[0]] = parts[1]
	}
	src := info["src"]
	dst := info["dst"]
	sport := info["sport"]
	dport := info["dport"]
	if src != "" && sport != "" {
		src = fmt.Sprintf("%s:%s", src, sport)
	}
	if dst != "" && dport != "" {
		dst = fmt.Sprintf("%s:%s", dst, dport)
	}
	return &firewall.PacketLogEntry{
		Timestamp: ts,
		Interface: info["zone"],
		Source:    src,
		Dest:      dst,
		Protocol:  proto,
		Action:    action,
		Reason:    state,
	}
}

func (p *provider) run(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	full := strings.TrimSpace(cmd + " " + strings.Join(args, " "))
	if p.debug {
		log.Printf("nft backend: executing %s", full)
	}
	c := exec.CommandContext(ctx, cmd, args...)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			if p.debug {
				log.Printf("nft backend: command failed %s: %v; stderr: %s", full, err, msg)
			}
			return nil, fmt.Errorf("%s: %w: %s", full, err, msg)
		}
		if p.debug {
			log.Printf("nft backend: command failed %s: %v", full, err)
		}
		return nil, fmt.Errorf("%s: %w", full, err)
	}
	if p.debug {
		log.Printf("nft backend: command succeeded %s (stdout %d bytes)", full, stdout.Len())
	}
	return stdout.Bytes(), nil
}

func (p *provider) StreamTraffic(context.Context, string) (io.ReadCloser, error) {
	return nil, firewall.ErrUnsupported
}

func requireBinary(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%w: required executable %q not found in PATH", firewall.ErrUnsupported, name)
	}
	return nil
}

func getString(m map[string]any, key string) string {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case string:
			return v
		case float64:
			return strconv.FormatInt(int64(v), 10)
		}
	}
	return ""
}

func getMap(m map[string]any, key string) map[string]any {
	if val, ok := m[key]; ok {
		if mapped, ok := val.(map[string]any); ok {
			return mapped
		}
	}
	return nil
}

func endpointFrom(m map[string]any, addrKey, portKey string) string {
	addr := getString(m, addrKey)
	port := getString(m, portKey)
	if addr == "" {
		return ""
	}
	if port == "" {
		return addr
	}
	return fmt.Sprintf("%s:%s", addr, port)
}

func sliceToString(val any) string {
	switch v := val.(type) {
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			switch s := item.(type) {
			case string:
				parts = append(parts, s)
			case float64:
				parts = append(parts, strconv.FormatInt(int64(s), 10))
			}
		}
		return strings.Join(parts, ",")
	case string:
		return v
	default:
		return ""
	}
}
