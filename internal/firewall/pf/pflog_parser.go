package pf

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"pfctl-golang/internal/firewall"
)

var (
	stateLineRegex = regexp.MustCompile(`^(?P<dir>\S+)\s+(?P<proto>\S+)\s+(?P<src>.+?)\s+->\s+(?P<dst>.+)$`)
	ageRegex       = regexp.MustCompile(`age\s+(\d+):(\d+):(\d+)`)
	timeLayouts    = []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.000000",
	}
	pflogLineRegex = regexp.MustCompile(`^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+rule\s+(?P<rule>\d+/\d+)\(match\):\s+(?P<action>[a-zA-Z]+)\s+(?P<direction>in|out)\s+on\s+(?P<iface>[^:]+):\s+(?P<payload>.*)$`)
)

func parsePflogOutput(out []byte) []firewall.PacketLogEntry {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var entries []firewall.PacketLogEntry
	for scanner.Scan() {
		line := scanner.Text()
		if entry, ok := parsePflogLine(line); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func parsePflogLine(line string) (firewall.PacketLogEntry, bool) {
	matches := pflogLineRegex.FindStringSubmatch(line)
	if matches == nil {
		return firewall.PacketLogEntry{}, false
	}

	fields := map[string]string{}
	for i, name := range pflogLineRegex.SubexpNames() {
		if i == 0 || name == "" {
			continue
		}
		fields[name] = matches[i]
	}

	timestampStr := fmt.Sprintf("%s %s", fields["date"], fields["time"])
	var ts time.Time
	var parseErr error
	for _, layout := range timeLayouts {
		ts, parseErr = time.ParseInLocation(layout, timestampStr, time.Local)
		if parseErr == nil {
			break
		}
	}
	if parseErr != nil {
		ts = time.Now()
	}

	action := strings.ToLower(strings.TrimSpace(fields["action"]))
	if action == "" {
		action = "unknown"
	}

	direction := strings.ToLower(strings.TrimSpace(fields["direction"]))
	if direction == "" {
		direction = "unknown"
	}

	iface := strings.TrimSpace(fields["iface"])
	ruleID := parseRuleID(fields["rule"])

	payload := fields["payload"]
	traffic, meta := splitTrafficMeta(payload)
	src, dst := parseEndpoints(traffic)

	proto := detectProtocol(meta)
	reason := strings.TrimSpace(meta)
	if reason == "" {
		reason = "pflog"
	}

	entry := firewall.PacketLogEntry{
		Timestamp: ts,
		Interface: iface,
		Source:    src,
		Dest:      dst,
		Protocol:  proto,
		Action:    action,
		Reason:    reason,
		Direction: direction,
		RuleID:    ruleID,
	}
	return entry, true
}

func splitTrafficMeta(payload string) (string, string) {
	idx := strings.Index(payload, ": ")
	if idx == -1 {
		return payload, ""
	}
	traffic := payload[:idx]
	meta := payload[idx+2:]
	return traffic, meta
}

func parseEndpoints(traffic string) (string, string) {
	parts := strings.Split(traffic, " > ")
	if len(parts) != 2 {
		return strings.TrimSpace(traffic), ""
	}
	src := strings.TrimSpace(parts[0])
	dst := strings.TrimSpace(parts[1])
	return src, dst
}

func parseRuleID(rule string) int {
	slashIdx := strings.Index(rule, "/")
	if slashIdx == -1 {
		if id, err := strconv.Atoi(rule); err == nil {
			return id
		}
		return 0
	}
	idStr := rule[:slashIdx]
	if id, err := strconv.Atoi(idStr); err == nil {
		return id
	}
	return 0
}

func detectProtocol(meta string) string {
	metaLower := strings.ToLower(meta)
	switch {
	case strings.Contains(metaLower, "proto tcp"), strings.Contains(metaLower, "flags ["):
		return "tcp"
	case strings.Contains(metaLower, "proto udp"):
		return "udp"
	case strings.Contains(metaLower, "proto icmp"):
		return "icmp"
	case strings.Contains(metaLower, "proto gre"):
		return "gre"
	default:
		return "unknown"
	}
}

func sanitizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return endpoint
	}
	if idx := strings.Index(endpoint, " "); idx != -1 {
		endpoint = endpoint[:idx]
	}
	endpoint = strings.Trim(endpoint, "()")
	return endpoint
}

func extractDestination(dst string) string {
	parts := strings.Fields(dst)
	if len(parts) == 0 {
		return dst
	}
	return parts[0]
}

func parseStateTable(out []byte) []firewall.PacketLogEntry {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var (
		entries    []firewall.PacketLogEntry
		header     string
		ageLine    string
		collecting bool
	)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if collecting && header != "" && ageLine != "" {
				if entry, ok := buildStateEntry(header, ageLine); ok {
					entries = append(entries, entry)
				}
			}
			header = line
			ageLine = ""
			collecting = true
			continue
		}
		if collecting && ageLine == "" && strings.Contains(line, "age ") {
			ageLine = strings.TrimSpace(line)
		}
	}
	if collecting && header != "" && ageLine != "" {
		if entry, ok := buildStateEntry(header, ageLine); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func buildStateEntry(header, ageLine string) (firewall.PacketLogEntry, bool) {
	match := stateLineRegex.FindStringSubmatch(header)
	if match == nil {
		return firewall.PacketLogEntry{}, false
	}
	result := map[string]string{}
	for i, name := range stateLineRegex.SubexpNames() {
		if i == 0 || name == "" {
			continue
		}
		result[name] = strings.TrimSpace(match[i])
	}

	src := sanitizeEndpoint(result["src"])
	dst := sanitizeEndpoint(extractDestination(result["dst"]))
	proto := strings.ToLower(result["proto"])
	if proto == "" {
		proto = "unknown"
	}

	timestamp := time.Now()
	if matches := ageRegex.FindStringSubmatch(ageLine); len(matches) == 4 {
		hours, _ := strconv.Atoi(matches[1])
		mins, _ := strconv.Atoi(matches[2])
		secs, _ := strconv.Atoi(matches[3])
		duration := time.Duration(hours)*time.Hour + time.Duration(mins)*time.Minute + time.Duration(secs)*time.Second
		timestamp = timestamp.Add(-duration)
	}

	entry := firewall.PacketLogEntry{
		Timestamp: timestamp,
		Interface: result["dir"],
		Source:    src,
		Dest:      dst,
		Protocol:  proto,
		Action:    "pass",
		Reason:    "state table",
		Direction: "unknown",
	}
	return entry, true
}
