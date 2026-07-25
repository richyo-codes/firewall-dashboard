//go:build freebsd || openbsd

package pf

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"pfctl-golang/internal/firewall"
)

const (
	pfctlBinary    = "pfctl"
	tcpdumpBinary  = "tcpdump"
	maxPflogLines  = 200
	maxStatesCount = 200
)

type provider struct {
	debug          bool
	blockedSource  string
	pflogInterface string
	pflogPath      string
	blockedMu      sync.RWMutex
	recentBlocked  []firewall.PacketLogEntry
}

// New returns a PF-backed provider.
func New(debug bool, blockedSource, pflogInterface, pflogPath string) (firewall.Provider, error) {
	if err := requireBinary(pfctlBinary); err != nil {
		return nil, err
	}
	if err := requireBinary(tcpdumpBinary); err != nil {
		return nil, err
	}
	blockedSource = strings.ToLower(strings.TrimSpace(blockedSource))
	if blockedSource == "" {
		blockedSource = "auto"
	}
	if blockedSource != "auto" && blockedSource != "live" && blockedSource != "file" {
		return nil, fmt.Errorf("invalid blocked traffic source %q", blockedSource)
	}
	pflogInterface = strings.TrimSpace(pflogInterface)
	if pflogInterface == "" {
		pflogInterface = "pflog0"
	}
	pflogPath = strings.TrimSpace(pflogPath)
	if pflogPath == "" {
		pflogPath = "/var/log/pflog"
	}
	provider := &provider{debug: debug, blockedSource: blockedSource, pflogInterface: pflogInterface, pflogPath: pflogPath}
	if blockedSource != "file" {
		provider.startBlockedCollector()
	}
	return provider, nil
}

func (p *provider) BlockedTraffic(ctx context.Context) ([]firewall.PacketLogEntry, error) {
	if p.blockedSource == "live" {
		return p.blockedSnapshot(), nil
	}
	live := p.blockedSnapshot()
	if _, err := os.Stat(p.pflogPath); err != nil {
		if p.blockedSource == "file" {
			return nil, fmt.Errorf("pflog capture: %w", err)
		}
		// pflogd is optional: the live collector reads pflog0 directly.
		return live, nil
	}
	out, err := p.run(ctx, tcpdumpBinary, "-e", "-n", "-tttt", "-r", p.pflogPath, "-c", strconv.Itoa(maxPflogLines))
	if err != nil {
		if len(live) > 0 {
			return live, nil
		}
		return nil, fmt.Errorf("pflog capture: %w", err)
	}
	return mergeBlockedEntries(live, filterPflogAction(parsePflogOutput(out), "block")), nil
}

// startBlockedCollector keeps recent blocked packets available even when
// pflogd is disabled or /var/log/pflog is rotated away.
func (p *provider) startBlockedCollector() {
	go func() {
		for {
			if err := p.collectBlockedTraffic(); err != nil && p.debug {
				log.Printf("pf backend blocked collector stopped: %v", err)
			}
			time.Sleep(5 * time.Second)
		}
	}()
}

func (p *provider) collectBlockedTraffic() error {
	cmd := exec.Command(tcpdumpBinary, "-e", "-n", "-tttt", "-l", "-i", p.pflogInterface, "action", "block")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("tcpdump stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tcpdump: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4*1024), 256*1024)
	for scanner.Scan() {
		entry, ok := parsePflogLine(scanner.Text())
		if ok && entry.Action == "block" {
			p.recordBlocked(entry)
		}
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return fmt.Errorf("read tcpdump output: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return fmt.Errorf("tcpdump exited: %w: %s", err, message)
		}
		return fmt.Errorf("tcpdump exited: %w", err)
	}
	return nil
}

func (p *provider) recordBlocked(entry firewall.PacketLogEntry) {
	p.blockedMu.Lock()
	defer p.blockedMu.Unlock()
	p.recentBlocked = append([]firewall.PacketLogEntry{entry}, p.recentBlocked...)
	if len(p.recentBlocked) > maxPflogLines {
		p.recentBlocked = p.recentBlocked[:maxPflogLines]
	}
}

func (p *provider) blockedSnapshot() []firewall.PacketLogEntry {
	p.blockedMu.RLock()
	defer p.blockedMu.RUnlock()
	return append([]firewall.PacketLogEntry(nil), p.recentBlocked...)
}

func mergeBlockedEntries(primary, secondary []firewall.PacketLogEntry) []firewall.PacketLogEntry {
	merged := append(append([]firewall.PacketLogEntry(nil), primary...), secondary...)
	seen := make(map[string]struct{}, len(merged))
	unique := merged[:0]
	for _, entry := range merged {
		key := fmt.Sprintf("%s|%s|%s|%s|%d", entry.Timestamp.UTC(), entry.Interface, entry.Source, entry.Dest, entry.RuleID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, entry)
	}
	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Timestamp.After(unique[j].Timestamp)
	})
	if len(unique) > maxPflogLines {
		unique = unique[:maxPflogLines]
	}
	return unique
}

func (p *provider) PassedTraffic(ctx context.Context) ([]firewall.PacketLogEntry, error) {
	out, err := p.run(ctx, pfctlBinary, "-s", "state", "-vv")
	if err != nil {
		return nil, fmt.Errorf("pfctl state: %w", err)
	}
	entries := parseStateTable(out)
	if len(entries) > maxStatesCount {
		entries = entries[:maxStatesCount]
	}
	return entries, nil
}

func (p *provider) RuleCounters(ctx context.Context) ([]firewall.RuleCounter, error) {
	out, err := p.run(ctx, pfctlBinary, "-vvsr")
	if err != nil {
		return nil, fmt.Errorf("pfctl rules: %w", err)
	}
	return parseRuleCounters(out), nil
}

func (p *provider) StreamTraffic(ctx context.Context, action string) (io.ReadCloser, error) {
	args := []string{"-e", "-n", "-tttt", "-l", "-i", p.pflogInterface}
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "", "pass", "block", "rdr", "*":
		if action != "" && action != "*" {
			args = append(args, "action", action)
		}
	default:
		return nil, fmt.Errorf("unsupported action %q", action)
	}

	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, tcpdumpBinary, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("tcpdump stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("tcpdump stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start tcpdump: %w", err)
	}

	go func() {
		buf := new(bytes.Buffer)
		_, _ = io.Copy(buf, stderr)
		if p.debug {
			msg := strings.TrimSpace(buf.String())
			if msg != "" {
				log.Printf("pf backend stream stderr: %s", msg)
			}
		}
	}()

	return &commandStream{ReadCloser: stdout, cancel: cancel, cmd: cmd}, nil
}

func (p *provider) run(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	full := strings.TrimSpace(cmd + " " + strings.Join(args, " "))
	if p.debug {
		log.Printf("pf backend: executing %s", full)
	}

	c := exec.CommandContext(ctx, cmd, args...)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			if p.debug {
				log.Printf("pf backend: command failed %s: %v; stderr: %s", full, err, msg)
			}
			return nil, fmt.Errorf("%s: %w: %s", full, err, msg)
		}
		if p.debug {
			log.Printf("pf backend: command failed %s: %v", full, err)
		}
		return nil, fmt.Errorf("%s: %w", full, err)
	}
	if p.debug {
		log.Printf("pf backend: command succeeded %s (stdout %d bytes)", full, stdout.Len())
	}
	return stdout.Bytes(), nil
}

func parseRuleCounters(out []byte) []firewall.RuleCounter {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var counters []firewall.RuleCounter
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "@") {
			id, label, err := parseRuleHeader(trimmed)
			if err != nil {
				continue
			}
			counters = append(counters, firewall.RuleCounter{
				RuleID:    id,
				RuleLabel: label,
			})
			continue
		}
		if len(counters) == 0 || !strings.HasPrefix(trimmed, "[") {
			continue
		}
		last := &counters[len(counters)-1]
		parseRuleMetrics(trimmed, last)
	}
	return counters
}

func parseRuleHeader(line string) (int, string, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, "", errors.New("invalid rule header")
	}
	idStr := strings.TrimPrefix(fields[0], "@")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, "", err
	}
	label := strings.TrimSpace(line[len(fields[0]):])
	return id, label, nil
}

func parseRuleMetrics(line string, counter *firewall.RuleCounter) {
	if v, ok := parseUintFromLine(line, "Evaluations:"); ok {
		counter.Evaluations = v
	}
	if v, ok := parseUintFromLine(line, "Packets:"); ok {
		counter.Packets = v
	}
	if v, ok := parseUintFromLine(line, "Bytes:"); ok {
		counter.Bytes = v
	}
}

func parseUintFromLine(line, label string) (uint64, bool) {
	idx := strings.Index(line, label)
	if idx == -1 {
		return 0, false
	}
	idx += len(label)
	for idx < len(line) && line[idx] == ' ' {
		idx++
	}
	end := idx
	for end < len(line) && line[end] >= '0' && line[end] <= '9' {
		end++
	}
	if end == idx {
		return 0, false
	}
	val, err := strconv.ParseUint(line[idx:end], 10, 64)
	if err != nil {
		return 0, false
	}
	return val, true
}

type commandStream struct {
	io.ReadCloser
	cancel context.CancelFunc
	cmd    *exec.Cmd
	once   sync.Once
}

func (c *commandStream) Close() error {
	var err error
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		if c.ReadCloser != nil {
			err = c.ReadCloser.Close()
		}
		waitErr := c.cmd.Wait()
		if waitErr != nil && !errors.Is(waitErr, context.Canceled) && err == nil {
			err = waitErr
		}
	})
	return err
}

func requireBinary(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%w: required executable %q not found in PATH", firewall.ErrUnsupported, name)
	}
	return nil
}
