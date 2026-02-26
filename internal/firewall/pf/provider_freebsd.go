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
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"pfctl-golang/internal/firewall"
)

const (
	pfctlBinary    = "pfctl"
	tcpdumpBinary  = "tcpdump"
	pflogPath      = "/var/log/pflog"
	pflogInterface = "pflog0"
	maxPflogLines  = 200
	maxStatesCount = 200
)

type provider struct {
	debug bool
}

// New returns a PF-backed provider.
func New(debug bool) (firewall.Provider, error) {
	if err := requireBinary(pfctlBinary); err != nil {
		return nil, err
	}
	if err := requireBinary(tcpdumpBinary); err != nil {
		return nil, err
	}
	return &provider{debug: debug}, nil
}

func (p *provider) BlockedTraffic(ctx context.Context) ([]firewall.PacketLogEntry, error) {
	out, err := p.run(ctx, tcpdumpBinary, "-e", "-n", "-tttt", "-r", pflogPath, "-c", strconv.Itoa(maxPflogLines))
	if err != nil {
		return nil, fmt.Errorf("pflog capture: %w", err)
	}
	return parsePflogOutput(out), nil
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
	args := []string{"-e", "-n", "-tttt", "-l", "-i", pflogInterface}
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
