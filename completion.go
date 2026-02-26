package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/pflag"

	"pfctl-golang/internal/config"
)

func maybeHandleCompletion(args []string, stdout, stderr io.Writer) (bool, error) {
	shell, ok := parseCompletionRequest(args)
	if !ok {
		return false, nil
	}
	if shell == "" {
		fmt.Fprintln(stderr, "usage: pf-dashboard completion <bash|zsh|fish>")
		fmt.Fprintln(stderr, "or:    pf-dashboard --completion <bash|zsh|fish>")
		return true, fmt.Errorf("missing completion shell")
	}

	flags, err := completionFlags()
	if err != nil {
		return true, err
	}

	switch shell {
	case "bash":
		writeBashCompletion(stdout, flags)
	case "zsh":
		writeZshCompletion(stdout, flags)
	case "fish":
		writeFishCompletion(stdout, flags)
	default:
		fmt.Fprintln(stderr, "unsupported shell for completion:", shell)
		fmt.Fprintln(stderr, "supported shells: bash, zsh, fish")
		return true, fmt.Errorf("unsupported completion shell %q", shell)
	}
	return true, nil
}

func parseCompletionRequest(args []string) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	if args[0] == "completion" {
		if len(args) >= 2 {
			return strings.ToLower(strings.TrimSpace(args[1])), true
		}
		return "", true
	}
	if strings.HasPrefix(args[0], "--completion=") {
		return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(args[0], "--completion="))), true
	}
	if args[0] == "--completion" {
		if len(args) >= 2 {
			return strings.ToLower(strings.TrimSpace(args[1])), true
		}
		return "", true
	}
	return "", false
}

func completionFlags() ([]string, error) {
	_, flagSet, err := config.Load([]string{})
	if err != nil {
		return nil, fmt.Errorf("build completion flags: %w", err)
	}

	flags := make([]string, 0)
	flagSet.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		flags = append(flags, "--"+f.Name)
	})
	sort.Strings(flags)
	return flags, nil
}

func writeBashCompletion(w io.Writer, flags []string) {
	opts := strings.Join(flags, " ")
	fmt.Fprintf(w, " _pf_dashboard_complete() {\n")
	fmt.Fprintf(w, "  local cur=\"${COMP_WORDS[COMP_CWORD]}\"\n")
	fmt.Fprintf(w, "  local opts=\"%s\"\n", opts)
	fmt.Fprintf(w, "  COMPREPLY=( $(compgen -W \"${opts}\" -- \"${cur}\") )\n")
	fmt.Fprintf(w, " }\n")
	fmt.Fprintf(w, " complete -F _pf_dashboard_complete pf-dashboard\n")
	fmt.Fprintf(w, " complete -F _pf_dashboard_complete pfctl-dashboard\n")
}

func writeZshCompletion(w io.Writer, flags []string) {
	fmt.Fprintln(w, "#compdef pf-dashboard pfctl-dashboard")
	fmt.Fprintln(w, "_pf_dashboard_complete() {")
	fmt.Fprintln(w, "  _arguments '*:flag:(")
	for _, flag := range flags {
		fmt.Fprintf(w, "    %s\n", flag)
	}
	fmt.Fprintln(w, "  )'")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w, "compdef _pf_dashboard_complete pf-dashboard pfctl-dashboard")
}

func writeFishCompletion(w io.Writer, flags []string) {
	opts := strings.Join(flags, " ")
	for _, cmd := range []string{"pf-dashboard", "pfctl-dashboard"} {
		fmt.Fprintf(w, "complete -c %s -f -a \"%s\"\n", cmd, opts)
	}
}
