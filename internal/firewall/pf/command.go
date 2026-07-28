package pf

import (
	"strconv"
	"strings"
)

// formatCommand produces a readable, copyable representation for debug logs.
func formatCommand(command string, args ...string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, command)
	for _, arg := range args {
		if strings.ContainsAny(arg, " \t\n\"'") {
			parts = append(parts, strconv.Quote(arg))
			continue
		}
		parts = append(parts, arg)
	}
	return strings.Join(parts, " ")
}
