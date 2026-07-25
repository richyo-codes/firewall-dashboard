package main

import (
	"bytes"
	"embed"
	"fmt"
	"io"
)

// freeBSDRC holds the rc.d service script distributed with the binary.
//
//go:embed packaging/freebsd/rc.d/pf_dashboard
var freeBSDRC embed.FS

func maybeHandleRCD(args []string, stdout, stderr io.Writer) (bool, error) {
	if len(args) < 2 || args[0] != "config" || args[1] != "rc.d" {
		return false, nil
	}
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: pf-dashboard config rc.d")
		return true, fmt.Errorf("rc.d does not accept arguments")
	}
	script, err := freeBSDRC.ReadFile("packaging/freebsd/rc.d/pf_dashboard")
	if err != nil {
		return true, fmt.Errorf("read embedded rc.d script: %w", err)
	}
	_, err = io.Copy(stdout, bytes.NewReader(script))
	return true, err
}
