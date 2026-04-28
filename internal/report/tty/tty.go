package tty

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/finding"
)

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	mag    = "\x1b[35m"
	cyan   = "\x1b[36m"
)

func color() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func c(code, s string) string {
	if !color() {
		return s
	}
	return code + s + reset
}

func sevColor(s finding.Severity) string {
	switch s {
	case finding.SevCritical:
		return mag
	case finding.SevHigh:
		return red
	case finding.SevMedium:
		return yellow
	case finding.SevLow:
		return blue
	}
	return dim
}

func statusGlyph(s finding.Status) string {
	switch s {
	case finding.StatusPass:
		return c(green, "PASS")
	case finding.StatusFail:
		return c(red, "FAIL")
	case finding.StatusWarn:
		return c(yellow, "WARN")
	case finding.StatusUnverified:
		return c(dim, "UNVR")
	case finding.StatusSkipped:
		return c(dim, "SKIP")
	case finding.StatusError:
		return c(mag, "ERR ")
	}
	return string(s)
}

func Write(w io.Writer, r finding.Report) error {
	fmt.Fprintf(w, "%s\n", c(bold, "Assessor Report"))
	fmt.Fprintf(w, "  host:    %s (%s, kernel %s)\n", r.Host.Hostname, r.Host.Distro, r.Host.KernelRel)
	fmt.Fprintf(w, "  profile: %s\n", r.Profile)
	fmt.Fprintf(w, "  started: %s\n", r.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "  total:   %d checks  risk score: %s\n\n",
		r.Summary.Total, c(bold, fmt.Sprintf("%d", r.Summary.RiskScore)))

	for _, f := range r.Findings {
		sev := c(sevColor(f.Meta.Severity), strings.ToUpper(string(f.Meta.Severity)))
		fmt.Fprintf(w, "[%s] %s %s  %s\n",
			statusGlyph(f.Status), sev, c(bold, f.Meta.ID), f.Meta.Title)
		if f.Message != "" {
			fmt.Fprintf(w, "       %s\n", f.Message)
		}
		for _, ev := range f.Evidence {
			fmt.Fprintf(w, "       %s %s\n", c(dim, "↳"), c(cyan, ev.Source))
			for _, line := range strings.Split(strings.TrimRight(ev.Content, "\n"), "\n") {
				if line == "" {
					continue
				}
				fmt.Fprintf(w, "         %s%s%s\n", dim, line, reset)
			}
		}
		if f.Remediation.Description != "" {
			fmt.Fprintf(w, "       %s %s\n", c(green, "fix:"), f.Remediation.Description)
			for _, cmd := range f.Remediation.Commands {
				fmt.Fprintf(w, "         $ %s\n", cmd)
			}
		}
		if f.Err != "" {
			fmt.Fprintf(w, "       %s %s\n", c(red, "error:"), f.Err)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%s\n", c(bold, "Summary"))
	for _, st := range []finding.Status{
		finding.StatusFail, finding.StatusWarn, finding.StatusPass,
		finding.StatusUnverified, finding.StatusSkipped, finding.StatusError,
	} {
		if n := r.Summary.ByStatus[st]; n > 0 {
			fmt.Fprintf(w, "  %s  %d\n", statusGlyph(st), n)
		}
	}
	return nil
}
