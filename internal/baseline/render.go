package baseline

import (
	"fmt"
	"io"
	"os"
	"sort"
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

// RenderTTY writes a colored, human-readable diff. Format:
//
//	Added fails    (since 2026-04-20 ...):
//	  [HIGH] ssh.sshd.hardening — sshd_config matches baseline
//	Resolved fails:
//	  [MED]  fs.mount.hardening — mount options OK
//	Status changes:
//	  ssh.banner.set            warn  -> pass
func RenderTTY(w io.Writer, prevPath string, prev, cur finding.Report, d Diff) {
	fmt.Fprintf(w, "%s\n", c(bold, "Diff vs "+prevPath))
	fmt.Fprintf(w, "  prev: %s    %d findings\n", prev.StartedAt.Format("2006-01-02 15:04 MST"), len(prev.Findings))
	fmt.Fprintf(w, "  cur:  %s    %d findings\n", cur.StartedAt.Format("2006-01-02 15:04 MST"), len(cur.Findings))
	fmt.Fprintf(w, "  delta risk: %s\n\n", riskDelta(prev, cur))

	if len(d.NewFails) == 0 && len(d.ResolvedFails) == 0 && len(d.StatusChanges) == 0 && len(d.EvidenceChanges) == 0 {
		fmt.Fprintln(w, c(green, "  no changes"))
		return
	}

	if len(d.NewFails) > 0 {
		fmt.Fprintf(w, "%s\n", c(bold, fmt.Sprintf("New fails (%d)", len(d.NewFails))))
		sortFindings(d.NewFails)
		for _, f := range d.NewFails {
			fmt.Fprintf(w, "  %s %s %s — %s\n",
				c(red, "+"),
				sevBadge(f.Meta.Severity),
				c(bold, f.Meta.ID),
				f.Message)
		}
		fmt.Fprintln(w)
	}
	if len(d.ResolvedFails) > 0 {
		fmt.Fprintf(w, "%s\n", c(bold, fmt.Sprintf("Resolved (%d)", len(d.ResolvedFails))))
		sortFindings(d.ResolvedFails)
		for _, f := range d.ResolvedFails {
			fmt.Fprintf(w, "  %s %s %s\n",
				c(green, "-"),
				sevBadge(f.Meta.Severity),
				c(bold, f.Meta.ID))
		}
		fmt.Fprintln(w)
	}
	if len(d.StatusChanges) > 0 {
		// Show only non-fail-related status changes (the fail transitions are
		// already covered above).
		var transitions []StatusChange
		for _, sc := range d.StatusChanges {
			if sc.From != finding.StatusFail && sc.To != finding.StatusFail {
				transitions = append(transitions, sc)
			}
		}
		if len(transitions) > 0 {
			fmt.Fprintf(w, "%s\n", c(bold, fmt.Sprintf("Other status changes (%d)", len(transitions))))
			for _, sc := range transitions {
				fmt.Fprintf(w, "  %s  %s %s %s\n",
					c(cyan, sc.ID),
					string(sc.From),
					c(dim, "->"),
					string(sc.To))
			}
			fmt.Fprintln(w)
		}
	}
	if len(d.EvidenceChanges) > 0 {
		// Group by finding for tidier output.
		byFinding := map[string][]EvidenceChange{}
		var ids []string
		for _, ec := range d.EvidenceChanges {
			if _, seen := byFinding[ec.FindingID]; !seen {
				ids = append(ids, ec.FindingID)
			}
			byFinding[ec.FindingID] = append(byFinding[ec.FindingID], ec)
		}
		sort.Strings(ids)
		fmt.Fprintf(w, "%s\n", c(bold, fmt.Sprintf("Evidence drift (%d finding%s)", len(ids), pluralS(len(ids)))))
		const maxPerSource = 12
		for _, id := range ids {
			fmt.Fprintf(w, "  %s\n", c(cyan, id))
			for _, ec := range byFinding[id] {
				fmt.Fprintf(w, "    %s %s\n", c(dim, "src:"), ec.Source)
				renderLines(w, ec.Added, c(green, "+"), maxPerSource)
				renderLines(w, ec.Removed, c(red, "-"), maxPerSource)
			}
		}
	}
}

func renderLines(w io.Writer, lines []string, marker string, maxLines int) {
	sort.Strings(lines)
	shown := lines
	if len(shown) > maxLines {
		shown = lines[:maxLines]
	}
	for _, l := range shown {
		fmt.Fprintf(w, "      %s %s\n", marker, l)
	}
	if len(lines) > maxLines {
		fmt.Fprintf(w, "      %s ...[%d more]\n", c(dim, " "), len(lines)-maxLines)
	}
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func sevBadge(s finding.Severity) string {
	switch s {
	case finding.SevCritical:
		return c(red+bold, "[CRIT]")
	case finding.SevHigh:
		return c(red, "[HIGH]")
	case finding.SevMedium:
		return c(yellow, "[MED] ")
	case finding.SevLow:
		return c(cyan, "[LOW] ")
	}
	return c(dim, "[INFO]")
}

func riskDelta(prev, cur finding.Report) string {
	delta := cur.Summary.RiskScore - prev.Summary.RiskScore
	switch {
	case delta > 0:
		return c(red, fmt.Sprintf("+%d  (now %d, was %d)", delta, cur.Summary.RiskScore, prev.Summary.RiskScore))
	case delta < 0:
		return c(green, fmt.Sprintf("%d  (now %d, was %d)", delta, cur.Summary.RiskScore, prev.Summary.RiskScore))
	}
	return c(dim, fmt.Sprintf("0  (unchanged at %d)", cur.Summary.RiskScore))
}

func sortFindings(fs []finding.Finding) {
	sort.Slice(fs, func(i, j int) bool {
		return sevRank(fs[i].Meta.Severity) > sevRank(fs[j].Meta.Severity) ||
			(sevRank(fs[i].Meta.Severity) == sevRank(fs[j].Meta.Severity) &&
				strings.Compare(fs[i].Meta.ID, fs[j].Meta.ID) < 0)
	})
}

func sevRank(s finding.Severity) int {
	switch s {
	case finding.SevCritical:
		return 5
	case finding.SevHigh:
		return 4
	case finding.SevMedium:
		return 3
	case finding.SevLow:
		return 2
	case finding.SevInfo:
		return 1
	}
	return 0
}
