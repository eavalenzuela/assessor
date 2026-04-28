package baseline

import (
	"testing"

	"github.com/t3rmit3/assessor/internal/finding"
)

func mkReport(states map[string]finding.Status) finding.Report {
	r := finding.Report{}
	for id, st := range states {
		r.Findings = append(r.Findings, finding.Finding{
			Meta:   finding.Metadata{ID: id},
			Status: st,
		})
	}
	return r
}

func mkFindingWithEvidence(id string, st finding.Status, evs ...finding.Evidence) finding.Finding {
	return finding.Finding{
		Meta:     finding.Metadata{ID: id},
		Status:   st,
		Evidence: evs,
	}
}

func TestCompare(t *testing.T) {
	prev := mkReport(map[string]finding.Status{
		"a.fail":      finding.StatusFail,
		"b.pass":      finding.StatusPass,
		"c.warn":      finding.StatusWarn,
		"d.gone_next": finding.StatusFail,
	})
	cur := mkReport(map[string]finding.Status{
		"a.fail":     finding.StatusPass, // resolved
		"b.pass":     finding.StatusFail, // new fail
		"c.warn":     finding.StatusWarn, // unchanged
		"e.new_pass": finding.StatusPass, // brand new, but pass — not a new fail
		"f.new_fail": finding.StatusFail, // brand new fail
	})

	d := Compare(prev, cur)

	wantNewFailIDs := map[string]bool{"b.pass": true, "f.new_fail": true}
	if len(d.NewFails) != len(wantNewFailIDs) {
		t.Fatalf("NewFails count = %d, want %d (%+v)", len(d.NewFails), len(wantNewFailIDs), d.NewFails)
	}
	for _, f := range d.NewFails {
		if !wantNewFailIDs[f.Meta.ID] {
			t.Errorf("unexpected new fail: %s", f.Meta.ID)
		}
	}

	if len(d.ResolvedFails) != 1 || d.ResolvedFails[0].Meta.ID != "a.fail" {
		t.Errorf("ResolvedFails = %+v, want [a.fail]", d.ResolvedFails)
	}

	statusChangeIDs := map[string]bool{}
	for _, sc := range d.StatusChanges {
		statusChangeIDs[sc.ID] = true
	}
	for _, want := range []string{"a.fail", "b.pass"} {
		if !statusChangeIDs[want] {
			t.Errorf("missing status change for %s", want)
		}
	}
}

func TestEvidenceDiff(t *testing.T) {
	tracked := func(src, content string) finding.Evidence {
		return finding.Evidence{Kind: "note", Source: src, Content: content, Tracked: true}
	}
	untracked := func(src, content string) finding.Evidence {
		return finding.Evidence{Kind: "note", Source: src, Content: content}
	}

	prev := finding.Report{Findings: []finding.Finding{
		mkFindingWithEvidence("fs.suid", finding.StatusWarn,
			tracked("walk", "/usr/bin/sudo\n/usr/bin/passwd")),
		mkFindingWithEvidence("noisy", finding.StatusPass,
			untracked("ps", "1234 systemd\n5678 cron")),
	}}
	cur := finding.Report{Findings: []finding.Finding{
		mkFindingWithEvidence("fs.suid", finding.StatusWarn,
			tracked("walk", "/usr/bin/sudo\n/tmp/sketch")),
		mkFindingWithEvidence("noisy", finding.StatusPass,
			untracked("ps", "9999 systemd\n8888 cron")),
	}}
	d := Compare(prev, cur)

	if len(d.EvidenceChanges) != 1 {
		t.Fatalf("got %d evidence changes, want 1 (untracked must be ignored)", len(d.EvidenceChanges))
	}
	ec := d.EvidenceChanges[0]
	if ec.FindingID != "fs.suid" {
		t.Errorf("FindingID = %q, want fs.suid", ec.FindingID)
	}
	if len(ec.Added) != 1 || ec.Added[0] != "/tmp/sketch" {
		t.Errorf("Added = %v, want [/tmp/sketch]", ec.Added)
	}
	if len(ec.Removed) != 1 || ec.Removed[0] != "/usr/bin/passwd" {
		t.Errorf("Removed = %v, want [/usr/bin/passwd]", ec.Removed)
	}
}

func TestEvidenceDiff_NoChange(t *testing.T) {
	tracked := func(src, content string) finding.Evidence {
		return finding.Evidence{Kind: "note", Source: src, Content: content, Tracked: true}
	}
	prev := finding.Report{Findings: []finding.Finding{
		mkFindingWithEvidence("inv", finding.StatusWarn,
			tracked("walk", "a\nb\nc")),
	}}
	// Same set, different order, with whitespace noise — should not produce a diff.
	cur := finding.Report{Findings: []finding.Finding{
		mkFindingWithEvidence("inv", finding.StatusWarn,
			tracked("walk", " c \nb\n  a")),
	}}
	d := Compare(prev, cur)
	if len(d.EvidenceChanges) != 0 {
		t.Errorf("got %d evidence changes, want 0; %+v", len(d.EvidenceChanges), d.EvidenceChanges)
	}
}
