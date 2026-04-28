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
