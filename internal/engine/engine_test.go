package engine

import (
	"context"
	"testing"

	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type fakeCheck struct {
	meta   finding.Metadata
	status finding.Status
}

func (f fakeCheck) Meta() finding.Metadata { return f.meta }
func (f fakeCheck) Run(_ context.Context, _ sysfacts.Facts) finding.Finding {
	return finding.Finding{Status: f.status}
}

func TestFilter(t *testing.T) {
	checks := []Check{
		fakeCheck{meta: finding.Metadata{ID: "a.1", Bucket: "auth", Profiles: []string{"server"}}},
		fakeCheck{meta: finding.Metadata{ID: "k.1", Bucket: "kernel", Profiles: []string{"server", "cis-l1"}}},
		fakeCheck{meta: finding.Metadata{ID: "n.1", Bucket: "network"}}, // no profile = always-on
	}

	cases := []struct {
		name string
		opts Options
		want []string
	}{
		{name: "no filter", opts: Options{}, want: []string{"a.1", "k.1", "n.1"}},
		{name: "bucket filter", opts: Options{Buckets: []string{"kernel"}}, want: []string{"k.1"}},
		{name: "id filter", opts: Options{IDs: []string{"a.1", "n.1"}}, want: []string{"a.1", "n.1"}},
		{name: "profile filter excludes non-matching", opts: Options{Profile: "cis-l1"}, want: []string{"k.1", "n.1"}},
		{name: "profile + bucket combined", opts: Options{Profile: "server", Buckets: []string{"auth"}}, want: []string{"a.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filter(checks, tc.opts)
			ids := []string{}
			for _, c := range got {
				ids = append(ids, c.Meta().ID)
			}
			if len(ids) != len(tc.want) {
				t.Fatalf("ids = %v, want %v", ids, tc.want)
			}
			seen := map[string]bool{}
			for _, id := range ids {
				seen[id] = true
			}
			for _, w := range tc.want {
				if !seen[w] {
					t.Errorf("missing %s", w)
				}
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	fs := []finding.Finding{
		{Meta: finding.Metadata{Severity: finding.SevCritical}, Status: finding.StatusFail},
		{Meta: finding.Metadata{Severity: finding.SevHigh}, Status: finding.StatusFail},
		{Meta: finding.Metadata{Severity: finding.SevMedium}, Status: finding.StatusWarn},
		{Status: finding.StatusPass},
		{Status: finding.StatusSkipped},
	}
	s := summarize(fs)
	if s.Total != 5 {
		t.Errorf("Total = %d, want 5", s.Total)
	}
	if s.ByStatus[finding.StatusFail] != 2 || s.ByStatus[finding.StatusPass] != 1 {
		t.Errorf("ByStatus = %+v", s.ByStatus)
	}
	// Crit fail (5*2=10) + High fail (4*2=8) + Med warn (3*1=3) = 21
	if s.RiskScore != 21 {
		t.Errorf("RiskScore = %d, want 21", s.RiskScore)
	}
}

func TestSevRankOrdering(t *testing.T) {
	order := []finding.Severity{
		finding.SevInfo, finding.SevLow, finding.SevMedium, finding.SevHigh, finding.SevCritical,
	}
	for i := 1; i < len(order); i++ {
		if sevRank(order[i]) <= sevRank(order[i-1]) {
			t.Errorf("sevRank not monotonic at %s vs %s", order[i-1], order[i])
		}
	}
}

func TestRunPanicRecovery(t *testing.T) {
	registry = nil
	Register(panickyCheck{})
	rep, err := Run(context.Background(), Options{Parallelism: 1, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings", len(rep.Findings))
	}
	if rep.Findings[0].Status != finding.StatusError {
		t.Errorf("status = %s, want error", rep.Findings[0].Status)
	}
}

type panickyCheck struct{}

func (panickyCheck) Meta() finding.Metadata { return finding.Metadata{ID: "p.1", Bucket: "x"} }
func (panickyCheck) Run(_ context.Context, _ sysfacts.Facts) finding.Finding {
	panic("boom")
}
