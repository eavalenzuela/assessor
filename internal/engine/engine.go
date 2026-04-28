package engine

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/profiles"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type Check interface {
	Meta() finding.Metadata
	Run(ctx context.Context, facts sysfacts.Facts) finding.Finding
}

var registry []Check
var regMu sync.Mutex

func Register(c Check) {
	regMu.Lock()
	defer regMu.Unlock()
	registry = append(registry, c)
}

func All() []Check {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]Check, len(registry))
	copy(out, registry)
	return out
}

type Options struct {
	Profile     string
	ProfileDef  *profiles.Profile
	Buckets     []string
	IDs         []string
	Parallelism int
	Version     string
}

func RequireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("assessor requires root (try: sudo assessor)")
	}
	return nil
}

func Run(ctx context.Context, opts Options) (finding.Report, error) {
	facts := sysfacts.Gather(opts.Version)
	checks := filter(All(), opts)
	if opts.Parallelism <= 0 {
		opts.Parallelism = 8
	}

	report := finding.Report{
		Host:      facts.Host,
		StartedAt: time.Now(),
		Profile:   opts.Profile,
	}

	results := make([]finding.Finding, len(checks))
	sem := make(chan struct{}, opts.Parallelism)
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, c Check) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					results[i] = finding.Finding{
						Meta:   c.Meta(),
						Status: finding.StatusError,
						Err:    fmt.Sprintf("panic: %v", r),
					}
				}
			}()
			start := time.Now()
			f := c.Run(ctx, facts)
			f.Meta = c.Meta()
			f.StartedAt = start
			f.Duration = time.Since(start).String()
			results[i] = f
		}(i, c)
	}
	wg.Wait()

	report.Findings = results
	report.FinishedAt = time.Now()
	report.Summary = summarize(results)
	sort.SliceStable(report.Findings, func(i, j int) bool {
		return sevRank(report.Findings[i].Meta.Severity) > sevRank(report.Findings[j].Meta.Severity)
	})
	return report, nil
}

func filter(in []Check, opts Options) []Check {
	out := in[:0:0]
	bucketSet := toSet(opts.Buckets)
	idSet := toSet(opts.IDs)
	for _, c := range in {
		m := c.Meta()
		if len(bucketSet) > 0 && !bucketSet[m.Bucket] {
			continue
		}
		if len(idSet) > 0 && !idSet[m.ID] {
			continue
		}
		// Profile filtering: if a structured ProfileDef was loaded, defer to it;
		// otherwise fall back to inline metadata matching by Profile name.
		if opts.ProfileDef != nil {
			if !opts.ProfileDef.Match(m) {
				continue
			}
		} else if opts.Profile != "" && len(m.Profiles) > 0 {
			ok := false
			for _, p := range m.Profiles {
				if p == opts.Profile {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func toSet(s []string) map[string]bool {
	if len(s) == 0 {
		return nil
	}
	m := make(map[string]bool, len(s))
	for _, x := range s {
		m[x] = true
	}
	return m
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

func summarize(fs []finding.Finding) finding.Summary {
	s := finding.Summary{
		Total:      len(fs),
		ByStatus:   map[finding.Status]int{},
		BySeverity: map[finding.Severity]int{},
	}
	for _, f := range fs {
		s.ByStatus[f.Status]++
		if f.Status == finding.StatusFail {
			s.BySeverity[f.Meta.Severity]++
			s.RiskScore += sevRank(f.Meta.Severity) * 2
		} else if f.Status == finding.StatusWarn {
			s.BySeverity[f.Meta.Severity]++
			s.RiskScore += sevRank(f.Meta.Severity)
		}
	}
	return s
}
