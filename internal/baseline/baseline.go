package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/t3rmit3/assessor/internal/finding"
)

const DefaultDir = "/var/lib/assessor"

func Save(dir string, r finding.Report) (string, error) {
	if dir == "" {
		dir = DefaultDir
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	name := fmt.Sprintf("snapshot-%s.json", r.StartedAt.UTC().Format("20060102T150405Z"))
	path := filepath.Join(dir, name)
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o640); err != nil {
		return "", err
	}
	return path, nil
}

func Load(path string) (finding.Report, error) {
	var r finding.Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(b, &r)
}

func Latest(dir string) (string, error) {
	if dir == "" {
		dir = DefaultDir
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var newest string
	var newestTime time.Time
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newestTime) {
			newestTime = info.ModTime()
			newest = filepath.Join(dir, e.Name())
		}
	}
	if newest == "" {
		return "", fmt.Errorf("no snapshots in %s", dir)
	}
	return newest, nil
}

type Diff struct {
	NewFails        []finding.Finding `json:"new_fails"`
	ResolvedFails   []finding.Finding `json:"resolved_fails"`
	StatusChanges   []StatusChange    `json:"status_changes"`
	EvidenceChanges []EvidenceChange  `json:"evidence_changes,omitempty"`
}

type StatusChange struct {
	ID   string         `json:"id"`
	From finding.Status `json:"from"`
	To   finding.Status `json:"to"`
}

// EvidenceChange records line-level adds/removes against a tracked
// evidence Source within a single finding.
type EvidenceChange struct {
	FindingID string   `json:"finding_id"`
	Source    string   `json:"source"`
	Added     []string `json:"added,omitempty"`
	Removed   []string `json:"removed,omitempty"`
}

func Compare(prev, cur finding.Report) Diff {
	prevMap := indexByID(prev.Findings)
	curMap := indexByID(cur.Findings)
	var d Diff
	for id, f := range curMap {
		p, ok := prevMap[id]
		if !ok {
			if f.Status == finding.StatusFail {
				d.NewFails = append(d.NewFails, f)
			}
			continue
		}
		if p.Status != f.Status {
			d.StatusChanges = append(d.StatusChanges, StatusChange{ID: id, From: p.Status, To: f.Status})
			if p.Status != finding.StatusFail && f.Status == finding.StatusFail {
				d.NewFails = append(d.NewFails, f)
			}
			if p.Status == finding.StatusFail && f.Status != finding.StatusFail {
				d.ResolvedFails = append(d.ResolvedFails, f)
			}
		}
		if changes := diffEvidence(id, p, f); len(changes) > 0 {
			d.EvidenceChanges = append(d.EvidenceChanges, changes...)
		}
	}
	return d
}

// diffEvidence returns line-level adds/removes for every Tracked evidence
// Source that appears in either prev or cur. Untracked evidence is ignored
// to keep noise out of the report (transient command output, timestamps).
func diffEvidence(id string, prev, cur finding.Finding) []EvidenceChange {
	prevByKey := trackedByKey(prev.Evidence)
	curByKey := trackedByKey(cur.Evidence)
	if len(prevByKey) == 0 && len(curByKey) == 0 {
		return nil
	}
	keys := map[string]struct{}{}
	for k := range prevByKey {
		keys[k] = struct{}{}
	}
	for k := range curByKey {
		keys[k] = struct{}{}
	}
	var out []EvidenceChange
	for k := range keys {
		added, removed := diffLines(prevByKey[k], curByKey[k])
		if len(added) == 0 && len(removed) == 0 {
			continue
		}
		out = append(out, EvidenceChange{
			FindingID: id,
			Source:    k,
			Added:     added,
			Removed:   removed,
		})
	}
	return out
}

func trackedByKey(evs []finding.Evidence) map[string]string {
	m := map[string]string{}
	for _, e := range evs {
		if !e.Tracked {
			continue
		}
		m[e.Source] = e.Content
	}
	return m
}

// diffLines returns lines present in cur but not prev (added) and in prev but
// not cur (removed). Order-insensitive set comparison; whitespace-only lines
// are ignored.
func diffLines(prev, cur string) (added, removed []string) {
	prevSet := lineSet(prev)
	curSet := lineSet(cur)
	for line := range curSet {
		if !prevSet[line] {
			added = append(added, line)
		}
	}
	for line := range prevSet {
		if !curSet[line] {
			removed = append(removed, line)
		}
	}
	return added, removed
}

func lineSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, line := range splitLines(s) {
		t := stripSpace(line)
		if t == "" {
			continue
		}
		m[t] = true
	}
	return m
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func stripSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}

func indexByID(fs []finding.Finding) map[string]finding.Finding {
	m := make(map[string]finding.Finding, len(fs))
	for _, f := range fs {
		m[f.Meta.ID] = f
	}
	return m
}
