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
	NewFails      []finding.Finding `json:"new_fails"`
	ResolvedFails []finding.Finding `json:"resolved_fails"`
	StatusChanges []StatusChange    `json:"status_changes"`
}

type StatusChange struct {
	ID   string         `json:"id"`
	From finding.Status `json:"from"`
	To   finding.Status `json:"to"`
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
	}
	return d
}

func indexByID(fs []finding.Finding) map[string]finding.Finding {
	m := make(map[string]finding.Finding, len(fs))
	for _, f := range fs {
		m[f.Meta.ID] = f
	}
	return m
}
