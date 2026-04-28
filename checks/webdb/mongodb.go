package webdb

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type mongoCheck struct{}

func (mongoCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "webdb.mongodb.auth_bind",
		Title:    "MongoDB has authorization enabled and is not bound to all interfaces",
		Bucket:   "webdb",
		Severity: finding.SevCritical,
	}
}

func (mongoCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const path = "/etc/mongod.conf"
	f, err := os.Open(path)
	if err != nil {
		return finding.Finding{Status: finding.StatusSkipped, Message: "mongod.conf not found"}
	}
	defer f.Close()

	// mongod.conf is YAML; we do a flat string scan to avoid pulling YAML for one check.
	var bind, auth string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "bindIp:") {
			bind = strings.TrimSpace(strings.TrimPrefix(l, "bindIp:"))
		}
		if strings.HasPrefix(l, "authorization:") {
			auth = strings.TrimSpace(strings.TrimPrefix(l, "authorization:"))
		}
	}
	ev, _ := evidence.File(path)
	var bad []string
	if bind == "" || strings.Contains(bind, "0.0.0.0") {
		bad = append(bad, "bindIp missing or includes 0.0.0.0")
	}
	if !strings.EqualFold(auth, "enabled") {
		bad = append(bad, "authorization != enabled")
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "mongodb config OK", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Set bindIp to 127.0.0.1 (or specific iface) and security.authorization: enabled.",
		},
	}
}

func init() { engine.Register(mongoCheck{}) }
