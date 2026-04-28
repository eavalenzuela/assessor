package crypto

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type certExpiryCheck struct{}

func (certExpiryCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "crypto.certs.expiry",
		Title:    "X.509 certs in /etc are not expired or near-expiry",
		Bucket:   "crypto",
		Severity: finding.SevHigh,
		Profiles: []string{"server"},
	}
}

func (certExpiryCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	roots := []string{"/etc/ssl", "/etc/pki", "/etc/letsencrypt"}
	var bad []string
	var evs []finding.Evidence
	now := time.Now()
	soon := now.Add(30 * 24 * time.Hour)
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(p, ".pem") && !strings.HasSuffix(p, ".crt") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			for {
				blk, rest := pem.Decode(b)
				if blk == nil {
					break
				}
				b = rest
				if blk.Type != "CERTIFICATE" {
					continue
				}
				c, err := x509.ParseCertificate(blk.Bytes)
				if err != nil {
					continue
				}
				if now.After(c.NotAfter) {
					bad = append(bad, fmt.Sprintf("EXPIRED %s (%s) on %s", c.Subject.CommonName, c.NotAfter.Format("2006-01-02"), p))
					evs = append(evs, evidence.Note(p, "expired: "+c.Subject.CommonName))
				} else if c.NotAfter.Before(soon) {
					bad = append(bad, fmt.Sprintf("expiring %s (%s) on %s", c.Subject.CommonName, c.NotAfter.Format("2006-01-02"), p))
					evs = append(evs, evidence.Note(p, "near expiry: "+c.Subject.CommonName))
				}
			}
			return nil
		})
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no expired or near-expiry certs in /etc"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  fmt.Sprintf("%d cert issue(s)", len(bad)),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Renew or remove expired certificates.",
		},
	}
}

func init() { engine.Register(certExpiryCheck{}) }
