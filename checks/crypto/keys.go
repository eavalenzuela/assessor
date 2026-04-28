package crypto

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type weakKeysCheck struct{}

func (weakKeysCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "crypto.keys.weak",
		Title:    "No weak (small or deprecated) keys in /etc/ssl and /etc/pki",
		Bucket:   "crypto",
		Severity: finding.SevHigh,
		Profiles: []string{"server"},
	}
}

func (weakKeysCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	roots := []string{"/etc/ssl", "/etc/pki"}
	var bad []string
	var evs []finding.Evidence
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(p, ".pem") && !strings.HasSuffix(p, ".crt") && !strings.HasSuffix(p, ".key") {
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
				switch blk.Type {
				case "CERTIFICATE":
					c, err := x509.ParseCertificate(blk.Bytes)
					if err != nil {
						continue
					}
					if k, ok := c.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
						bad = append(bad, fmt.Sprintf("%s: cert %s RSA %d", p, c.Subject.CommonName, k.N.BitLen()))
						evs = append(evs, evidence.Note(p, fmt.Sprintf("RSA %d", k.N.BitLen())))
					}
					if c.SignatureAlgorithm == x509.MD5WithRSA || c.SignatureAlgorithm == x509.SHA1WithRSA {
						bad = append(bad, fmt.Sprintf("%s: weak sig %s", p, c.SignatureAlgorithm))
					}
				case "RSA PRIVATE KEY":
					k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
					if err != nil {
						continue
					}
					if k.N.BitLen() < 2048 {
						bad = append(bad, fmt.Sprintf("%s: RSA private %d bits", p, k.N.BitLen()))
						evs = append(evs, evidence.Note(p, fmt.Sprintf("RSA private %d", k.N.BitLen())))
					}
				}
			}
			return nil
		})
	}
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no weak keys found"}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: evs,
		Remediation: finding.Remediation{
			Description: "Reissue affected certs/keys with RSA >= 2048 (or ECDSA P-256+) and SHA-256+.",
		},
	}
}

func init() { engine.Register(weakKeysCheck{}) }
