package webdb

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type nginxTLSCheck struct{}

func (nginxTLSCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "webdb.nginx.tls",
		Title:    "nginx hides version, restricts protocols, and uses strong ciphers",
		Bucket:   "webdb",
		Severity: finding.SevHigh,
	}
}

var nginxConfRoots = []string{"/etc/nginx"}

func (nginxTLSCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	if _, err := os.Stat("/etc/nginx/nginx.conf"); err != nil {
		return finding.Finding{Status: finding.StatusSkipped, Message: "nginx not installed"}
	}
	contents := concatConfigs(nginxConfRoots, []string{".conf"})
	if contents == "" {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no nginx config readable"}
	}

	var bad []string
	if !regexp.MustCompile(`(?m)^\s*server_tokens\s+off\s*;`).MatchString(contents) {
		bad = append(bad, "server_tokens not set to off")
	}
	if m := regexp.MustCompile(`(?m)ssl_protocols\s+([^;]+);`).FindStringSubmatch(contents); len(m) > 1 {
		protos := strings.ToUpper(m[1])
		if strings.Contains(protos, "SSLV") || strings.Contains(protos, "TLSV1 ") || strings.Contains(protos, "TLSV1.0") || strings.Contains(protos, "TLSV1.1") {
			bad = append(bad, "ssl_protocols includes legacy: "+strings.TrimSpace(m[1]))
		}
	} else {
		bad = append(bad, "ssl_protocols not explicitly set")
	}
	if regexp.MustCompile(`(?i)ssl_ciphers\s+[^;]*(?:RC4|3DES|MD5|EXPORT|NULL)`).MatchString(contents) {
		bad = append(bad, "ssl_ciphers includes weak suite (RC4/3DES/MD5/EXPORT/NULL)")
	}
	if regexp.MustCompile(`(?i)add_header\s+strict-transport-security`).MatchString(contents) == false {
		bad = append(bad, "no Strict-Transport-Security header configured")
	}

	ev := evidence.Note("nginx config (concatenated)", truncate(contents, 4096))
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "nginx TLS posture OK", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Set server_tokens off, ssl_protocols TLSv1.2 TLSv1.3, modern ciphers, HSTS.",
		},
	}
}

func concatConfigs(roots, exts []string) string {
	var b strings.Builder
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			ok := false
			for _, e := range exts {
				if strings.HasSuffix(p, e) {
					ok = true
					break
				}
			}
			if !ok {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			fmt.Fprintf(&b, "# %s\n", p)
			b.Write(data)
			b.WriteString("\n")
			return nil
		})
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n...[truncated]"
}

func init() { engine.Register(nginxTLSCheck{}) }
