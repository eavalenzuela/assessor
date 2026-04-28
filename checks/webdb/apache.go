package webdb

import (
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type apacheTLSCheck struct{}

func (apacheTLSCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "webdb.apache.tls",
		Title:    "Apache hides version, restricts SSL protocols, uses strong ciphers",
		Bucket:   "webdb",
		Severity: finding.SevHigh,
	}
}

func (apacheTLSCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	roots := []string{"/etc/apache2", "/etc/httpd"}
	var existing []string
	for _, r := range roots {
		if _, err := os.Stat(r); err == nil {
			existing = append(existing, r)
		}
	}
	if len(existing) == 0 {
		return finding.Finding{Status: finding.StatusSkipped, Message: "apache not installed"}
	}
	contents := concatConfigs(existing, []string{".conf"})
	if contents == "" {
		return finding.Finding{Status: finding.StatusSkipped, Message: "no apache config readable"}
	}

	var bad []string
	if !regexp.MustCompile(`(?mi)^\s*ServerTokens\s+(Prod|ProductOnly)`).MatchString(contents) {
		bad = append(bad, "ServerTokens not set to Prod")
	}
	if !regexp.MustCompile(`(?mi)^\s*ServerSignature\s+Off`).MatchString(contents) {
		bad = append(bad, "ServerSignature not Off")
	}
	if m := regexp.MustCompile(`(?mi)^\s*SSLProtocol\s+([^\n]+)`).FindStringSubmatch(contents); len(m) > 1 {
		v := strings.ToLower(m[1])
		if strings.Contains(v, "sslv") || strings.Contains(v, "+tlsv1 ") || strings.Contains(v, "+tlsv1.1") || strings.Contains(v, "all -ssl") && !strings.Contains(v, "-tlsv1.1") {
			bad = append(bad, "SSLProtocol allows legacy: "+strings.TrimSpace(m[1]))
		}
	} else {
		bad = append(bad, "SSLProtocol not explicitly set")
	}
	if regexp.MustCompile(`(?i)SSLCipherSuite\s+[^\n]*(RC4|3DES|MD5|EXPORT|NULL)`).MatchString(contents) {
		bad = append(bad, "SSLCipherSuite includes weak suite")
	}

	ev := evidence.Note("apache config (concatenated)", truncate(contents, 4096))
	if len(bad) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "apache TLS posture OK", Evidence: []finding.Evidence{ev}}
	}
	return finding.Finding{
		Status:   finding.StatusFail,
		Message:  strings.Join(bad, "; "),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "Set ServerTokens Prod, ServerSignature Off, SSLProtocol -all +TLSv1.2 +TLSv1.3, modern ciphers.",
		},
	}
}

func init() { engine.Register(apacheTLSCheck{}) }
