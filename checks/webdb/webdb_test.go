package webdb

import (
	"strings"
	"testing"

	"github.com/t3rmit3/assessor/internal/finding"
)

func TestIsLoopbackOnly(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":             true,
		"::1":                   true,
		"127.0.0.1 ::1":         true,
		"0.0.0.0":               false,
		"127.0.0.1 192.168.1.5": false,
		"::":                    false,
		"":                      true, // no hosts -> vacuously loopback-only
	}
	for bind, want := range cases {
		if got := isLoopbackOnly(bind); got != want {
			t.Errorf("isLoopbackOnly(%q) = %v, want %v", bind, got, want)
		}
	}
}

func TestEvaluateRedis(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]string
		want finding.Status
	}{
		{"loopback bind", map[string]string{"bind": "127.0.0.1"}, finding.StatusPass},
		{"no bind", map[string]string{}, finding.StatusPass},
		{"external bind no auth", map[string]string{"bind": "0.0.0.0"}, finding.StatusFail},
		{"external bind protected only", map[string]string{"bind": "0.0.0.0", "protected-mode": "yes"}, finding.StatusFail},
		{"external bind pass only", map[string]string{"bind": "0.0.0.0", "requirepass": "s3cret"}, finding.StatusFail},
		{"external bind fully locked", map[string]string{"bind": "0.0.0.0", "protected-mode": "yes", "requirepass": "s3cret"}, finding.StatusPass},
		{"external bind protected uppercase", map[string]string{"bind": "10.0.0.5", "protected-mode": "YES", "requirepass": "s3cret"}, finding.StatusPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, msg := evaluateRedis(tc.cfg)
			if got != tc.want {
				t.Errorf("evaluateRedis(%v) = %s (%q), want %s", tc.cfg, got, msg, tc.want)
			}
		})
	}
}

func TestEvaluateMysqlBind(t *testing.T) {
	cases := map[string]finding.Status{
		"":          finding.StatusWarn,
		"0.0.0.0":   finding.StatusFail,
		"::":        finding.StatusFail,
		"127.0.0.1": finding.StatusPass,
		"10.0.0.5":  finding.StatusPass,
	}
	for bind, want := range cases {
		if got, _ := evaluateMysqlBind(bind); got != want {
			t.Errorf("evaluateMysqlBind(%q) = %s, want %s", bind, got, want)
		}
	}
}

func TestParseKV(t *testing.T) {
	in := `# redis.conf
bind 127.0.0.1 ::1
protected-mode yes
requirepass "p a s s"

# comment
maxmemory 256mb
`
	m := parseKV(strings.NewReader(in))
	if m["bind"] != "127.0.0.1 ::1" {
		t.Errorf("bind = %q", m["bind"])
	}
	if m["protected-mode"] != "yes" {
		t.Errorf("protected-mode = %q", m["protected-mode"])
	}
	if m["requirepass"] != "p a s s" { // surrounding quotes stripped
		t.Errorf("requirepass = %q", m["requirepass"])
	}
	if _, ok := m["comment"]; ok {
		t.Error("comment line should be skipped")
	}
}

func TestParseINIValue(t *testing.T) {
	in := `[mysqld]
; a comment
# another
bind-address = 127.0.0.1
port = 3306
`
	if got := parseINIValue(strings.NewReader(in), "bind-address"); got != "127.0.0.1" {
		t.Errorf("bind-address = %q, want 127.0.0.1", got)
	}
	if got := parseINIValue(strings.NewReader(in), "BIND-ADDRESS"); got != "127.0.0.1" {
		t.Errorf("case-insensitive lookup failed: %q", got)
	}
	if got := parseINIValue(strings.NewReader(in), "missing"); got != "" {
		t.Errorf("absent key should return empty, got %q", got)
	}
}

func TestScanPgHbaTrust(t *testing.T) {
	in := `# TYPE  DATABASE  USER  ADDRESS        METHOD
local   all       all                  trust
host    all       all   127.0.0.1/32   trust
host    all       all   0.0.0.0/0      scram-sha-256
hostssl all       all   10.0.0.0/8     trust
`
	bad, evs := scanPgHbaTrust(strings.NewReader(in), "/etc/postgresql/pg_hba.conf")
	// Two risky entries: the `host ... trust` and `hostssl ... trust`.
	// The `local ... trust` is acceptable (Unix peer); scram line is fine.
	if len(bad) != 2 {
		t.Fatalf("got %d risky entries, want 2: %v", len(bad), bad)
	}
	if len(evs) != len(bad) {
		t.Errorf("evidence count %d != bad count %d", len(evs), len(bad))
	}
	for _, b := range bad {
		if !strings.Contains(b, "trust") {
			t.Errorf("bad entry missing trust: %q", b)
		}
	}
}
