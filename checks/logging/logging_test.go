package logging

import (
	"strings"
	"testing"
)

func TestMissingAuditRules(t *testing.T) {
	t.Run("all present", func(t *testing.T) {
		rules := strings.Join(auditExpect, "\n")
		if m := missingAuditRules(rules); len(m) != 0 {
			t.Errorf("expected none missing, got %v", m)
		}
	})
	t.Run("some missing", func(t *testing.T) {
		rules := "-w /etc/passwd -p wa\n-w /etc/shadow -p wa\n"
		m := missingAuditRules(rules)
		// 6 expected - 2 present = 4 missing
		if len(m) != len(auditExpect)-2 {
			t.Errorf("got %d missing, want %d: %v", len(m), len(auditExpect)-2, m)
		}
	})
	t.Run("empty", func(t *testing.T) {
		if m := missingAuditRules(""); len(m) != len(auditExpect) {
			t.Errorf("got %d, want %d", len(m), len(auditExpect))
		}
	})
}

func TestHasRemoteForwarding(t *testing.T) {
	cases := map[string]bool{
		"*.* @@logserver:514":                          true, // rsyslog TCP
		"*.* @192.168.1.1:514":                         true, // rsyslog UDP to IP (@1)
		"*.* @203.0.113.5":                             true, // @2
		"destination d_net { tcp(\"h\" port(514)); };": true,
		"destination d { syslog(\"host\"); };":         true,
		"*.* /var/log/messages":                        false, // local only
		"":                                             false,
	}
	for in, want := range cases {
		if got := hasRemoteForwarding(in); got != want {
			t.Errorf("hasRemoteForwarding(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseJournaldKey(t *testing.T) {
	in := `# journald.conf
[Journal]
Storage=PERSISTENT
RateLimitBurst = 1000
`
	if v := parseJournaldKey(strings.NewReader(in), "Storage"); v != "persistent" {
		t.Errorf("Storage = %q, want persistent (lower-cased)", v)
	}
	if v := parseJournaldKey(strings.NewReader(in), "storage"); v != "persistent" {
		t.Errorf("case-insensitive key lookup failed: %q", v)
	}
	if v := parseJournaldKey(strings.NewReader(in), "RateLimitBurst"); v != "1000" {
		t.Errorf("RateLimitBurst = %q (whitespace around = should be trimmed)", v)
	}
	if v := parseJournaldKey(strings.NewReader(in), "Compress"); v != "" {
		t.Errorf("absent key should be empty, got %q", v)
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{
		0: "0", 7: "7", 42: "42", 100: "100", -5: "-5", -123: "-123",
	}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}
