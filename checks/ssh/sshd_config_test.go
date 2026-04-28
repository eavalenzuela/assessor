package ssh

import (
	"strings"
	"testing"

	"github.com/t3rmit3/assessor/internal/finding"
)

func TestParseSshdConfig(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string]directiveValue
	}{
		{
			name: "basic",
			in:   "PermitRootLogin no\nPort 22\n",
			want: map[string]directiveValue{
				"permitrootlogin": {val: "no", line: 1},
				"port":            {val: "22", line: 2},
			},
		},
		{
			name: "comments and blanks ignored",
			in:   "# header\n\n   \nPasswordAuthentication yes\n#X11Forwarding no\n",
			want: map[string]directiveValue{
				"passwordauthentication": {val: "yes", line: 4},
			},
		},
		{
			name: "case-insensitive directive, multi-word value",
			in:   "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\nALLOWUSERS alice bob\n",
			want: map[string]directiveValue{
				"ciphers":    {val: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com", line: 1},
				"allowusers": {val: "alice bob", line: 2},
			},
		},
		{
			name: "lone directive ignored",
			in:   "Subsystem\n",
			want: map[string]directiveValue{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSshdConfig(strings.NewReader(tc.in))
			if len(got) != len(tc.want) {
				t.Fatalf("got %d directives, want %d (%v)", len(got), len(tc.want), got)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %+v, want %+v", k, got[k], v)
				}
			}
		})
	}
}

func TestEvaluateSshd(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantBad     int
		wantHighest finding.Severity
	}{
		{
			name: "all good",
			in: `PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 0
Protocol 2
LoginGraceTime 60
`,
			wantBad:     0,
			wantHighest: finding.SevInfo,
		},
		{
			name:        "empty password is critical",
			in:          "PermitEmptyPasswords yes\n",
			wantBad:     9,
			wantHighest: finding.SevCritical,
		},
		{
			name:        "root login worst-case",
			in:          "PermitRootLogin yes\nPasswordAuthentication no\nPermitEmptyPasswords no\nX11Forwarding no\nMaxAuthTries 4\nClientAliveInterval 300\nClientAliveCountMax 0\nProtocol 2\nLoginGraceTime 60\n",
			wantBad:     1,
			wantHighest: finding.SevHigh,
		},
		{
			name:        "missing directives counted",
			in:          "",
			wantBad:     9,
			wantHighest: finding.SevCritical,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSshdConfig(strings.NewReader(tc.in))
			bad, highest, _ := evaluateSshd(got)
			if len(bad) != tc.wantBad {
				t.Errorf("bad count = %d, want %d (%v)", len(bad), tc.wantBad, bad)
			}
			if highest != tc.wantHighest {
				t.Errorf("highest = %s, want %s", highest, tc.wantHighest)
			}
		})
	}
}
