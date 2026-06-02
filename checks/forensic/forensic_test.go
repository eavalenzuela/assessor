package forensic

import (
	"sort"
	"strings"
	"testing"
)

func TestParsePSPids(t *testing.T) {
	m := parsePSPids("  1\n  2\n 4242\nnotanumber\n")
	if len(m) != 3 || !m[1] || !m[2] || !m[4242] {
		t.Fatalf("got %v, want {1,2,4242}", m)
	}
}

func TestPidsOnlyIn(t *testing.T) {
	proc := map[int]bool{1: true, 2: true, 3: true, 4: true}
	ps := map[int]bool{1: true, 2: true}
	got := pidsOnlyIn(proc, ps)
	sort.Ints(got)
	if len(got) != 2 || got[0] != 3 || got[1] != 4 {
		t.Fatalf("got %v, want [3 4]", got)
	}
	if h := pidsOnlyIn(ps, proc); len(h) != 0 {
		t.Errorf("subset should yield nothing, got %v", h)
	}
}

func TestScanHistorySecrets(t *testing.T) {
	hist := `ls -la
export PASSWORD=hunter2
echo hello
aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
curl -H "Authorization: Bearer abcdefghij0123456789XYZ" https://api.example
git status
api_key=0123456789abcdefghABCDEF
`
	hits := scanHistorySecrets(strings.NewReader(hist), "/root/.bash_history")
	// password=, AKIA..., bearer ..., api_key=... => 4 hits.
	if len(hits) != 4 {
		t.Fatalf("got %d hits, want 4: %v", len(hits), hits)
	}
	for _, h := range hits {
		if !strings.HasPrefix(h, "/root/.bash_history:") {
			t.Errorf("hit missing path:line prefix: %q", h)
		}
		// The matched secret value must NOT be echoed in the hit metadata.
		if strings.Contains(h, "hunter2") || strings.Contains(h, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("hit leaked secret value: %q", h)
		}
	}
}

func TestScanHistorySecretsClean(t *testing.T) {
	clean := "ls\ncd /tmp\ngit pull\nmake test\n"
	if hits := scanHistorySecrets(strings.NewReader(clean), "/h/.bash_history"); len(hits) != 0 {
		t.Errorf("clean history flagged: %v", hits)
	}
}

func TestParseHistoryHomes(t *testing.T) {
	in := `root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000::/home/alice:/bin/bash
svc:x:200:200::/var/lib/svc:/usr/sbin/nologin
weird:x:1001:1001::/:/bin/zsh
bob:x:1002:1002::/home/bob:/bin/bash
`
	homes := parseHistoryHomes(strings.NewReader(in))
	sort.Strings(homes)
	// /root excluded (scanned separately), svc nologin, weird home "/".
	want := []string{"/home/alice", "/home/bob"}
	if len(homes) != len(want) || homes[0] != want[0] || homes[1] != want[1] {
		t.Fatalf("got %v, want %v", homes, want)
	}
}
