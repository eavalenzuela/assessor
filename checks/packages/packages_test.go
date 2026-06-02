package packages

import (
	"testing"
	"time"

	"github.com/t3rmit3/assessor/internal/finding"
)

func TestParseTabbed(t *testing.T) {
	in := "openssl\t3.0.13-1ubuntu1\ncurl\t8.5.0-2\n\nbroken-no-tab\n\temptyname\n"
	pkgs := parseTabbed(in, "deb")
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "openssl" || pkgs[0].Version != "3.0.13-1ubuntu1" || pkgs[0].Ecosystem != "deb" {
		t.Errorf("pkg[0] = %+v", pkgs[0])
	}
}

func TestParsePacman(t *testing.T) {
	in := "openssl 3.0.13-1\nlinux 6.6.10.arch1-1\nbad\n"
	pkgs := parsePacman(in)
	if len(pkgs) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(pkgs), pkgs)
	}
	if pkgs[1].Name != "linux" || pkgs[1].Version != "6.6.10.arch1-1" || pkgs[1].Ecosystem != "Arch" {
		t.Errorf("pkg[1] = %+v", pkgs[1])
	}
}

func TestParseApk(t *testing.T) {
	in := "musl-1.2.4-r2 - the musl c library\nbusybox-1.36.1-r5 - size optimized toolbox\nnodescription\n"
	pkgs := parseApk(in)
	if len(pkgs) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(pkgs), pkgs)
	}
	// Name/version split is the LAST hyphen before " - ", so version keeps the
	// alpine release suffix r2.
	if pkgs[0].Name != "musl-1.2.4" || pkgs[0].Version != "r2" {
		t.Errorf("apk split unexpected: %+v", pkgs[0])
	}
	if pkgs[0].Ecosystem != "Alpine" {
		t.Errorf("ecosystem = %q", pkgs[0].Ecosystem)
	}
}

func TestCountAptUpgrades(t *testing.T) {
	out := `Reading package lists...
Inst libssl3 [3.0.2-0ubuntu1.12] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])
Inst tzdata [2024a] (2024b-0ubuntu0.22.04 Ubuntu:22.04/jammy-updates [all])
Inst curl [7.81.0] (7.81.0-1ubuntu1.16 Ubuntu:22.04/jammy-security [amd64])
Conf libssl3 (3.0.2-0ubuntu1.15)
`
	up, sec := countAptUpgrades(out)
	if up != 3 {
		t.Errorf("upgrades = %d, want 3", up)
	}
	if sec != 2 {
		t.Errorf("security = %d, want 2", sec)
	}
}

func TestCountDnfUpdates(t *testing.T) {
	out := `Last metadata expiration check: 0:10:00 ago on Mon.

openssl.x86_64    1:3.0.7-27.el9    baseos
kernel.x86_64     5.14.0-427.el9    baseos
`
	if n := countDnfUpdates(out); n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
}

func TestEvaluateEOL(t *testing.T) {
	// Ubuntu 22.04 EOL is 2027-04-30 in distroEOL.
	cases := []struct {
		name    string
		id, ver string
		now     time.Time
		want    finding.Status
	}{
		{"supported", "ubuntu", "22.04", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), finding.StatusPass},
		{"within 90 days", "ubuntu", "22.04", time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC), finding.StatusWarn},
		{"past eol", "ubuntu", "20.04", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), finding.StatusFail},
		{"unknown distro", "gentoo", "2.0", time.Now(), finding.StatusUnverified},
		{"unknown version", "ubuntu", "18.04", time.Now(), finding.StatusUnverified},
		{"empty id", "", "", time.Now(), finding.StatusUnverified},
		{"case-insensitive id", "Ubuntu", "22.04", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), finding.StatusPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, msg := evaluateEOL(tc.id, tc.ver, tc.now)
			if got != tc.want {
				t.Errorf("evaluateEOL(%q,%q) = %s (%q), want %s", tc.id, tc.ver, got, msg, tc.want)
			}
		})
	}
}

func TestRebootPending(t *testing.T) {
	cases := []struct {
		running, newest string
		want            bool
	}{
		{"6.17.0-22-generic", "6.17.0-22-generic", false},             // identical
		{"6.17.0-22-generic", "6.17.0-25-generic", true},              // newer installed
		{"6.17.0-22-generic", "linux-image-6.17.0-22-generic", false}, // wrapped name contains running
		{"6.17.0-22", "6.17.0-22-generic", false},                     // running is prefix of newest
		{"6.17.0-25-generic", "6.17.0-22-generic", true},              // divergent
	}
	for _, tc := range cases {
		if got := rebootPending(tc.running, tc.newest); got != tc.want {
			t.Errorf("rebootPending(%q, %q) = %v, want %v", tc.running, tc.newest, got, tc.want)
		}
	}
}

func TestScanAptTrusted(t *testing.T) {
	content := `# main repo
deb https://example.com/ubuntu jammy main
deb [trusted=yes] https://sketchy.example/ubuntu jammy main
# deb [trusted=yes] commented-out should be ignored
deb [arch=amd64 trusted=yes] https://other.example jammy main
`
	bad, evs := scanAptTrusted(content, "/etc/apt/sources.list")
	if len(bad) != 2 {
		t.Fatalf("got %d trusted=yes lines, want 2: %v", len(bad), bad)
	}
	if len(evs) != len(bad) {
		t.Errorf("evidence count %d != bad %d", len(evs), len(bad))
	}
}

func TestScanDnfGpgcheck(t *testing.T) {
	content := `[baseos]
name=BaseOS
gpgcheck=1
[sketchy]
name=Sketchy
gpgcheck = 0
[other]
gpgcheck=0
`
	bad, _ := scanDnfGpgcheck(content, "/etc/yum.repos.d/test.repo")
	// Both "gpgcheck = 0" (spaces) and "gpgcheck=0" count; gpgcheck=1 does not.
	if len(bad) != 2 {
		t.Fatalf("got %d gpgcheck=0 lines, want 2: %v", len(bad), bad)
	}
}

func TestMapSevAndRank(t *testing.T) {
	// mapSev maps cve severities onto finding severities; sevRank orders them.
	if sevRank(mapSev("critical")) <= sevRank(mapSev("high")) {
		t.Error("critical should outrank high")
	}
	if sevRank(mapSev("high")) <= sevRank(mapSev("medium")) {
		t.Error("high should outrank medium")
	}
	if mapSev("nonsense") != finding.SevInfo {
		t.Errorf("unknown severity should map to info, got %s", mapSev("nonsense"))
	}
}
