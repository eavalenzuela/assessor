package auth

import (
	"strings"
	"testing"
)

func TestScanUIDZero(t *testing.T) {
	passwd := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
toor:x:0:0:backdoor:/root:/bin/bash
alice:x:1000:1000::/home/alice:/bin/bash
malformed-line-no-colons
`
	roots, evs := scanUIDZero(strings.NewReader(passwd), "/etc/passwd")
	if len(roots) != 2 {
		t.Fatalf("got %d UID-0 accounts, want 2: %v", len(roots), roots)
	}
	if roots[0] != "root" || roots[1] != "toor" {
		t.Errorf("roots = %v, want [root toor]", roots)
	}
	if len(evs) != 2 {
		t.Errorf("evidence count = %d, want 2", len(evs))
	}
}

func TestScanEmptyPasswords(t *testing.T) {
	shadow := `root:$6$abc...:19000:0:99999:7:::
nobody::19000:0:99999:7:::
alice:!:19000:0:99999:7:::
bob:$6$xyz:19000:0:99999:7:::
short
`
	bad, evs := scanEmptyPasswords(strings.NewReader(shadow), "/etc/shadow")
	if len(bad) != 1 || bad[0] != "nobody" {
		t.Fatalf("got %v, want [nobody]", bad)
	}
	if len(evs) != 1 {
		t.Errorf("evidence count = %d, want 1", len(evs))
	}
}

func TestParseLoginDefs(t *testing.T) {
	in := `# comment
PASS_MAX_DAYS	90
pass_min_days 7
UMASK 027

ENCRYPT_METHOD SHA512
`
	got := parseLoginDefs(strings.NewReader(in))
	if got["PASS_MAX_DAYS"] != "90" {
		t.Errorf("PASS_MAX_DAYS = %q", got["PASS_MAX_DAYS"])
	}
	if got["PASS_MIN_DAYS"] != "7" { // key upper-cased regardless of source case
		t.Errorf("PASS_MIN_DAYS = %q", got["PASS_MIN_DAYS"])
	}
	if got["ENCRYPT_METHOD"] != "SHA512" {
		t.Errorf("ENCRYPT_METHOD = %q", got["ENCRYPT_METHOD"])
	}
}

func TestEvaluateLoginDefs(t *testing.T) {
	t.Run("compliant", func(t *testing.T) {
		got := map[string]string{
			"PASS_MAX_DAYS":  "90",
			"PASS_MIN_DAYS":  "7",
			"PASS_WARN_AGE":  "14",
			"UMASK":          "027",
			"ENCRYPT_METHOD": "SHA512",
		}
		if bad := evaluateLoginDefs(got); len(bad) != 0 {
			t.Errorf("expected compliant, got %v", bad)
		}
	})
	t.Run("violations", func(t *testing.T) {
		got := map[string]string{
			"PASS_MAX_DAYS":  "99999", // > 365
			"PASS_MIN_DAYS":  "0",     // < 1
			"PASS_WARN_AGE":  "3",     // < 7
			"UMASK":          "022",   // not 027/077
			"ENCRYPT_METHOD": "MD5",   // weak
		}
		bad := evaluateLoginDefs(got)
		if len(bad) != 5 {
			t.Errorf("got %d violations, want 5: %v", len(bad), bad)
		}
	})
	t.Run("unset keys", func(t *testing.T) {
		// Empty map: 3 unset int rules + ENCRYPT_METHOD missing = 4 (UMASK only
		// flagged when present and wrong).
		bad := evaluateLoginDefs(map[string]string{})
		if len(bad) != 4 {
			t.Errorf("got %d violations, want 4: %v", len(bad), bad)
		}
	})
	t.Run("non-numeric", func(t *testing.T) {
		bad := evaluateLoginDefs(map[string]string{
			"PASS_MAX_DAYS": "abc", "PASS_MIN_DAYS": "7", "PASS_WARN_AGE": "14",
			"ENCRYPT_METHOD": "YESCRYPT",
		})
		if len(bad) != 1 || !strings.Contains(bad[0], "not numeric") {
			t.Errorf("expected one not-numeric violation, got %v", bad)
		}
	})
}

func TestScanNopasswd(t *testing.T) {
	in := `# /etc/sudoers
root    ALL=(ALL:ALL) ALL
%admin  ALL=(ALL) ALL
deploy  ALL=(ALL) NOPASSWD: /usr/bin/systemctl
# %ci ALL=(ALL) NOPASSWD: ALL   <- commented, must be ignored
`
	bad, evs := scanNopasswd(strings.NewReader(in), "/etc/sudoers")
	if len(bad) != 1 {
		t.Fatalf("got %d NOPASSWD entries, want 1: %v", len(bad), bad)
	}
	if !strings.Contains(bad[0], "deploy") {
		t.Errorf("unexpected entry: %q", bad[0])
	}
	if len(evs) != 1 {
		t.Errorf("evidence count = %d, want 1", len(evs))
	}
}

func TestEvaluatePwquality(t *testing.T) {
	t.Run("strong", func(t *testing.T) {
		cfg := map[string]string{
			"minlen": "16", "dcredit": "-1", "ucredit": "-1", "ocredit": "-1", "lcredit": "-1",
		}
		if bad := evaluatePwquality(cfg); len(bad) != 0 {
			t.Errorf("expected compliant, got %v", bad)
		}
	})
	t.Run("short and positive credits", func(t *testing.T) {
		cfg := map[string]string{
			"minlen": "8", "dcredit": "0", "ucredit": "1", "ocredit": "-1", "lcredit": "-1",
		}
		// minlen too short + dcredit(0) + ucredit(1) flagged = 3
		bad := evaluatePwquality(cfg)
		if len(bad) != 3 {
			t.Errorf("got %d violations, want 3: %v", len(bad), bad)
		}
	})
	t.Run("empty config", func(t *testing.T) {
		// minlen + all 4 credits unset = 5
		if bad := evaluatePwquality(map[string]string{}); len(bad) != 5 {
			t.Errorf("got %d violations, want 5: %v", len(bad), bad)
		}
	})
}

func TestHasLockoutModule(t *testing.T) {
	cases := map[string]bool{
		"auth required pam_faillock.so preauth": true,
		"auth required pam_tally2.so deny=5":    true,
		"auth required pam_unix.so":             false,
		"":                                      false,
	}
	for in, want := range cases {
		if got := hasLockoutModule(in); got != want {
			t.Errorf("hasLockoutModule(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestScanServiceShells(t *testing.T) {
	passwd := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
backdoor:x:99:99:svc:/var/lib/svc:/bin/bash
games:x:5:60:games:/usr/games:/usr/bin/false
alice:x:1000:1000::/home/alice:/bin/bash
`
	bad := scanServiceShells(strings.NewReader(passwd))
	// Only `backdoor` qualifies: UID in (0,1000) with an interactive shell.
	// root (uid 0) and alice (uid>=1000) are skipped; sync is exempt; daemon
	// (nologin) and games (false) are fine.
	if len(bad) != 1 || !strings.Contains(bad[0], "backdoor") {
		t.Fatalf("got %v, want one entry for backdoor", bad)
	}
}

func TestAtoi(t *testing.T) {
	cases := map[string]int{
		"0":   0,
		"14":  14,
		"-1":  -1,
		"-99": -99,
		"":    0,
		"abc": -1, // non-numeric sentinel
		"1a2": -1,
		"007": 7,
	}
	for in, want := range cases {
		if got := atoi(in); got != want {
			t.Errorf("atoi(%q) = %d, want %d", in, got, want)
		}
	}
}
