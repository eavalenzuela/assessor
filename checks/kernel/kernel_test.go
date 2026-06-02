package kernel

import (
	"strings"
	"testing"
)

func TestEvaluateSysctl(t *testing.T) {
	t.Run("all match", func(t *testing.T) {
		got := map[string]string{}
		for k, v := range sysctlBaseline {
			got[k] = v
		}
		if bad := evaluateSysctl(got); len(bad) != 0 {
			t.Errorf("expected no drift, got %v", bad)
		}
	})
	t.Run("drift flagged", func(t *testing.T) {
		got := map[string]string{
			"kernel.kptr_restrict":        "0", // want 2
			"net.ipv4.tcp_syncookies":     "1", // matches
			"net.ipv4.conf.all.rp_filter": "0", // want 1
		}
		bad := evaluateSysctl(got)
		if len(bad) != 2 {
			t.Fatalf("got %d drifts, want 2: %v", len(bad), bad)
		}
		joined := strings.Join(bad, " ")
		if !strings.Contains(joined, "kernel.kptr_restrict=0 (want 2)") {
			t.Errorf("missing kptr_restrict drift: %v", bad)
		}
	})
	t.Run("absent keys skipped", func(t *testing.T) {
		// A key not present in `got` (kernel doesn't expose it) must not be flagged.
		if bad := evaluateSysctl(map[string]string{}); len(bad) != 0 {
			t.Errorf("absent keys should be skipped, got %v", bad)
		}
	})
}

func TestMissingCmdlineFlags(t *testing.T) {
	t.Run("all present", func(t *testing.T) {
		cmdline := "BOOT_IMAGE=/vmlinuz ro quiet " + strings.Join(wantedCmdlineFlags, " ")
		if m := missingCmdlineFlags(cmdline); len(m) != 0 {
			t.Errorf("expected none missing, got %v", m)
		}
	})
	t.Run("some missing", func(t *testing.T) {
		cmdline := "BOOT_IMAGE=/vmlinuz ro quiet slab_nomerge vsyscall=none"
		m := missingCmdlineFlags(cmdline)
		// init_on_alloc=1, init_on_free=1, page_alloc.shuffle=1 missing = 3
		if len(m) != 3 {
			t.Errorf("got %d missing, want 3: %v", len(m), m)
		}
	})
	t.Run("none present", func(t *testing.T) {
		if m := missingCmdlineFlags("ro quiet"); len(m) != len(wantedCmdlineFlags) {
			t.Errorf("got %d missing, want %d", len(m), len(wantedCmdlineFlags))
		}
	})
}

func TestIsLockdownNone(t *testing.T) {
	cases := map[string]bool{
		"[none] integrity confidentiality": true,
		"none [integrity] confidentiality": false,
		"none integrity [confidentiality]": false,
		"":                                 false,
	}
	for in, want := range cases {
		if got := isLockdownNone(in); got != want {
			t.Errorf("isLockdownNone(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestBlocklistedLoaded(t *testing.T) {
	lsmod := `Module                  Size  Used by
squashfs              property 0
xfs                   123456  1
usb_storage            73728  0
nf_tables             1234    0
dccp                   45056  0
`
	bad := blocklistedLoaded(lsmod)
	// squashfs and dccp are in the blocklist (with underscores normalized by
	// lsmod). usb_storage uses an underscore so does NOT match "usb-storage";
	// that mirrors the original behavior.
	if len(bad) != 2 {
		t.Fatalf("got %v, want [squashfs dccp]", bad)
	}
	joined := strings.Join(bad, " ")
	if !strings.Contains(joined, "squashfs") || !strings.Contains(joined, "dccp") {
		t.Errorf("unexpected blocklist hits: %v", bad)
	}
}

func TestBlocklistedLoadedEmpty(t *testing.T) {
	// Only the header line, no modules loaded.
	if bad := blocklistedLoaded("Module Size Used by\n"); len(bad) != 0 {
		t.Errorf("expected none, got %v", bad)
	}
}

func TestDmesgHits(t *testing.T) {
	out := `[ 0.0] usb 1-1: new high-speed USB device
[ 12.3] Out of memory: Killed process 4242 (java)
[ 13.0] normal informational line
[ 14.1] mce: [Hardware Error]: Machine check events logged
[ 15.0] traps: general protection fault in module
`
	hits := dmesgHits(out)
	// OOM line, hardware-error line (matches multiple patterns but counts once),
	// and the GPF line = 3.
	if len(hits) != 3 {
		t.Fatalf("got %d hits, want 3: %v", len(hits), hits)
	}
}
