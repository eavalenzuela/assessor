package fs

import (
	"sort"
	"strings"
	"testing"
)

func TestParseMounts(t *testing.T) {
	in := `proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
short line
`
	m := parseMounts(in)
	if opts, ok := m["/tmp"]; !ok || len(opts) != 3 {
		t.Errorf("/tmp opts = %v", opts)
	}
	if _, ok := m["/"]; !ok {
		t.Error("/ not parsed")
	}
	if _, ok := m["short"]; ok {
		t.Error("short line should be skipped")
	}
}

func TestEvaluateMounts(t *testing.T) {
	t.Run("compliant", func(t *testing.T) {
		mounts := map[string][]string{
			"/tmp":     {"rw", "nosuid", "nodev", "noexec"},
			"/var/tmp": {"nosuid", "nodev", "noexec"},
			"/dev/shm": {"nosuid", "nodev", "noexec"},
		}
		bad, paths := evaluateMounts(mounts)
		if len(bad) != 0 || len(paths) != 0 {
			t.Errorf("expected compliant, got %v", bad)
		}
	})
	t.Run("missing options flagged", func(t *testing.T) {
		mounts := map[string][]string{
			"/tmp":  {"rw", "nosuid"},          // missing nodev, noexec
			"/home": {"rw", "nosuid", "nodev"}, // OK (only needs nosuid,nodev)
		}
		bad, paths := evaluateMounts(mounts)
		if len(bad) != 1 || len(paths) != 1 {
			t.Fatalf("got %v / %v, want 1 each", bad, paths)
		}
		if !strings.Contains(bad[0], "/tmp") || !strings.Contains(bad[0], "nodev") || !strings.Contains(bad[0], "noexec") {
			t.Errorf("unexpected message: %q", bad[0])
		}
	})
	t.Run("absent mountpoints skipped", func(t *testing.T) {
		// A sensitive path not mounted separately must not be flagged.
		if bad, _ := evaluateMounts(map[string][]string{}); len(bad) != 0 {
			t.Errorf("absent mounts should be skipped, got %v", bad)
		}
	})
}

func TestParseSwapDevices(t *testing.T) {
	in := `Filename				Type		Size	Used	Priority
/dev/dm-1                               partition	8000000	0	-2
/swapfile                               file		2000000	0	-3
`
	devs := parseSwapDevices(in)
	if len(devs) != 2 || devs[0] != "/dev/dm-1" || devs[1] != "/swapfile" {
		t.Fatalf("got %v, want [/dev/dm-1 /swapfile]", devs)
	}
	if d := parseSwapDevices("Filename Type Size Used Priority\n"); len(d) != 0 {
		t.Errorf("header-only should yield no devices, got %v", d)
	}
	if d := parseSwapDevices(""); len(d) != 0 {
		t.Errorf("empty should yield no devices, got %v", d)
	}
}

func TestUnencryptedSwap(t *testing.T) {
	lsblk := `NAME        FSTYPE      TYPE  MOUNTPOINTS
sda                     disk
├─sda1      ext4        part  /
└─sda2      crypto_LUKS part
  └─dm-1    swap        crypt  [SWAP]
`
	t.Run("encrypted swap passes", func(t *testing.T) {
		if bad := unencryptedSwap([]string{"/dev/dm-1"}, lsblk); len(bad) != 0 {
			t.Errorf("dm-1 is on a crypt line; want no bad, got %v", bad)
		}
	})
	t.Run("plaintext swapfile flagged", func(t *testing.T) {
		bad := unencryptedSwap([]string{"/swapfile"}, lsblk)
		if len(bad) != 1 || bad[0] != "/swapfile" {
			t.Errorf("got %v, want [/swapfile]", bad)
		}
	})
}

func TestParsePasswdHomes(t *testing.T) {
	in := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
alice:x:1000:1000::/home/alice:/bin/bash
weird:x:1001:1001::/:/bin/zsh
nohome:x:1002:1002:::/bin/bash
short:line
`
	homes := parsePasswdHomes(strings.NewReader(in))
	sort.Strings(homes)
	// Expected: /root, /bin (sync's home, shell /bin/sync is not nologin/false),
	// /home/alice. Excluded: daemon (nologin), weird (home "/"), nohome (empty home).
	want := []string{"/bin", "/home/alice", "/root"}
	if len(homes) != len(want) {
		t.Fatalf("got %v, want %v", homes, want)
	}
	for i := range want {
		if homes[i] != want[i] {
			t.Errorf("homes = %v, want %v", homes, want)
			break
		}
	}
}
