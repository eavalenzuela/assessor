package cron

import (
	"os"
	"testing"
)

// cron's checks are otherwise filesystem-bound (os.Stat / WalkDir); the
// world-writable bit test is the only pure security predicate worth pinning.
func TestIsWorldWritable(t *testing.T) {
	cases := map[os.FileMode]bool{
		0o644: false,
		0o600: false,
		0o664: false, // group-writable, but not world — not flagged
		0o646: true,  // other-write
		0o777: true,
		0o002: true,
		0o020: false, // group-write only
	}
	for mode, want := range cases {
		if got := isWorldWritable(mode); got != want {
			t.Errorf("isWorldWritable(%o) = %v, want %v", mode, got, want)
		}
	}
}
