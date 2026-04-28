package cve

import "testing"

func TestCompareDeb(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1}, // numeric segment ordering
		// tilde sorts before empty: 1.0~rc1 < 1.0
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		// epoch dominates upstream
		{"1:1.0", "2.0", 1},
		{"2.0", "1:0.5", -1},
		// debian revision
		{"1.0-1", "1.0-2", -1},
		{"1.0-1ubuntu1", "1.0-1ubuntu2", -1},
		// real-world-shaped versions from openssl in apt
		{"3.0.13-1ubuntu1", "3.0.13-1ubuntu2", -1},
		{"3.0.13-1ubuntu2", "3.0.13-1ubuntu2", 0},
		{"3.0.13-1ubuntu2", "3.0.13-2", -1}, // letters sort before non-letters per Debian rules
		// missing revision treated as "0"
		{"1.0", "1.0-1", -1},
	}
	for _, tc := range cases {
		got := compareDeb(tc.a, tc.b)
		if signum(got) != tc.want {
			t.Errorf("compareDeb(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareRpm(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		// rpm: tilde sorts before empty
		{"1.0~rc1", "1.0", -1},
		// trailing alpha is *newer* in rpm (no implicit pre-release semantics —
		// that's what tilde is for).
		{"1.0a", "1.0", 1},
		{"1.0a1", "1.0a2", -1},
		// epoch
		{"1:1.0-1", "2.0-1", 1},
		// release portion compared
		{"1.0-1.el8", "1.0-2.el8", -1},
		// real shape
		{"4.18.0-553.16.1.el8_10", "4.18.0-553.27.1.el8_10", -1},
	}
	for _, tc := range cases {
		got := compareRpm(tc.a, tc.b)
		if signum(got) != tc.want {
			t.Errorf("compareRpm(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareForEcosystem(t *testing.T) {
	if CompareForEcosystem("deb", "1.0~rc1", "1.0") >= 0 {
		t.Error("deb dispatch wrong")
	}
	if CompareForEcosystem("rpm", "4.18.0-553.16.1.el8_10", "4.18.0-553.27.1.el8_10") >= 0 {
		t.Error("rpm dispatch wrong")
	}
	if CompareForEcosystem("npm", "1.2.3", "1.2.4") >= 0 {
		t.Error("fallback dispatch wrong")
	}
}

func signum(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
