package cve

import "testing"

// compareVersions is a deliberately naïve comparator — pre-release suffix
// handling and distro-epoch semantics live in package adapters, not here.
// Tests cover only the upstream-numeric cases the helper is meant to handle.
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.2.10", "1.2.9", 1},
		{"1.10.0", "1.9.0", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.0", "1.0.0", -1},
		{"1.2.3", "1.2.3.1", -1},
		{"0.9", "1.0", -1},
	}
	for _, tc := range cases {
		got := compareVersions(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDBMatch(t *testing.T) {
	db := NewDB()
	db.Add(Vuln{
		ID:       "CVE-2024-0001",
		Severity: SevHigh,
		Affected: []Affected{
			{Ecosystem: "deb", Package: "openssl", Introduced: "0", Fixed: "3.0.10"},
		},
	})
	db.Add(Vuln{
		ID:       "CVE-2024-0002",
		Severity: SevMedium,
		Affected: []Affected{
			{Ecosystem: "deb", Package: "curl", Fixed: "8.4.0"},
		},
	})

	cases := []struct {
		name      string
		pkgs      []Package
		wantCount int
	}{
		{
			name:      "vulnerable openssl",
			pkgs:      []Package{{Ecosystem: "deb", Name: "openssl", Version: "3.0.9"}},
			wantCount: 1,
		},
		{
			name:      "patched openssl",
			pkgs:      []Package{{Ecosystem: "deb", Name: "openssl", Version: "3.0.10"}},
			wantCount: 0,
		},
		{
			name:      "wrong ecosystem",
			pkgs:      []Package{{Ecosystem: "rpm", Name: "openssl", Version: "3.0.9"}},
			wantCount: 0,
		},
		{
			name: "case-insensitive name",
			pkgs: []Package{{Ecosystem: "deb", Name: "OpenSSL", Version: "3.0.9"}},
			wantCount: 1,
		},
		{
			name: "multiple matches",
			pkgs: []Package{
				{Ecosystem: "deb", Name: "openssl", Version: "3.0.9"},
				{Ecosystem: "deb", Name: "curl", Version: "8.0.0"},
			},
			wantCount: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := db.Match(tc.pkgs)
			if len(got) != tc.wantCount {
				t.Errorf("Match: got %d, want %d (%+v)", len(got), tc.wantCount, got)
			}
		})
	}
}
