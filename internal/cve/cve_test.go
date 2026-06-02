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
			name:      "case-insensitive name",
			pkgs:      []Package{{Ecosystem: "deb", Name: "OpenSSL", Version: "3.0.9"}},
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

// TestDBMatchEcosystemSpellings is the regression test for the bug where feed
// records and package listers used different ecosystem spellings and so never
// shared an index key. An OSV record tagged "Debian"/"Ubuntu" must match a
// package the apt lister tags "deb", and likewise for the rpm/arch/alpine
// families — but cross-family pairs must still NOT match.
func TestDBMatchEcosystemSpellings(t *testing.T) {
	db := NewDB()
	db.Add(Vuln{ID: "CVE-DEB", Severity: SevHigh,
		Affected: []Affected{{Ecosystem: "Debian", Package: "openssl", Fixed: "3.0.10"}}})
	db.Add(Vuln{ID: "CVE-UBU", Severity: SevHigh,
		Affected: []Affected{{Ecosystem: "Ubuntu", Package: "curl", Fixed: "8.4.0"}}})
	db.Add(Vuln{ID: "CVE-RPM", Severity: SevHigh,
		Affected: []Affected{{Ecosystem: "Red Hat", Package: "bash", Fixed: "5.2.0"}}})
	db.Add(Vuln{ID: "CVE-ALP", Severity: SevHigh,
		Affected: []Affected{{Ecosystem: "Alpine", Package: "musl", Fixed: "1.2.5"}}})

	cases := []struct {
		name      string
		pkg       Package
		wantCount int
	}{
		{"deb lister vs Debian feed", Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.9"}, 1},
		{"deb lister vs Ubuntu feed", Package{Ecosystem: "deb", Name: "curl", Version: "8.0.0"}, 1},
		{"rpm lister vs Red Hat feed", Package{Ecosystem: "rpm", Name: "bash", Version: "5.1.0"}, 1},
		{"alpine lister vs Alpine feed", Package{Ecosystem: "Alpine", Name: "musl", Version: "1.2.4"}, 1},
		{"cross-family deb vs rpm record", Package{Ecosystem: "deb", Name: "bash", Version: "5.1.0"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := db.Match([]Package{tc.pkg})
			if len(got) != tc.wantCount {
				t.Errorf("Match(%+v): got %d, want %d", tc.pkg, len(got), tc.wantCount)
			}
		})
	}
}

func TestCanonicalEcosystem(t *testing.T) {
	cases := map[string]string{
		"deb":              "deb",
		"Debian":           "deb",
		"Ubuntu":           "deb",
		"rpm":              "rpm",
		"Red Hat":          "rpm",
		"fedora":           "rpm",
		"Rocky Linux":      "rpm",
		"Arch Linux":       "arch",
		"Alpine":           "alpine",
		"":                 "",
		"npm":              "npm", // unknown -> lowercased passthrough
		"  Debian  ":       "deb", // surrounding whitespace tolerated
		"Debian:12":        "deb", // OSV release suffix stripped
		"Ubuntu:22.04:LTS": "deb", // multi-segment suffix stripped
		"Alpine:v3.18":     "alpine",
	}
	for in, want := range cases {
		if got := canonicalEcosystem(in); got != want {
			t.Errorf("canonicalEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}
