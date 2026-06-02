package cve

import (
	"archive/zip"
	"bytes"
	"testing"
)

// buildOSVZip assembles an in-memory OSV-style bulk export from name->JSON
// entries so the parser can be exercised without touching the network.
func buildOSVZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestParseOSVZip(t *testing.T) {
	good := `{
	  "id": "DSA-1234-1",
	  "summary": "openssl flaw",
	  "affected": [{
	    "package": {"ecosystem": "Debian:12", "name": "openssl"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.10"}]}]
	  }]
	}`
	withdrawn := `{
	  "id": "DSA-9999-1",
	  "withdrawn": "2024-01-01T00:00:00Z",
	  "affected": [{"package": {"ecosystem": "Debian:12", "name": "curl"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0"}]}]}]
	}`
	noAffected := `{"id": "DSA-0000-1", "summary": "no packages", "affected": []}`
	junk := `not json at all`

	data := buildOSVZip(t, map[string]string{
		"DSA-1234-1.json": good,
		"DSA-9999-1.json": withdrawn,
		"DSA-0000-1.json": noAffected,
		"junk.json":       junk,
		"README.txt":      "ignored, not .json",
	})

	vulns, err := parseOSVZip(data)
	if err != nil {
		t.Fatalf("parseOSVZip: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("got %d vulns, want 1 (withdrawn/empty/junk/non-json must be skipped): %+v", len(vulns), vulns)
	}
	v := vulns[0]
	if v.ID != "DSA-1234-1" {
		t.Errorf("ID = %q, want DSA-1234-1", v.ID)
	}

	// End-to-end: the parsed record must match a package the apt lister tags "deb".
	db := NewDB()
	db.Add(v)
	if got := db.Match([]Package{{Ecosystem: "deb", Name: "openssl", Version: "3.0.9"}}); len(got) != 1 {
		t.Errorf("vulnerable openssl: got %d matches, want 1", len(got))
	}
	if got := db.Match([]Package{{Ecosystem: "deb", Name: "openssl", Version: "3.0.10"}}); len(got) != 0 {
		t.Errorf("patched openssl: got %d matches, want 0", len(got))
	}
}

func TestParseOSVZipBadArchive(t *testing.T) {
	if _, err := parseOSVZip([]byte("this is not a zip")); err == nil {
		t.Error("expected error on non-zip input")
	}
}
