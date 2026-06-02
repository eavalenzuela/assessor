package cve

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultOSVEcosystems is the set of distro ecosystems pulled by `cve sync`
// when none are specified. These are the OSV ecosystems whose package names
// line up with what the on-host package listers emit (see checks/packages),
// so matches actually land. Arch is intentionally absent — OSV does not
// publish an Arch Linux feed.
var DefaultOSVEcosystems = []string{
	"Debian",
	"Ubuntu",
	"Alpine",
	"Red Hat",
	"Rocky Linux",
	"AlmaLinux",
}

const osvBucketBase = "https://osv-vulnerabilities.storage.googleapis.com"

// OSVDownloader fetches OSV's per-ecosystem bulk exports. Each ecosystem is
// published as a single `all.zip` containing one JSON record per vulnerability.
type OSVDownloader struct {
	Client  *http.Client
	BaseURL string // overridable for testing; defaults to osvBucketBase
}

// FetchEcosystem downloads and parses the bulk export for one OSV ecosystem
// (e.g. "Debian", "Ubuntu"). The ecosystem is URL-escaped, so values with
// spaces like "Red Hat" work unchanged.
func (d *OSVDownloader) FetchEcosystem(ecosystem string) ([]Vuln, error) {
	if d.Client == nil {
		d.Client = &http.Client{Timeout: 120 * time.Second}
	}
	base := d.BaseURL
	if base == "" {
		base = osvBucketBase
	}
	u := fmt.Sprintf("%s/%s/all.zip", base, url.PathEscape(ecosystem))
	resp, err := d.Client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("osv %s: %w", ecosystem, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv %s: %s", ecosystem, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("osv %s: reading body: %w", ecosystem, err)
	}
	return parseOSVZip(body)
}

// parseOSVZip decodes an OSV bulk-export zip (one JSON record per entry) into
// Vulns. Entries that aren't JSON, fail to decode, or are withdrawn are
// skipped rather than aborting the whole import — a single malformed record
// shouldn't sink an entire ecosystem sync.
func parseOSVZip(data []byte) ([]Vuln, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	var out []Vuln
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		v, ok := decodeOSVEntry(f)
		if !ok {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// decodeOSVEntry reads a single zip entry as an OSV record. Withdrawn records
// (those carrying a "withdrawn" timestamp) and records with no affected
// packages are dropped. Returns ok=false on any read/parse failure.
func decodeOSVEntry(f *zip.File) (Vuln, bool) {
	rc, err := f.Open()
	if err != nil {
		return Vuln{}, false
	}
	defer rc.Close()
	var raw osvBulkRecord
	if err := json.NewDecoder(rc).Decode(&raw); err != nil {
		return Vuln{}, false
	}
	if raw.Withdrawn != "" || len(raw.Affected) == 0 {
		return Vuln{}, false
	}
	v := raw.osvRecord.toVuln()
	if len(v.Affected) == 0 {
		return Vuln{}, false
	}
	return v, true
}

// osvBulkRecord extends the single-record OSV schema with the "withdrawn"
// field present in bulk exports.
type osvBulkRecord struct {
	osvRecord
	Withdrawn string `json:"withdrawn"`
}
