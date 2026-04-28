package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Severity string

const (
	SevNone     Severity = "none"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

type Vuln struct {
	ID         string   `json:"id"`
	Source     string   `json:"source"`
	Summary    string   `json:"summary"`
	Severity   Severity `json:"severity"`
	CVSS       float64  `json:"cvss,omitempty"`
	Published  string   `json:"published,omitempty"`
	References []string `json:"references,omitempty"`
	Affected   []Affected `json:"affected"`
}

type Affected struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Introduced string `json:"introduced,omitempty"`
	Fixed     string `json:"fixed,omitempty"`
}

type Package struct {
	Ecosystem string
	Name      string
	Version   string
}

type Match struct {
	Package Package
	Vuln    Vuln
}

type DB struct {
	byPackage map[string][]Vuln
}

func NewDB() *DB {
	return &DB{byPackage: map[string][]Vuln{}}
}

func (db *DB) Add(v Vuln) {
	for _, a := range v.Affected {
		key := a.Ecosystem + "::" + strings.ToLower(a.Package)
		db.byPackage[key] = append(db.byPackage[key], v)
	}
}

func (db *DB) Match(pkgs []Package) []Match {
	var out []Match
	for _, p := range pkgs {
		key := p.Ecosystem + "::" + strings.ToLower(p.Name)
		for _, v := range db.byPackage[key] {
			if affects(v, p) {
				out = append(out, Match{Package: p, Vuln: v})
			}
		}
	}
	return out
}

func affects(v Vuln, p Package) bool {
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package, p.Name) {
			continue
		}
		if a.Fixed == "" {
			return true
		}
		if compareVersions(p.Version, a.Fixed) < 0 {
			if a.Introduced == "" || compareVersions(p.Version, a.Introduced) >= 0 {
				return true
			}
		}
	}
	return false
}

// LoadCache loads previously-fetched feed JSON from disk.
func (db *DB) LoadCache(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var vs []Vuln
	if err := json.Unmarshal(b, &vs); err != nil {
		return err
	}
	for _, v := range vs {
		db.Add(v)
	}
	return nil
}

func (db *DB) SaveCache(path string) error {
	all := []Vuln{}
	seen := map[string]bool{}
	for _, vs := range db.byPackage {
		for _, v := range vs {
			if seen[v.ID] {
				continue
			}
			seen[v.ID] = true
			all = append(all, v)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o640)
}

// FetchOSV fetches a single OSV record by ID.
// Bulk download is via OSV.dev export buckets per ecosystem; left as a follow-up
// because it is large and should be cached.
func FetchOSV(ctx string, id string) (Vuln, error) {
	url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", id)
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return Vuln{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Vuln{}, fmt.Errorf("osv: %s", resp.Status)
	}
	var raw osvRecord
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Vuln{}, err
	}
	return raw.toVuln(), nil
}

type osvRecord struct {
	ID        string `json:"id"`
	Summary   string `json:"summary"`
	Published string `json:"published"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func (r osvRecord) toVuln() Vuln {
	v := Vuln{ID: r.ID, Source: "osv", Summary: r.Summary, Published: r.Published}
	for _, ref := range r.References {
		v.References = append(v.References, ref.URL)
	}
	for _, a := range r.Affected {
		af := Affected{Ecosystem: a.Package.Ecosystem, Package: a.Package.Name}
		for _, rng := range a.Ranges {
			for _, e := range rng.Events {
				if e.Introduced != "" {
					af.Introduced = e.Introduced
				}
				if e.Fixed != "" {
					af.Fixed = e.Fixed
				}
			}
		}
		v.Affected = append(v.Affected, af)
	}
	for _, s := range r.Severity {
		if strings.HasPrefix(s.Type, "CVSS") {
			v.Severity = mapCVSSToSeverity(s.Score)
		}
	}
	return v
}

func mapCVSSToSeverity(score string) Severity {
	switch {
	case strings.Contains(score, "/AV:N") && strings.Contains(score, "/I:H"):
		return SevHigh
	default:
		return SevMedium
	}
}

// NVDDownloader is a stub for NVD JSON 2.0 feed ingest. The feed is paginated
// and rate-limited; production callers should use an API key and incremental sync.
type NVDDownloader struct {
	APIKey string
	Client *http.Client
}

func (n *NVDDownloader) FetchPage(startIndex int) ([]Vuln, int, error) {
	if n.Client == nil {
		n.Client = &http.Client{Timeout: 30 * time.Second}
	}
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=%d&resultsPerPage=2000", startIndex)
	req, _ := http.NewRequest("GET", url, nil)
	if n.APIKey != "" {
		req.Header.Set("apiKey", n.APIKey)
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("nvd: %s: %s", resp.Status, string(body))
	}
	var raw nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, 0, err
	}
	out := make([]Vuln, 0, len(raw.Vulnerabilities))
	for _, item := range raw.Vulnerabilities {
		out = append(out, item.CVE.toVuln())
	}
	return out, raw.TotalResults, nil
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	ResultsPerPage  int `json:"resultsPerPage"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CvssMetricV31 []struct {
			CvssData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CpeMatch []struct {
				Criteria              string `json:"criteria"`
				VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
				VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

func (c nvdCVE) toVuln() Vuln {
	v := Vuln{ID: c.ID, Source: "nvd", Published: c.Published}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			v.Summary = d.Value
			break
		}
	}
	if len(c.Metrics.CvssMetricV31) > 0 {
		m := c.Metrics.CvssMetricV31[0].CvssData
		v.CVSS = m.BaseScore
		v.Severity = Severity(strings.ToLower(m.BaseSeverity))
	}
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			for _, m := range n.CpeMatch {
				parts := strings.Split(m.Criteria, ":")
				if len(parts) >= 6 {
					v.Affected = append(v.Affected, Affected{
						Ecosystem:  "cpe",
						Package:    parts[3] + "/" + parts[4],
						Introduced: m.VersionStartIncluding,
						Fixed:      m.VersionEndExcluding,
					})
				}
			}
		}
	}
	return v
}

// compareVersions returns -1/0/1 using a best-effort numeric/segmented comparison.
// Good enough for upstream semver-ish strings; distro epoch handling lives in
// the distro-specific package adapters.
func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	as := splitVer(a)
	bs := splitVer(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv string
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av == bv {
			continue
		}
		if isNumeric(av) && isNumeric(bv) {
			if len(av) != len(bv) {
				if len(av) < len(bv) {
					return -1
				}
				return 1
			}
		}
		if av < bv {
			return -1
		}
		return 1
	}
	return 0
}

func splitVer(s string) []string {
	var out []string
	cur := strings.Builder{}
	for _, r := range s {
		if r == '.' || r == '-' || r == '+' || r == '~' {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
