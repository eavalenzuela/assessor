package profiles

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/t3rmit3/assessor/internal/finding"
)

// Profile is the on-disk schema for profiles/<name>.yaml. Each field is
// optional; an empty profile matches every check.
type Profile struct {
	Name           string   `yaml:"name"`
	Description    string   `yaml:"description"`
	IncludeBuckets []string `yaml:"include_buckets"`
	ExcludeBuckets []string `yaml:"exclude_buckets"`
	IncludeIDs     []string `yaml:"include_ids"`
	ExcludeIDs     []string `yaml:"exclude_ids"`
}

// Load reads a profile from a YAML file. If the path doesn't exist and
// `name` matches a check's inline profile metadata, returns a synthetic
// profile that matches by name only (the engine then uses the legacy
// `Metadata.Profiles` field for filtering).
func Load(dir, name string) (*Profile, error) {
	if name == "" {
		return nil, nil
	}
	path := filepath.Join(dir, name+".yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Fall back to inline profile metadata. Caller will use Profile.Name
			// as the legacy filter key.
			return &Profile{Name: name}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var p Profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if p.Name == "" {
		p.Name = name
	}
	return &p, nil
}

// Match returns true if the given check metadata is included in the profile.
// Logic:
//  1. ExcludeBuckets / ExcludeIDs always win.
//  2. If IncludeBuckets / IncludeIDs are set, require a match against them.
//  3. If any include/exclude list is set (even just excludes), match-all-rest.
//  4. Otherwise (no lists), fall back to inline `m.Profiles` matching by name.
func (p *Profile) Match(m finding.Metadata) bool {
	if p == nil {
		return true
	}
	for _, b := range p.ExcludeBuckets {
		if b == m.Bucket {
			return false
		}
	}
	for _, id := range p.ExcludeIDs {
		if id == m.ID {
			return false
		}
	}
	hasIncludes := len(p.IncludeBuckets) > 0 || len(p.IncludeIDs) > 0
	hasExcludes := len(p.ExcludeBuckets) > 0 || len(p.ExcludeIDs) > 0
	if hasIncludes {
		for _, b := range p.IncludeBuckets {
			if b == m.Bucket {
				return true
			}
		}
		for _, id := range p.IncludeIDs {
			if id == m.ID {
				return true
			}
		}
		return false
	}
	if hasExcludes {
		return true // exclude-only profile: everything not excluded passes
	}
	// No lists at all — fall back to inline-profile-list match by name.
	if len(m.Profiles) == 0 {
		return true
	}
	for _, mp := range m.Profiles {
		if mp == p.Name {
			return true
		}
	}
	return false
}
