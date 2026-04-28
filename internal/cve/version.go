package cve

import (
	"strings"
	"unicode"
)

// CompareForEcosystem dispatches to the right comparator for the given
// ecosystem string. Falls back to the naïve segmented comparator for
// upstream-style versions (OSV / NVD CPE).
func CompareForEcosystem(eco, a, b string) int {
	switch strings.ToLower(eco) {
	case "deb", "debian", "ubuntu":
		return compareDeb(a, b)
	case "rpm", "rhel", "fedora", "centos", "rocky", "alma":
		return compareRpm(a, b)
	}
	return compareVersions(a, b)
}

// compareDeb implements Debian's version comparison from `man deb-version`.
// Format: [epoch:]upstream_version[-debian_revision]
//   - epoch: integer; absent means 0; compared numerically.
//   - upstream_version: alternating runs of digits and non-digits; non-digit
//     runs are compared lexically except '~' sorts BEFORE empty (and thus before
//     anything else), letters sort before non-letters, '~' < empty < letters < everything else.
//   - debian_revision: same algorithm; absent means "0" (treated as less than any non-empty).
func compareDeb(a, b string) int {
	ea, ua, ra := splitDeb(a)
	eb, ub, rb := splitDeb(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := compareDebPart(ua, ub); c != 0 {
		return c
	}
	return compareDebPart(ra, rb)
}

func splitDeb(v string) (epoch int, upstream, revision string) {
	if i := strings.Index(v, ":"); i >= 0 {
		// epoch must be all digits.
		ok := true
		for _, r := range v[:i] {
			if r < '0' || r > '9' {
				ok = false
				break
			}
		}
		if ok && i > 0 {
			for _, r := range v[:i] {
				epoch = epoch*10 + int(r-'0')
			}
			v = v[i+1:]
		}
	}
	if i := strings.LastIndex(v, "-"); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, "0"
}

// compareDebPart compares two upstream / debian-revision strings using
// Debian's mixed-alpha rules.
func compareDebPart(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		// 1) compare a non-digit prefix
		ai := nonDigitPrefix(a)
		bi := nonDigitPrefix(b)
		if c := compareDebNonDigit(a[:ai], b[:bi]); c != 0 {
			return c
		}
		a = a[ai:]
		b = b[bi:]
		// 2) compare a digit prefix as integer
		ai = digitPrefix(a)
		bi = digitPrefix(b)
		if c := compareDigits(a[:ai], b[:bi]); c != 0 {
			return c
		}
		a = a[ai:]
		b = b[bi:]
	}
	return 0
}

func nonDigitPrefix(s string) int {
	for i, r := range s {
		if unicode.IsDigit(r) {
			return i
		}
	}
	return len(s)
}

func digitPrefix(s string) int {
	for i, r := range s {
		if !unicode.IsDigit(r) {
			return i
		}
	}
	return len(s)
}

// compareDebNonDigit applies Debian's lexicographic ordering with the
// '~' < empty < letter < other rule.
func compareDebNonDigit(a, b string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var av, bv byte
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av == bv {
			continue
		}
		return debCharOrder(av) - debCharOrder(bv)
	}
	return 0
}

// debCharOrder maps a byte to its sort weight under Debian rules.
// '~' sorts lowest, then empty (encoded as 0), then letters, then others.
func debCharOrder(b byte) int {
	switch {
	case b == '~':
		return -1
	case b == 0:
		return 0
	case b >= 'A' && b <= 'Z':
		return int(b)
	case b >= 'a' && b <= 'z':
		return int(b)
	}
	return int(b) + 256 // bump non-letters above letters
}

func compareDigits(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// compareRpm implements rpmvercmp behavior: split into segments of digits or
// alphas, compare digit-vs-digit numerically, alpha-vs-alpha lexically, digit
// always wins over alpha. Tilde sorts before empty.
func compareRpm(a, b string) int {
	// epoch handling: `[epoch:]ver-rel`
	if i := strings.Index(a, ":"); i >= 0 {
		ai, bi := 0, 0
		j := strings.Index(b, ":")
		if j < 0 {
			j = -1
		}
		// fall through to compareDigits for epoch portion
		ea := a[:i]
		eb := ""
		if j >= 0 {
			eb = b[:j]
		}
		_ = ai
		_ = bi
		if c := compareDigits(ea, eb); c != 0 {
			return c
		}
		a = a[i+1:]
		if j >= 0 {
			b = b[j+1:]
		}
	}
	// rpmvercmp main loop
	for len(a) > 0 && len(b) > 0 {
		// strip leading non-alphanumerics, but tilde is special.
		if a[0] == '~' || b[0] == '~' {
			if a[0] != '~' {
				return 1
			}
			if b[0] != '~' {
				return -1
			}
			a = a[1:]
			b = b[1:]
			continue
		}
		for len(a) > 0 && !isAlnum(a[0]) && a[0] != '~' {
			a = a[1:]
		}
		for len(b) > 0 && !isAlnum(b[0]) && b[0] != '~' {
			b = b[1:]
		}
		if len(a) == 0 || len(b) == 0 {
			break
		}
		if isDigit(a[0]) || isDigit(b[0]) {
			ai := digitPrefix(a)
			bi := digitPrefix(b)
			if ai == 0 {
				return -1 // alpha < digit in rpm
			}
			if bi == 0 {
				return 1
			}
			if c := compareDigits(a[:ai], b[:bi]); c != 0 {
				return c
			}
			a = a[ai:]
			b = b[bi:]
		} else {
			ai := alphaPrefix(a)
			bi := alphaPrefix(b)
			seg1, seg2 := a[:ai], b[:bi]
			if seg1 < seg2 {
				return -1
			}
			if seg1 > seg2 {
				return 1
			}
			a = a[ai:]
			b = b[bi:]
		}
	}
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		if len(b) > 0 && b[0] == '~' {
			return 1
		}
		return -1
	}
	if a[0] == '~' {
		return -1
	}
	return 1
}

func isAlnum(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func alphaPrefix(s string) int {
	for i := 0; i < len(s); i++ {
		if !((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z')) {
			return i
		}
	}
	return len(s)
}
