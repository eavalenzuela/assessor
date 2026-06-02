package services

import "testing"

func TestNonEmptyLines(t *testing.T) {
	in := "  \nfoo.service loaded failed\n\n   \nbar.timer active\n"
	lines := nonEmptyLines(in)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %v", len(lines), lines)
	}
	if lines[0] != "foo.service loaded failed" || lines[1] != "bar.timer active" {
		t.Errorf("unexpected lines: %v", lines)
	}
	if l := nonEmptyLines(""); len(l) != 0 {
		t.Errorf("empty input should yield no lines, got %v", l)
	}
}

func TestIsUnwantedEnabledState(t *testing.T) {
	cases := map[string]bool{
		"enabled":  true,
		"static":   true,
		"disabled": false,
		"masked":   false,
		"":         false,
	}
	for state, want := range cases {
		if got := isUnwantedEnabledState(state); got != want {
			t.Errorf("isUnwantedEnabledState(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestRiskyUnits(t *testing.T) {
	out := `UNIT                          EXPOSURE PREDICATE HAPPY
foo.service                        9.6 EXPOSED   🙁
bar.service                        2.1 OK        🙂
baz.service                       10.0 UNSAFE    😨
qux.service                        4.0 MEDIUM    😐
`
	risky := riskyUnits(out)
	if len(risky) != 2 {
		t.Fatalf("got %d risky, want 2: %v", len(risky), risky)
	}
}
