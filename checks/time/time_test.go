package time

import (
	"testing"

	"github.com/t3rmit3/assessor/internal/finding"
)

func TestTimedatectlSynced(t *testing.T) {
	synced := "Timezone=UTC\nNTPSynchronized=yes\nLocalRTC=no\n"
	notSynced := "Timezone=UTC\nNTPSynchronized=no\nLocalRTC=no\n"
	if !timedatectlSynced(synced) {
		t.Error("expected synced")
	}
	if timedatectlSynced(notSynced) {
		t.Error("expected not synced")
	}
	if timedatectlSynced("") {
		t.Error("empty should be not synced")
	}
}

func TestChronySynced(t *testing.T) {
	good := `Reference ID    : 0A0A0A0A (ntp.example)
Stratum         : 3
Leap status     : Normal
`
	bad := `Reference ID    : 00000000 ()
Leap status     : Not synchronised
`
	if !chronySynced(good) {
		t.Error("expected synced")
	}
	if chronySynced(bad) {
		t.Error("'Not synchronised' must not count as synced")
	}
	if chronySynced("no leap line") {
		t.Error("missing Leap status should be not synced")
	}
}

func TestClassifyTimezone(t *testing.T) {
	cases := []struct {
		target string
		want   finding.Status
	}{
		{"../usr/share/zoneinfo/Europe/Berlin", finding.StatusPass},
		{"/usr/share/zoneinfo/UTC", finding.StatusPass},
		{"../usr/share/zoneinfo/Factory", finding.StatusFail},
		{"", finding.StatusFail},
	}
	for _, tc := range cases {
		if got, _ := classifyTimezone(tc.target); got != tc.want {
			t.Errorf("classifyTimezone(%q) = %s, want %s", tc.target, got, tc.want)
		}
	}
}
