package mac

import "testing"

func TestSelinuxBoolsOn(t *testing.T) {
	out := `abrt_anon_write --> off
antivirus_can_scan_system --> on
auditadm_exec_content --> on
cron_can_relabel --> off
`
	on := selinuxBoolsOn(out)
	if len(on) != 2 {
		t.Fatalf("got %d on-bools, want 2: %v", len(on), on)
	}
}

func TestCountComplainProfiles(t *testing.T) {
	out := `apparmor module is loaded.
32 profiles are loaded.
28 profiles are in enforce mode.
4 profiles are in complain mode.
   /usr/sbin/foo
0 processes are unconfined but have a profile defined.
`
	if got := countComplainProfiles(out); got != 4 {
		t.Errorf("got %d, want 4", got)
	}
	if got := countComplainProfiles("no complain line here"); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestUnconfinedSELinux(t *testing.T) {
	psOut := `LABEL                             PID TTY          TIME CMD
system_u:system_r:init_t:s0         1 ?        00:00:01 systemd
unconfined_u:unconfined_r:unconfined_t:s0  4242 ?  00:00:00 rogue
system_u:system_r:sshd_t:s0       900 ?        00:00:00 sshd
unconfined_u:unconfined_r:unconfined_t:s0  4300 ?  00:00:00 shell
`
	un := unconfinedSELinux(psOut)
	if len(un) != 2 {
		t.Fatalf("got %d unconfined, want 2: %v", len(un), un)
	}
}
