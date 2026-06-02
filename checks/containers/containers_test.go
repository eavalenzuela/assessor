package containers

import (
	"strings"
	"testing"

	"github.com/t3rmit3/assessor/internal/finding"
)

func TestEvaluateDockerDaemon(t *testing.T) {
	t.Run("hardened", func(t *testing.T) {
		j := `{"userns-remap":"default","no-new-privileges":true,"live-restore":true}`
		bad, err := evaluateDockerDaemon([]byte(j))
		if err != nil || len(bad) != 0 {
			t.Errorf("expected hardened, got %v (err %v)", bad, err)
		}
	})
	t.Run("insecure defaults", func(t *testing.T) {
		bad, err := evaluateDockerDaemon([]byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(bad) != 3 {
			t.Errorf("got %d issues, want 3: %v", len(bad), bad)
		}
	})
	t.Run("malformed json", func(t *testing.T) {
		if _, err := evaluateDockerDaemon([]byte(`{not json`)); err == nil {
			t.Error("expected parse error")
		}
	})
}

func TestEvaluatePrivileged(t *testing.T) {
	inspects := []containerInspect{
		{Name: "/safe"},
		func() containerInspect {
			c := containerInspect{Name: "/danger"}
			c.HostConfig.Privileged = true
			c.HostConfig.NetworkMode = "host"
			return c
		}(),
		func() containerInspect {
			c := containerInspect{Name: "/capper"}
			c.HostConfig.CapAdd = []string{"NET_ADMIN", "SYS_ADMIN"}
			c.HostConfig.PidMode = "host"
			return c
		}(),
	}
	bad := evaluatePrivileged(inspects)
	if len(bad) != 2 {
		t.Fatalf("got %d flagged, want 2: %v", len(bad), bad)
	}
	joined := strings.Join(bad, " | ")
	if !strings.Contains(joined, "danger: privileged,net=host") {
		t.Errorf("danger issues wrong: %v", bad)
	}
	if !strings.Contains(joined, "capper: pid=host,cap_add=SYS_ADMIN") {
		t.Errorf("capper issues wrong: %v", bad)
	}
}

func TestEvaluateKubelet(t *testing.T) {
	t.Run("hardened yaml", func(t *testing.T) {
		y := `
authentication:
  anonymous:
    enabled: false
authorization:
  mode: Webhook
readOnlyPort: 0
`
		bad, err := evaluateKubelet([]byte(y))
		if err != nil || len(bad) != 0 {
			t.Errorf("expected hardened, got %v (err %v)", bad, err)
		}
	})
	t.Run("insecure yaml", func(t *testing.T) {
		y := `
authentication:
  anonymous:
    enabled: true
authorization:
  mode: AlwaysAllow
readOnlyPort: 10255
`
		bad, err := evaluateKubelet([]byte(y))
		if err != nil {
			t.Fatal(err)
		}
		if len(bad) != 3 {
			t.Errorf("got %d issues, want 3: %v", len(bad), bad)
		}
	})
	t.Run("empty mode flagged", func(t *testing.T) {
		// No authorization.mode set -> defaults to "" which must be flagged.
		bad, _ := evaluateKubelet([]byte("readOnlyPort: 0\n"))
		if len(bad) != 1 || !strings.Contains(bad[0], "authorization.mode") {
			t.Errorf("expected empty-mode flag, got %v", bad)
		}
	})
	t.Run("json config", func(t *testing.T) {
		j := `{"authentication":{"anonymous":{"enabled":false}},"authorization":{"mode":"Webhook"},"readOnlyPort":0}`
		bad, err := evaluateKubelet([]byte(j))
		if err != nil || len(bad) != 0 {
			t.Errorf("json parse: got %v (err %v)", bad, err)
		}
	})
}

func TestClassifyDockerRootless(t *testing.T) {
	cases := []struct {
		in   string
		want finding.Status
	}{
		{"[name=seccomp,profile=default name=rootless]", finding.StatusPass},
		{"[name=userns name=seccomp]", finding.StatusPass},
		{"[name=seccomp,profile=default]", finding.StatusWarn},
		{"", finding.StatusWarn},
	}
	for _, tc := range cases {
		if got, _ := classifyDockerRootless(tc.in); got != tc.want {
			t.Errorf("classifyDockerRootless(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
