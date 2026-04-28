package containers

import (
	"context"
	"os"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type libvirtSocketCheck struct{}

func (libvirtSocketCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:       "containers.libvirt.socket_perms",
		Title:    "libvirt socket has restrictive perms",
		Bucket:   "containers",
		Severity: finding.SevHigh,
	}
}

func (libvirtSocketCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	const sock = "/var/run/libvirt/libvirt-sock"
	st, err := os.Stat(sock)
	if err != nil {
		return finding.Finding{Status: finding.StatusSkipped, Message: "libvirt socket absent"}
	}
	mode := st.Mode().Perm()
	ev := evidence.Note(sock, mode.String())
	if mode&0o006 != 0 {
		return finding.Finding{
			Status:   finding.StatusFail,
			Message:  "libvirt socket world-accessible",
			Evidence: []finding.Evidence{ev},
			Remediation: finding.Remediation{
				Commands: []string{"chmod 0660 " + sock, "chown root:libvirt " + sock},
			},
		}
	}
	return finding.Finding{Status: finding.StatusPass, Message: "libvirt socket perms OK", Evidence: []finding.Evidence{ev}}
}

func init() { engine.Register(libvirtSocketCheck{}) }
