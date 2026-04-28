package network

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/t3rmit3/assessor/internal/engine"
	"github.com/t3rmit3/assessor/internal/evidence"
	"github.com/t3rmit3/assessor/internal/finding"
	"github.com/t3rmit3/assessor/internal/sysfacts"
)

type listeningCheck struct{}

func (listeningCheck) Meta() finding.Metadata {
	return finding.Metadata{
		ID:          "network.listening.inventory",
		Title:       "Listening TCP/UDP sockets bound to non-loopback addresses",
		Bucket:      "network",
		Severity:    finding.SevMedium,
		Description: "Catalog every listener and flag externally exposed ones",
		Profiles:    []string{"server", "workstation"},
	}
}

func (listeningCheck) Run(ctx context.Context, _ sysfacts.Facts) finding.Finding {
	var external, internal []string
	for _, p := range []struct{ proto, path string }{
		{"tcp", "/proc/net/tcp"},
		{"tcp6", "/proc/net/tcp6"},
		{"udp", "/proc/net/udp"},
		{"udp6", "/proc/net/udp6"},
	} {
		ents, err := readProcNet(p.path, p.proto)
		if err != nil {
			continue
		}
		for _, e := range ents {
			addr := e.local.String()
			if e.local.IP.IsLoopback() {
				internal = append(internal, fmt.Sprintf("%s %s", p.proto, addr))
			} else {
				external = append(external, fmt.Sprintf("%s %s", p.proto, addr))
			}
		}
	}
	sort.Strings(external)
	sort.Strings(internal)
	ev := evidence.Note("/proc/net/{tcp,tcp6,udp,udp6}",
		"external:\n  "+strings.Join(external, "\n  ")+
			"\nloopback-only:\n  "+strings.Join(internal, "\n  "))

	if len(external) == 0 {
		return finding.Finding{Status: finding.StatusPass, Message: "no external listeners",
			Evidence: []finding.Evidence{ev}}
	}
	sev := finding.SevMedium
	if len(external) > 5 {
		sev = finding.SevHigh
	}
	out := finding.Finding{
		Status:   finding.StatusWarn,
		Message:  fmt.Sprintf("%d external listener(s) — verify each is intended", len(external)),
		Evidence: []finding.Evidence{ev},
		Remediation: finding.Remediation{
			Description: "For each unintended listener, stop the service or bind to 127.0.0.1.",
		},
	}
	out.Meta.Severity = sev
	return out
}

type sock struct {
	local net.TCPAddr
	state string
}

func readProcNet(path, proto string) ([]sock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Scan() // header
	var out []sock
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 4 {
			continue
		}
		ip, port, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}
		if strings.HasPrefix(proto, "tcp") && fields[3] != "0A" {
			continue
		}
		out = append(out, sock{local: net.TCPAddr{IP: ip, Port: port}, state: fields[3]})
	}
	return out, nil
}

func parseHexAddr(s string) (net.IP, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("bad addr %q", s)
	}
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return nil, 0, err
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, 0, err
	}
	if len(raw) == 4 {
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]), int(port), nil
	}
	if len(raw) == 16 {
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			ip[i*4+0] = raw[i*4+3]
			ip[i*4+1] = raw[i*4+2]
			ip[i*4+2] = raw[i*4+1]
			ip[i*4+3] = raw[i*4+0]
		}
		return ip, int(port), nil
	}
	return nil, 0, fmt.Errorf("bad addr length")
}

func init() { engine.Register(listeningCheck{}) }
